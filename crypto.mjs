import crypto from 'node:crypto';
import net from 'node:net';
import EventEmitter from 'node:events';

const PROTOCOL_VERSION = Buffer.from([0x01]);
const ALGORITHM = 'aes-256-gcm';
const MAX_PACKET_SIZE = 1024 * 1024;
const HANDSHAKE_TIMEOUT = 10000;

const STATE = { HANDSHAKE: 0, AUTHORIZING: 1, SECURE: 2 };

function computeFinished(key, transcript) {
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(Buffer.concat(transcript));
  return hmac.digest();
}

class ShadowSession extends EventEmitter {
  constructor(socket) {
    super();
    this.socket = socket;
    this.state = STATE.HANDSHAKE;
    this.buffer = Buffer.alloc(0);
    this.keys = { tx: null, rx: null, master: null };
    this.transcript = [PROTOCOL_VERSION];
    this.seq = { tx: 0n, rx: 0n };

    this.socket.on('data', (chunk) => this._onData(chunk));
    this.socket.on('error', (err) => this.emit('error', err));
    this.socket.on('close', () => this._destroy());
    this.socket.setTimeout(HANDSHAKE_TIMEOUT, () => {
      if (this.state !== STATE.SECURE) this.socket.destroy();
    });
  }

  _updateTranscript(data) { this.transcript.push(Buffer.from(data)); }

  _deriveKeys(sharedSecret) {
    const salt = Buffer.from('ShadowTunnel_v1_Salt');
    this.keys.master = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, 'master_secret', 32));
    const derived = Buffer.from(crypto.hkdfSync('sha256', this.keys.master, salt, 'session_keys', 64));
    return { tx: derived.subarray(0, 32), rx: derived.subarray(32, 64) };
  }

  write(data) {
    if (this.state === STATE.HANDSHAKE) return;

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ALGORITHM, this.keys.tx, iv);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(data.length + 12 + 16);

    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(this.seq.tx++);
    cipher.setAAD(Buffer.concat([header, seqBuf]));

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    this.socket.write(Buffer.concat([header, iv, cipher.getAuthTag(), encrypted]));
  }

  _decrypt(header, payload) {
    const iv = payload.subarray(0, 12);
    const tag = payload.subarray(12, 28);
    const ciphertext = payload.subarray(28);
    const decipher = crypto.createDecipheriv(ALGORITHM, this.keys.rx, iv);

    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(this.seq.rx++);
    decipher.setAuthTag(tag);
    decipher.setAAD(Buffer.concat([header, seqBuf]));

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  _onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    try {
      if (this.state === STATE.HANDSHAKE) this._handleHandshake();
      else this._processPackets();
    } catch (e) {
      console.error(`[Crypto Error] State: ${this.state}, Reason:`, e.message);
      this.socket.destroy();
    }
  }

  _processPackets() {
    while (this.buffer.length >= 4) {
      const packetLen = this.buffer.readUInt32BE(0);
      if (packetLen > MAX_PACKET_SIZE) throw new Error('Packet too large');
      if (this.buffer.length < packetLen + 4) break;

      const header = this.buffer.subarray(0, 4);
      const payload = this.buffer.subarray(4, 4 + packetLen);
      this.buffer = this.buffer.subarray(4 + packetLen);

      const decrypted = this._decrypt(header, payload);
      if (this.state === STATE.AUTHORIZING) this._handleAuthResponse(decrypted);
      else this.emit('data', decrypted);
    }
  }

  _destroy() {
    if (this.keys.tx) this.keys.tx.fill(0);
    if (this.keys.rx) this.keys.rx.fill(0);
    if (this.keys.master) this.keys.master.fill(0);
    this.emit('close');
  }
}

export class Server extends EventEmitter {
  constructor(options) {
    super();
    this.options = options;
    this.server = net.createServer((socket) => {
      const session = new ServerSession(socket, this.options);
      session.on('secure', () => this.emit('connection', session));
    });
  }
  listen(port, cb) { this.server.listen(port, cb); }
}

class ServerSession extends ShadowSession {
  constructor(socket, options) {
    super(socket);
    this.identityKey = options.privateKey;
    this.password = options.password;
    this.ecdh = crypto.createECDH('prime256v1');
    this.ecdh.generateKeys();
  }

  _handleHandshake() {
    if (this.buffer.length < 66) return;
    const version = this.buffer[0];
    const clientPub = this.buffer.subarray(1, 66);
    this.buffer = this.buffer.subarray(66);

    if (version !== PROTOCOL_VERSION[0]) throw new Error('Version mismatch');

    this._updateTranscript(clientPub);

    const serverPub = this.ecdh.getPublicKey();
    const sharedSecret = this.ecdh.computeSecret(clientPub);
    const derived = this._deriveKeys(sharedSecret);
    this.keys.tx = derived.rx;
    this.keys.rx = derived.tx;

    this._updateTranscript(serverPub);
    const signature = crypto.sign(undefined, Buffer.concat(this.transcript), this.identityKey);

    const res = Buffer.alloc(4);
    res.writeUInt32BE(signature.length);
    this.socket.write(Buffer.concat([serverPub, res, signature]));
    this.state = STATE.AUTHORIZING;
  }

  _handleAuthResponse(data) {
    const passPart = data.subarray(0, data.length - 32).toString();
    const clientFinished = data.subarray(data.length - 32);

    const expectedFinished = computeFinished(this.keys.master, this.transcript);
    if (!crypto.timingSafeEqual(clientFinished, expectedFinished)) throw new Error('Handshake integrity failed');

    if (passPart === this.password) {
      this.state = STATE.SECURE;
      this.socket.setTimeout(0);
      const serverFinished = computeFinished(this.keys.master, [...this.transcript, clientFinished]);
      this.write(Buffer.concat([Buffer.from('AUTH_OK'), serverFinished]));
      this.emit('secure');
    } else {
      this.socket.destroy();
    }
  }
}

export class Client extends ShadowSession {
  constructor({ serverPublicKey, password }) {
    super(new net.Socket());
    this.serverIdentity = serverPublicKey;
    this.password = password;
    this.ecdh = crypto.createECDH('prime256v1');
    this.ecdh.generateKeys();
  }

  connect(port, host, cb) {
    if (cb) this.on('secure', cb);
    this.socket.connect(port, host, () => {
      const clientPub = this.ecdh.getPublicKey();
      this._updateTranscript(clientPub);
      this.socket.write(Buffer.concat([PROTOCOL_VERSION, clientPub]));
    });
  }

  _handleHandshake() {
    if (this.buffer.length < 69) return;
    const serverPub = this.buffer.subarray(0, 65);
    const signLen = this.buffer.readUInt32BE(65);
    if (this.buffer.length < 69 + signLen) return;

    const signature = this.buffer.subarray(69, 69 + signLen);
    this.buffer = this.buffer.subarray(69 + signLen);

    const transcriptForVerify = Buffer.concat([...this.transcript, serverPub]);

    const isVerified = crypto.verify(undefined, transcriptForVerify, this.serverIdentity, signature);
    if (!isVerified) throw new Error('Signature invalid');

    this._updateTranscript(serverPub);

    const sharedSecret = this.ecdh.computeSecret(serverPub);
    const derived = this._deriveKeys(sharedSecret);
    this.keys.tx = derived.tx;
    this.keys.rx = derived.rx;

    this.state = STATE.AUTHORIZING;

    const finished = computeFinished(this.keys.master, this.transcript);
    this.write(Buffer.concat([Buffer.from(this.password), finished]));
    this._updateTranscript(finished);
  }

  _handleAuthResponse(data) {
    const status = data.subarray(0, 7).toString();
    const serverFinished = data.subarray(7);

    const expectedFinished = computeFinished(this.keys.master, this.transcript);

    if (status === 'AUTH_OK' && crypto.timingSafeEqual(serverFinished, expectedFinished)) {
      this.state = STATE.SECURE;
      this.socket.setTimeout(0);
      this.emit('secure');
    } else {
      this.socket.destroy();
    }
  }
}
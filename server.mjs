import net from 'node:net';
import fs from 'node:fs';
import crypto from 'node:crypto';

import {
  PROTO_VERSION,
  MSG_HANDSHAKE,
  MSG_DATA,
  generateEphemeralKeys,
  computeSharedSecret,
  deriveKeys,
  encrypt,
  decrypt,
  signData,
  verifyData,
  encodeFrame,
  PacketParser,
} from './crypto.mjs';

const PORT = 1235;

// Server long-term identity (pinned by clients)
const serverPrivKey = crypto.createPrivateKey(fs.readFileSync('./server_identity'));

// Optional: if set, server will REQUIRE client auth and verify against this key
const CLIENT_PUB_PATH = process.env.CLIENT_PUB_KEY_PATH; // e.g. "./client_identity.pub"
const clientPubKey = CLIENT_PUB_PATH
  ? crypto.createPublicKey(fs.readFileSync(CLIENT_PUB_PATH))
  : null;

class Conn {
  constructor(socket) {
    this.socket = socket;
    this.handshakeDone = false;

    const { publicKey, privateKey } = generateEphemeralKeys();
    this.ephPub = publicKey;
    this.ephPriv = privateKey;

    this.sPubDer = this.ephPub.export({ type: 'spki', format: 'der' });

    this.sendSeq = 0n;
    this.recvSeq = 0n;

    this.inKey = null;
    this.outKey = null;

    this.parser = new PacketParser({
      onPacket: (type, seq, payload) => this.onPacket(type, seq, payload),
      onError: () => this.socket.destroy(),
    });

    socket.setNoDelay(true);

    socket.on('data', (d) => this.parser.add(d));
    socket.on('error', () => {});
    socket.on('close', () => {
      this.handshakeDone = false;
    });

    this.sendServerHello();
  }

  sendServerHello() {
    // SERVER_HELLO payload:
    // u8 version | u16 sPubLen | sPubDer | u16 sigLen | sig
    const version = Buffer.from([PROTO_VERSION]);

    const pubLen = Buffer.alloc(2);
    pubLen.writeUInt16BE(this.sPubDer.length);

    const toSign = Buffer.concat([
      Buffer.from([PROTO_VERSION]),
      Buffer.from('server', 'utf8'),
      this.sPubDer,
    ]);
    const sig = signData(toSign, serverPrivKey);

    const sigLen = Buffer.alloc(2);
    sigLen.writeUInt16BE(sig.length);

    const payload = Buffer.concat([version, pubLen, this.sPubDer, sigLen, sig]);
    this.socket.write(encodeFrame(MSG_HANDSHAKE, 0n, payload));
  }

  onPacket(type, seq, payload) {
    if (type === MSG_HANDSHAKE && !this.handshakeDone) {
      this.handleClientHello(payload);
      return;
    }

    if (type === MSG_DATA && this.handshakeDone) {
      // Strict monotonic sequence (TCP-ordered)
      if (seq !== this.recvSeq) return this.socket.destroy();

      try {
        const pt = decrypt(payload, this.inKey, seq);
        this.recvSeq++;
        process.stdout.write(pt.toString());
      } catch {
        this.socket.destroy();
      }
      return;
    }

    // Anything else (unexpected) => drop connection
    this.socket.destroy();
  }

  handleClientHello(payload) {
    // CLIENT_HELLO payload:
    // u8 version | u16 cPubLen | cPubDer | u16 sigLen | sig
    if (payload.length < 1 + 2 + 2) return this.socket.destroy();

    const version = payload.readUInt8(0);
    if (version !== PROTO_VERSION) return this.socket.destroy();

    const cPubLen = payload.readUInt16BE(1);
    const minLen = 1 + 2 + cPubLen + 2;
    if (payload.length < minLen) return this.socket.destroy();

    const cPubDer = payload.subarray(3, 3 + cPubLen);
    const sigLen = payload.readUInt16BE(3 + cPubLen);
    const sig = payload.subarray(3 + cPubLen + 2);

    if (sig.length !== sigLen) return this.socket.destroy();

    // If server expects client auth, require signature
    if (clientPubKey) {
      if (sigLen === 0) return this.socket.destroy();

      const toVerify = Buffer.concat([
        Buffer.from([PROTO_VERSION]),
        Buffer.from('client', 'utf8'),
        cPubDer,
        this.sPubDer, // bind client hello to this server ephemeral
      ]);

      if (!verifyData(toVerify, sig, clientPubKey)) return this.socket.destroy();
    }

    const cPubKeyObj = crypto.createPublicKey({ key: cPubDer, type: 'spki', format: 'der' });
    const shared = computeSharedSecret(this.ephPriv, cPubKeyObj);

    const { k_c2s, k_s2c } = deriveKeys(shared, this.sPubDer, cPubDer);
    // Server receives from client using c2s, and sends using s2c
    this.inKey = k_c2s;
    this.outKey = k_s2c;

    this.handshakeDone = true;
    console.error(`Client connected: ${this.socket.remoteAddress}:${this.socket.remotePort}`);
  }

  sendData(plaintextBuf) {
    if (!this.handshakeDone) return;

    const seq = this.sendSeq;
    const enc = encrypt(plaintextBuf, this.outKey, seq);

    this.socket.write(encodeFrame(MSG_DATA, seq, enc));
    this.sendSeq++;
  }
}

const clients = new Set();

const server = net.createServer((socket) => {
  const c = new Conn(socket);
  clients.add(c);

  socket.on('close', () => {
    clients.delete(c);
  });
});

server.listen(PORT, () => {
  console.error(`Server listening on port ${PORT}`);
});

// ONE stdin handler for broadcast
process.stdin.on('data', (d) => {
  for (const c of clients) c.sendData(d);
});

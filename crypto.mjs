import crypto from 'node:crypto';

export const PROTO_VERSION = 1;
export const MSG_HANDSHAKE = 0x01;
export const MSG_DATA = 0x02;

export const HEADER_LEN = 4 + 1 + 8; // len(uint32) + type(uint8) + seq(uint64)
export const MAX_FRAME_LEN = 1 * 1024 * 1024; // 1 MiB payload cap (anti-DoS)

// --- Key agreement ---
export function generateEphemeralKeys() {
  return crypto.generateKeyPairSync('x25519');
}

export function computeSharedSecret(priv, pub) {
  return crypto.diffieHellman({ privateKey: priv, publicKey: pub }); // Buffer
}

function u64be(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

export function deriveKeys(sharedSecret, sPubDer, cPubDer) {
  // salt = H(version || sPubDer || cPubDer)
  const salt = crypto
    .createHash('sha256')
    .update(Buffer.from([PROTO_VERSION]))
    .update(sPubDer)
    .update(cPubDer)
    .digest();

  const okm = crypto.hkdfSync('sha256', sharedSecret, salt, 'secure-chat-v3', 64);
  const buf = Buffer.isBuffer(okm) ? okm : Buffer.from(okm);

  return {
    k_c2s: buf.subarray(0, 32),
    k_s2c: buf.subarray(32, 64),
  };
}

// --- AEAD (AES-256-GCM) ---
export function encrypt(plaintextBuf, key, seq) {
  const iv = crypto.randomBytes(12); // 96-bit nonce
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const aad = u64be(seq);
  cipher.setAAD(aad);

  const pt = Buffer.isBuffer(plaintextBuf) ? plaintextBuf : Buffer.from(plaintextBuf);
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes by default

  return Buffer.concat([iv, tag, ct]); // payload
}

export function decrypt(payload, key, seq) {
  if (payload.length < 12 + 16) throw new Error('Packet too short');

  const iv = payload.subarray(0, 12);
  const tag = payload.subarray(12, 28);
  const ct = payload.subarray(28);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  const aad = u64be(seq);

  decipher.setAAD(aad);
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// --- Sign/verify helpers ---
export function signData(data, privKey) {
  // For Ed25519 keys: crypto.sign(null, ...) is commonly used in Node.
  return crypto.sign(null, data, privKey);
}

export function verifyData(data, sig, pubKey) {
  try {
    return crypto.verify(null, data, pubKey, sig);
  } catch {
    return false;
  }
}

// --- Framing ---
export function encodeFrame(type, seq, payload) {
  if (!Buffer.isBuffer(payload)) payload = Buffer.from(payload);
  if (payload.length > MAX_FRAME_LEN) throw new Error('Payload too large');

  const h = Buffer.alloc(HEADER_LEN);
  h.writeUInt32BE(payload.length, 0);
  h.writeUInt8(type, 4);
  h.writeBigUInt64BE(BigInt(seq), 5);
  return Buffer.concat([h, payload]);
}

export class PacketParser {
  constructor({ onPacket, onError, maxLen = MAX_FRAME_LEN } = {}) {
    this.buffer = Buffer.alloc(0);
    this.onPacket = onPacket;
    this.onError = onError ?? (() => {});
    this.maxLen = maxLen;
  }

  add(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);

    while (true) {
      if (this.buffer.length < HEADER_LEN) return;

      const len = this.buffer.readUInt32BE(0);
      const type = this.buffer.readUInt8(4);
      const seq = this.buffer.readBigUInt64BE(5);

      if (len > this.maxLen) {
        this.onError(new Error(`Frame too large: ${len}`));
        return;
      }

      const frameSize = HEADER_LEN + len;
      if (this.buffer.length < frameSize) return;

      const payload = this.buffer.subarray(HEADER_LEN, frameSize);
      this.buffer = this.buffer.subarray(frameSize);

      this.onPacket?.(type, seq, payload);
    }
  }
}

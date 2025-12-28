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

const HOST = 'localhost';
const PORT = 1235;

// Pinned server identity pubkey
const serverPubKey = crypto.createPublicKey(fs.readFileSync('./server_identity.pub'));

// Optional client identity (for mutual auth)
const CLIENT_PRIV_PATH = process.env.CLIENT_PRIV_KEY_PATH; // e.g. "./client_identity"
const clientPrivKey = CLIENT_PRIV_PATH
  ? crypto.createPrivateKey(fs.readFileSync(CLIENT_PRIV_PATH))
  : null;

const socket = new net.Socket();
socket.setNoDelay(true);

const { publicKey: cEphPub, privateKey: cEphPriv } = generateEphemeralKeys();
const cPubDer = cEphPub.export({ type: 'spki', format: 'der' });

let handshakeDone = false;
let inKey = null;
let outKey = null;
let sendSeq = 0n;
let recvSeq = 0n;

let sPubDer = null; // learned from server hello

const parser = new PacketParser({
  onPacket: (type, seq, payload) => {
    if (type === MSG_HANDSHAKE && !handshakeDone) return handleServerHello(payload);
    if (type === MSG_DATA && handshakeDone) return handleData(seq, payload);
    socket.destroy();
  },
  onError: () => socket.destroy(),
});

function handleServerHello(payload) {
  // SERVER_HELLO:
  // u8 version | u16 sPubLen | sPubDer | u16 sigLen | sig
  if (payload.length < 1 + 2 + 2) return socket.destroy();

  const version = payload.readUInt8(0);
  if (version !== PROTO_VERSION) return socket.destroy();

  const sLen = payload.readUInt16BE(1);
  const minLen = 1 + 2 + sLen + 2;
  if (payload.length < minLen) return socket.destroy();

  sPubDer = payload.subarray(3, 3 + sLen);
  const sigLen = payload.readUInt16BE(3 + sLen);
  const sig = payload.subarray(3 + sLen + 2);

  if (sig.length !== sigLen) return socket.destroy();

  const toVerify = Buffer.concat([
    Buffer.from([PROTO_VERSION]),
    Buffer.from('server', 'utf8'),
    sPubDer,
  ]);
  if (!verifyData(toVerify, sig, serverPubKey)) return socket.destroy();

  // Derive session keys
  const sPubKeyObj = crypto.createPublicKey({ key: sPubDer, type: 'spki', format: 'der' });
  const shared = computeSharedSecret(cEphPriv, sPubKeyObj);
  const { k_c2s, k_s2c } = deriveKeys(shared, sPubDer, cPubDer);

  // Client sends using c2s, receives using s2c
  outKey = k_c2s;
  inKey = k_s2c;

  // Send CLIENT_HELLO (with optional signature)
  const versionBuf = Buffer.from([PROTO_VERSION]);

  const pubLen = Buffer.alloc(2);
  pubLen.writeUInt16BE(cPubDer.length);

  let sigBuf = Buffer.alloc(0);
  if (clientPrivKey) {
    const toSign = Buffer.concat([
      Buffer.from([PROTO_VERSION]),
      Buffer.from('client', 'utf8'),
      cPubDer,
      sPubDer, // bind to this server ephemeral
    ]);
    sigBuf = signData(toSign, clientPrivKey);
  }

  const sigLenBuf = Buffer.alloc(2);
  sigLenBuf.writeUInt16BE(sigBuf.length);

  const helloPayload = Buffer.concat([versionBuf, pubLen, cPubDer, sigLenBuf, sigBuf]);
  socket.write(encodeFrame(MSG_HANDSHAKE, 0n, helloPayload));

  handshakeDone = true;
  console.error('Secure channel established.');
}

function handleData(seq, payload) {
  if (seq !== recvSeq) return socket.destroy();

  try {
    const pt = decrypt(payload, inKey, seq);
    recvSeq++;
    process.stdout.write(pt.toString());
  } catch {
    socket.destroy();
  }
}

socket.on('data', (d) => parser.add(d));
socket.on('error', () => {});
socket.connect(PORT, HOST, () => console.error('Connected.'));

process.stdin.on('data', (d) => {
  if (!handshakeDone) return;

  const seq = sendSeq;
  const enc = encrypt(d, outKey, seq);

  socket.write(encodeFrame(MSG_DATA, seq, enc));
  sendSeq++;
});

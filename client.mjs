import net from 'net';
import fs from 'fs';
import { Client } from './crypto.mjs';

const SERVER_PUBLIC_KEY = fs.readFileSync('server_identity.pub');
const PASSWORD = 'super-secret-password';
const SERVER_HOST = '127.0.0.1';
const SERVER_PORT = 3000;
const LOCAL_PROXY_PORT = 8080;

const localServer = net.createServer((localSocket) => {
  console.log('New local proxy connection');

  const tunnelSocket = net.connect(SERVER_PORT, SERVER_HOST);

  const clientSession = new Client(tunnelSocket, {
    serverPublicKey: SERVER_PUBLIC_KEY,
    password: PASSWORD
  });

  clientSession.on('secure', () => {
    console.log('Tunnel secure, forwarding...');
    localSocket.pipe(clientSession);
    clientSession.pipe(localSocket);
  });

  const cleanup = () => {
    localSocket.destroy();
    tunnelSocket.destroy();
  };

  clientSession.on('error', cleanup);
  localSocket.on('error', cleanup);
  tunnelSocket.on('error', cleanup);
  localSocket.on('close', cleanup);
});

localServer.listen(LOCAL_PROXY_PORT, () => {
  console.log(`Local HTTP proxy listening on ${LOCAL_PROXY_PORT}`);
  console.log('Configure your browser/system to use HTTP proxy 127.0.0.1:' + LOCAL_PROXY_PORT);
});
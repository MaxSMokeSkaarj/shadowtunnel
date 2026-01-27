import net from 'net';
import fs from 'fs';
import { Server } from './crypto.mjs';
import { URL } from 'url';

const SERVER_PRIVATE_KEY = fs.readFileSync('server_identity');
const PASSWORD = 'super-secret-password';
const PORT = 3000;

function handleProxyConnection(secureSession) {
  let buffer = Buffer.alloc(0);

  const onData = (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    const headerEnd = buffer.indexOf('\r\n\r\n');
    if (headerEnd === -1) return;

    const headers = buffer.slice(0, headerEnd + 4).toString('utf-8');
    const remainingData = buffer.slice(headerEnd + 4);
    buffer = Buffer.alloc(0);

    secureSession.removeListener('data', onData);

    const requestLine = headers.split('\r\n')[0];
    const parts = requestLine.split(' ');
    const method = parts[0];
    const target = parts[1];
    const version = parts[2] || 'HTTP/1.1';

    let host, port;

    if (method === 'CONNECT') {
      [host, port = '443'] = target.split(':');
      port = Number(port);
    } else {
      try {
        const url = new URL(target);
        host = url.hostname;
        port = url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80);
      } catch (e) {
        secureSession.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        return;
      }
    }

    const remoteSocket = net.connect(port, host, () => {
      if (method === 'CONNECT') {
        secureSession.write(`${version} 200 Connection Established\r\n\r\n`);
      } else {
        const url = new URL(target);
        const modifiedRequestLine = `${method} ${url.pathname}${url.search} ${version}`;
        let modifiedHeaders = headers.replace(requestLine, modifiedRequestLine);

        modifiedHeaders = modifiedHeaders.replace(/Proxy-Connection: .*\r\n/gi, '');
        modifiedHeaders = modifiedHeaders.replace(/Proxy-Authorization: .*\r\n/gi, '');

        remoteSocket.write(modifiedHeaders);
        if (remainingData.length) remoteSocket.write(remainingData);
      }

      secureSession.pipe(remoteSocket);
      remoteSocket.pipe(secureSession);
    });

    remoteSocket.on('error', (err) => {
      console.error('Remote error:', err.message);
      if (!secureSession.destroyed) {
        secureSession.end(`${version} 502 Bad Gateway\r\n\r\n`);
      }
    });
  };

  secureSession.on('data', onData);
  secureSession.on('error', (err) => console.error('Session error:', err));
}

const server = net.createServer((socket) => {
  const serverSession = new Server(socket, {
    privateKey: SERVER_PRIVATE_KEY,
    password: PASSWORD
  });

  serverSession.on('secure', () => {
    console.log('Secure tunnel established from', socket.remoteAddress);
    handleProxyConnection(serverSession);
  });

  serverSession.on('error', (err) => {
    console.error('Auth/crypto error:', err.message);
    socket.end();
  });
});

server.listen(PORT, () => console.log(`Secure proxy server listening on port ${PORT}`));
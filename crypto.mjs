import { Socket, Server as netServer, createServer, createConnection } from "node:net";
import { Duplex } from "node:stream";
import { hkdfSync, diffieHellman, generateKeyPairSync, verify, sign, createDecipheriv, createCipheriv, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { buffer } from "node:stream/consumers";

/**
 * A simple TCP server that handles multiple connections.
 * @class Server
 */
export class Server {

  /**
   * Set of active connections.
   * @type {Set<Socket>}
   */
  connections = new Set();

  /**
   * The endpoint stream.
   * @type {Duplex}
   */
  endpoint = new Duplex({
    read(size) {
      // No-op
    },
    write(chunk, encoding, callback) {
      // No-op
      callback();
    }
  });

  /**
   * The encryption stream.
   * @type {Duplex}
   */
  encryptStream = new Duplex({
    read(size) {
      // No-op
    },
    write(chunk, encoding, callback) {
      // No-op
      callback();
    }
  });

  /**
   * The decryption stream.
   * @type {Duplex}
   */
  decryptStream = new Duplex({
    read(size) {
      // No-op
    },
    write(chunk, encoding, callback) {
      // No-op
      callback();
    }
  });

  /**
   * The current state of the client.
   * @type {"AUTH" | "ENCRYPTION" | "SECURE"}
   */
  state = "AUTH";

  /**
   * The TCP server instance.
   * @type {netServer}
   * @param {function(Socket): void} onConnection - Callback for new connections.
   */
  server = createServer((socket) => {

    console.log(`New connection established from ${socket.remoteAddress}:${socket.remotePort}`);

    console.log(`Active connections: ${this.connections.size}`);
    this.connections.add(socket);

    this.auth(socket);

    socket.on("error", (err) => {
      console.error("Socket error:", err);
    });

    socket.on('close', () => {
      this.connections.delete(socket);
      console.log("Socket closed");
    });
  });

  /**
   * Creates a Server instance.
   * @constructor
   * @param {string} privKeyPath - Path to the server's private key file.
   * @param {function(Socket): void} onConnection - Callback for new connections.
   */
  constructor(privKeyPath, onConnection) {
    this.onConnection = onConnection;
    this.privKey = readFileSync(privKeyPath);
  };

  /**
   * Starts the server and listens on the specified port.
   * @param {number} port - The port number to listen on.
   */
  listen(port) {
    this.server.listen(port, () => {
      console.log(`Server listening on port ${port}`);
    });
  };

  auth(socket) {
    const nonce = randomBytes(32);
    const dataToSign = Buffer.concat([Buffer.from('SMokeTunnel_v1'), nonce]);
    const signature = sign(null, dataToSign, { key: this.privKey, format: 'pem', type: 'pkcs8' });
    const writeData = Buffer.concat([nonce, signature]);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(writeData.length, 0);

    socket.write(Buffer.concat([header, writeData]));

  };

};

/**
 * A simple TCP client that connects to a server.
 * @class Client
 */
export class Client {

  /**
   * The endpoint stream.
   * @type {Duplex}
   */
  endpoint = new Duplex({
    read(size) {
      // No-op
    },
    write(chunk, encoding, callback) {
      // No-op
      callback();
    }
  });

  /**
   * The encryption stream.
   * @type {Duplex}
   */
  encryptStream = new Duplex({
    read(size) {
      // No-op
    },
    write(chunk, encoding, callback) {
      // No-op
      callback();
    }
  });

  /**
   * The decryption stream.
   * @type {Duplex}
   */
  decryptStream = new Duplex({
    read(size) {
      // No-op
    },
    write(chunk, encoding, callback) {
      // No-op
      callback();
    }
  });

  /**
   * The current state of the client.
   * @type {"AUTH" | "ENCRYPTION" | "SECURE"}
   */
  state = "AUTH";

  /**
   * The TCP connection instance.
   * @param {number} port 
   * @param {string} host 
   */
  constructor(port, host) {
    this.connection = createConnection(port, host, () => {
      console.log("Connected to server");

      switch (this.state) {
        case 'AUTH':
          //this.handleAuth(packet, socket);
          break;
        case 'ENCRYPTION':
          //this.handleECDH(packet, socket);
          break;
        case 'SECURE':
          //this.handleData(packet);
          break;
      }

      this.connection.on("error", (err) => {
        console.error("Connection error:", err);
        this.connection.end();
      });
      this.connection.on('close', () => {
        console.log("Connection closed");
        this.connection.end();
      });

    });
  }
}

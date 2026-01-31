import net from "node:net";

/**
 * A simple TCP server that handles multiple connections.
 * @class Server
 */
export class Server {

  /**
   * Set of active connections.
   * @type {Set<net.Socket>}
   */
  connections = new Set();
  
  /**
   * The TCP server instance.
   * @type {net.Server}
   * @param {function(net.Socket): void} onConnection - Callback for new connections.
   */
  server = net.createServer((socket) => {
    
    console.log(`New connection established from ${socket.remoteAddress}:${socket.remotePort}`);
    
    console.log(`Active connections: ${this.connections.size}`);
    this.connections.add(socket);

    this.onConnection(socket);

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
   * @param {function(net.Socket): void} onConnection - Callback for new connections.
   */

  constructor(onConnection) {
    this.onConnection = onConnection;
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
};

/**
 * A simple TCP client that connects to a server.
 * @class Client
 */
export class Client {

  /**
   * The TCP connection instance.
   * @param {number} port 
   * @param {string} host 
   */
  constructor(port, host) {
    this.connection = net.createConnection(port, host, () => {
      console.log("Connected to server");
    });
  }
}

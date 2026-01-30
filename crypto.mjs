import net from "node:net";

export class Server {
  #counter = 0;
  connections = new Set();
  server = net.createServer((socket) => {
    
    console.log("New connection established");

    this.#counter += 1;
    console.log(`Active connections: ${this.#counter}, ${socket.remoteAddress}:${socket.remotePort}`);
    this.connections.add(socket);

    this.onConnection(socket);
    //socket.pipe(socket); // Echo server

    socket.on("end", () => {
      console.log("Connection ended");
      this.#counter -= 1;
      this.connections.delete(socket);
      console.log(`Active connections: ${this.#counter}, ${socket.remoteAddress}:${socket.remotePort}`);
    });

    socket.on("error", (err) => {
      console.error("Socket error:", err);
      this.#counter -= 1;
      this.connections.delete(socket);

      console.log(`Active connections: ${this.#counter}, connections: ${
        Array.from(this.connections).map((connection) =>
          `${connection.remoteAddress}:${connection.remotePort}`
        )}`
      );
    });

    socket.on("finish", () => {
      console.log("Socket finished");
    });
  });

  constructor(port, onConnection) {
    this.onConnection = onConnection;
    this.server.listen(port, () => {
      console.log(`Server listening on port ${port}`);
    });
  }
}

export class Client {
  constructor(port, host) {
    this.connection = net.createConnection(port, host, () => {
      console.log("Connected to server");
    });
  }
}

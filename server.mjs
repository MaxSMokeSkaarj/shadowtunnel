import { Server } from "./crypto.mjs";

const server = new Server('./server_identity', connection => {
  connection.on('data', (data) => {
    console.log(server.connections.size);
    connection.write(data);
  });
});

server.listen(5123);

import { Server } from "./crypto.mjs";

const server = new Server(8080, (connection) => {
  connection.on('data', (data) => {
    for (const con of server.connections) {
      if (con === connection) continue;
      con.write(data);
    };
  });
});


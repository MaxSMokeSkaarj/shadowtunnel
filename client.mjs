import { Client } from "./crypto.mjs";

const client = new Client(8080, '127.0.0.1');

process.stdin.pipe(client.connection)

client.connection.pipe(process.stdout)
//client.connection.end();
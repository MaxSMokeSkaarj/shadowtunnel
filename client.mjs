import { Client } from './crypto.mjs';
import fs from 'node:fs';

const PORT = 3000;
const HOST = '127.0.0.1';
const PASSWORD = 'super-secret-password';

const serverPublicKey = fs.readFileSync('server_identity.pub', 'utf8');

const client = new Client({
    serverPublicKey: serverPublicKey,
    password: PASSWORD
});

client.on('secure', () => {
    console.log('Соединение защищено, авторизация пройдена!');
    
    setInterval(() => {
        const msg = `Привет, сейчас ${new Date().toLocaleTimeString()}`;
        console.log(`[Client] Отправляю: ${msg}`);
        client.write(Buffer.from(msg));
    }, 2000);
});

client.on('data', (data) => {
    console.log(`[Client] Ответ от сервера: ${data.toString()}`);
});

client.on('error', (err) => console.error('[Client] Ошибка:', err.message));
client.on('close', () => {
    console.log('[Client] Соединение закрыто');
    process.exit();
});

console.log(`🔗 Подключаюсь к ${HOST}:${PORT}...`);
client.connect(PORT, HOST);
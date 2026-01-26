import { Server } from './crypto.mjs';
import fs from 'node:fs';

const PORT = 3000;
const PASSWORD = 'super-secret-password';


const privateKey = fs.readFileSync('server_identity', 'utf8');

const echoServer = new Server({
    privateKey: privateKey,
    password: PASSWORD
});

echoServer.on('connection', (session) => {
    console.log(`[Server] Новый защищенный клиент ${session.socket.remoteAddress}`);

    session.on('data', (data) => {
        console.log(`[Server] Получено: ${data.toString()}`);
        
        session.write(Buffer.concat([Buffer.from('Echo: '), data]));
    });

    session.on('close', () => console.log('[Server] Клиент отключился'));
    session.on('error', (err) => console.error('[Server] Ошибка сессии:', err.message));
});

echoServer.listen(PORT, () => {
    console.log(`Echo-сервер запущен на порту ${PORT}`);
    console.log(`Пароль: ${PASSWORD}`);
});
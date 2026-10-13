import { httpServerHandler } from 'cloudflare:node';
import app from '../server.js';

app.listen(3000);

export const onRequest = httpServerHandler({ port: 3000 });

import { httpServerHandler } from 'cloudflare:node';
import app from './server.js';

// No Cloudflare Workers, a porta atua como chave interna de roteamento
const PORT = 3000;
app.listen(PORT);

export default httpServerHandler({ port: PORT });

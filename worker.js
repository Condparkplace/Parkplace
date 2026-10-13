import { httpServerHandler } from 'cloudflare:node';
import app from './server.js';

// No Cloudflare Workers, a porta atua como chave interna de roteamento
const PORT = 3000;
app.listen(PORT);

const handler = httpServerHandler({ port: PORT });

export default {
  async fetch(request, env, ctx) {
    if (env) {
      for (const [key, val] of Object.entries(env)) {
        if (typeof val === 'string' && val) {
          process.env[key] = val;
        }
      }
    }
    return handler.fetch(request, env, ctx);
  }
};

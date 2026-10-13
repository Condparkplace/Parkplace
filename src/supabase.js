const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.warn(
    '[AVISO] SUPABASE_URL / SUPABASE_ANON_KEY não configurados. ' +
      'Copie .env.example para .env e preencha as chaves.'
  );
}

/**
 * Cliente administrativo (service_role) - ignora RLS.
 * Usar SOMENTE no backend para operacoes de admin (criar usuarios etc.).
 */
const supabaseAdmin = createClient(
  SUPABASE_URL || 'http://localhost',
  SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY || 'anon',
  { auth: { autoRefreshToken: false, persistSession: false } }
);

/**
 * Cria um cliente "em nome do usuario", usando o access_token dele.
 * Assim o RLS do Supabase e respeitado para cada requisicao.
 */
function supabaseForToken(accessToken) {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

/**
 * Cliente anonimo para operacoes de login/signup.
 */
const supabaseAnon = createClient(
  SUPABASE_URL || 'http://localhost',
  SUPABASE_ANON_KEY || 'anon',
  { auth: { autoRefreshToken: false, persistSession: false } }
);

module.exports = { supabaseAdmin, supabaseAnon, supabaseForToken };

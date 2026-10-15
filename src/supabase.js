const { createClient } = require('@supabase/supabase-js');

let _adminClient = null;
let _anonClient = null;

function getSupabaseUrl() {
  const url = process.env.SUPABASE_URL;
  if (!url) {
    console.error('[CONFIG] SUPABASE_URL ausente. Configure a variável de ambiente/secret.');
  }
  return url || '';
}

function getAnonKey() {
  const k = process.env.SUPABASE_ANON_KEY;
  if (!k) {
    console.error('[CONFIG] SUPABASE_ANON_KEY ausente. Configure a variável de ambiente/secret.');
  }
  return k || '';
}

function getServiceRoleKey() {
  // NUNCA cair para a anon key: isso mascara erro de configuração e faz o
  // cliente "admin" rodar com permissões insuficientes de forma silenciosa.
  const k = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!k) {
    console.error('[CONFIG] SUPABASE_SERVICE_ROLE_KEY ausente. Operações administrativas vão falhar até configurá-la.');
  }
  return k || '';
}

function getAdminClient() {
  const url = getSupabaseUrl();
  const key = getServiceRoleKey();
  if (!_adminClient || _adminClient.__url !== url || _adminClient.__key !== key) {
    // createClient exige strings não-vazias; usamos placeholders só para não
    // lançar na criação. Sem as envs corretas, as chamadas ao Supabase falham
    // de forma visível (401/erro), em vez de operar com permissões erradas.
    _adminClient = createClient(url || 'http://invalid.local', key || 'MISSING_SERVICE_ROLE_KEY', {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    _adminClient.__url = url;
    _adminClient.__key = key;
  }
  return _adminClient;
}

function getAnonClient() {
  const url = getSupabaseUrl();
  const key = getAnonKey();
  if (!_anonClient || _anonClient.__url !== url || _anonClient.__key !== key) {
    _anonClient = createClient(url || 'http://invalid.local', key || 'MISSING_ANON_KEY', {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    _anonClient.__url = url;
    _anonClient.__key = key;
  }
  return _anonClient;
}

/**
 * Cliente administrativo (service_role) - ignora RLS.
 * Usar SOMENTE no backend para operacoes de admin (criar usuarios etc.).
 */
const supabaseAdmin = new Proxy({}, {
  get(target, prop) {
    const client = getAdminClient();
    const val = client[prop];
    return typeof val === 'function' ? val.bind(client) : val;
  }
});

/**
 * Cliente anonimo para operacoes de login/signup.
 */
const supabaseAnon = new Proxy({}, {
  get(target, prop) {
    const client = getAnonClient();
    const val = client[prop];
    return typeof val === 'function' ? val.bind(client) : val;
  }
});

/**
 * Cria um cliente "em nome do usuario", usando o access_token dele.
 * Assim o RLS do Supabase e respeitado para cada requisicao.
 */
function supabaseForToken(accessToken) {
  return createClient(getSupabaseUrl() || 'http://invalid.local', getAnonKey() || 'MISSING_ANON_KEY', {
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

module.exports = { supabaseAdmin, supabaseAnon, supabaseForToken };

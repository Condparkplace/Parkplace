const { createClient } = require('@supabase/supabase-js');

let _adminClient = null;
let _anonClient = null;

function getSupabaseUrl() {
  return process.env.SUPABASE_URL || 'https://sbslmojboixbjlrvqkpt.supabase.co';
}

function getAnonKey() {
  return process.env.SUPABASE_ANON_KEY || '';
}

function getServiceRoleKey() {
  return process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || '';
}

function getAdminClient() {
  const url = getSupabaseUrl();
  const key = getServiceRoleKey();
  if (!_adminClient || _adminClient.__url !== url || _adminClient.__key !== key) {
    _adminClient = createClient(url, key || 'anon', {
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
    _anonClient = createClient(url, key || 'anon', {
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
  return createClient(getSupabaseUrl(), getAnonKey() || 'anon', {
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

module.exports = { supabaseAdmin, supabaseAnon, supabaseForToken };

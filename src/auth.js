const { supabaseForToken, supabaseAdmin, supabaseAnon } = require('./supabase');

const COOKIE_NAME = 'pp_session';

const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  path: '/',
};

// Duração longa do cookie (1 ano). O access_token do Supabase expira em ~1h,
// mas o refresh_token guardado no cookie é usado para renovar a sessão
// automaticamente (ver requireAuth), então a sessão não cai sozinha.
const COOKIE_MAX_AGE = 1000 * 60 * 60 * 24 * 365; // 1 ano

function setSessionCookie(res, session, rememberMe = false) {
  const payload = JSON.stringify({
    access_token: session.access_token,
    refresh_token: session.refresh_token,
  });

  const options = { ...cookieOptions, maxAge: COOKIE_MAX_AGE };
  res.cookie(COOKIE_NAME, Buffer.from(payload).toString('base64'), options);
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

function readSessionFromCookie(req) {
  const raw = req.cookies?.[COOKIE_NAME];
  if (!raw) return null;
  try {
    const json = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
    return { access_token: json.access_token || null, refresh_token: json.refresh_token || null };
  } catch {
    return null;
  }
}

function readTokenFromCookie(req) {
  return readSessionFromCookie(req)?.access_token || null;
}

/**
 * Middleware: exige usuario autenticado. Carrega req.user, req.perfil
 * e req.supabase (cliente escopado ao token, respeitando RLS).
 */
async function requireAuth(req, res, next) {
  const sessao = readSessionFromCookie(req);
  if (!sessao || !sessao.access_token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }

  let token = sessao.access_token;
  let client = supabaseForToken(token);
  let { data: userData, error } = await client.auth.getUser();

  // Token de acesso expirado: tenta renovar automaticamente usando o
  // refresh_token guardado no cookie. Assim a sessão não cai sozinha — o
  // usuário só sai de fato ao trocar de turno / "Apenas sair".
  if ((error || !userData?.user) && sessao.refresh_token) {
    try {
      const { data: refreshData, error: refreshErr } = await supabaseAnon.auth.refreshSession({
        refresh_token: sessao.refresh_token,
      });
      if (!refreshErr && refreshData?.session?.access_token) {
        // Reemite o cookie com os tokens novos e segue a requisição.
        setSessionCookie(res, refreshData.session);
        token = refreshData.session.access_token;
        client = supabaseForToken(token);
        ({ data: userData, error } = await client.auth.getUser());
      }
    } catch (e) {
      // Se a renovação falhar, cai no tratamento de erro abaixo.
    }
  }

  if (error || !userData?.user) {
    clearSessionCookie(res);
    return res.status(401).json({ error: 'Sessão inválida ou expirada.' });
  }

  // Perfil via service role para evitar recursao em RLS no proprio middleware.
  const { data: perfil, error: perfilErr } = await supabaseAdmin
    .from('perfis')
    .select('*')
    .eq('id', userData.user.id)
    .single();

  if (perfilErr || !perfil) {
    return res.status(403).json({ error: 'Perfil não encontrado.' });
  }
  if (!perfil.ativo) {
    clearSessionCookie(res);
    return res.status(403).json({ error: 'Usuário desativado.' });
  }

  req.user = userData.user;
  req.perfil = perfil;
  req.supabase = client;
  next();
}

/**
 * Middleware factory: exige um dos tipos informados.
 */
function requireRole(...tipos) {
  return (req, res, next) => {
    if (!req.perfil || !tipos.includes(req.perfil.tipo)) {
      return res.status(403).json({ error: 'Acesso negado para seu perfil.' });
    }
    next();
  };
}

module.exports = {
  COOKIE_NAME,
  setSessionCookie,
  clearSessionCookie,
  readTokenFromCookie,
  requireAuth,
  requireRole,
};

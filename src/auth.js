const { supabaseForToken, supabaseAdmin } = require('./supabase');

const COOKIE_NAME = 'pp_session';

const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 1000 * 60 * 60 * 8, // 8 horas
  path: '/',
};

function setSessionCookie(res, session) {
  const payload = JSON.stringify({
    access_token: session.access_token,
    refresh_token: session.refresh_token,
  });
  res.cookie(COOKIE_NAME, Buffer.from(payload).toString('base64'), cookieOptions);
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

function readTokenFromCookie(req) {
  const raw = req.cookies?.[COOKIE_NAME];
  if (!raw) return null;
  try {
    const json = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
    return json.access_token || null;
  } catch {
    return null;
  }
}

/**
 * Middleware: exige usuario autenticado. Carrega req.user, req.perfil
 * e req.supabase (cliente escopado ao token, respeitando RLS).
 */
async function requireAuth(req, res, next) {
  const token = readTokenFromCookie(req);
  if (!token) {
    return res.status(401).json({ error: 'Nao autenticado.' });
  }

  const client = supabaseForToken(token);
  const { data: userData, error } = await client.auth.getUser();
  if (error || !userData?.user) {
    clearSessionCookie(res);
    return res.status(401).json({ error: 'Sessao invalida ou expirada.' });
  }

  // Perfil via service role para evitar recursao em RLS no proprio middleware.
  const { data: perfil, error: perfilErr } = await supabaseAdmin
    .from('perfis')
    .select('*')
    .eq('id', userData.user.id)
    .single();

  if (perfilErr || !perfil) {
    return res.status(403).json({ error: 'Perfil nao encontrado.' });
  }
  if (!perfil.ativo) {
    clearSessionCookie(res);
    return res.status(403).json({ error: 'Usuario desativado.' });
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

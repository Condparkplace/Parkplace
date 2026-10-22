require('dotenv').config();
try { require('iconv-lite'); require('iconv-lite/encodings'); } catch {}

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const webpush = require('web-push');

// Push Notifications (Web Push / VAPID).
// As chaves vêm EXCLUSIVAMENTE das variáveis de ambiente/secrets.
// Sem elas, o push fica desativado (não há fallback de chave no código).
const vapidPublicKey = process.env.VAPID_PUBLIC_KEY || '';
const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY || '';
const vapidSubject = process.env.VAPID_SUBJECT || 'mailto:contato@parkplace.com';
let pushAtivo = false;
if (vapidPublicKey && vapidPrivateKey) {
  try {
    webpush.setVapidDetails(vapidSubject, vapidPublicKey, vapidPrivateKey);
    pushAtivo = true;
  } catch (err) {
    console.warn('[AVISO] Falha ao configurar VAPID (push desativado):', err.message);
  }
} else {
  console.warn('[AVISO] VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY ausentes. Push desativado.');
}

const { supabaseAnon, supabaseAdmin, supabaseForToken } = require('./src/supabase');
const { whatsappAtivo, enviarTemplateEntrada, descreverEntrada } = require('./src/whatsapp');
const {
  setSessionCookie,
  clearSessionCookie,
  requireAuth,
  requireRole,
} = require('./src/auth');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ============================================================
// RATE LIMITING (defesa contra brute force / enumeração)
// Em memória, por IP+rota. No Cloudflare Workers os isolates não compartilham
// memória, então esta é uma 2ª camada; a 1ª deve ser o WAF Rate Limiting da
// Cloudflare. Mesmo assim, mitiga rajadas dentro de um mesmo isolate.
// ============================================================
const _rlStore = new Map(); // chave: ip|bucket -> { count, resetEm }

function rateLimit({ bucket, max, janelaMs }) {
  return (req, res, next) => {
    const ip = req.headers['cf-connecting-ip']
      || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
      || req.ip
      || 'desconhecido';
    const chave = `${ip}|${bucket}`;
    const agora = Date.now();
    let reg = _rlStore.get(chave);
    if (!reg || agora > reg.resetEm) {
      reg = { count: 0, resetEm: agora + janelaMs };
    }
    reg.count++;
    _rlStore.set(chave, reg);

    // Limpeza oportunista para não crescer indefinidamente.
    if (_rlStore.size > 5000) {
      for (const [k, v] of _rlStore) if (agora > v.resetEm) _rlStore.delete(k);
    }

    if (reg.count > max) {
      const retrySeg = Math.ceil((reg.resetEm - agora) / 1000);
      res.set('Retry-After', String(retrySeg));
      return res.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos e tente novamente.' });
    }
    next();
  };
}

// Limites por rota
const limiteLogin = rateLimit({ bucket: 'login', max: 10, janelaMs: 15 * 60 * 1000 });     // 10 / 15 min
const limitePublico = rateLimit({ bucket: 'publico', max: 30, janelaMs: 10 * 60 * 1000 });  // 30 / 10 min

// Escapa os curingas do LIKE/ILIKE (%, _, \) para que a entrada do usuário não
// seja interpretada como padrão de busca (LIKE injection).
function likeSafe(valor) {
  return String(valor || '').replace(/[\\%_]/g, (c) => '\\' + c);
}

// ============================================================
// LINKS DE CADASTRO DE VISITA COM VALIDADE (2 horas)
// O link enviado ao visitante/prestador carrega: morador, tipo, exp (expiração)
// e sig (assinatura HMAC). Sem a assinatura correta ou após a expiração o
// backend recusa o envio do aviso, evitando burlar o prazo editando a URL.
// ============================================================
const LINK_VISITA_VALIDADE_MS = 2 * 60 * 60 * 1000; // 2 horas
// Segredo para assinar os links de visita. DEVE vir do ambiente.
// Sem ele, as assinaturas seriam forjáveis — por isso avisamos em log.
const LINK_SECRET = process.env.SESSION_SECRET || '';
if (!LINK_SECRET) {
  console.error('[CONFIG] SESSION_SECRET ausente: links de visita assinados ficam inseguros. Configure o secret.');
}

function assinarLinkVisita(moradorId, tipo, exp) {
  return crypto
    .createHmac('sha256', LINK_SECRET)
    .update(`${moradorId}|${tipo}|${exp}`)
    .digest('hex');
}

// Gera um token curto compacto (stateless, ~42 caracteres em base64url)
// Evita links com mais de 200 caracteres no WhatsApp que o iOS quebra
function gerarTokenCurtoVisita(moradorId, tipo, exp) {
  try {
    const uuidClean = (moradorId || '').replace(/-/g, '');
    if (uuidClean.length !== 32) return null;
    const bufUuid = Buffer.from(uuidClean, 'hex');
    const bufTipo = Buffer.from([tipo === 'Prestador' ? 1 : 0]);
    const bufExp = Buffer.alloc(6);
    bufExp.writeUIntBE(Number(exp), 0, 6);
    const payload = Buffer.concat([bufUuid, bufTipo, bufExp]);
    const hmac = crypto.createHmac('sha256', LINK_SECRET).update(payload).digest().subarray(0, 8);
    return Buffer.concat([payload, hmac]).toString('base64url');
  } catch {
    return null;
  }
}

// Decodifica e valida o token curto
function decodificarTokenCurtoVisita(token) {
  try {
    const buf = Buffer.from(token, 'base64url');
    if (buf.length !== 31) return null;
    const payload = buf.subarray(0, 23);
    const hmacRecebido = buf.subarray(23, 31);
    const hmacEsperado = crypto.createHmac('sha256', LINK_SECRET).update(payload).digest().subarray(0, 8);
    if (!crypto.timingSafeEqual(hmacRecebido, hmacEsperado)) return null;

    const hexUuid = payload.subarray(0, 16).toString('hex');
    const moradorId = `${hexUuid.slice(0, 8)}-${hexUuid.slice(8, 12)}-${hexUuid.slice(12, 16)}-${hexUuid.slice(16, 20)}-${hexUuid.slice(20)}`;
    const tipo = payload[16] === 1 ? 'Prestador' : 'Visitante';
    const exp = payload.readUIntBE(17, 6);

    return { moradorId, tipo, exp };
  } catch {
    return null;
  }
}

// Retorna { ok } ou { ok:false, motivo:'expirado'|'invalido' }
function validarLinkVisita(moradorId, tipo, exp, sig) {
  const expNum = Number(exp);
  if (!moradorId || !exp || !sig || !Number.isFinite(expNum)) {
    return { ok: false, motivo: 'invalido' };
  }
  const esperado = assinarLinkVisita(moradorId, tipo || 'Visitante', expNum);
  // Comparação em tempo constante para evitar vazamento por timing.
  const a = Buffer.from(String(sig));
  const b = Buffer.from(esperado);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, motivo: 'invalido' };
  }
  if (Date.now() > expNum) {
    return { ok: false, motivo: 'expirado' };
  }
  return { ok: true };
}

// Rota de link curto para convites (/c/:token ou /convite/:token)
// Redireciona com segurança para a página completa de cadastro de visita
app.get(['/c/:token', '/convite/:token'], (req, res) => {
  const { token } = req.params;
  const dados = decodificarTokenCurtoVisita(token);
  if (!dados) {
    return res.redirect('/cadastro-visita.html?erro=invalido');
  }
  if (Date.now() > dados.exp) {
    return res.redirect('/cadastro-visita.html?erro=expirado');
  }
  const sig = assinarLinkVisita(dados.moradorId, dados.tipo, dados.exp);
  const params = new URLSearchParams({
    morador: dados.moradorId,
    tipo: dados.tipo,
    exp: String(dados.exp),
    sig,
  });
  return res.redirect(`/cadastro-visita.html?${params.toString()}`);
});

// ============================================================
// AUTENTICACAO
// ============================================================

// Login (todos os perfis usam a mesma rota - aceita e-mail OU nome do porteiro/usuario)
app.post('/api/login', limiteLogin, async (req, res) => {
  const loginInput = (req.body?.login || req.body?.email || '').trim();
  const { password, rememberMe } = req.body || {};
  if (!loginInput || !password) {
    return res.status(400).json({ error: 'Informe seu login (nome ou e-mail) e a senha.' });
  }

  const normalizar = (s) => (s || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const termoBusca = normalizar(loginInput);

  let sessaoValida = null;
  let perfilValido = null;

  // 1. Se parece um e-mail (contem @), tenta autenticar diretamente pelo Supabase Auth
  if (loginInput.includes('@')) {
    const { data, error } = await supabaseAnon.auth.signInWithPassword({
      email: loginInput.toLowerCase(),
      password,
    });
    if (!error && data?.session) {
      const { data: perfil } = await supabaseAdmin
        .from('perfis')
        .select('*')
        .eq('id', data.user.id)
        .single();

      if (perfil) {
        sessaoValida = data.session;
        perfilValido = perfil;
      }
    }
  }

  // 2. Se nao era e-mail ou a tentativa direta de e-mail falhou, busca pelo Nome em perfis
  if (!sessaoValida) {
    // Busca exata ou compativel em perfis
    let { data: perfis } = await supabaseAdmin
      .from('perfis')
      .select('*')
      .ilike('nome', loginInput);

    if (!perfis || perfis.length === 0) {
      const { data: todosPerfis } = await supabaseAdmin
        .from('perfis')
        .select('*');

      if (todosPerfis && todosPerfis.length > 0) {
        // Coincidencia exata normalizada (sem acentos)
        perfis = todosPerfis.filter(p => normalizar(p.nome) === termoBusca);

        // Se ainda nao achou, busca quem comeca com o nome ou contem
        if (perfis.length === 0) {
          perfis = todosPerfis.filter(p => {
            const pNorm = normalizar(p.nome);
            return pNorm.startsWith(termoBusca) || termoBusca.startsWith(pNorm);
          });
        }
      }
    }

    if (perfis && perfis.length > 0) {
      // Prioriza correspondencia exata e perfil porteiro
      perfis.sort((a, b) => {
        const aExato = normalizar(a.nome) === termoBusca ? 1 : 0;
        const bExato = normalizar(b.nome) === termoBusca ? 1 : 0;
        if (aExato !== bExato) return bExato - aExato;
        const aPort = a.tipo === 'porteiro' ? 1 : 0;
        const bPort = b.tipo === 'porteiro' ? 1 : 0;
        return bPort - aPort;
      });

      // Testa os candidatos encontrados buscando o email no Auth
      for (const p of perfis) {
        try {
          const { data: authUser, error: authErr } = await supabaseAdmin.auth.admin.getUserById(p.id);
          if (!authErr && authUser?.user?.email) {
            const { data: signData, error: signErr } = await supabaseAnon.auth.signInWithPassword({
              email: authUser.user.email,
              password,
            });
            if (!signErr && signData?.session) {
              sessaoValida = signData.session;
              perfilValido = p;
              break;
            }
          }
        } catch (err) {
          console.error('Erro ao testar credencial do perfil:', err);
        }
      }
    }
  }

  if (!sessaoValida || !perfilValido) {
    return res.status(401).json({ error: 'Nome/E-mail ou senha inválidos.' });
  }

  if (perfilValido.aprovado === false) {
    return res.status(403).json({ error: 'Seu cadastro ainda está aguardando aprovação da administração.' });
  }
  if (!perfilValido.ativo) {
    return res.status(403).json({ error: 'Usuário desativado. Procure a administração.' });
  }

  setSessionCookie(res, sessaoValida, rememberMe);
  res.json({ perfil: perfilValido });
});


// Esqueci minha senha: dispara o e-mail de recuperação do Supabase.
// Resposta sempre genérica (não revela se o e-mail existe).
app.post('/api/esqueci-senha', limiteLogin, async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Informe um e-mail válido.' });
  }

  // Monta a URL de retorno (página onde o usuário define a nova senha).
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0];
  const host = req.headers['x-forwarded-host'] || req.get('host');
  const redirectTo = `${proto}://${host}/redefinir-senha.html`;

  try {
    await supabaseAnon.auth.resetPasswordForEmail(email, { redirectTo });
  } catch (e) {
    console.warn('[Esqueci senha] Falha ao enviar e-mail:', e.message);
  }
  // Sempre ok (evita enumeração de e-mails).
  res.json({ ok: true });
});

// Redefinir senha: recebe o access_token (do link de recuperação) + nova senha.
// Valida o token identificando o usuário e troca a senha via service role.
app.post('/api/redefinir-senha', limiteLogin, async (req, res) => {
  const { access_token, password } = req.body || {};
  if (!access_token) {
    return res.status(400).json({ error: 'Link inválido ou expirado. Solicite um novo e-mail de recuperação.' });
  }
  if (!password || String(password).length < 6) {
    return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });
  }

  try {
    // Identifica o usuário a partir do token de recuperação.
    const client = supabaseForToken(access_token);
    const { data: userData, error } = await client.auth.getUser();
    if (error || !userData?.user) {
      return res.status(400).json({ error: 'Link inválido ou expirado. Solicite um novo e-mail de recuperação.' });
    }
    // Troca a senha com permissão administrativa.
    const { error: errUpd } = await supabaseAdmin.auth.admin.updateUserById(userData.user.id, {
      password: String(password),
    });
    if (errUpd) return res.status(400).json({ error: errUpd.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'Não foi possível redefinir a senha. Solicite um novo e-mail de recuperação.' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

// Cadastro publico de morador (link enviado pela administracao).
// O morador fica PENDENTE (inativo) ate o admin aprovar.
const LOTES_VALIDOS = Array.from({ length: 28 }, (_, i) => 'Lote ' + String(i + 1).padStart(2, '0'));

function cpfValido(cpf) {
  const d = (cpf || '').replace(/\D/g, '');
  if (d.length !== 11 || /^(\d)\1+$/.test(d)) return false;
  for (let t = 9; t < 11; t++) {
    let s = 0;
    for (let i = 0; i < t; i++) s += Number(d[i]) * (t + 1 - i);
    if (((s * 10) % 11) % 10 !== Number(d[t])) return false;
  }
  return true;
}

function formatarDocumento(doc) {
  if (!doc) return null;
  const limpo = String(doc).replace(/\D/g, '');
  if (limpo.length === 11) {
    return `${limpo.slice(0, 3)}.${limpo.slice(3, 6)}.${limpo.slice(6, 9)}-${limpo.slice(9, 11)}`;
  }
  if (limpo.length === 14) {
    return `${limpo.slice(0, 2)}.${limpo.slice(2, 5)}.${limpo.slice(5, 8)}/${limpo.slice(8, 12)}-${limpo.slice(12, 14)}`;
  }
  return String(doc).trim();
}

// Valores sentinela de nome_pessoa comparados com === em várias partes do código.
// NUNCA podem virar maiúsculas, senão quebram as comparações.
const SENTINELAS_NOME = ['Encomenda', 'Troca de turno'];

// Comparador para ordenar perfis por número do lote (Lote 01, 02, 03...),
// deixando quem NÃO tem lote (porteiro/admin) no final, ordenado por nome.
// Usa o campo `bloco` (ex.: "Lote 07", "7", "07"). Extrai os dígitos.
function ordenarPorLote(a, b) {
  const numLote = (p) => {
    const digitos = (p && p.bloco ? String(p.bloco) : '').replace(/\D/g, '');
    return digitos ? parseInt(digitos, 10) : null;
  };
  const la = numLote(a);
  const lb = numLote(b);
  // Ambos sem lote: ordena por nome.
  if (la === null && lb === null) {
    return (a.nome || '').localeCompare(b.nome || '', 'pt-BR');
  }
  if (la === null) return 1;  // a (sem lote) vai depois
  if (lb === null) return -1; // b (sem lote) vai depois
  if (la !== lb) return la - lb; // ordem numérica do lote
  // Mesmo lote: desempata por nome.
  return (a.nome || '').localeCompare(b.nome || '', 'pt-BR');
}

// Coloca um texto de CONTEÚDO em MAIÚSCULAS (nome, observação, endereço, placa, etc.).
// Preserva null/vazio e os valores sentinela. Não use em e-mail, senha, cpf, telefone, cep ou enums.
function maiuscula(valor) {
  if (valor === null || valor === undefined) return valor;
  const s = String(valor).trim();
  if (!s) return s;
  // Preserva sentinelas exatos e nomes de entregador de app (ex.: "Entregador iFood - ...").
  if (SENTINELAS_NOME.includes(s)) return s;
  if (s.startsWith('Entregador iFood')) return s;
  return s.toUpperCase();
}

app.post('/api/public/cadastro', limitePublico, async (req, res) => {
  const { nome, bloco, telefone, email, password } = req.body || {};
  const cpf = (req.body?.cpf || '').replace(/\D/g, '');
  if (!nome?.trim() || !bloco || !telefone?.trim() || !email?.trim() || !password || !cpf) {
    return res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
  }
  if (!cpfValido(cpf)) {
    return res.status(400).json({ error: 'CPF inválido.' });
  }
  const { data: cpfExiste } = await supabaseAdmin.from('perfis').select('id').eq('cpf', cpf).limit(1);
  if (cpfExiste && cpfExiste.length > 0) {
    return res.status(400).json({ error: 'Este CPF já está cadastrado.' });
  }
  if (!LOTES_VALIDOS.includes(bloco)) {
    return res.status(400).json({ error: 'Lote inválido.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });
  }

  const meta = { nome: maiuscula(nome.trim()), tipo: 'morador', bloco, telefone: telefone.trim(), pendente: true };
  const { data, error } = await supabaseAdmin.auth.admin.createUser({
    email: email.trim().toLowerCase(),
    password,
    email_confirm: true,
    user_metadata: meta,
  });
  if (error) {
    const jaExiste = /already|registered|exists/i.test(error.message);
    return res.status(400).json({ error: jaExiste ? 'Este e-mail já está cadastrado.' : error.message });
  }

  await supabaseAdmin.from('perfis').upsert({
    id: data.user.id,
    nome: meta.nome,
    tipo: 'morador',
    bloco,
    telefone: meta.telefone,
    cpf,
    ativo: false,
    aprovado: false,
  });

  res.status(201).json({ ok: true });
});

// Dados do usuario logado
app.get('/api/me', requireAuth, (req, res) => {
  // Anexa o e-mail (vive no Auth) ao perfil, só para exibição.
  // Em impersonação, sinaliza o estado para a UI do morador mostrar a faixa.
  res.json({
    perfil: {
      ...req.perfil,
      email: req.user?.email || null,
      impersonando: !!req.impersonando,
      admin_real: req.impersonando ? (req.adminReal?.nome || 'Administrador') : null,
    },
  });
});

// Atualiza o proprio cadastro (campos que o usuario pode editar)
app.put('/api/me', requireAuth, async (req, res) => {
  const {
    nome, telefone, bloco, apartamento,
    cep, endereco_logradouro, endereco_numero, endereco_bairro,
    endereco_cidade, endereco_uf, endereco_complemento,
  } = req.body || {};
  if (!nome || !nome.trim()) {
    return res.status(400).json({ error: 'Informe o nome.' });
  }

  // Monta a atualização apenas com os campos realmente enviados, para não
  // apagar dados que o formulário não envia (ex: o lote, que nunca muda aqui).
  const patch = { nome: maiuscula(nome.trim()) };
  if (telefone !== undefined) patch.telefone = telefone?.trim() || null;
  if (bloco !== undefined) patch.bloco = bloco?.trim() || null;
  if (apartamento !== undefined) patch.apartamento = maiuscula(apartamento?.trim()) || null;
  if (cep !== undefined) patch.cep = String(cep).replace(/\D/g, '') || null;
  if (endereco_logradouro !== undefined) patch.endereco_logradouro = maiuscula(endereco_logradouro?.trim()) || null;
  if (endereco_numero !== undefined) patch.endereco_numero = endereco_numero?.trim() || null;
  if (endereco_bairro !== undefined) patch.endereco_bairro = maiuscula(endereco_bairro?.trim()) || null;
  if (endereco_cidade !== undefined) patch.endereco_cidade = maiuscula(endereco_cidade?.trim()) || null;
  if (endereco_uf !== undefined) patch.endereco_uf = endereco_uf?.trim().toUpperCase().slice(0, 2) || null;
  if (endereco_complemento !== undefined) patch.endereco_complemento = maiuscula(endereco_complemento?.trim()) || null;

  const { data, error } = await supabaseAdmin
    .from('perfis')
    .update(patch)
    .eq('id', req.user.id)
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json({ perfil: data });
});

// ============================================================
// PUSH NOTIFICATIONS
// ============================================================

// Expõe a chave pública VAPID para o frontend (evita hardcode no HTML).
app.get('/api/push/public-key', (req, res) => {
  res.json({ publicKey: vapidPublicKey });
});

app.post('/api/push/subscribe', requireAuth, async (req, res) => {
  const subscription = req.body;
  if (!subscription) return res.status(400).json({ error: 'Subscription missing' });
  
  // Salva no perfil do morador (a coluna push_subscription deve existir como JSONB)
  const { error } = await req.supabase
    .from('perfis')
    .update({ push_subscription: subscription })
    .eq('id', req.user.id);
    
  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({});
});

// Funcao auxiliar para notificar moradores de um lote
async function notificarLote(bloco, titulo, mensagem) {
  if (!pushAtivo) return; // push não configurado: nada a enviar
  if (!bloco) return;
  const numeroBloco = bloco.replace(/lote\s*/i, '').trim();
  const { data: moradores } = await supabaseAdmin
    .from('perfis')
    .select('push_subscription')
    .ilike('bloco', `%${numeroBloco}%`)
    .not('push_subscription', 'is', null);

  if (moradores && moradores.length > 0) {
    const payload = JSON.stringify({ title: titulo, body: mensagem });
    moradores.forEach(m => {
      webpush.sendNotification(m.push_subscription, payload).catch(err => console.error("Erro push:", err));
    });
  }
}

// Formata um horário (ISO) como "13/10 às 14:32" para o aviso de WhatsApp.
function horarioCurto(iso) {
  try {
    const d = iso ? new Date(iso) : new Date();
    const dia = String(d.getDate()).padStart(2, '0');
    const mes = String(d.getMonth() + 1).padStart(2, '0');
    const hora = String(d.getHours()).padStart(2, '0');
    const min = String(d.getMinutes()).padStart(2, '0');
    return `${dia}/${mes} às ${hora}:${min}`;
  } catch {
    return '';
  }
}

// Dispara o aviso de WhatsApp para o morador destino de uma entrada registrada.
// "Dispara e esquece": nunca lança, apenas loga. O registro de entrada não pode
// falhar por causa do WhatsApp. Resolve o telefone por destino_morador (quando
// o porteiro selecionou o morador) ou por lote (todos os moradores do lote).
async function notificarWhatsappEntrada(registro) {
  try {
    if (!whatsappAtivo()) return;
    if (!registro) return;

    const tipo = registro.tipo || 'Visitante';
    // Não notifica a entrada do próprio morador (evita auto-aviso).
    if (tipo === 'Morador') return;
    // Sentinela administrativa: troca de turno não é visita.
    if (registro.nome_pessoa === 'Troca de turno') return;

    const oQueChegou = descreverEntrada({ nome_pessoa: registro.nome_pessoa, tipo });
    const destino = registro.destino_bloco || 'portaria';
    const horario = horarioCurto(registro.entrada);

    // 1) Destino direto: um morador específico foi selecionado.
    let telefones = [];
    if (registro.destino_morador) {
      const { data: m } = await supabaseAdmin
        .from('perfis')
        .select('telefone')
        .eq('id', registro.destino_morador)
        .single();
      if (m && m.telefone) telefones.push(m.telefone);
    }

    // 2) Fallback: sem morador específico, avisa todos os moradores do lote.
    if (telefones.length === 0 && registro.destino_bloco) {
      const numeroBloco = registro.destino_bloco.replace(/lote\s*/i, '').trim();
      if (numeroBloco) {
        const { data: moradores } = await supabaseAdmin
          .from('perfis')
          .select('telefone, tipo')
          .ilike('bloco', `%${numeroBloco}%`)
          .in('tipo', ['morador', 'admin'])
          .not('telefone', 'is', null);
        (moradores || []).forEach((m) => {
          if (m.telefone) telefones.push(m.telefone);
        });
      }
    }

    // Remove duplicados.
    telefones = [...new Set(telefones.filter(Boolean))];
    if (telefones.length === 0) return;

    for (const tel of telefones) {
      const r = await enviarTemplateEntrada({ telefone: tel, oQueChegou, destino, horario });
      if (!r.ok && r.motivo !== 'desativado') {
        console.warn('[WhatsApp] Falha ao notificar entrada:', r.motivo, r.detalhe || '');
      }
    }
  } catch (err) {
    console.warn('[WhatsApp] Erro inesperado ao notificar entrada:', err.message);
  }
}

// ============================================================
// MORADOR - avisos de visita
// ============================================================

// Busca registros de portaria (sem aviso) direcionados a UM morador específico.
// - Novos registros: vínculo direto por destino_morador = id do morador.
// - Registros antigos (sem destino_morador): fallback por lote + nome na observação,
//   para preservar o histórico já existente sem vazar entre vizinhos de lote.
async function buscarRegistrosDoMorador(perfil, moradorId) {
  const resultados = new Map();

  // 1) Vínculo direto (preferencial)
  const { data: diretos } = await supabaseAdmin
    .from('registros_portaria')
    .select('*')
    .eq('destino_morador', moradorId)
    .is('aviso_id', null)
    .order('entrada', { ascending: false });
  (diretos || []).forEach((r) => resultados.set(r.id, r));

  // 2) Fallback para registros antigos (sem destino_morador) do mesmo lote,
  //    filtrando pelo nome do morador quando ele aparece na observação.
  if (perfil && perfil.bloco && perfil.nome) {
    const numeroBloco = perfil.bloco.replace(/lote\s*/i, '').trim();
    const primeiroNome = perfil.nome.trim().split(/\s+/)[0];
    const { data: antigos } = await supabaseAdmin
      .from('registros_portaria')
      .select('*')
      .ilike('destino_bloco', `%${numeroBloco}%`)
      .is('aviso_id', null)
      .is('destino_morador', null)
      .ilike('observacao', `%${primeiroNome}%`)
      .order('entrada', { ascending: false });
    (antigos || []).forEach((r) => {
      if (!resultados.has(r.id)) resultados.set(r.id, r);
    });
  }

  return Array.from(resultados.values()).sort(
    (a, b) => new Date(b.entrada) - new Date(a.entrada)
  );
}

// Monta a lista de "visitas" de um morador: os avisos cadastrados por ele +
// os registros da portaria direcionados a ele. Usado tanto na visão própria
// quanto na visão de supervisão do lote. Usa supabaseAdmin (service role).
async function montarHistoricoVisitas(perfilMorador, moradorId) {
  const { data: avisosData } = await supabaseAdmin
    .from('avisos_visitas')
    .select('*')
    .eq('morador_id', moradorId)
    .order('criado_em', { ascending: false });

  let historico = [...(avisosData || [])];

  const regData = await buscarRegistrosDoMorador(perfilMorador, moradorId);
  if (regData.length) {
    const diretos = regData.map((p) => ({
      id: `p_${p.id}`,
      nome_visitante: p.nome_pessoa === 'Encomenda' ? p.observacao : p.nome_pessoa,
      documento_visitante: p.documento,
      veiculo_placa: p.veiculo_placa,
      tipo: p.nome_pessoa === 'Encomenda' ? 'Encomenda' : p.tipo,
      data_prevista: p.entrada,
      status: p.saida ? 'Finalizada' : 'Entrada Realizada',
      criado_em: p.entrada,
    }));
    historico = historico.concat(diretos);
  }

  // Notificações da administração também entram no histórico (registro permanente).
  // A tabela só existe se o schema foi migrado; por isso o try/catch silencioso.
  try {
    const { data: notifs } = await supabaseAdmin
      .from('notificacoes_morador')
      .select('*')
      .eq('morador_id', moradorId)
      .order('criado_em', { ascending: false });
    (notifs || []).forEach((n) => {
      historico.push({
        id: `n_${n.id}`,
        nome_visitante: n.titulo,
        veiculo_placa: (n.texto || '').slice(0, 80), // vira o subtítulo na coluna do nome
        documento_visitante: null,
        tipo: 'Notificação',
        data_prevista: n.criado_em,
        status: n.visualizado_em ? 'Visualizada' : 'Pendente',
        criado_em: n.criado_em,
      });
    });
  } catch (e) {
    // Tabela de notificações ainda não migrada: ignora.
  }

  historico.sort((a, b) => new Date(b.criado_em) - new Date(a.criado_em));
  return historico;
}

// Lista o histórico do próprio morador: avisos de visita + registros da portaria
// direcionados a ele + notificações da administração.
app.get('/api/morador/avisos', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const historico = await montarHistoricoVisitas(req.perfil, req.user.id);
    res.json({ avisos: historico });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Lista os OUTROS moradores do mesmo lote (visão de supervisão).
// Só é liberada se o morador logado tiver a permissão ver_lote.
app.get('/api/morador/lote/moradores', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const souAdmin = req.perfil?.tipo === 'admin';
    if (!souAdmin && !req.perfil?.ver_lote) {
      return res.status(403).json({ error: 'Você não tem permissão para ver as visitas do lote.' });
    }
    const bloco = req.perfil?.bloco;
    if (!bloco) return res.json({ moradores: [] });

    const { data, error } = await supabaseAdmin
      .from('perfis')
      .select('id, nome, bloco, telefone, ativo, aprovado')
      .eq('bloco', bloco)
      .eq('tipo', 'morador')
      .neq('id', req.user.id) // exclui o próprio
      .order('nome', { ascending: true });
    if (error) throw error;
    res.json({ moradores: data || [] });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// O "admin do lote" (morador com ver_lote) libera ou bloqueia o acesso de outro
// morador DO MESMO LOTE ao sistema. body: { liberar: true|false }.
app.post('/api/morador/lote/moradores/:moradorId/acesso', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const souAdmin = req.perfil?.tipo === 'admin';
    if (!souAdmin && !req.perfil?.ver_lote) {
      return res.status(403).json({ error: 'Você não tem permissão para administrar os moradores do lote.' });
    }

    const { moradorId } = req.params;
    const liberar = !!(req.body && req.body.liberar);

    if (moradorId === req.user.id) {
      return res.status(400).json({ error: 'Você não pode alterar o seu próprio acesso.' });
    }

    // Confirma que o alvo é um morador do MESMO lote.
    const { data: alvo, error: erroAlvo } = await supabaseAdmin
      .from('perfis')
      .select('id, bloco, tipo')
      .eq('id', moradorId)
      .single();
    if (erroAlvo || !alvo) return res.status(404).json({ error: 'Morador não encontrado.' });

    if (!souAdmin) {
      if (alvo.bloco !== req.perfil?.bloco) {
        return res.status(403).json({ error: 'Este morador não pertence ao seu lote.' });
      }
      if (alvo.tipo !== 'morador') {
        return res.status(403).json({ error: 'Só é possível administrar moradores.' });
      }
    }

    // Liberar = ativo e aprovado; Bloquear = inativo (sem acesso).
    const { error: erroUpd } = await supabaseAdmin
      .from('perfis')
      .update({ ativo: liberar, aprovado: liberar ? true : alvo.aprovado })
      .eq('id', moradorId);
    if (erroUpd) throw erroUpd;

    res.json({ sucesso: true, ativo: liberar });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Morador com permissão ver_lote cadastra outro morador NO MESMO LOTE.
// O novo morador entra ativo/aprovado. O lote é forçado para o do solicitante
// (nunca aceito do cliente), e o perfil só pode ser morador.
app.post('/api/morador/lote/cadastrar', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const souAdmin = req.perfil?.tipo === 'admin';
    if (!souAdmin && !req.perfil?.ver_lote) {
      return res.status(403).json({ error: 'Você não tem permissão para cadastrar moradores do lote.' });
    }

    const bloco = req.perfil?.bloco;
    if (!bloco) {
      return res.status(400).json({ error: 'Seu cadastro não tem um lote definido. Fale com a administração.' });
    }

    let { nome, email, password, telefone, cpf } = req.body || {};
    nome = maiuscula((nome || '').trim()) || '';
    email = (email || '').trim().toLowerCase();
    telefone = (telefone || '').trim();
    const cpfLimpo = (cpf || '').replace(/\D/g, '') || null;

    if (!nome) return res.status(400).json({ error: 'Informe o nome completo.' });
    if (!email) return res.status(400).json({ error: 'Informe o e-mail de acesso.' });
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });
    }
    if (cpfLimpo && !cpfValido(cpfLimpo)) {
      return res.status(400).json({ error: 'CPF inválido.' });
    }

    const { data, error } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { nome, tipo: 'morador', bloco, telefone, cpf: cpfLimpo },
    });

    if (error) {
      const jaExiste = /already|registered|exists/i.test(error.message);
      return res.status(400).json({ error: jaExiste ? 'Este e-mail já está cadastrado.' : error.message });
    }

    // Garante o perfil (ativo e aprovado; lote travado no do solicitante).
    await supabaseAdmin.from('perfis').upsert({
      id: data.user.id,
      nome,
      tipo: 'morador',
      bloco,
      telefone: telefone || null,
      cpf: cpfLimpo,
      ativo: true,
      aprovado: true,
      ver_lote: false, // o novo morador não herda a permissão de supervisão
    });

    res.status(201).json({ id: data.user.id });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Visitas de um morador específico do lote (visão de supervisão).
// Valida: solicitante tem ver_lote E o alvo é do MESMO lote.
app.get('/api/morador/lote/visitas/:moradorId', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const souAdmin = req.perfil?.tipo === 'admin';
    if (!souAdmin && !req.perfil?.ver_lote) {
      return res.status(403).json({ error: 'Você não tem permissão para ver as visitas do lote.' });
    }

    const { moradorId } = req.params;
    const { data: alvo, error: errAlvo } = await supabaseAdmin
      .from('perfis')
      .select('id, nome, bloco, tipo')
      .eq('id', moradorId)
      .single();
    if (errAlvo || !alvo) return res.status(404).json({ error: 'Morador não encontrado.' });

    // Segurança: admin pode ver qualquer um; morador só do próprio lote.
    if (!souAdmin && (alvo.bloco || '') !== (req.perfil?.bloco || '')) {
      return res.status(403).json({ error: 'Este morador não pertence ao seu lote.' });
    }

    const visitas = await montarHistoricoVisitas(alvo, moradorId);
    res.json({ morador: { id: alvo.id, nome: alvo.nome, bloco: alvo.bloco }, avisos: visitas });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ---------- Visitas recorrentes (frequência semanal) ----------

// Lista as recorrências do lote vinculado (compartilhado entre moradores do mesmo lote).
app.get('/api/morador/recorrencias', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const bloco = req.query.lote || req.perfil?.bloco;
    let idsMoradores = [req.user.id];
    if (bloco) {
      const { data: moradoresDoLote } = await supabaseAdmin
        .from('perfis')
        .select('id')
        .eq('bloco', bloco);
      if (moradoresDoLote && moradoresDoLote.length) {
        idsMoradores = moradoresDoLote.map((m) => m.id);
        if (!idsMoradores.includes(req.user.id)) idsMoradores.push(req.user.id);
      }
    }
    const { data, error } = await supabaseAdmin
      .from('visitas_recorrentes')
      .select('*')
      .in('morador_id', idsMoradores)
      .eq('ativo', true)
      .order('criado_em', { ascending: false });
    if (error) return res.status(400).json({ error: error.message });
    res.json({ recorrencias: data || [] });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Cria/atualiza a recorrência de um visitante (define os dias da semana).
// Se já existir uma recorrência ativa para o mesmo nome, substitui os dias.
app.post('/api/morador/recorrencias', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const { nome_visitante, documento_visitante, tipo, veiculo_placa, dias_semana } = req.body || {};
  const nome = maiuscula((nome_visitante || '').trim()) || '';
  if (!nome) return res.status(400).json({ error: 'Informe o nome do visitante.' });

  // CPF obrigatório e válido.
  const cpfRec = (documento_visitante || '').replace(/\D/g, '');
  if (cpfRec.length !== 11 || !cpfValido(cpfRec)) {
    return res.status(400).json({ error: 'Informe um CPF válido (11 dígitos) para o visitante.' });
  }

  // Normaliza os dias: inteiros únicos entre 0 (Dom) e 6 (Sáb).
  const dias = Array.isArray(dias_semana)
    ? [...new Set(dias_semana.map((d) => parseInt(d, 10)).filter((d) => d >= 0 && d <= 6))]
    : [];
  if (!dias.length) {
    return res.status(400).json({ error: 'Selecione pelo menos um dia da semana.' });
  }

  // Se já há recorrência ativa para esse visitante (mesmo nome), atualiza os dias.
  const nomeNorm = nome.toLowerCase();
  const { data: existentes } = await supabaseAdmin
    .from('visitas_recorrentes')
    .select('*')
    .eq('morador_id', req.user.id)
    .eq('ativo', true);
  const jaExiste = (existentes || []).find((r) => (r.nome_visitante || '').trim().toLowerCase() === nomeNorm);

  if (jaExiste) {
    const { data, error } = await supabaseAdmin
      .from('visitas_recorrentes')
      .update({
        dias_semana: dias,
        documento_visitante: documento_visitante || jaExiste.documento_visitante || null,
        tipo: tipo || jaExiste.tipo || 'Visitante',
        veiculo_placa: maiuscula(veiculo_placa) || jaExiste.veiculo_placa || null,
      })
      .eq('id', jaExiste.id)
      .select()
      .single();
    if (error) return res.status(400).json({ error: error.message });
    return res.json({ recorrencia: data });
  }

  const { data, error } = await supabaseAdmin
    .from('visitas_recorrentes')
    .insert({
      morador_id: req.user.id,
      nome_visitante: nome,
      documento_visitante: documento_visitante || null,
      tipo: tipo || 'Visitante',
      veiculo_placa: maiuscula(veiculo_placa) || null,
      dias_semana: dias,
      ativo: true,
    })
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ recorrencia: data });
});

// Remove (desativa) uma recorrência do morador.
app.delete('/api/morador/recorrencias/:id', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const { id } = req.params;
  const { error } = await supabaseAdmin
    .from('visitas_recorrentes')
    .delete()
    .eq('id', id)
    .eq('morador_id', req.user.id); // só pode remover as próprias
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true });
});

// Busca visitas frequentes agregadas por nome/documento SOMENTE do lote vinculado (compartilhado entre moradores do mesmo lote)
app.get('/api/morador/visitas-frequentes', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const bloco = req.query.lote || req.perfil?.bloco;
    if (!bloco) {
      return res.json({ frequentes: [] });
    }

    const num = bloco.replace(/\D/g, '');
    const numPadded = num ? String(parseInt(num, 10)).padStart(2, '0') : '';
    const numUnpadded = num ? String(parseInt(num, 10)) : '';
    const lotesPermitidos = [...new Set([bloco, 'Lote ' + numPadded, 'Lote ' + numUnpadded, numPadded, numUnpadded].filter(Boolean))];

    // Busca todos os moradores deste lote
    const { data: moradoresDoLote } = await supabaseAdmin
      .from('perfis')
      .select('id, nome, cpf')
      .eq('bloco', bloco);

    const idsMoradores = (moradoresDoLote || []).map(m => m.id);
    if (req.user?.id && !idsMoradores.includes(req.user.id)) {
      idsMoradores.push(req.user.id);
    }

    // Busca moradores/admins do condomínio para não listar nenhum deles como "visitante" do lote.
    const { data: todosMoradores } = await supabaseAdmin
      .from('perfis')
      .select('nome, cpf')
      .in('tipo', ['morador', 'admin']);
    const nomesMoradores = new Set((todosMoradores || []).map(m => (m.nome || '').trim().toLowerCase()));
    const cpfsMoradores = new Set((todosMoradores || []).map(m => (m.cpf || '').replace(/\D/g, '')).filter(Boolean));

    // Busca avisos deste lote e registros da portaria direcionados a este lote/moradores
    const [qAvisos, qRegistrosBloco, qRegistrosMorador] = await Promise.all([
      supabaseAdmin
        .from('avisos_visitas')
        .select('*')
        .in('morador_id', idsMoradores)
        .order('criado_em', { ascending: false })
        .limit(3000),
      supabaseAdmin
        .from('registros_portaria')
        .select('*')
        .is('aviso_id', null)
        .in('destino_bloco', lotesPermitidos)
        .order('entrada', { ascending: false })
        .limit(3000),
      idsMoradores.length > 0
        ? supabaseAdmin
            .from('registros_portaria')
            .select('*')
            .is('aviso_id', null)
            .in('destino_morador', idsMoradores)
            .order('entrada', { ascending: false })
            .limit(3000)
        : Promise.resolve({ data: [] })
    ]);

    const avisosData = qAvisos.data || [];
    const mapRegs = new Map();
    (qRegistrosBloco.data || []).forEach(r => mapRegs.set(r.id, r));
    (qRegistrosMorador.data || []).forEach(r => mapRegs.set(r.id, r));

    // Agrupar por chave (documento limpo ou nome normalizado)
    const map = {};

    avisosData.forEach(a => {
      const nomeLimpo = (a.nome_visitante || '').trim();
      if (!nomeLimpo || nomeLimpo === 'Entregador iFood' || nomeLimpo === 'Encomenda') return;
      if (a.tipo === 'Morador' || a.tipo === 'Outro' || a.tipo === 'Entregador') return;
      const docLimpo = (a.documento_visitante || '').replace(/\D/g, '');
      if (docLimpo && cpfsMoradores.has(docLimpo)) return;
      if (nomesMoradores.has(nomeLimpo.toLowerCase())) return;

      const chave = docLimpo || nomeLimpo.toLowerCase();
      if (!map[chave]) {
        map[chave] = { count: 0, ultimo: a };
      }
      map[chave].count++;
    });

    Array.from(mapRegs.values()).forEach(r => {
      const nomeLimpo = (r.nome_pessoa || '').trim();
      if (!nomeLimpo || nomeLimpo === 'Entregador iFood' || nomeLimpo === 'Encomenda') return;
      if (r.tipo === 'Morador' || r.tipo === 'Outro' || r.tipo === 'Entregador') return;
      const docLimpo = (r.documento || '').replace(/\D/g, '');
      if (docLimpo && cpfsMoradores.has(docLimpo)) return;
      if (nomesMoradores.has(nomeLimpo.toLowerCase())) return;

      const chave = docLimpo || nomeLimpo.toLowerCase();
      if (!map[chave]) {
        map[chave] = {
          count: 0,
          ultimo: {
            nome_visitante: r.nome_pessoa,
            documento_visitante: r.documento,
            veiculo_placa: r.veiculo_placa,
            tipo: r.tipo,
            endereco_visitante: r.endereco_visitante,
            cep_visitante: r.cep_visitante
          }
        };
      }
      map[chave].count++;
    });

    const frequentes = Object.values(map)
      .sort((a, b) => b.count - a.count)
      .map(x => ({ ...x.ultimo, count: x.count }))
      .filter(x => x.tipo !== 'Entregador' && x.tipo !== 'Morador' && x.tipo !== 'Outro' && x.nome_visitante !== 'Encomenda');

    res.json({ frequentes });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Gera um link de solicitação de cadastro (visitante/prestador) com validade de 2h.
// O link é assinado no servidor para que o prazo não possa ser burlado na URL.
app.get('/api/morador/link-visita', requireAuth, requireRole('morador', 'admin'), (req, res) => {
  const tipo = (req.query.tipo === 'Prestador') ? 'Prestador' : 'Visitante';
  const moradorId = req.user.id;
  const exp = Date.now() + LINK_VISITA_VALIDADE_MS;
  const sig = assinarLinkVisita(moradorId, tipo, exp);

  const params = new URLSearchParams({
    morador: moradorId,
    tipo,
    exp: String(exp),
    sig,
  });

  const tokenCurto = gerarTokenCurtoVisita(moradorId, tipo, exp);
  const caminhoCurto = tokenCurto ? `/c/${tokenCurto}` : `/cadastro-visita.html?${params.toString()}`;

  // Registra o compartilhamento do link (por morador + tipo) para o relatório
  // do admin. Não conta quando o admin está "vendo como morador" (impersonação),
  // para não inflar o contador. Dispara-e-esquece; tolera tabela ainda não criada.
  if (!req.impersonando) {
    supabaseAdmin
      .from('compartilhamentos_link')
      .insert({ morador_id: moradorId, tipo })
      .then(() => {}, () => {});
  }

  res.json({
    caminho: caminhoCurto,
    caminhoLongo: `/cadastro-visita.html?${params.toString()}`,
    exp,
    validade_minutos: Math.round(LINK_VISITA_VALIDADE_MS / 60000),
  });
});

// Morador bloqueia um visitante: registra o motivo como observação-alerta no
// histórico do visitante (mesmo histórico visto pelo admin/portaria).
app.post('/api/morador/visitantes/bloquear', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const { nome, documento, motivo } = req.body || {};
    const nomeLimpo = (nome || '').trim();
    const motivoLimpo = (motivo || '').trim();

    if (!nomeLimpo && !(documento || '').trim()) {
      return res.status(400).json({ error: 'Visitante não identificado.' });
    }
    if (!motivoLimpo) {
      return res.status(400).json({ error: 'Informe o motivo do bloqueio.' });
    }

    // Identifica de quem partiu o bloqueio (nome + lote do morador logado).
    const origemMorador = req.perfil
      ? `${req.perfil.nome}${req.perfil.bloco ? ' (' + req.perfil.bloco + ')' : ''}`
      : 'Morador';

    const texto = `[BLOQUEADO] Solicitado por ${origemMorador}. Motivo: ${motivoLimpo}`;

    const salvo = await adicionarObservacaoAoHistorico({
      nome: nomeLimpo,
      documento: documento || null,
      texto,
      exibir_alerta: true,
      userId: req.user.id,
      origem: 'bloqueio_morador',
    });

    res.json({ ok: true, visitante: salvo });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Morador edita os dados de um visitante/prestador do SEU lote.
// Atualiza nome/documento/tipo/placa nos avisos e recorrências dos moradores do
// lote e nos registros de portaria direcionados ao lote. Escopo restrito ao lote.
app.post('/api/morador/visitantes/editar', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const { nomeOriginal, documentoOriginal, nome, documento, tipo, veiculo_placa } = req.body || {};

    const novoNome = maiuscula((nome || '').trim()) || '';
    if (!novoNome) return res.status(400).json({ error: 'Informe o nome do visitante.' });

    // CPF obrigatório e válido.
    const cpfEdit = (documento || '').replace(/\D/g, '');
    if (cpfEdit.length !== 11 || !cpfValido(cpfEdit)) {
      return res.status(400).json({ error: 'Informe um CPF válido (11 dígitos) para o visitante.' });
    }

    const bloco = req.perfil?.bloco;
    if (!bloco) return res.status(400).json({ error: 'Seu cadastro não tem um lote definido.' });

    // Moradores do mesmo lote (para escopar avisos/recorrências).
    const { data: moradoresLote } = await supabaseAdmin
      .from('perfis').select('id').eq('bloco', bloco);
    const idsLote = (moradoresLote || []).map((m) => m.id);
    if (req.user?.id && !idsLote.includes(req.user.id)) idsLote.push(req.user.id);

    // Formatos de lote aceitos nos registros de portaria.
    const numLote = (bloco || '').replace(/\D/g, '');
    const lotesPermitidos = [...new Set([
      bloco,
      numLote ? `Lote ${String(parseInt(numLote, 10)).padStart(2, '0')}` : null,
      numLote ? `Lote ${String(parseInt(numLote, 10))}` : null,
      numLote ? String(parseInt(numLote, 10)) : null,
    ].filter(Boolean))];

    const docLimpoOriginal = (documentoOriginal || '').replace(/\D/g, '');
    const nomeNormOriginal = (nomeOriginal || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    const novoDocFormatado = formatarDocumento(documento);
    const novoTipo = tipo || 'Visitante';
    const novaPlaca = maiuscula((veiculo_placa || '').trim()) || null;

    const casaPorNomeOuDoc = (regDoc, regNome) => {
      const d = (regDoc || '').replace(/\D/g, '');
      if (docLimpoOriginal && d && d === docLimpoOriginal) return true;
      const n = (regNome || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      return !!(nomeNormOriginal && n === nomeNormOriginal);
    };

    // 1) avisos_visitas dos moradores do lote
    if (idsLote.length) {
      const { data: avisos } = await supabaseAdmin
        .from('avisos_visitas')
        .select('id, nome_visitante, documento_visitante')
        .in('morador_id', idsLote);
      const ids = (avisos || []).filter((a) => casaPorNomeOuDoc(a.documento_visitante, a.nome_visitante)).map((a) => a.id);
      if (ids.length) {
        await supabaseAdmin.from('avisos_visitas')
          .update({ nome_visitante: novoNome, documento_visitante: novoDocFormatado || null, tipo: novoTipo, veiculo_placa: novaPlaca })
          .in('id', ids);
      }
    }

    // 2) visitas_recorrentes dos moradores do lote
    if (idsLote.length) {
      const { data: recs } = await supabaseAdmin
        .from('visitas_recorrentes')
        .select('id, nome_visitante, documento_visitante')
        .in('morador_id', idsLote);
      const ids = (recs || []).filter((r) => casaPorNomeOuDoc(r.documento_visitante, r.nome_visitante)).map((r) => r.id);
      if (ids.length) {
        await supabaseAdmin.from('visitas_recorrentes')
          .update({ nome_visitante: novoNome, documento_visitante: novoDocFormatado || null, tipo: novoTipo, veiculo_placa: novaPlaca })
          .in('id', ids);
      }
    }

    // 3) registros_portaria direcionados ao lote
    const { data: regs } = await supabaseAdmin
      .from('registros_portaria')
      .select('id, nome_pessoa, documento, destino_bloco')
      .in('destino_bloco', lotesPermitidos);
    const idsRegs = (regs || []).filter((r) => casaPorNomeOuDoc(r.documento, r.nome_pessoa)).map((r) => r.id);
    if (idsRegs.length) {
      await supabaseAdmin.from('registros_portaria')
        .update({ nome_pessoa: novoNome, documento: novoDocFormatado || null, tipo: novoTipo, veiculo_placa: novaPlaca })
        .in('id', idsRegs);
    }

    res.json({ ok: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Cria um novo aviso de visita
app.post('/api/morador/avisos', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const {
    nome_visitante,
    documento_visitante,
    veiculo_placa,
    tipo,
    data_prevista,
    endereco_visitante,
    cep_visitante,
    observacao,
  } = req.body || {};

  if (!nome_visitante) {
    return res.status(400).json({ error: 'Informe o nome do visitante.' });
  }

  // CPF obrigatório e válido (11 dígitos) para Visitante/Prestador.
  // Entregador (iFood) e Encomenda não têm CPF do visitante — isentos.
  const cpfAviso = (documento_visitante || '').replace(/\D/g, '');
  const tipoAviso = tipo || 'Visitante';
  const exigeCpfAviso = (tipoAviso === 'Visitante' || tipoAviso === 'Prestador');
  if (exigeCpfAviso && (cpfAviso.length !== 11 || !cpfValido(cpfAviso))) {
    return res.status(400).json({ error: 'Informe um CPF válido (11 dígitos) para o visitante.' });
  }

  const docFormatado = formatarDocumento(documento_visitante);
  const { data, error } = await req.supabase
    .from('avisos_visitas')
    .insert({
      morador_id: req.user.id,
      nome_visitante: maiuscula(nome_visitante),
      documento_visitante: docFormatado || null,
      veiculo_placa: maiuscula(veiculo_placa) || null,
      tipo: tipo || 'Visitante',
      data_prevista: data_prevista || null,
      endereco_visitante: maiuscula(endereco_visitante) || null,
      cep_visitante: cep_visitante || null,
      observacao: maiuscula(observacao) || null,
      status: 'Pendente',
    })
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ aviso: data });
});

// Criar aviso via link publico (visitante se cadastra)
app.post('/api/public/avisos', limitePublico, async (req, res) => {
  const {
    morador_id,
    nome_visitante,
    documento_visitante,
    veiculo_placa,
    tipo,
    data_prevista,
    endereco_visitante,
    cep_visitante,
    observacao,
    link_exp,
    link_sig,
  } = req.body || {};

  if (!morador_id || !nome_visitante) {
    return res.status(400).json({ error: 'Morador e nome do visitante são obrigatórios.' });
  }

  // CPF obrigatório e válido (11 dígitos).
  const cpfPub = (documento_visitante || '').replace(/\D/g, '');
  if (cpfPub.length !== 11 || !cpfValido(cpfPub)) {
    return res.status(400).json({ error: 'Informe um CPF válido (11 dígitos).' });
  }

  // Valida o prazo (2h) e a assinatura do link antes de aceitar o cadastro.
  const validacaoLink = validarLinkVisita(morador_id, tipo || 'Visitante', link_exp, link_sig);
  if (!validacaoLink.ok) {
    const msg = validacaoLink.motivo === 'expirado'
      ? 'Este link expirou. Peça ao morador um novo link para solicitar o acesso ao condomínio.'
      : 'Link inválido. Peça ao morador um novo link para solicitar o acesso ao condomínio.';
    return res.status(403).json({ error: msg, motivo: validacaoLink.motivo });
  }

  const { data: morador, error: errMorador } = await supabaseAdmin
    .from('perfis')
    .select('id')
    .eq('id', morador_id)
    .single();

  if (errMorador || !morador) {
    return res.status(400).json({ error: 'Morador não encontrado.' });
  }

  // Impede o cadastro se o visitante/prestador estiver bloqueado.
  const docLimpoVis = (documento_visitante || '').replace(/\D/g, '');
  const nomeNormVis = (nome_visitante || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const obsBloqueio = await obterObservacaoVisitante(docLimpoVis, docLimpoVis, nomeNormVis);
  if (visitanteEstaBloqueado(obsBloqueio)) {
    return res.status(403).json({ error: MENSAGEM_BLOQUEIO, motivo: 'bloqueado' });
  }

  const docFormatado = formatarDocumento(documento_visitante);
  const { data, error } = await supabaseAdmin
    .from('avisos_visitas')
    .insert({
      morador_id,
      nome_visitante: maiuscula(nome_visitante),
      documento_visitante: docFormatado || null,
      veiculo_placa: maiuscula(veiculo_placa) || null,
      tipo: tipo || 'Visitante',
      data_prevista: data_prevista || null,
      endereco_visitante: maiuscula(endereco_visitante) || null,
      cep_visitante: cep_visitante || null,
      observacao: maiuscula(observacao) || null,
      status: 'Pendente',
    })
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ aviso: data });
});

// Verifica se o visitante/prestador ja possui cadastro previo pelo CPF (rota publica)
// Protegida por: rate limit + link assinado válido (evita enumeração de CPFs).
app.get('/api/public/visitantes/verificar', limitePublico, async (req, res) => {
  try {
    // Exige o mesmo link assinado (morador/tipo/exp/sig) usado na tela de cadastro.
    // Sem link válido e dentro do prazo, a consulta é recusada — fecha o oráculo
    // de enumeração que antes respondia a qualquer CPF sem contexto.
    const linkMorador = (req.query.morador || '').trim();
    const linkTipo = (req.query.tipo || 'Visitante').trim();
    const linkExp = req.query.exp;
    const linkSig = req.query.sig;
    const valido = validarLinkVisita(linkMorador, linkTipo, linkExp, linkSig);
    if (!valido.ok) {
      return res.status(403).json({
        error: valido.motivo === 'expirado'
          ? 'Este link expirou. Peça ao morador um novo link.'
          : 'Link inválido. Peça ao morador um novo link.',
        motivo: valido.motivo,
      });
    }

    const doc = (req.query.cpf || req.query.documento || '').trim();
    if (!doc) return res.status(400).json({ error: 'Informe o CPF para verificar.' });

    const docLimpo = doc.replace(/\D/g, '');
    // A consulta é por CPF: exige os 11 dígitos completos e válidos.
    if (docLimpo.length !== 11) {
      return res.status(400).json({ error: 'Digite o CPF completo (11 dígitos).' });
    }
    if (!cpfValido(docLimpo)) {
      return res.status(400).json({ error: 'CPF inválido.' });
    }

    // 1. Procura na base oficial de moradores/perfis
    const { data: perfis } = await supabaseAdmin
      .from('perfis')
      .select('id, nome, bloco, apartamento, telefone, cpf, tipo')
      .not('cpf', 'is', null);

    const morador = (perfis || []).find(
      (p) => (p.cpf || '').replace(/\D/g, '') === docLimpo && docLimpo
    );

    if (morador) {
      return res.json({
        cadastrado: true,
        eh_morador: true,
        visitante: {
          nome: morador.nome,
          documento: morador.cpf || doc,
          tipo: 'Morador',
          veiculo_placa: '',
          endereco_visitante: null,
          cep_visitante: null,
        },
      });
    }

    // 2. Procura em registros de portaria anteriores
    const { data: registros } = await supabaseAdmin
      .from('registros_portaria')
      .select('nome_pessoa, documento, veiculo_placa, tipo, endereco_visitante, cep_visitante, entrada')
      .not('documento', 'is', null)
      .order('entrada', { ascending: false })
      .limit(500);

    const reg = (registros || []).find(
      (r) => (r.documento || '').replace(/\D/g, '') === docLimpo && docLimpo
    );

    // 3. Procura em avisos de visita anteriores
    const { data: avisos } = await supabaseAdmin
      .from('avisos_visitas')
      .select('nome_visitante, documento_visitante, veiculo_placa, tipo, endereco_visitante, cep_visitante, criado_em')
      .not('documento_visitante', 'is', null)
      .order('criado_em', { ascending: false })
      .limit(500);

    const aviso = (avisos || []).find(
      (a) => (a.documento_visitante || '').replace(/\D/g, '') === docLimpo && docLimpo
    );

    // 4. Procura em observações cadastradas de visitantes
    const obsVisitante = await obterObservacaoVisitante(docLimpo, docLimpo, null);
    const bloqueado = visitanteEstaBloqueado(obsVisitante);
    const extraBloqueio = bloqueado
      ? { bloqueado: true, mensagem_bloqueio: MENSAGEM_BLOQUEIO }
      : { bloqueado: false };

    if (reg) {
      return res.json({
        cadastrado: true,
        eh_morador: false,
        ...extraBloqueio,
        visitante: {
          nome: reg.nome_pessoa,
          documento: reg.documento || doc,
          tipo: reg.tipo || 'Visitante',
          veiculo_placa: reg.veiculo_placa || '',
          endereco_visitante: reg.endereco_visitante || null,
          cep_visitante: reg.cep_visitante || null,
        },
      });
    }

    if (aviso) {
      return res.json({
        cadastrado: true,
        eh_morador: false,
        ...extraBloqueio,
        visitante: {
          nome: aviso.nome_visitante,
          documento: aviso.documento_visitante || doc,
          tipo: aviso.tipo || 'Visitante',
          veiculo_placa: aviso.veiculo_placa || '',
          endereco_visitante: aviso.endereco_visitante || null,
          cep_visitante: aviso.cep_visitante || null,
        },
      });
    }

    if (obsVisitante && obsVisitante.nome) {
      return res.json({
        cadastrado: true,
        eh_morador: false,
        ...extraBloqueio,
        visitante: {
          nome: obsVisitante.nome,
          documento: obsVisitante.documento || doc,
          tipo: 'Visitante',
          veiculo_placa: '',
          endereco_visitante: null,
          cep_visitante: null,
        },
      });
    }

    return res.json({ cadastrado: false, ...extraBloqueio });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Informacoes basicas do morador para exibicao publica (cadastro de visita)
app.get('/api/public/moradores/:id', limitePublico, async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabaseAdmin
    .from('perfis')
    .select('nome, bloco')
    .eq('id', id)
    .single();

  if (error || !data) return res.status(404).json({ error: 'Morador não encontrado' });
  res.json({ morador: data });
});

// Cancela um aviso (apenas o dono)
app.post('/api/morador/avisos/:id/cancelar', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const { id } = req.params;
  const { data, error } = await req.supabase
    .from('avisos_visitas')
    .update({ status: 'Cancelada' })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ aviso: data });
});

// Lista de encomendas pendentes para o morador logado (apenas as dele).
app.get('/api/morador/encomendas', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const { data: perfil } = await supabaseAdmin.from('perfis').select('bloco, nome').eq('id', req.user.id).single();
  const bloco = perfil?.bloco;
  const nome = perfil?.nome;

  const encomendas = new Map();

  // 1) Encomendas vinculadas diretamente a este morador (destino_morador).
  const { data: diretas, error: errDir } = await supabaseAdmin
    .from('registros_portaria')
    .select('*')
    .eq('nome_pessoa', 'Encomenda')
    .eq('destino_morador', req.user.id)
    .is('saida', null)
    .order('entrada', { ascending: false });
  if (errDir) return res.status(400).json({ error: errDir.message });
  (diretas || []).forEach((e) => encomendas.set(e.id, e));

  // 2) Fallback para encomendas antigas (sem destino_morador) do mesmo lote,
  //    filtrando pelo nome do morador na observação ("[ENCOMENDA] Para: Nome").
  if (bloco && nome) {
    const numeroBloco = bloco.replace(/lote\s*/i, '').trim();
    const primeiroNome = nome.trim().split(/\s+/)[0];
    const { data: antigas } = await supabaseAdmin
      .from('registros_portaria')
      .select('*')
      .eq('nome_pessoa', 'Encomenda')
      .ilike('destino_bloco', `%${numeroBloco}%`)
      .is('destino_morador', null)
      .ilike('observacao', `%${primeiroNome}%`)
      .is('saida', null)
      .order('entrada', { ascending: false });
    (antigas || []).forEach((e) => {
      if (!encomendas.has(e.id)) encomendas.set(e.id, e);
    });
  }

  const lista = Array.from(encomendas.values()).sort(
    (a, b) => new Date(b.entrada) - new Date(a.entrada)
  );
  res.json({ encomendas: await comPorteiros(lista) });
});

// ============================================================
// PORTEIRO - visitas previstas, entradas e saidas
// ============================================================

// Helpers de fuso horário de Brasília (America/Sao_Paulo)
function dataHojeBR() {
  const agora = new Date();
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(agora);
}

function diaSemanaHojeBR() {
  const agora = new Date();
  const dStr = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/Sao_Paulo',
    weekday: 'short',
  }).format(agora);
  const mapa = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return mapa[dStr];
}

function ehDoDiaHoje(dataPrevistaIso) {
  if (!dataPrevistaIso) return true;
  try {
    const d = new Date(dataPrevistaIso);
    if (isNaN(d.getTime())) return false;
    const dataAviso = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Sao_Paulo',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).format(d);
    return dataAviso === dataHojeBR();
  } catch (e) {
    return false;
  }
}

// Avisos pendentes/autorizados que a portaria deve esperar (SOMENTE do dia de hoje)
app.get('/api/portaria/avisos', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { data, error } = await req.supabase
    .from('avisos_visitas')
    .select('*, morador:perfis!avisos_visitas_morador_id_fkey(nome, bloco, apartamento, telefone)')
    .in('status', ['Pendente', 'Autorizada'])
    .order('data_prevista', { ascending: true, nullsFirst: false });
  if (error) return res.status(400).json({ error: error.message });

  // 1) Filtra avisos normais para exibir SOMENTE as visitas previstas para HOJE
  let avisos = (data || []).filter((a) => ehDoDiaHoje(a.data_prevista));

  // 2) Acrescenta as VISITAS RECORRENTES cujo dia da semana corresponde a hoje
  try {
    const hojeDOW = diaSemanaHojeBR();

    const { data: recs, error: recsErr } = await supabaseAdmin
      .from('visitas_recorrentes')
      .select('*, morador:perfis!visitas_recorrentes_morador_id_fkey(nome, bloco, apartamento, telefone)')
      .eq('ativo', true);

    if (recsErr) {
      console.error('Erro ao buscar visitas_recorrentes:', recsErr);
    }

    const doDia = (recs || []).filter(
      (r) => Array.isArray(r.dias_semana) && r.dias_semana.includes(hojeDOW)
    );

    // Documentos já presentes em avisos reais de hoje (evita duplicar na lista).
    const docsAvisos = new Set(
      avisos.map((a) => (a.documento_visitante || '').replace(/\D/g, '')).filter(Boolean)
    );

    const recorrentes = doDia
      .filter((r) => {
        const d = (r.documento_visitante || '').replace(/\D/g, '');
        if (d && docsAvisos.has(d)) return false; // já tem aviso específico hoje
        return true;
      })
      .map((r) => ({
        id: 'rec-' + r.id,
        recorrente: true,
        recorrencia_id: r.id,
        morador_id: r.morador_id,
        nome_visitante: r.nome_visitante,
        documento_visitante: r.documento_visitante,
        veiculo_placa: r.veiculo_placa,
        tipo: r.tipo,
        data_prevista: null,
        status: 'Pendente',
        observacao: 'Frequência programada para hoje',
        morador: r.morador || null,
      }));

    avisos = avisos.concat(recorrentes);
  } catch (e) {
    console.error('Falha ao processar visitas recorrentes:', e);
  }

  res.json({ avisos });
});

// Marca um aviso como "Nao compareceu" (vai direto para o historico, sem entrada)
app.post('/api/portaria/avisos/:id/nao-veio', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { id } = req.params;
  // Usa supabaseAdmin (service role) para a ação persistir independentemente de RLS,
  // igual às demais ações da portaria. Avisos recorrentes (id "rec-...") não são
  // persistíveis aqui — são regras semanais, não avisos reais.
  if (String(id).startsWith('rec-')) {
    return res.status(400).json({ error: 'Visita recorrente não pode ser marcada como "não veio". Ela reaparece automaticamente no próximo dia programado.' });
  }
  const { data, error } = await supabaseAdmin
    .from('avisos_visitas')
    .update({ status: 'Nao compareceu', nao_veio_por: req.user.id })
    .eq('id', id)
    .select();
  if (error) return res.status(400).json({ error: error.message });
  if (!data || !data.length) {
    return res.status(404).json({ error: 'Aviso não encontrado.' });
  }
  res.json({ aviso: data[0] });
});

// Busca os nomes dos porteiros (por id) para exibir quem fez cada acao.
async function mapaNomes(ids) {
  const unicos = [...new Set(ids.filter(Boolean))];
  if (!unicos.length) return {};
  const { data } = await supabaseAdmin.from('perfis').select('id, nome').in('id', unicos);
  return Object.fromEntries((data || []).map((p) => [p.id, p.nome]));
}

async function comPorteiros(registros) {
  const nomes = await mapaNomes(registros.flatMap((r) => [r.registrado_por, r.saida_por]));
  return registros.map((r) => ({
    ...r,
    porteiro_entrada: nomes[r.registrado_por] || null,
    porteiro_saida: nomes[r.saida_por] || null,
  }));
}

// Quem esta dentro do condominio agora (saida nula e nao e morador)
app.get('/api/portaria/presentes', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { data, error } = await req.supabase
    .from('registros_portaria')
    .select('*')
    .neq('nome_pessoa', 'Encomenda')
    .neq('tipo', 'Morador')
    .is('saida', null)
    .order('entrada', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });

  // Exclui moradores mesmo se salvos como 'Outro' pelo fallback do enum
  const apenasVisitantes = (data || []).filter(
    (r) => r.tipo !== 'Morador' && !(r.observacao || '').includes('[Entrada de Morador]')
  );

  res.json({ presentes: await comPorteiros(apenasVisitantes) });
});
// Historico completo (com filtro opcional por data e cpf).
// Inclui os registros de entrada/saida E os avisos marcados como "Nao compareceu".
app.get('/api/portaria/historico', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  let query = req.supabase
    .from('registros_portaria')
    .select('*')
    .order('id', { ascending: false });

  if (req.query.de) {
    query = query.or(`entrada.gte.${req.query.de},saida.gte.${req.query.de}`);
  }
  if (req.query.ate) {
    query = query.or(`entrada.lte.${req.query.ate},saida.lte.${req.query.ate}`);
  }
  if (req.query.cpf) query = query.ilike('documento', `%${likeSafe(req.query.cpf)}%`);
  if (req.query.lote) query = query.ilike('destino_bloco', `%${likeSafe(req.query.lote)}%`);

  query = query.limit(200);

  const { data, error } = await query;
  if (error) return res.status(400).json({ error: error.message });

  // Avisos que nao compareceram, no mesmo intervalo de data (por data_prevista ou criado_em).
  let qAvisos = req.supabase
    .from('avisos_visitas')
    .select('*, morador:perfis!avisos_visitas_morador_id_fkey!inner(bloco, apartamento)')
    .eq('status', 'Nao compareceu');

  if (req.query.de) qAvisos = qAvisos.or(`data_prevista.gte.${req.query.de},criado_em.gte.${req.query.de}`);
  if (req.query.ate) qAvisos = qAvisos.or(`data_prevista.lte.${req.query.ate},criado_em.lte.${req.query.ate}`);
  if (req.query.cpf) qAvisos = qAvisos.ilike('documento_visitante', `%${likeSafe(req.query.cpf)}%`);
  if (req.query.lote) qAvisos = qAvisos.ilike('perfis.bloco', `%${likeSafe(req.query.lote)}%`);

  qAvisos = qAvisos.limit(50);

  const { data: avisos, error: errAv } = await qAvisos;
  if (errAv) return res.status(400).json({ error: errAv.message });

  // Normaliza os avisos "nao compareceu" para o mesmo formato do historico.
  const nomesNaoVeio = await mapaNomes((avisos || []).map((a) => a.nao_veio_por));
  const naoCompareceu = (avisos || []).map((a) => {
    const m = a.morador || {};
    return {
      id: 'aviso-' + a.id,
      nome_pessoa: a.nome_visitante,
      tipo: a.tipo,
      destino_bloco: m.bloco || null,
      destino_apto: m.apartamento || null,
      entrada: a.data_prevista || a.criado_em,
      data_acao_real: a.criado_em,
      saida: null,
      status: 'Nao compareceu',
      porteiro_nao_veio: nomesNaoVeio[a.nao_veio_por] || null,
      observacao: a.observacao
    };
  });

  const registrosComPorteiros = await comPorteiros(data || []);
  const registrosNormalizados = registrosComPorteiros.map((r) => {
    let tipo = r.tipo;
    let observacao = r.observacao || '';
    if (observacao.includes('[Entrada de Morador]')) {
      tipo = 'Morador';
      observacao = observacao.replace('[Entrada de Morador]', '').trim();
    }
    return {
      ...r,
      tipo,
      observacao,
    };
  });

  // Determina o timestamp da última ação para ordenar sequencialmente:
  // Se já registrou saída, a última ação sequencial é o horário de SAÍDA.
  // Se ainda não saiu, a entrada é a última ação.
  // Para "Não compareceu", utiliza o momento real (criado_em / agora) sem avançar para datas futuras.
  const timestampUltimaAcao = (r) => {
    if (r.saida) {
      const tSaida = new Date(r.saida).getTime();
      if (!Number.isNaN(tSaida)) return tSaida;
    }
    if (r.status === 'Nao compareceu') {
      const tReal = r.data_acao_real ? new Date(r.data_acao_real).getTime() : Date.now();
      const tEntrada = new Date(r.entrada || 0).getTime();
      return Math.min(tEntrada, tReal || Date.now());
    }
    return new Date(r.entrada || 0).getTime();
  };

  const registros = [...registrosNormalizados, ...naoCompareceu].sort((x, y) => {
    const diff = timestampUltimaAcao(y) - timestampUltimaAcao(x);
    if (diff !== 0) return diff;
    return (Number(y.id) || 0) - (Number(x.id) || 0);
  }).slice(0, 100);

  res.json({ registros });
});

// ------------------------------------------------------------
// Observações cadastrais fixas de visitantes e prestadores
// ------------------------------------------------------------
// Caminho do cache local de observações. Em ambientes sem filesystem gravável
// (ex.: Cloudflare Workers) fica nulo e o cache opera só em memória + Supabase.
const OBS_VISITANTES_FILE = (typeof __dirname !== 'undefined')
  ? path.join(__dirname, 'scratch', 'observacoes_visitantes.json')
  : null;
let cacheObsVisitantes = new Map();

function carregarCacheObsVisitantes() {
  if (!OBS_VISITANTES_FILE) return; // sem filesystem: só memória + Supabase
  try {
    if (fs.existsSync(OBS_VISITANTES_FILE)) {
      const raw = fs.readFileSync(OBS_VISITANTES_FILE, 'utf8');
      const data = JSON.parse(raw);
      cacheObsVisitantes = new Map(Object.entries(data));
    }
  } catch (e) {
    // Silencioso se o ambiente restringir leitura local
  }
}

function salvarCacheObsVisitantes() {
  if (!OBS_VISITANTES_FILE) return; // sem filesystem: a persistência real é o Supabase
  try {
    const dir = path.dirname(OBS_VISITANTES_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const obj = Object.fromEntries(cacheObsVisitantes);
    fs.writeFileSync(OBS_VISITANTES_FILE, JSON.stringify(obj, null, 2), 'utf8');
  } catch (e) {
    // Silencioso se fs for somente leitura
  }
}

function formatarDataHoraSimples(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return '';
  return d.toLocaleString('pt-BR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function normalizarRegistroObs(item) {
  if (!item) return null;
  if (!Array.isArray(item.historico)) {
    item.historico = [];
    if (item.observacao && item.observacao.trim()) {
      item.historico.push({
        id: 'obs_inicial',
        data: item.atualizado_em || new Date().toISOString(),
        autor_id: item.atualizado_por || null,
        autor_nome: 'Cadastro',
        texto: item.observacao.trim(),
        exibir_alerta: true,
        origem: 'cadastro',
      });
    }
  }
  return item;
}

function montarTextoObservacaoAtiva(historico) {
  if (!Array.isArray(historico)) return '';
  const ativas = historico.filter((h) => h && h.exibir_alerta && (h.texto || '').trim());
  if (!ativas.length) return '';
  return ativas
    .map((h) => {
      const dataStr = formatarDataHoraSimples(h.data);
      const autorStr = h.autor_nome ? ` (${h.autor_nome})` : '';
      return `• ${dataStr}${autorStr}: ${h.texto.trim()}`;
    })
    .join('\n');
}

// Telefone/mensagem do administrador exibidos quando um visitante bloqueado
// tenta solicitar entrada.
const ADMIN_TELEFONE_BLOQUEIO = '11971537119';
const MENSAGEM_BLOQUEIO = `Sua entrada encontra-se bloqueada. Favor ligar para o Administrador no telefone ${ADMIN_TELEFONE_BLOQUEIO} para liberar.`;

// Um visitante está bloqueado se houver no histórico uma observação ATIVA
// (exibir_alerta) cujo texto começa com "[BLOQUEADO]". Desmarcar o alerta ou
// excluir a observação (pelo admin) remove o bloqueio.
function visitanteEstaBloqueado(obsItem) {
  if (!obsItem || !Array.isArray(obsItem.historico)) return false;
  return obsItem.historico.some(
    (h) => h && h.exibir_alerta && (h.texto || '').trim().toUpperCase().startsWith('[BLOQUEADO]')
  );
}

carregarCacheObsVisitantes();

async function obterTodasObservacoesVisitantes() {
  const mapa = new Map(cacheObsVisitantes);
  try {
    const { data, error } = await supabaseAdmin
      .from('observacoes_visitantes')
      .select('*');
    if (!error && Array.isArray(data)) {
      data.forEach((item) => {
        if (item.chave) {
          normalizarRegistroObs(item);
          const cached = cacheObsVisitantes.get(item.chave);
          if (cached && Array.isArray(cached.historico) && cached.historico.length > (item.historico || []).length) {
            item.historico = cached.historico;
          }
          if (!item.observacao && Array.isArray(item.historico)) {
            item.observacao = montarTextoObservacaoAtiva(item.historico);
          }
          mapa.set(item.chave, item);
          cacheObsVisitantes.set(item.chave, item);
        }
      });
      salvarCacheObsVisitantes();
    }
  } catch (err) {
    // Supabase pode ainda não ter a tabela migrada; segue com cache local
  }
  return mapa;
}

async function obterObservacaoVisitante(chave, docLimpo, nomeNorm) {
  const todas = await obterTodasObservacoesVisitantes();
  // Se um documento (CPF) foi informado, a identificação é feita SOMENTE pelo
  // documento. O match por nome só vale quando NÃO há documento — caso contrário
  // dois visitantes diferentes com o mesmo nome (ex.: "Teste") se confundiriam,
  // fazendo um CPF novo herdar o bloqueio de outro.
  const docPuro = (docLimpo || '').replace(/\D/g, '');
  const chavePura = (chave || '').replace(/\D/g, '');
  const temDocumento = !!(docPuro || chavePura);

  let item = null;
  if (chave && !chavePura && todas.has(chave)) item = todas.get(chave); // chave não-numérica (ex.: 'nome:...')
  else if (docPuro && todas.has(docPuro)) item = todas.get(docPuro);
  else if (chavePura && todas.has(chavePura)) item = todas.get(chavePura);
  else if (!temDocumento && nomeNorm && todas.has('nome:' + nomeNorm)) item = todas.get('nome:' + nomeNorm);
  else {
    for (const cad of todas.values()) {
      const itemDoc = (cad.documento || '').replace(/\D/g, '');
      const itemChave = (cad.chave || '').replace(/\D/g, '');
      if (docPuro && ((itemDoc && itemDoc === docPuro) || (itemChave && itemChave === docPuro))) {
        item = cad;
        break;
      }
      // Fallback por nome só quando NÃO há documento informado.
      if (!temDocumento) {
        const itemNome = (cad.nome || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        if (nomeNorm && itemNome && itemNome === nomeNorm) {
          item = cad;
          break;
        }
      }
    }
  }
  if (item) {
    normalizarRegistroObs(item);
  }
  return item;
}

async function adicionarObservacaoAoHistorico({ chave, nome, documento, texto, exibir_alerta = true, userId = null, origem = 'manual' }) {
  const agora = new Date().toISOString();
  const docLimpo = (documento || '').replace(/\D/g, '');
  const docFormatado = formatarDocumento(documento);
  const nomeLimpo = maiuscula((nome || '').trim()) || '';
  const nomeNorm = nomeLimpo.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const finalChave = (chave || '').trim() || docLimpo || ('nome:' + nomeNorm);

  if (!finalChave && !nomeLimpo) {
    throw new Error('Identificação do visitante não informada.');
  }

  let item = await obterObservacaoVisitante(finalChave, docLimpo, nomeNorm);
  if (!item) {
    item = {
      chave: finalChave,
      nome: nomeLimpo,
      documento: docFormatado || null,
      observacao: '',
      historico: [],
      atualizado_em: agora,
      atualizado_por: userId || null,
    };
  } else {
    normalizarRegistroObs(item);
  }

  let autorNome = origem === 'saida_portaria' ? 'Porteiro' : 'Administração';
  if (userId) {
    const nomes = await mapaNomes([userId]);
    if (nomes[userId]) autorNome = nomes[userId];
  }

  const novoItem = {
    id: 'obs_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
    data: agora,
    autor_id: userId || null,
    autor_nome: autorNome,
    texto: maiuscula((texto || '').trim()) || '',
    exibir_alerta: Boolean(exibir_alerta),
    origem: origem,
  };

  item.historico = [novoItem, ...(item.historico || [])];
  item.observacao = montarTextoObservacaoAtiva(item.historico);
  item.atualizado_em = agora;
  item.atualizado_por = userId || item.atualizado_por;
  if (nomeLimpo && !item.nome) item.nome = nomeLimpo;
  if (docFormatado && !item.documento) item.documento = docFormatado;

  cacheObsVisitantes.set(finalChave, item);
  if (docLimpo && docLimpo !== finalChave) cacheObsVisitantes.set(docLimpo, item);
  if (nomeNorm) cacheObsVisitantes.set('nome:' + nomeNorm, item);
  salvarCacheObsVisitantes();

  try {
    const payload = {
      chave: item.chave,
      nome: item.nome,
      documento: item.documento,
      observacao: item.observacao,
      historico: item.historico,
      atualizado_em: item.atualizado_em,
      atualizado_por: item.atualizado_por,
    };
    const { error: errUp } = await supabaseAdmin
      .from('observacoes_visitantes')
      .upsert(payload, { onConflict: 'chave' });
    if (errUp) {
      console.warn(
        '[Obs Visitantes] Upsert com histórico falhou (a coluna "historico" jsonb existe no Supabase? rode supabase_schema.sql). ' +
        'Salvando sem histórico como fallback. Detalhe:', errUp.message
      );
      const { historico: _, ...basePayload } = payload;
      await supabaseAdmin.from('observacoes_visitantes').upsert(basePayload, { onConflict: 'chave' });
    }
  } catch (err) {
    console.warn('[Obs Visitantes] Erro ao sincronizar com Supabase:', err.message);
  }

  return item;
}

async function alternarAlertaObservacao({ chave, obs_id, exibir_alerta }) {
  let item = await obterObservacaoVisitante(chave, chave, null);
  if (!item) throw new Error('Cadastro do visitante não encontrado.');

  normalizarRegistroObs(item);
  const obs = item.historico.find((h) => h.id === obs_id);
  if (!obs) throw new Error('Observação não encontrada no histórico.');

  obs.exibir_alerta = Boolean(exibir_alerta);
  item.observacao = montarTextoObservacaoAtiva(item.historico);
  item.atualizado_em = new Date().toISOString();

  cacheObsVisitantes.set(item.chave, item);
  salvarCacheObsVisitantes();

  try {
    const payload = {
      chave: item.chave,
      nome: item.nome,
      documento: item.documento,
      observacao: item.observacao,
      historico: item.historico,
      atualizado_em: item.atualizado_em,
      atualizado_por: item.atualizado_por,
    };
    const { error: errUp } = await supabaseAdmin.from('observacoes_visitantes').upsert(payload, { onConflict: 'chave' });
    if (errUp) {
      const { historico: _, ...basePayload } = payload;
      await supabaseAdmin.from('observacoes_visitantes').upsert(basePayload, { onConflict: 'chave' });
    }
  } catch (err) {}

  return item;
}

async function excluirObservacaoDoHistorico({ chave, obs_id }) {
  let item = await obterObservacaoVisitante(chave, chave, null);
  if (!item) throw new Error('Cadastro do visitante não encontrado.');

  normalizarRegistroObs(item);
  item.historico = item.historico.filter((h) => h.id !== obs_id);
  item.observacao = montarTextoObservacaoAtiva(item.historico);
  item.atualizado_em = new Date().toISOString();

  cacheObsVisitantes.set(item.chave, item);
  salvarCacheObsVisitantes();

  try {
    const payload = {
      chave: item.chave,
      nome: item.nome,
      documento: item.documento,
      observacao: item.observacao,
      historico: item.historico,
      atualizado_em: item.atualizado_em,
      atualizado_por: item.atualizado_por,
    };
    const { error: errUp } = await supabaseAdmin.from('observacoes_visitantes').upsert(payload, { onConflict: 'chave' });
    if (errUp) {
      const { historico: _, ...basePayload } = payload;
      await supabaseAdmin.from('observacoes_visitantes').upsert(basePayload, { onConflict: 'chave' });
    }
  } catch (err) {}

  return item;
}

async function salvarObservacaoVisitante(chave, nome, documento, observacao, userId) {
  return adicionarObservacaoAoHistorico({
    chave,
    nome,
    documento,
    texto: observacao,
    exibir_alerta: true,
    userId,
    origem: 'admin_direto',
  });
}

// Busca o cadastro de uma pessoa pelo documento (CPF).
// Verifica:
// 1. Base oficial de MORADORES (perfis) -> Prioridade máxima para unificação de cadastro!
// 2. Registros de portaria anteriores (para puxar placa de veículo ou histórico de visitantes)
// 3. Avisos de visita cadastrados pelos moradores
app.get('/api/portaria/buscar', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const doc = (req.query.documento || '').trim();
  if (!doc) return res.status(400).json({ error: 'Informe o documento para buscar.' });

  const docLimpo = doc.replace(/\D/g, '');

  if (docLimpo.length === 11 && !cpfValido(docLimpo)) {
    return res.status(400).json({ error: 'CPF inválido. Verifique os números digitados.' });
  }

  // 1. Procura primeiro na base oficial de MORADORES / ADMINS
  const { data: perfis, error: errPerfis } = await supabaseAdmin
    .from('perfis')
    .select('id, nome, bloco, apartamento, telefone, cpf, tipo')
    .not('cpf', 'is', null);

  const moradorEncontrado = (perfis || []).find(
    (p) => (p.cpf || '').replace(/\D/g, '') === docLimpo && docLimpo
  );

  // 2. Busca histórico nos registros de portaria (quem ja entrou)
  const { data: registros, error: errReg } = await req.supabase
    .from('registros_portaria')
    .select('*')
    .not('documento', 'is', null)
    .order('entrada', { ascending: false })
    .limit(500);

  const achoReg = (registros || []).find(
    (r) => (r.documento || '').replace(/\D/g, '') === docLimpo && docLimpo
  );

  // 3. Busca nos avisos de visita cadastrados pelos moradores
  const { data: avisos, error: errAv } = await req.supabase
    .from('avisos_visitas')
    .select('*, morador:perfis!avisos_visitas_morador_id_fkey(bloco, apartamento)')
    .not('documento_visitante', 'is', null)
    .order('criado_em', { ascending: false })
    .limit(500);

  const achoAviso = (avisos || []).find(
    (a) => (a.documento_visitante || '').replace(/\D/g, '') === docLimpo && docLimpo
  );

  // Identifica o nome para busca por nome caso necessário
  const nomeCandidato = moradorEncontrado
    ? moradorEncontrado.nome
    : (achoReg ? achoReg.nome_pessoa : (achoAviso ? achoAviso.nome_visitante : null));
  const nomeNorm = (nomeCandidato || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');

  // Busca observação fixa no cadastro (se existir)
  const obsVisitante = await obterObservacaoVisitante(docLimpo, docLimpo, nomeNorm);
  const obsCad = obsVisitante ? (obsVisitante.observacao || '').trim() : '';
  const estaBloqueado = visitanteEstaBloqueado(obsVisitante);

  // SE FOR MORADOR: Unifica o cadastro pelo perfil oficial do morador
  if (moradorEncontrado) {
    return res.json({
      encontrado: true,
      eh_morador: true,
      origem: 'morador',
      bloqueado: estaBloqueado,
      observacao_cadastro: obsCad,
      morador: {
        nome: moradorEncontrado.nome,
        bloco: moradorEncontrado.bloco,
        apartamento: moradorEncontrado.apartamento,
        telefone: moradorEncontrado.telefone,
        cpf: moradorEncontrado.cpf,
        tipo: moradorEncontrado.tipo,
      },
      pessoa: {
        nome_pessoa: moradorEncontrado.nome,
        documento: moradorEncontrado.cpf || doc,
        tipo: 'Morador',
        veiculo_placa: '',
        destino_bloco: moradorEncontrado.bloco || null,
        destino_apto: moradorEncontrado.apartamento || null,
        endereco_visitante: null,
        cep_visitante: null,
        observacao_cadastro: obsCad,
      },
    });
  }

  // SE NÃO FOR MORADOR: Busca no histórico de registros ou avisos
  if (achoReg) {
    return res.json({
      encontrado: true,
      eh_morador: false,
      origem: 'registro',
      bloqueado: estaBloqueado,
      observacao_cadastro: obsCad,
      pessoa: {
        nome_pessoa: achoReg.nome_pessoa,
        documento: achoReg.documento,
        tipo: achoReg.tipo,
        veiculo_placa: '',
        destino_bloco: achoReg.destino_bloco,
        destino_apto: achoReg.destino_apto,
        endereco_visitante: achoReg.endereco_visitante,
        cep_visitante: achoReg.cep_visitante,
        observacao_cadastro: obsCad,
      },
    });
  }

  if (achoAviso) {
    const m = achoAviso.morador || {};
    return res.json({
      encontrado: true,
      eh_morador: false,
      origem: 'aviso',
      bloqueado: estaBloqueado,
      observacao_cadastro: obsCad,
      pessoa: {
        nome_pessoa: achoAviso.nome_visitante,
        documento: achoAviso.documento_visitante,
        tipo: achoAviso.tipo,
        veiculo_placa: '',
        destino_bloco: m.bloco || null,
        destino_apto: m.apartamento || null,
        endereco_visitante: achoAviso.endereco_visitante || null,
        cep_visitante: achoAviso.cep_visitante || null,
        observacao_cadastro: obsCad,
      },
    });
  }

  res.json({ encontrado: false, eh_morador: false });
});

// Registra entrada (pode vir de um aviso ou ser avulsa)
app.post('/api/portaria/entrada', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const {
    aviso_id,
    nome_pessoa,
    documento,
    tipo,
    destino_bloco,
    destino_apto,
    destino_morador,
    veiculo_placa,
    endereco_visitante,
    cep_visitante,
    observacao,
  } = req.body || {};

  if (!nome_pessoa) {
    return res.status(400).json({ error: 'Informe o nome da pessoa.' });
  }

  const docLimpo = (documento || '').replace(/\D/g, '');
  // CPF obrigatório e válido para Visitante/Prestador. Encomenda, Entregador
  // (iFood) e Morador não exigem CPF do visitante.
  const tipoEntrada = tipo || 'Visitante';
  const exigeCpf = (tipoEntrada === 'Visitante' || tipoEntrada === 'Prestador') && nome_pessoa !== 'Encomenda';
  if (exigeCpf) {
    if (docLimpo.length !== 11 || !cpfValido(docLimpo)) {
      return res.status(400).json({ error: 'Informe um CPF válido (11 dígitos) para registrar a entrada.' });
    }
  } else if (docLimpo.length === 11 && !cpfValido(docLimpo)) {
    return res.status(400).json({ error: 'O CPF informado no documento é inválido.' });
  }

  // Segurança: recusa a entrada se o visitante estiver bloqueado (não confia só no front).
  // Encomendas e entradas sem documento/nome identificável não entram nessa checagem.
  if (nome_pessoa !== 'Encomenda') {
    const nomeNormVis = (nome_pessoa || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    const obsBloq = await obterObservacaoVisitante(docLimpo, docLimpo, nomeNormVis);
    if (visitanteEstaBloqueado(obsBloq)) {
      return res.status(403).json({ error: 'Visitante bloqueado. Entrada não permitida. Contate a administração.' });
    }
  }

  const docFormatado = formatarDocumento(documento);
  const tipoFinal = tipo || 'Visitante';
  const isMorador = tipoFinal === 'Morador';
  const agora = new Date().toISOString();
  const rawAvisoId = aviso_id;
  const avisoIdValido = (rawAvisoId && !String(rawAvisoId).startsWith('rec-') && !isNaN(Number(rawAvisoId)))
    ? Number(rawAvisoId)
    : null;

  const entradaFinal = req.body.entrada ? new Date(req.body.entrada).toISOString() : agora;

  const insertPayload = {
    aviso_id: avisoIdValido,
    nome_pessoa: maiuscula(nome_pessoa),
    documento: docFormatado || null,
    tipo: tipoFinal,
    destino_bloco: maiuscula(destino_bloco) || null,
    destino_apto: destino_apto || null,
    destino_morador: destino_morador || null,
    veiculo_placa: maiuscula(veiculo_placa) || null,
    endereco_visitante: maiuscula(endereco_visitante) || null,
    cep_visitante: cep_visitante || null,
    observacao: maiuscula(observacao) || null,
    registrado_por: req.user.id,
    entrada: entradaFinal,
    saida: isMorador ? agora : null,
    saida_por: isMorador ? req.user.id : null,
  };

  let { data, error } = await req.supabase
    .from('registros_portaria')
    .insert(insertPayload)
    .select()
    .single();

  // Fallback caso o banco ainda nao tenha a coluna destino_morador migrada.
  if (error && error.message && error.message.includes('destino_morador')) {
    delete insertPayload.destino_morador;
    const semMorador = await req.supabase
      .from('registros_portaria')
      .insert(insertPayload)
      .select()
      .single();
    data = semMorador.data;
    error = semMorador.error;
  }

  // Fallback caso o banco ainda nao tenha a migracao do enum para 'Morador'
  if (error && error.message && error.message.includes('tipo_acesso') && isMorador) {
    insertPayload.tipo = 'Outro';
    insertPayload.observacao = (insertPayload.observacao ? insertPayload.observacao + ' ' : '') + '[Entrada de Morador]';
    const fallbackRes = await req.supabase
      .from('registros_portaria')
      .insert(insertPayload)
      .select()
      .single();
    if (!fallbackRes.error) {
      data = fallbackRes.data;
      error = null;
    }
  }

  if (error) return res.status(400).json({ error: error.message });

  // Se veio de um aviso real do banco (não de recorrência virtual), atualiza o status dele
  if (avisoIdValido) {
    await req.supabase
      .from('avisos_visitas')
      .update({ status: 'Entrada Realizada' })
      .eq('id', avisoIdValido);
  }

  // Disparar notificação push se for encomenda
  if (nome_pessoa === 'Encomenda') {
    notificarLote(destino_bloco, '📦 Nova Encomenda', 'Você tem uma encomenda na portaria!');
  } else {
    notificarLote(destino_bloco, '🛎️ Nova Visita', `O visitante ${nome_pessoa} chegou na portaria.`);
  }

  // Dispara o aviso por WhatsApp (dispara-e-esquece; não bloqueia a resposta).
  notificarWhatsappEntrada(data);

  res.status(201).json({ registro: data });
});

// Lista de encomendas pendentes
app.get('/api/portaria/encomendas/pendentes', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { data, error } = await req.supabase
    .from('registros_portaria')
    .select('*')
    .eq('nome_pessoa', 'Encomenda')
    .is('saida', null)
    .order('entrada', { ascending: false });

  if (error) return res.status(400).json({ error: error.message });
  res.json({ registros: await comPorteiros(data || []) });
});

// Registra saida
app.post('/api/portaria/saida/:id', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { id } = req.params;
  const { observacao_saida, exibir_alerta } = req.body || {};

  const { data: regAtual, error: errGet } = await supabaseAdmin
    .from('registros_portaria')
    .select('*')
    .eq('id', id)
    .single();
  if (errGet || !regAtual) return res.status(400).json({ error: 'Registro não encontrado.' });

  const agora = new Date().toISOString();
  let novaObsAcesso = (regAtual.observacao || '').trim();
  const obsSaidaTexto = maiuscula((observacao_saida || '').trim()) || '';

  if (obsSaidaTexto) {
    novaObsAcesso = (novaObsAcesso ? novaObsAcesso + ' | ' : '') + `[Saída: ${obsSaidaTexto}]`;
  }

  const { data, error } = await req.supabase
    .from('registros_portaria')
    .update({
      saida: agora,
      saida_por: req.user.id,
      observacao: novaObsAcesso || null,
    })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });

  // Se o porteiro registrou ocorrência/observação na saída, salva no cadastro do visitante
  if (obsSaidaTexto) {
    try {
      await adicionarObservacaoAoHistorico({
        nome: regAtual.nome_pessoa,
        documento: regAtual.documento,
        texto: obsSaidaTexto,
        exibir_alerta: exibir_alerta !== false,
        userId: req.user.id,
        origem: 'saida_portaria',
      });
    } catch (e) {
      console.error('[Portaria Saida] Erro ao registrar observação no cadastro do visitante:', e);
    }
  }

  if (data?.aviso_id) {
    await req.supabase
      .from('avisos_visitas')
      .update({ status: 'Finalizada' })
      .eq('id', data.aviso_id);
  }

  res.json({ registro: data });
});

// Registra uma troca de turno no histórico da portaria.
// Chamada pelo frontend logo após o novo porteiro assumir (já com a sessão dele).
app.post('/api/portaria/troca-turno', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { porteiro_anterior } = req.body || {};
  const anterior = (porteiro_anterior || '').trim() || 'Não informado';
  const assumiu = req.perfil?.nome || 'Porteiro';
  const agora = new Date().toISOString();

  const insertPayload = {
    nome_pessoa: 'Troca de turno',
    tipo: 'Outro',
    destino_bloco: null,
    entrada: agora,
    saida: agora, // evento pontual: não fica "no local"
    registrado_por: req.user.id, // quem assumiu
    saida_por: req.user.id,
    observacao: `[TROCA DE TURNO] Saiu: ${anterior} | Assumiu: ${assumiu}`,
  };

  const { data, error } = await supabaseAdmin
    .from('registros_portaria')
    .insert(insertPayload)
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ registro: data });
});

// Registra retirada de encomenda com nome de quem retirou
app.post('/api/portaria/encomendas/:id/retirada', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { id } = req.params;
  const { retiradoPor, observacaoAtual } = req.body || {};
  
  // Exemplo da observacao atual: [ENCOMENDA] Para: Fabio Camargo
  // Nova: [ENCOMENDA] de : Fabio Camargo retirado por {retiradoPor}
  let novaObs = observacaoAtual || '';
  if (novaObs.startsWith('[ENCOMENDA] Para: ')) {
    const nomeDestino = novaObs.replace('[ENCOMENDA] Para: ', '').trim();
    novaObs = `[ENCOMENDA] de : ${nomeDestino} retirado por ${maiuscula(retiradoPor) || 'MORADOR'}`;
  }

  const { data, error } = await req.supabase
    .from('registros_portaria')
    .update({ 
      saida: new Date().toISOString(), 
      saida_por: req.user.id,
      observacao: novaObs 
    })
    .eq('id', id)
    .select()
    .single();
    
  if (error) return res.status(400).json({ error: error.message });
  res.json({ registro: data });
});

// Cancela a entrada registrada (reverte status do aviso e exclui registro)
app.post('/api/portaria/entrada/:id/cancelar', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { id } = req.params;
  const { motivo } = req.body || {};

  // Busca o registro para saber se estava atrelado a um aviso
  const { data: reg, error: errFetch } = await req.supabase
    .from('registros_portaria')
    .select('aviso_id')
    .eq('id', id)
    .single();

  if (errFetch) return res.status(400).json({ error: errFetch.message });

  // Marca o registro como finalizado e insere a observacao de cancelamento
  const ts = new Date().toLocaleString('pt-BR');
  const msgCancelamento = `[Cancelado]: ${maiuscula(motivo) || 'SEM MOTIVO'}`;

  const { error: errUpd } = await req.supabase
    .from('registros_portaria')
    .update({ 
      saida: new Date().toISOString(),
      observacao: msgCancelamento
    })
    .eq('id', id);

  if (errUpd) return res.status(400).json({ error: errUpd.message });

  // Se tinha um aviso, atualiza o status para Cancelada e salva o motivo
  if (reg?.aviso_id) {
    const { data: aviso } = await req.supabase
      .from('avisos_visitas')
      .select('observacao')
      .eq('id', reg.aviso_id)
      .single();

    let obs = aviso?.observacao || '';
    obs = obs ? `${obs}\n${msgCancelamento} (${ts})` : `${msgCancelamento} (${ts})`;

    await req.supabase
      .from('avisos_visitas')
      .update({ status: 'Cancelada', observacao: obs })
      .eq('id', reg.aviso_id);
  }

  res.json({ sucesso: true });
});

// Lista moradores de um lote especifico (usado para entregas rapidas como iFood, encomendas e identificacao na portaria)
app.get('/api/portaria/moradores', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  let lote = req.query.lote;
  if (!lote) return res.status(400).json({ error: 'Lote não informado.' });

  const numLote = lote.replace(/\D/g, '');
  let formats = [lote.trim()];
  if (numLote) {
    formats.push(`Lote ${String(numLote).padStart(2, '0')}`);
    formats.push(`Lote ${String(parseInt(numLote, 10))}`);
    formats.push(String(parseInt(numLote, 10)));
    formats.push(String(numLote).padStart(2, '0'));
  }
  formats = [...new Set(formats)];

  const { data, error } = await supabaseAdmin
    .from('perfis')
    .select('id, nome, bloco, telefone, tipo')
    .in('bloco', formats)
    .in('tipo', ['morador', 'admin'])
    .order('nome', { ascending: true });

  if (error) return res.status(400).json({ error: error.message });
  res.json({ moradores: data || [] });
});

// Busca de moradores por lote OU nome (aba "Condomínio" da portaria).
// Retorna os dados do morador EXCETO o CPF.
app.get('/api/portaria/condominio/moradores', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const termo = (req.query.q || '').trim();
  if (!termo) return res.json({ moradores: [] });

  let query = supabaseAdmin
    .from('perfis')
    .select('id, nome, bloco, apartamento, telefone, tipo')
    .in('tipo', ['morador', 'admin'])
    .order('bloco', { ascending: true })
    .order('nome', { ascending: true });

  const numLote = termo.replace(/\D/g, '');
  // Se o termo é essencialmente numérico, trata como busca por lote (vários formatos).
  if (numLote && numLote.length === termo.replace(/\s|lote/gi, '').length) {
    let formats = [termo.trim()];
    formats.push(`Lote ${String(numLote).padStart(2, '0')}`);
    formats.push(`Lote ${String(parseInt(numLote, 10))}`);
    formats.push(String(parseInt(numLote, 10)));
    formats.push(String(numLote).padStart(2, '0'));
    formats = [...new Set(formats)];
    query = query.in('bloco', formats);
  } else {
    // Busca por nome (parcial, sem diferenciar maiúsculas) OU por texto do lote.
    const like = `%${termo}%`;
    query = query.or(`nome.ilike.${like},bloco.ilike.${like}`);
  }

  const { data, error } = await query;
  if (error) return res.status(400).json({ error: error.message });

  // Retorna apenas os campos necessários (sem CPF e sem e-mail).
  const moradores = (data || []).map(m => ({
    nome: m.nome,
    bloco: m.bloco,
    apartamento: m.apartamento,
    telefone: m.telefone,
    tipo: m.tipo,
  }));

  res.json({ moradores });
});

// Mapa do condomínio: retorna, por lote, o número da casa dos moradores que
// habilitaram a permissão "ver_lote". Usado para exibir "Casa (número)" no mapa.
app.get('/api/portaria/mapa/casas', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  // Ordena por data de cadastro: o endereço exibido é o do PRIMEIRO morador
  // com permissão "ver_lote" cadastrado em cada lote.
  const { data, error } = await supabaseAdmin
    .from('perfis')
    .select('bloco, ver_lote, tipo, endereco_numero, endereco_logradouro, endereco_bairro, endereco_cidade, endereco_uf, cep, criado_em')
    .in('tipo', ['morador', 'admin'])
    .eq('ver_lote', true)
    .order('criado_em', { ascending: true });

  if (error) return res.status(400).json({ error: error.message });

  // Monta um mapa: número do lote -> { numero, enderecoCompleto }.
  // Usa SEMPRE o primeiro morador com ver_lote de cada lote (o primeiro cadastrado).
  const lotesDefinidos = new Set(); // lotes já "reservados" pelo primeiro morador com ver_lote
  const casas = {};
  (data || []).forEach((p) => {
    const numLote = (p.bloco || '').replace(/\D/g, '');
    if (!numLote) return;
    const chave = String(parseInt(numLote, 10));
    // O primeiro morador com ver_lote (por data de cadastro) "reserva" o lote;
    // os demais do mesmo lote são ignorados, mesmo que ele não tenha endereço.
    if (lotesDefinidos.has(chave)) return;
    lotesDefinidos.add(chave);

    const numero = (p.endereco_numero || '').trim();
    const logradouro = (p.endereco_logradouro || '').trim();
    const bairro = (p.endereco_bairro || '').trim();
    const cidade = (p.endereco_cidade || '').trim();
    const uf = (p.endereco_uf || '').trim();

    // O mapa exibe apenas o número da casa; sem número, nada a mostrar.
    if (!numero) return;

    // Mantém também o endereço completo no retorno (uso futuro), mas o mapa usa só o número.
    const linha1 = [logradouro, numero].filter(Boolean).join(', ');
    const localidade = cidade && uf ? `${cidade}/${uf}` : (cidade || uf);
    const partes = [linha1, bairro, localidade].filter(Boolean);
    const enderecoCompleto = partes.join(' - ');

    casas[chave] = { numero, enderecoCompleto };
  });

  res.json({ casas });
});

// ============================================================
// ADMIN - gestao de usuarios
// ============================================================

// Lista todos os perfis (com e-mail do Auth)
app.get('/api/admin/usuarios', requireAuth, requireRole('admin'), async (req, res) => {
  const { data: perfis, error } = await supabaseAdmin
    .from('perfis')
    .select('*')
    .order('criado_em', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });

  try {
    const { data: authData } = await supabaseAdmin.auth.admin.listUsers({ perPage: 1000 });
    const emailMap = new Map((authData?.users || []).map(u => [u.id, u.email]));
    const usuarios = (perfis || []).map(u => ({
      ...u,
      email: emailMap.get(u.id) || '',
    }));
    res.json({ usuarios });
  } catch {
    res.json({ usuarios: perfis });
  }
});

// Lista prestadores cadastrados/registrados para importacao no cadastro de porteiro
app.get('/api/admin/prestadores', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const q = (req.query.q || '').trim();

    // 1. Busca nos registros de portaria
    let qReg = supabaseAdmin
      .from('registros_portaria')
      .select('nome_pessoa, documento, tipo, veiculo_placa, endereco_visitante, observacao')
      .not('nome_pessoa', 'is', null)
      .neq('nome_pessoa', 'Encomenda')
      .neq('nome_pessoa', 'Entregador iFood')
      .order('entrada', { ascending: false })
      .limit(300);

    // 2. Busca nos avisos de visitas
    let qAv = supabaseAdmin
      .from('avisos_visitas')
      .select('nome_visitante, documento_visitante, tipo, veiculo_placa, endereco_visitante, observacao')
      .not('nome_visitante', 'is', null)
      .neq('nome_visitante', 'Entregador iFood')
      .order('criado_em', { ascending: false })
      .limit(300);

    const [{ data: regData, error: errReg }, { data: avData, error: errAv }] = await Promise.all([qReg, qAv]);

    if (errReg) console.error('Erro ao buscar registros_portaria:', errReg);
    if (errAv) console.error('Erro ao buscar avisos_visitas:', errAv);

    const mapa = new Map();
    const normalizar = s => (s || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');

    (regData || []).forEach(r => {
      const nome = (r.nome_pessoa || '').trim();
      const doc = (r.documento || '').trim();
      if (!nome) return;
      const chave = doc ? doc.replace(/\D/g, '') : normalizar(nome);
      if (!mapa.has(chave)) {
        mapa.set(chave, {
          nome,
          documento: doc,
          tipo: r.tipo || 'Prestador',
          veiculo_placa: r.veiculo_placa || '',
          endereco: r.endereco_visitante || '',
          observacao: r.observacao || ''
        });
      }
    });

    (avData || []).forEach(a => {
      const nome = (a.nome_visitante || '').trim();
      const doc = (a.documento_visitante || '').trim();
      if (!nome) return;
      const chave = doc ? doc.replace(/\D/g, '') : normalizar(nome);
      if (!mapa.has(chave)) {
        mapa.set(chave, {
          nome,
          documento: doc,
          tipo: a.tipo || 'Prestador',
          veiculo_placa: a.veiculo_placa || '',
          endereco: a.endereco_visitante || '',
          observacao: a.observacao || ''
        });
      }
    });

    let lista = Array.from(mapa.values());

    // Se houve busca por termo, filtra pelo nome ou documento
    if (q) {
      const qNorm = normalizar(q);
      const qDoc = q.replace(/\D/g, '');
      lista = lista.filter(item => {
        const nNorm = normalizar(item.nome);
        const dLimpo = (item.documento || '').replace(/\D/g, '');
        return nNorm.includes(qNorm) || (qDoc && dLimpo.includes(qDoc));
      });
    }

    // Ordena: Prestador primeiro, depois por ordem alfabetica
    lista.sort((a, b) => {
      if (a.tipo === 'Prestador' && b.tipo !== 'Prestador') return -1;
      if (b.tipo === 'Prestador' && a.tipo !== 'Prestador') return 1;
      return a.nome.localeCompare(b.nome);
    });

    res.json({ prestadores: lista.slice(0, 30) });
  } catch (err) {
    console.error('Erro na rota /api/admin/prestadores:', err);
    res.status(500).json({ error: 'Erro ao buscar prestadores cadastrados.' });
  }
});

// Lista moradores cadastrados para autopreenchimento e promocao a Administrador
app.get('/api/admin/moradores-busca', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const q = (req.query.q || '').trim();

    const { data: perfis, error } = await supabaseAdmin
      .from('perfis')
      .select('id, nome, tipo, bloco, telefone, cpf, aprovado, ativo')
      .order('bloco', { ascending: true });

    if (error) throw error;

    // Busca e-mails no Auth
    const { data: authData } = await supabaseAdmin.auth.admin.listUsers({ perPage: 1000 });
    const emailMap = new Map((authData?.users || []).map(u => [u.id, u.email]));

    let lista = (perfis || []).map(p => ({
      ...p,
      email: emailMap.get(p.id) || '',
    }));

    if (q) {
      const qNorm = q.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      const qNum = q.replace(/\D/g, '');
      lista = lista.filter(item => {
        const nomeNorm = (item.nome || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        const blocoNorm = (item.bloco || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        const emailNorm = (item.email || '').toLowerCase();
        const telNum = (item.telefone || '').replace(/\D/g, '');
        const cpfNum = (item.cpf || '').replace(/\D/g, '');
        return nomeNorm.includes(qNorm) ||
               blocoNorm.includes(qNorm) ||
               emailNorm.includes(qNorm) ||
               (qNum && telNum.includes(qNum)) ||
               (qNum && cpfNum.includes(qNum));
      });
    }

    // Ordena: Lotes preenchidos primeiro, depois por nome alfabetico
    lista.sort((a, b) => {
      if (a.bloco && !b.bloco) return -1;
      if (!a.bloco && b.bloco) return 1;
      return a.nome.localeCompare(b.nome);
    });

    res.json({ moradores: lista.slice(0, 30) });
  } catch (err) {
    console.error('Erro na rota /api/admin/moradores-busca:', err);
    res.status(500).json({ error: 'Erro ao buscar moradores cadastrados.' });
  }
});


// Cria um novo usuario (porteiro, morador ou admin) ou promove morador existente a admin
app.post('/api/admin/usuarios', requireAuth, requireRole('admin'), async (req, res) => {
  let {
    email, password, nome, tipo, bloco, telefone, cpf, morador_id,
    cep, endereco_logradouro, endereco_numero, endereco_bairro,
    endereco_cidade, endereco_uf, endereco_complemento
  } = req.body || {};

  nome = maiuscula((nome || '').trim()) || '';
  tipo = (tipo || '').trim();
  email = (email || '').trim().toLowerCase();
  const cpfLimpo = (cpf || '').replace(/\D/g, '') || null;
  const cepLimpo = (cep || '').replace(/\D/g, '') || null;

  if (cpfLimpo && !cpfValido(cpfLimpo)) {
    return res.status(400).json({ error: 'CPF inválido.' });
  }

  if (!nome || !tipo) {
    return res.status(400).json({ error: 'Preencha o nome e o perfil.' });
  }
  if (!['admin', 'porteiro', 'morador'].includes(tipo)) {
    return res.status(400).json({ error: 'Tipo inválido.' });
  }

  // CPF obrigatório e válido para morador e admin (porteiro loga por nome, CPF opcional).
  if ((tipo === 'morador' || tipo === 'admin') && !morador_id) {
    if (!cpfLimpo || cpfLimpo.length !== 11 || !cpfValido(cpfLimpo)) {
      return res.status(400).json({ error: 'Informe um CPF válido (11 dígitos).' });
    }
  }

  // Se morador_id foi fornecido (ou seja, selecionou morador existente para admin)
  if (morador_id && tipo === 'admin') {
    const { data: moradorPerfil } = await supabaseAdmin
      .from('perfis')
      .select('id, nome, bloco, telefone, cpf, cep, endereco_logradouro, endereco_numero, endereco_bairro, endereco_cidade, endereco_uf, endereco_complemento')
      .eq('id', morador_id)
      .single();

    if (moradorPerfil) {
      await supabaseAdmin.from('perfis').update({
        nome: nome || moradorPerfil.nome,
        tipo: 'admin',
        bloco: bloco || moradorPerfil.bloco,
        telefone: telefone || moradorPerfil.telefone,
        cpf: cpfLimpo || moradorPerfil.cpf || null,
        cep: cepLimpo || moradorPerfil.cep || null,
        endereco_logradouro: endereco_logradouro !== undefined ? (endereco_logradouro?.trim() || null) : moradorPerfil.endereco_logradouro,
        endereco_numero: endereco_numero !== undefined ? (endereco_numero?.trim() || null) : moradorPerfil.endereco_numero,
        endereco_bairro: endereco_bairro !== undefined ? (endereco_bairro?.trim() || null) : moradorPerfil.endereco_bairro,
        endereco_cidade: endereco_cidade !== undefined ? (endereco_cidade?.trim() || null) : moradorPerfil.endereco_cidade,
        endereco_uf: endereco_uf !== undefined ? (endereco_uf?.trim().toUpperCase().slice(0, 2) || null) : moradorPerfil.endereco_uf,
        endereco_complemento: endereco_complemento !== undefined ? (endereco_complemento?.trim() || null) : moradorPerfil.endereco_complemento,
        ativo: true,
        aprovado: true,
      }).eq('id', morador_id);

      const authUpdates = {
        user_metadata: {
          nome: nome || moradorPerfil.nome,
          tipo: 'admin',
          bloco: bloco || moradorPerfil.bloco,
          telefone: telefone || moradorPerfil.telefone,
          cpf: cpfLimpo || moradorPerfil.cpf || null,
        }
      };
      if (password && password.trim().length >= 6) {
        authUpdates.password = password.trim();
      }
      await supabaseAdmin.auth.admin.updateUserById(morador_id, authUpdates);

      return res.status(200).json({ id: morador_id, promovido: true });
    }
  }

  // Se nao e morador existente sendo promovido, a senha e obrigatoria
  if (!password) {
    return res.status(400).json({ error: 'Informe a senha de acesso.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });
  }

  // Para porteiro, e-mail e opcional (se nao informado, gera e-mail interno transparente)
  if (tipo === 'porteiro') {
    // Verifica se ja existe outro porteiro com o mesmo nome para evitar conflitos no login
    const { data: existente } = await supabaseAdmin
      .from('perfis')
      .select('id, nome')
      .eq('tipo', 'porteiro')
      .ilike('nome', nome);

    if (existente && existente.length > 0) {
      return res.status(400).json({
        error: `Já existe um porteiro cadastrado com o nome "${nome}". Por favor, utilize um sobrenome ou complemento para identificá-lo (ex: ${nome} Silva).`
      });
    }

    if (!email) {
      const slug = nome.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]/g, '');
      const sufixo = Math.floor(1000 + Math.random() * 9000);
      email = `${slug || 'porteiro'}_${sufixo}@porteiro.parkplace.local`;
    }
  } else {
    // Para morador ou admin, e-mail e obrigatorio
    if (!email) {
      return res.status(400).json({ error: 'Preencha o e-mail de acesso.' });
    }
  }

  const { data, error } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { nome, tipo, bloco, telefone, cpf: cpfLimpo },
  });

  if (error) {
    const jaExiste = /already|registered|exists/i.test(error.message);
    if (jaExiste && tipo === 'admin' && email) {
      // Se já existe e está cadastrando como Administrador, promove o perfil existente
      const { data: authData } = await supabaseAdmin.auth.admin.listUsers({ perPage: 1000 });
      const existenteAuth = (authData?.users || []).find(u => u.email?.toLowerCase() === email);
      if (existenteAuth) {
        await supabaseAdmin.from('perfis').update({
          nome,
          tipo: 'admin',
          bloco: bloco || null,
          telefone: telefone || null,
          cpf: cpfLimpo || undefined,
          cep: cepLimpo || undefined,
          endereco_logradouro: endereco_logradouro?.trim() || undefined,
          endereco_numero: endereco_numero?.trim() || undefined,
          endereco_bairro: endereco_bairro?.trim() || undefined,
          endereco_cidade: endereco_cidade?.trim() || undefined,
          endereco_uf: endereco_uf?.trim().toUpperCase().slice(0, 2) || undefined,
          endereco_complemento: endereco_complemento?.trim() || undefined,
          ativo: true,
          aprovado: true,
        }).eq('id', existenteAuth.id);

        const authUpdates = {
          user_metadata: { nome, tipo: 'admin', bloco, telefone, cpf: cpfLimpo }
        };
        if (password && password.trim().length >= 6) {
          authUpdates.password = password.trim();
        }
        await supabaseAdmin.auth.admin.updateUserById(existenteAuth.id, authUpdates);

        return res.status(200).json({ id: existenteAuth.id, promovido: true });
      }
    }
    return res.status(400).json({ error: jaExiste ? 'Este e-mail/usuário já está cadastrado.' : error.message });
  }

  // Garante o perfil mesmo se o trigger nao rodar
  await supabaseAdmin.from('perfis').upsert({
    id: data.user.id,
    nome,
    tipo,
    bloco: bloco || null,
    telefone: telefone || null,
    cpf: cpfLimpo,
    cep: cepLimpo,
    endereco_logradouro: maiuscula(endereco_logradouro?.trim()) || null,
    endereco_numero: endereco_numero?.trim() || null,
    endereco_bairro: maiuscula(endereco_bairro?.trim()) || null,
    endereco_cidade: maiuscula(endereco_cidade?.trim()) || null,
    endereco_uf: endereco_uf?.trim().toUpperCase().slice(0, 2) || null,
    endereco_complemento: maiuscula(endereco_complemento?.trim()) || null,
    ativo: true,
    aprovado: true,
  });

  res.status(201).json({ id: data.user.id });
});

// Atualiza usuario existente
app.put('/api/admin/usuarios/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const {
    nome, tipo, bloco, telefone, cpf, password, ver_lote,
    cep, endereco_logradouro, endereco_numero, endereco_bairro,
    endereco_cidade, endereco_uf, endereco_complemento
  } = req.body || {};

  if (!['admin', 'porteiro', 'morador'].includes(tipo)) {
    return res.status(400).json({ error: 'Tipo inválido.' });
  }

  const nomeLimpo = maiuscula((nome || '').trim()) || '';
  const cpfLimpo = cpf !== undefined ? ((cpf || '').replace(/\D/g, '') || null) : undefined;

  if (cpfLimpo && !cpfValido(cpfLimpo)) {
    return res.status(400).json({ error: 'CPF inválido.' });
  }

  // Se for porteiro e alterou o nome, verifica duplicidade com outros porteiros
  if (tipo === 'porteiro' && nomeLimpo) {
    const { data: existente } = await supabaseAdmin
      .from('perfis')
      .select('id, nome')
      .eq('tipo', 'porteiro')
      .ilike('nome', nomeLimpo)
      .neq('id', id);

    if (existente && existente.length > 0) {
      return res.status(400).json({
        error: `Já existe outro porteiro cadastrado com o nome "${nomeLimpo}". Escolha um complemento para diferenciá-lo.`
      });
    }
  }

  const updatesPerfil = {
    nome: nomeLimpo,
    tipo,
    bloco: bloco || null,
    telefone: telefone || null,
  };
  if (cpfLimpo !== undefined) {
    updatesPerfil.cpf = cpfLimpo;
  }
  if (ver_lote !== undefined) {
    updatesPerfil.ver_lote = !!ver_lote;
  }
  if (cep !== undefined) {
    updatesPerfil.cep = String(cep).replace(/\D/g, '') || null;
  }
  if (endereco_logradouro !== undefined) {
    updatesPerfil.endereco_logradouro = maiuscula((endereco_logradouro || '').trim()) || null;
  }
  if (endereco_numero !== undefined) {
    updatesPerfil.endereco_numero = (endereco_numero || '').trim() || null;
  }
  if (endereco_bairro !== undefined) {
    updatesPerfil.endereco_bairro = maiuscula((endereco_bairro || '').trim()) || null;
  }
  if (endereco_cidade !== undefined) {
    updatesPerfil.endereco_cidade = maiuscula((endereco_cidade || '').trim()) || null;
  }
  if (endereco_uf !== undefined) {
    updatesPerfil.endereco_uf = (endereco_uf || '').trim().toUpperCase().slice(0, 2) || null;
  }
  if (endereco_complemento !== undefined) {
    updatesPerfil.endereco_complemento = maiuscula((endereco_complemento || '').trim()) || null;
  }

  // Atualiza metadados no Auth
  const authUpdates = {
    user_metadata: {
      nome: nomeLimpo,
      tipo,
      bloco,
      telefone,
      ...(cpfLimpo !== undefined ? { cpf: cpfLimpo } : {}),
      ...(updatesPerfil.cep !== undefined ? { cep: updatesPerfil.cep } : {}),
      ...(updatesPerfil.endereco_logradouro !== undefined ? { endereco_logradouro: updatesPerfil.endereco_logradouro } : {}),
      ...(updatesPerfil.endereco_numero !== undefined ? { endereco_numero: updatesPerfil.endereco_numero } : {})
    }
  };
  // Se informou nova senha, atualiza tambem
  if (password && password.trim().length >= 6) {
    authUpdates.password = password.trim();
  }

  try {
    await supabaseAdmin.auth.admin.updateUserById(id, authUpdates);
  } catch (errAuth) {
    console.warn('[Admin] Aviso ao atualizar Auth:', errAuth.message);
  }

  let { data, error } = await supabaseAdmin
    .from('perfis')
    .update(updatesPerfil)
    .eq('id', id)
    .select()
    .single();

  // Fallback caso a coluna ver_lote ainda nao exista no banco.
  if (error && error.message && error.message.includes('ver_lote')) {
    delete updatesPerfil.ver_lote;
    const semVerLote = await supabaseAdmin
      .from('perfis')
      .update(updatesPerfil)
      .eq('id', id)
      .select()
      .single();
    data = semVerLote.data;
    error = semVerLote.error;
  }

  if (error) return res.status(400).json({ error: error.message });
  res.json({ perfil: data });
});

// Aprova o cadastro de um morador (libera o acesso)
app.post('/api/admin/usuarios/:id/aprovar', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabaseAdmin
    .from('perfis')
    .update({ aprovado: true, ativo: true })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ perfil: data });
});

// Ativa/desativa usuario
app.post('/api/admin/usuarios/:id/toggle', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { ativo } = req.body || {};
  const { data, error } = await supabaseAdmin
    .from('perfis')
    .update({ ativo: !!ativo })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ perfil: data });
});

// Liga/desliga a permissão do morador ver as visitas de todo o lote.
app.post('/api/admin/usuarios/:id/ver-lote', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { ver_lote } = req.body || {};
  const { data, error } = await supabaseAdmin
    .from('perfis')
    .update({ ver_lote: !!ver_lote })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ perfil: data });
});

// Remove usuario (auth + perfil em cascata)
app.delete('/api/admin/usuarios/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  if (id === req.user.id) {
    return res.status(400).json({ error: 'Você não pode remover o próprio usuário.' });
  }
  const { error } = await supabaseAdmin.auth.admin.deleteUser(id);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true });
});

// Lista de visitantes cadastrados (agrega avisos de visita + registros da portaria).
// Suporta busca por nome ou documento (CPF) via ?busca=
app.get('/api/admin/visitantes', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const busca = (req.query.busca || '').trim();
    const buscaNorm = busca.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    const buscaDoc = busca.replace(/\D/g, '');

    // Avisos cadastrados pelos moradores
    const { data: avisos, error: errAv } = await supabaseAdmin
      .from('avisos_visitas')
      .select('nome_visitante, documento_visitante, veiculo_placa, tipo, endereco_visitante, cep_visitante, criado_em')
      .order('criado_em', { ascending: false })
      .limit(2000);
    if (errAv) throw errAv;

    // Registros reais da portaria (entradas) - ignora encomendas
    const { data: registros, error: errReg } = await supabaseAdmin
      .from('registros_portaria')
      .select('nome_pessoa, documento, veiculo_placa, tipo, endereco_visitante, cep_visitante, entrada')
      .neq('nome_pessoa', 'Encomenda')
      .order('entrada', { ascending: false })
      .limit(2000);
    if (errReg) throw errReg;

    // Agrega por chave (documento quando houver; senao, nome normalizado).
    const mapa = new Map();

    const adicionar = (nome, documento, placa, tipo, quando, endereco, cep) => {
      if (!nome || !nome.trim()) return;
      if (nome === 'Entregador iFood') return; // entregas automaticas nao sao visitantes cadastrados
      const nomeLimpo = nome.trim();
      const docLimpo = (documento || '').replace(/\D/g, '');
      const docFormatado = formatarDocumento(documento);
      const chave = docLimpo || ('nome:' + nomeLimpo.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, ''));
      const enderecoLimpo = (endereco || '').trim();
      const cepLimpo = (cep || '').trim();

      const existente = mapa.get(chave);
      if (!existente) {
        mapa.set(chave, {
          chave,
          nome: nomeLimpo,
          documento: docFormatado || null,
          veiculo_placa: placa || null,
          tipo: tipo || 'Visitante',
          endereco_visitante: enderecoLimpo || null,
          cep_visitante: cepLimpo || null,
          vezes: 1,
          ultima_vez: quando || null,
          // Marca de tempo do endereço mais recente registrado, para preferir o valor mais novo.
          _endereco_em: enderecoLimpo ? (quando || null) : null,
        });
      } else {
        existente.vezes += 1;
        if (!existente.documento && docFormatado) existente.documento = docFormatado;
        else if (docFormatado && docLimpo.length === 11) existente.documento = docFormatado;
        if (!existente.veiculo_placa && placa) existente.veiculo_placa = placa;
        if (quando && (!existente.ultima_vez || new Date(quando) > new Date(existente.ultima_vez))) {
          existente.ultima_vez = quando;
        }
        // Prefere o endereço/CEP do registro mais recente que tenha endereço preenchido.
        if (enderecoLimpo) {
          const maisNovo = !existente._endereco_em || (quando && new Date(quando) > new Date(existente._endereco_em));
          if (!existente.endereco_visitante || maisNovo) {
            existente.endereco_visitante = enderecoLimpo;
            existente.cep_visitante = cepLimpo || existente.cep_visitante || null;
            existente._endereco_em = quando || existente._endereco_em || null;
          }
        } else if (cepLimpo && !existente.cep_visitante) {
          existente.cep_visitante = cepLimpo;
        }
      }
    };

    (avisos || []).forEach((a) =>
      adicionar(a.nome_visitante, a.documento_visitante, a.veiculo_placa, a.tipo, a.criado_em, a.endereco_visitante, a.cep_visitante)
    );
    (registros || []).forEach((r) =>
      adicionar(r.nome_pessoa, r.documento, r.veiculo_placa, r.tipo, r.entrada, r.endereco_visitante, r.cep_visitante)
    );

    const mapaObs = await obterTodasObservacoesVisitantes();
    let visitantes = Array.from(mapa.values()).map((v) => {
      const docLimpo = (v.documento || '').replace(/\D/g, '');
      const nomeNorm = v.nome.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      const obsObj = (v.chave && mapaObs.get(v.chave)) || (docLimpo && mapaObs.get(docLimpo)) || mapaObs.get('nome:' + nomeNorm);
      const { _endereco_em, ...limpo } = v;
      return {
        ...limpo,
        observacao_cadastro: obsObj ? (obsObj.observacao || '') : '',
        observacao_atualizada_em: obsObj ? obsObj.atualizado_em : null,
      };
    });

    // Filtro por nome ou documento
    if (busca) {
      visitantes = visitantes.filter((v) => {
        const nomeNorm = v.nome.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        const docNum = (v.documento || '').replace(/\D/g, '');
        const casaNome = nomeNorm.includes(buscaNorm);
        const casaDoc = buscaDoc && docNum.includes(buscaDoc);
        return casaNome || casaDoc;
      });
    }

    visitantes.sort((a, b) => a.nome.localeCompare(b.nome, 'pt-BR'));

    res.json({ visitantes });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Edita dados cadastrais de um visitante (atualiza registros_portaria, avisos_visitas, visitas_recorrentes e observações)
app.post('/api/admin/visitantes/editar', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const {
      chaveOriginal,
      nomeOriginal,
      documentoOriginal,
      nome,
      documento,
      tipo,
      veiculo_placa,
      endereco_visitante,
      cep_visitante,
      observacao,
    } = req.body || {};

    const novoNome = maiuscula((nome || '').trim()) || '';
    if (!novoNome) {
      return res.status(400).json({ error: 'Informe o nome do visitante.' });
    }

    // CPF obrigatório e válido.
    const cpfEditAdmin = (documento || '').replace(/\D/g, '');
    if (cpfEditAdmin.length !== 11 || !cpfValido(cpfEditAdmin)) {
      return res.status(400).json({ error: 'Informe um CPF válido (11 dígitos) para o visitante.' });
    }

    const docLimpoOriginal = (documentoOriginal || '').replace(/\D/g, '');
    const nomeNormOriginal = (nomeOriginal || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');

    const novoDocFormatado = formatarDocumento(documento);
    const novoDocLimpo = (documento || '').replace(/\D/g, '');
    const novoNomeNorm = novoNome.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    const novoTipo = tipo || 'Visitante';
    const novaPlaca = (veiculo_placa || '').trim().toUpperCase() || null;
    // Endereço/CEP só fazem sentido para Prestador; para outros tipos limpamos.
    const ehPrestador = novoTipo === 'Prestador';
    const novoEndereco = ehPrestador ? (maiuscula((endereco_visitante || '').trim()) || null) : null;
    const novoCep = ehPrestador ? ((cep_visitante || '').trim() || null) : null;

    // 1. Atualiza em registros_portaria
    const { data: todosRegs } = await supabaseAdmin
      .from('registros_portaria')
      .select('id, nome_pessoa, documento');
    const idsRegs = (todosRegs || [])
      .filter((r) => {
        const rDoc = (r.documento || '').replace(/\D/g, '');
        if (docLimpoOriginal && rDoc && rDoc === docLimpoOriginal) return true;
        const rNome = (r.nome_pessoa || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        if (nomeNormOriginal && rNome === nomeNormOriginal) return true;
        return false;
      })
      .map((r) => r.id);

    if (idsRegs.length > 0) {
      await supabaseAdmin
        .from('registros_portaria')
        .update({
          nome_pessoa: novoNome,
          documento: novoDocFormatado || null,
          tipo: novoTipo,
          veiculo_placa: novaPlaca,
          endereco_visitante: novoEndereco,
          cep_visitante: novoCep,
        })
        .in('id', idsRegs);
    }

    // 2. Atualiza em avisos_visitas
    const { data: todosAvisos } = await supabaseAdmin
      .from('avisos_visitas')
      .select('id, nome_visitante, documento_visitante');
    const idsAvisos = (todosAvisos || [])
      .filter((a) => {
        const aDoc = (a.documento_visitante || '').replace(/\D/g, '');
        if (docLimpoOriginal && aDoc && aDoc === docLimpoOriginal) return true;
        const aNome = (a.nome_visitante || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        if (nomeNormOriginal && aNome === nomeNormOriginal) return true;
        return false;
      })
      .map((a) => a.id);

    if (idsAvisos.length > 0) {
      await supabaseAdmin
        .from('avisos_visitas')
        .update({
          nome_visitante: novoNome,
          documento_visitante: novoDocFormatado || null,
          tipo: novoTipo,
          veiculo_placa: novaPlaca,
          endereco_visitante: novoEndereco,
          cep_visitante: novoCep,
        })
        .in('id', idsAvisos);
    }

    // 3. Atualiza em visitas_recorrentes
    const { data: todosRecs } = await supabaseAdmin
      .from('visitas_recorrentes')
      .select('id, nome_visitante, documento_visitante');
    const idsRecs = (todosRecs || [])
      .filter((r) => {
        const rDoc = (r.documento_visitante || '').replace(/\D/g, '');
        if (docLimpoOriginal && rDoc && rDoc === docLimpoOriginal) return true;
        const rNome = (r.nome_visitante || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        if (nomeNormOriginal && rNome === nomeNormOriginal) return true;
        return false;
      })
      .map((r) => r.id);

    if (idsRecs.length > 0) {
      await supabaseAdmin
        .from('visitas_recorrentes')
        .update({
          nome_visitante: novoNome,
          documento_visitante: novoDocFormatado || null,
          tipo: novoTipo,
          veiculo_placa: novaPlaca,
        })
        .in('id', idsRecs);
    }

    // 4. Atualiza em observacoes_visitantes
    const novaChave = novoDocLimpo || ('nome:' + novoNomeNorm);
    const chaveAntiga = chaveOriginal || docLimpoOriginal || ('nome:' + nomeNormOriginal);

    if (observacao !== undefined && observacao !== null) {
      const textoObs = observacao.trim();
      if (textoObs) {
        await salvarObservacaoVisitante({
          chave: novaChave,
          doc: novoDocFormatado,
          nome: novoNome,
          texto: textoObs,
          userId: req.user.id,
          exibirAlerta: true,
        });
      }
    }

    // Se a chave mudou e existia observação com a chave antiga, migra para a nova chave
    if (chaveAntiga && chaveAntiga !== novaChave) {
      const obsAntiga = cacheObsVisitantes.get(chaveAntiga);
      if (obsAntiga) {
        cacheObsVisitantes.delete(chaveAntiga);
        obsAntiga.chave = novaChave;
        obsAntiga.nome = novoNome;
        obsAntiga.documento = novoDocFormatado;
        cacheObsVisitantes.set(novaChave, obsAntiga);
        salvarCacheObsVisitantes();
        try {
          await supabaseAdmin.from('observacoes_visitantes').delete().eq('chave', chaveAntiga);
          await supabaseAdmin.from('observacoes_visitantes').upsert({
            chave: novaChave,
            nome: novoNome,
            documento: novoDocFormatado,
            observacao: obsAntiga.observacao,
            historico: obsAntiga.historico || [],
            atualizado_em: new Date().toISOString(),
            atualizado_por: req.user.id,
          }, { onConflict: 'chave' });
        } catch (e) {}
      }
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Exclui um visitante cadastrado (remove registros_portaria, avisos_visitas, visitas_recorrentes e observações vinculadas)
app.post('/api/admin/visitantes/excluir', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { chave, nome, documento } = req.body || {};
    const docLimpo = (documento || '').replace(/\D/g, '');
    const nomeNorm = (nome || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');

    if (!chave && !docLimpo && !nomeNorm) {
      return res.status(400).json({ error: 'Informe a identificação do visitante para exclusão.' });
    }

    // 1. Exclui registros_portaria
    const { data: todosRegs } = await supabaseAdmin
      .from('registros_portaria')
      .select('id, nome_pessoa, documento');
    const idsRegs = (todosRegs || [])
      .filter((r) => {
        const rDoc = (r.documento || '').replace(/\D/g, '');
        if (docLimpo && rDoc && rDoc === docLimpo) return true;
        const rNome = (r.nome_pessoa || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        if (nomeNorm && rNome === nomeNorm) return true;
        return false;
      })
      .map((r) => r.id);

    if (idsRegs.length > 0) {
      await supabaseAdmin
        .from('registros_portaria')
        .delete()
        .in('id', idsRegs);
    }

    // 2. Exclui avisos_visitas
    const { data: todosAvisos } = await supabaseAdmin
      .from('avisos_visitas')
      .select('id, nome_visitante, documento_visitante');
    const idsAvisos = (todosAvisos || [])
      .filter((a) => {
        const aDoc = (a.documento_visitante || '').replace(/\D/g, '');
        if (docLimpo && aDoc && aDoc === docLimpo) return true;
        const aNome = (a.nome_visitante || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        if (nomeNorm && aNome === nomeNorm) return true;
        return false;
      })
      .map((a) => a.id);

    if (idsAvisos.length > 0) {
      await supabaseAdmin
        .from('avisos_visitas')
        .delete()
        .in('id', idsAvisos);
    }

    // 3. Exclui visitas_recorrentes
    const { data: todosRecs } = await supabaseAdmin
      .from('visitas_recorrentes')
      .select('id, nome_visitante, documento_visitante');
    const idsRecs = (todosRecs || [])
      .filter((r) => {
        const rDoc = (r.documento_visitante || '').replace(/\D/g, '');
        if (docLimpo && rDoc && rDoc === docLimpo) return true;
        const rNome = (r.nome_visitante || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        if (nomeNorm && rNome === nomeNorm) return true;
        return false;
      })
      .map((r) => r.id);

    if (idsRecs.length > 0) {
      await supabaseAdmin
        .from('visitas_recorrentes')
        .delete()
        .in('id', idsRecs);
    }

    // 4. Exclui observações do visitante
    const chavesParaDeletar = [chave, docLimpo, 'nome:' + nomeNorm].filter(Boolean);
    for (const c of chavesParaDeletar) {
      cacheObsVisitantes.delete(c);
      try {
        await supabaseAdmin.from('observacoes_visitantes').delete().eq('chave', c);
      } catch (e) {}
    }
    salvarCacheObsVisitantes();

    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Detalhes completos e dashboard do visitante para o pop-up
app.get('/api/admin/visitantes/detalhes', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const chave = (req.query.chave || '').trim();
    const nome = (req.query.nome || '').trim();
    const doc = (req.query.documento || '').trim();
    const docLimpo = doc.replace(/\D/g, '');
    const nomeNorm = nome.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');

    if (!chave && !nome && !docLimpo) {
      return res.status(400).json({ error: 'Informe a chave, nome ou documento do visitante.' });
    }

    // 1. Observação fixa de cadastro
    const obsObj = await obterObservacaoVisitante(chave, docLimpo, nomeNorm);

    // 2. Registros reais de portaria
    const { data: todosReg, error: errReg } = await supabaseAdmin
      .from('registros_portaria')
      .select('*')
      .neq('nome_pessoa', 'Encomenda')
      .order('entrada', { ascending: false })
      .limit(1000);
    if (errReg) throw errReg;

    // Filtra registros desse visitante
    const registrosPessoa = (todosReg || []).filter((r) => {
      const rDoc = (r.documento || '').replace(/\D/g, '');
      if (docLimpo && rDoc && rDoc === docLimpo) return true;
      const rNome = (r.nome_pessoa || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      if (nomeNorm && rNome === nomeNorm) return true;
      return false;
    });

    const registrosComPorteiros = await comPorteiros(registrosPessoa);

    // 3. Avisos de moradores para esse visitante
    const { data: todosAv, error: errAv } = await supabaseAdmin
      .from('avisos_visitas')
      .select('*, morador:perfis!avisos_visitas_morador_id_fkey(nome, bloco, apartamento)')
      .order('criado_em', { ascending: false })
      .limit(1000);
    if (errAv) throw errAv;

    const avisosPessoa = (todosAv || []).filter((a) => {
      const aDoc = (a.documento_visitante || '').replace(/\D/g, '');
      if (docLimpo && aDoc && aDoc === docLimpo) return true;
      const aNome = (a.nome_visitante || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      if (nomeNorm && aNome === nomeNorm) return true;
      return false;
    });

    // 4. Métricas e Dashboard
    const veiculosSet = new Set();
    const destinosMap = new Map();
    let primeiraData = null;
    let ultimaData = null;
    let presenteAgora = false;

    registrosComPorteiros.forEach((r) => {
      if (r.veiculo_placa && r.veiculo_placa.trim()) {
        veiculosSet.add(r.veiculo_placa.trim().toUpperCase());
      }
      const destino = (r.destino_bloco || '').trim();
      if (destino) {
        destinosMap.set(destino, (destinosMap.get(destino) || 0) + 1);
      }
      if (r.entrada) {
        if (!primeiraData || new Date(r.entrada) < new Date(primeiraData)) primeiraData = r.entrada;
        if (!ultimaData || new Date(r.entrada) > new Date(ultimaData)) ultimaData = r.entrada;
      }
      if (!r.saida && r.tipo !== 'Morador') {
        presenteAgora = true;
      }
    });

    avisosPessoa.forEach((a) => {
      if (a.veiculo_placa && a.veiculo_placa.trim()) {
        veiculosSet.add(a.veiculo_placa.trim().toUpperCase());
      }
      const destinoAviso = (a.morador?.bloco || '').trim();
      if (destinoAviso && !destinosMap.has(destinoAviso)) {
        destinosMap.set(destinoAviso, (destinosMap.get(destinoAviso) || 0) + 1);
      }
    });

    const destinos = Array.from(destinosMap.entries())
      .map(([destino, total]) => ({ destino, total }))
      .sort((a, b) => b.total - a.total);

    const destinoHabitual = destinos.length ? destinos[0].destino : '-';
    const listaVeiculos = Array.from(veiculosSet);
    const veiculoHabitual = listaVeiculos.length ? listaVeiculos[0] : '-';

    const nomeFinal = nome || registrosPessoa[0]?.nome_pessoa || avisosPessoa[0]?.nome_visitante || 'Visitante';
    const docFinal = formatarDocumento(doc || registrosPessoa[0]?.documento || avisosPessoa[0]?.documento_visitante || null);
    const tipoFinal = registrosPessoa[0]?.tipo || avisosPessoa[0]?.tipo || 'Visitante';

    res.json({
      visitante: {
        chave: chave || docLimpo || ('nome:' + nomeNorm),
        nome: nomeFinal,
        documento: docFinal,
        tipo: tipoFinal,
        observacao_cadastro: obsObj ? (obsObj.observacao || '') : '',
        observacao_atualizada_em: obsObj ? obsObj.atualizado_em : null,
        historico_observacoes: obsObj ? (obsObj.historico || []) : [],
      },
      kpis: {
        total_visitas: registrosPessoa.length,
        total_avisos: avisosPessoa.length,
        primeira_visita: primeiraData,
        ultima_visita: ultimaData,
        presente_agora: presenteAgora,
        veiculos: listaVeiculos,
        veiculo_habitual: veiculoHabitual,
        destinos,
        destino_habitual: destinoHabitual,
      },
      registros: registrosComPorteiros,
      avisos: avisosPessoa,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Salva observação cadastral fixa de um visitante (legado / fallback)
app.post('/api/admin/visitantes/observacao', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { chave, nome, documento, observacao } = req.body || {};
    if (!chave && !nome && !documento) {
      return res.status(400).json({ error: 'Informe a identificação do visitante.' });
    }

    const salvo = await salvarObservacaoVisitante(chave, nome, documento, observacao, req.user.id);
    res.json({ ok: true, observacao: salvo });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Adiciona nova observação ao histórico de um visitante
app.post('/api/admin/visitantes/observacao/adicionar', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { chave, nome, documento, texto, exibir_alerta } = req.body || {};
    if (!texto || !texto.trim()) {
      return res.status(400).json({ error: 'Digite o texto da observação.' });
    }
    const salvo = await adicionarObservacaoAoHistorico({
      chave,
      nome,
      documento,
      texto,
      exibir_alerta: exibir_alerta !== false,
      userId: req.user.id,
      origem: 'admin',
    });
    res.json({ ok: true, visitante: salvo });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Alterna checkbox exibir_alerta de uma ocorrência no histórico
app.post('/api/admin/visitantes/observacao/toggle-alerta', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { chave, obs_id, exibir_alerta } = req.body || {};
    if (!chave || !obs_id) {
      return res.status(400).json({ error: 'Chave e ID da observação são obrigatórios.' });
    }
    const salvo = await alternarAlertaObservacao({ chave, obs_id, exibir_alerta });
    res.json({ ok: true, visitante: salvo });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Exclui uma ocorrência do histórico do visitante
app.post('/api/admin/visitantes/observacao/excluir', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { chave, obs_id } = req.body || {};
    if (!chave || !obs_id) {
      return res.status(400).json({ error: 'Chave e ID da observação são obrigatórios.' });
    }
    const salvo = await excluirObservacaoDoHistorico({ chave, obs_id });
    res.json({ ok: true, visitante: salvo });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Relatorio resumido para o admin
app.get('/api/admin/resumo', requireAuth, requireRole('admin'), async (req, res) => {
  const [{ count: totalMoradores }, { count: totalPorteiros }, { count: presentes }, { count: avisosPendentes }] =
    await Promise.all([
      supabaseAdmin.from('perfis').select('*', { count: 'exact', head: true }).eq('tipo', 'morador'),
      supabaseAdmin.from('perfis').select('*', { count: 'exact', head: true }).eq('tipo', 'porteiro'),
      supabaseAdmin.from('registros_portaria').select('*', { count: 'exact', head: true }).is('saida', null),
      supabaseAdmin.from('avisos_visitas').select('*', { count: 'exact', head: true }).in('status', ['Pendente', 'Autorizada']),
    ]);
  res.json({
    totalMoradores: totalMoradores || 0,
    totalPorteiros: totalPorteiros || 0,
    presentes: presentes || 0,
    avisosPendentes: avisosPendentes || 0,
  });
});

// Relatório de Sessões / Acessos (só admin).
// - Separa quem está "online agora" (acesso nos últimos N minutos) de quem está
//   offline, usando perfis.ultimo_acesso (carimbado pelo requireAuth).
// - Identifica o porteiro de plantão pela última "Troca de turno".
app.get('/api/admin/sessoes', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const JANELA_MIN = Math.min(Math.max(parseInt(req.query.janela, 10) || 5, 1), 120);
    const agora = Date.now();
    const limiteOnline = agora - JANELA_MIN * 60 * 1000;

    // 1) Todos os perfis com o carimbo de último acesso.
    const { data: perfis, error } = await supabaseAdmin
      .from('perfis')
      .select('id, nome, tipo, bloco, ativo, ultimo_acesso')
      .order('ultimo_acesso', { ascending: false, nullsFirst: false });
    if (error) throw error;

    // 2) Porteiro de plantão: último registro "Troca de turno".
    let porteiroPlantao = null;
    const { data: trocas } = await supabaseAdmin
      .from('registros_portaria')
      .select('registrado_por, entrada, observacao')
      .eq('nome_pessoa', 'Troca de turno')
      .order('entrada', { ascending: false })
      .limit(1);
    if (trocas && trocas.length > 0) {
      const t = trocas[0];
      const perfilPort = (perfis || []).find((p) => p.id === t.registrado_por);
      porteiroPlantao = {
        id: t.registrado_por || null,
        nome: perfilPort ? perfilPort.nome : null,
        desde: t.entrada || null,
        online: perfilPort && perfilPort.ultimo_acesso
          ? new Date(perfilPort.ultimo_acesso).getTime() >= limiteOnline
          : false,
      };
    }

    const mapear = (p) => ({
      id: p.id,
      nome: p.nome,
      tipo: p.tipo,
      bloco: p.bloco || null,
      ativo: p.ativo !== false,
      ultimo_acesso: p.ultimo_acesso || null,
    });

    const online = [];
    const offline = [];
    (perfis || []).forEach((p) => {
      const ts = p.ultimo_acesso ? new Date(p.ultimo_acesso).getTime() : 0;
      if (ts && ts >= limiteOnline) online.push(mapear(p));
      else offline.push(mapear(p));
    });

    // Ordena por lote (Lote 01, 02, ...) e joga quem não tem lote
    // (porteiro/admin) para o final da lista.
    online.sort(ordenarPorLote);
    offline.sort(ordenarPorLote);

    res.json({
      janelaMinutos: JANELA_MIN,
      agora: new Date(agora).toISOString(),
      porteiroPlantao,
      totalOnline: online.length,
      totalOffline: offline.length,
      online,
      offline,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Histórico de acessos de um perfil (só admin). Usado no pop-up do relatório
// de Sessões ao passar o mouse sobre uma pessoa.
app.get('/api/admin/sessoes/:id/acessos', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const perfilId = req.params.id;
    const limite = Math.min(Math.max(parseInt(req.query.limite, 10) || 20, 1), 200);

    const { data, error } = await supabaseAdmin
      .from('acessos_log')
      .select('acesso_em')
      .eq('perfil_id', perfilId)
      .order('acesso_em', { ascending: false })
      .limit(limite);
    if (error) throw error;

    res.json({ total: (data || []).length, acessos: (data || []).map((a) => a.acesso_em) });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Relatório: quantas vezes cada morador compartilhou o link do WhatsApp,
// separado por tipo (Visitante / Prestador). Só admin.
app.get('/api/admin/relatorio/compartilhamentos', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { data: eventos, error } = await supabaseAdmin
      .from('compartilhamentos_link')
      .select('morador_id, tipo, criado_em')
      .order('criado_em', { ascending: false })
      .limit(20000);
    if (error) throw error;

    // Agrupa por morador.
    const agrupado = new Map(); // morador_id -> { visitante, prestador, total, ultima }
    (eventos || []).forEach((e) => {
      const id = e.morador_id;
      if (!id) return;
      let g = agrupado.get(id);
      if (!g) { g = { visitante: 0, prestador: 0, total: 0, ultima: null }; agrupado.set(id, g); }
      if (e.tipo === 'Prestador') g.prestador += 1; else g.visitante += 1;
      g.total += 1;
      if (e.criado_em && (!g.ultima || new Date(e.criado_em) > new Date(g.ultima))) g.ultima = e.criado_em;
    });

    // Resolve nome/lote dos moradores envolvidos.
    const ids = [...agrupado.keys()];
    let mapaPerfis = new Map();
    if (ids.length > 0) {
      const { data: perfis } = await supabaseAdmin
        .from('perfis')
        .select('id, nome, bloco')
        .in('id', ids);
      mapaPerfis = new Map((perfis || []).map((p) => [p.id, p]));
    }

    const linhas = ids.map((id) => {
      const g = agrupado.get(id);
      const p = mapaPerfis.get(id) || {};
      return {
        morador_id: id,
        nome: p.nome || '(morador removido)',
        bloco: p.bloco || null,
        visitante: g.visitante,
        prestador: g.prestador,
        total: g.total,
        ultima: g.ultima,
      };
    }).sort((a, b) => b.total - a.total || a.nome.localeCompare(b.nome, 'pt-BR'));

    res.json({ total: (eventos || []).length, moradores: linhas });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Relatório: entradas em que o porteiro DIGITOU o nome do morador manualmente
// (em vez de escolher da lista). Heurística: o registro tem a tag "[Falou com: X]"
// na observação MAS não tem destino_morador vinculado (morador não estava na
// lista do lote / foi digitado à mão). Serve para o admin identificar moradores
// que aparecem manualmente e, por exemplo, cadastrá-los ou corrigir o lote.
app.get('/api/admin/relatorio/moradores-manuais', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    // Extrai o nome que está dentro de "[Falou com: NOME]" (case-insensitive).
    const extrairFalouCom = (obs) => {
      if (!obs) return null;
      const m = String(obs).match(/\[falou com:\s*([^\]]+)\]/i);
      return m ? m[1].trim() : null;
    };

    const { data: registros, error } = await supabaseAdmin
      .from('registros_portaria')
      .select('id, nome_pessoa, documento, tipo, destino_bloco, destino_apto, destino_morador, observacao, entrada, registrado_por')
      .is('destino_morador', null)
      .ilike('observacao', '%falou com%')
      .order('entrada', { ascending: false })
      .limit(3000);
    if (error) throw error;

    // Resolve o nome do porteiro que registrou cada entrada.
    const idsPorteiros = [...new Set((registros || []).map((r) => r.registrado_por).filter(Boolean))];
    let mapaPorteiros = new Map();
    if (idsPorteiros.length > 0) {
      const { data: perfisPorteiros } = await supabaseAdmin
        .from('perfis')
        .select('id, nome')
        .in('id', idsPorteiros);
      mapaPorteiros = new Map((perfisPorteiros || []).map((p) => [p.id, p.nome]));
    }

    const ocorrencias = [];
    const agrupado = new Map(); // nomeNorm -> { nome, lotes:Set, vezes, ultima_vez }

    (registros || []).forEach((r) => {
      const nomeMorador = extrairFalouCom(r.observacao);
      if (!nomeMorador) return; // sem nome legível, ignora

      ocorrencias.push({
        id: r.id,
        morador_digitado: nomeMorador,
        lote: r.destino_bloco || '-',
        visitante: r.nome_pessoa === 'Encomenda' ? '📦 Encomenda' : r.nome_pessoa,
        tipo: r.tipo || '-',
        entrada: r.entrada,
        porteiro: mapaPorteiros.get(r.registrado_por) || '-',
      });

      const chave = nomeMorador.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      const g = agrupado.get(chave);
      if (!g) {
        agrupado.set(chave, {
          nome: nomeMorador,
          lotes: new Set(r.destino_bloco ? [r.destino_bloco] : []),
          vezes: 1,
          ultima_vez: r.entrada || null,
        });
      } else {
        g.vezes += 1;
        if (r.destino_bloco) g.lotes.add(r.destino_bloco);
        if (r.entrada && (!g.ultima_vez || new Date(r.entrada) > new Date(g.ultima_vez))) {
          g.ultima_vez = r.entrada;
        }
      }
    });

    const resumo = Array.from(agrupado.values())
      .map((g) => ({
        nome: g.nome,
        lotes: Array.from(g.lotes),
        vezes: g.vezes,
        ultima_vez: g.ultima_vez,
      }))
      .sort((a, b) => b.vezes - a.vezes || a.nome.localeCompare(b.nome, 'pt-BR'));

    res.json({ total: ocorrencias.length, resumo, ocorrencias });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================================
// NOTIFICAÇÕES DO ADMIN PARA MORADORES
// ============================================================

// Admin cria uma notificação para um morador (título, texto e validade em dias).
app.post('/api/admin/notificacoes', requireAuth, requireRole('admin'), async (req, res) => {
  const { morador_id, titulo, texto, dias } = req.body || {};
  if (!morador_id) return res.status(400).json({ error: 'Morador não informado.' });
  if (!titulo || !titulo.trim()) return res.status(400).json({ error: 'Informe o título.' });
  if (!texto || !texto.trim()) return res.status(400).json({ error: 'Informe o texto da notificação.' });

  const diasNum = Math.min(Math.max(parseInt(dias, 10) || 7, 1), 365); // entre 1 e 365 dias
  const expiraEm = new Date(Date.now() + diasNum * 24 * 60 * 60 * 1000).toISOString();

  // Confirma que o destinatário existe e é morador.
  const { data: morador, error: errMor } = await supabaseAdmin
    .from('perfis')
    .select('id, tipo')
    .eq('id', morador_id)
    .single();
  if (errMor || !morador) return res.status(400).json({ error: 'Morador não encontrado.' });

  const { data, error } = await supabaseAdmin
    .from('notificacoes_morador')
    .insert({
      morador_id,
      titulo: maiuscula(titulo.trim()),
      texto: maiuscula(texto.trim()),
      dias: diasNum,
      expira_em: expiraEm,
      criado_por: req.user.id,
    })
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ notificacao: data });
});

// Admin lista as notificações de um morador (com status de visualização).
app.get('/api/admin/notificacoes/:moradorId', requireAuth, requireRole('admin'), async (req, res) => {
  const { moradorId } = req.params;
  const { data, error } = await supabaseAdmin
    .from('notificacoes_morador')
    .select('*')
    .eq('morador_id', moradorId)
    .order('criado_em', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ notificacoes: data || [] });
});

// Admin remove uma notificação.
app.delete('/api/admin/notificacoes/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { error } = await supabaseAdmin
    .from('notificacoes_morador')
    .delete()
    .eq('id', id);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true });
});

// Morador lista TODAS as próprias notificações (histórico completo, inclusive expiradas).
app.get('/api/morador/notificacoes/historico', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('notificacoes_morador')
    .select('*')
    .eq('morador_id', req.user.id)
    .order('criado_em', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ notificacoes: data || [] });
});

// Morador lista as próprias notificações ainda válidas (não expiradas).
// Retorna separadas em: pendentes (não confirmadas, travam a tela) e ativas (já confirmadas, viram card).
app.get('/api/morador/notificacoes', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const agora = new Date().toISOString();
  const { data, error } = await supabaseAdmin
    .from('notificacoes_morador')
    .select('*')
    .eq('morador_id', req.user.id)
    .gt('expira_em', agora)
    .order('criado_em', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });

  const todas = data || [];
  const pendentes = todas.filter((n) => !n.visualizado_em);
  const ativas = todas.filter((n) => n.visualizado_em);
  res.json({ pendentes, ativas });
});

// Morador confirma o recebimento de uma notificação (grava data/hora de visualização).
app.post('/api/morador/notificacoes/:id/confirmar', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const { id } = req.params;

  // Garante que a notificação é deste morador e ainda não foi confirmada.
  const { data: notif, error: errGet } = await supabaseAdmin
    .from('notificacoes_morador')
    .select('*')
    .eq('id', id)
    .eq('morador_id', req.user.id)
    .single();
  if (errGet || !notif) return res.status(404).json({ error: 'Notificação não encontrada.' });

  if (notif.visualizado_em) {
    return res.json({ notificacao: notif }); // já confirmada: idempotente
  }

  const { data, error } = await supabaseAdmin
    .from('notificacoes_morador')
    .update({ visualizado_em: new Date().toISOString() })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ notificacao: data });
});

// Porteiro lista as próprias notificações válidas (mesma tabela; o destinatário é o id do usuário logado).
app.get('/api/portaria/notificacoes', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const agora = new Date().toISOString();
  const { data, error } = await supabaseAdmin
    .from('notificacoes_morador')
    .select('*')
    .eq('morador_id', req.user.id)
    .gt('expira_em', agora)
    .order('criado_em', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });

  const todas = data || [];
  const pendentes = todas.filter((n) => !n.visualizado_em);
  const ativas = todas.filter((n) => n.visualizado_em);
  res.json({ pendentes, ativas });
});

// Porteiro confirma o recebimento de uma notificação.
app.post('/api/portaria/notificacoes/:id/confirmar', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { id } = req.params;

  const { data: notif, error: errGet } = await supabaseAdmin
    .from('notificacoes_morador')
    .select('*')
    .eq('id', id)
    .eq('morador_id', req.user.id)
    .single();
  if (errGet || !notif) return res.status(404).json({ error: 'Notificação não encontrada.' });

  if (notif.visualizado_em) {
    return res.json({ notificacao: notif });
  }

  const { data, error } = await supabaseAdmin
    .from('notificacoes_morador')
    .update({ visualizado_em: new Date().toISOString() })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ notificacao: data });
});

// ============================================================
// Arquivos estaticos (frontend)
// ============================================================
if (typeof __dirname !== 'undefined') {
  app.use(express.static(path.join(__dirname, 'public')));
}

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`\n  Park Place Portaria rodando em http://localhost:${PORT}\n`);
  });
}


require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const webpush = require('web-push');

// Inicializa VAPID Keys para Push Notifications
// Substitua as chaves públicas e privadas abaixo se precisar (foram geradas no backend)
const vapidPublicKey = 'BIOSYWts_mjXNf9VlPkqU_jnGCsXVaf64QLsyw-hI7AbyCbh0D0XufMoWEXWO0RJmJd3RPsQVRp9wgOLEIhe-O0';
const vapidPrivateKey = 'a12m4cF5E3njmkKf8P2SKRcid34mRAualhbIm05NLsI';
webpush.setVapidDetails(
  'mailto:contato@parkplace.com',
  vapidPublicKey,
  vapidPrivateKey
);

const { supabaseAnon, supabaseAdmin } = require('./src/supabase');
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
// AUTENTICACAO
// ============================================================

// Login (todos os perfis usam a mesma rota - aceita e-mail OU nome do porteiro/usuario)
app.post('/api/login', async (req, res) => {
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

app.post('/api/public/cadastro', async (req, res) => {
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

  const meta = { nome: nome.trim(), tipo: 'morador', bloco, telefone: telefone.trim(), pendente: true };
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
  res.json({ perfil: req.perfil });
});

// Atualiza o proprio cadastro (campos que o usuario pode editar)
app.put('/api/me', requireAuth, async (req, res) => {
  const { nome, telefone, bloco, apartamento } = req.body || {};
  if (!nome || !nome.trim()) {
    return res.status(400).json({ error: 'Informe o nome.' });
  }

  const { data, error } = await supabaseAdmin
    .from('perfis')
    .update({
      nome: nome.trim(),
      telefone: telefone?.trim() || null,
      bloco: bloco?.trim() || null,
      apartamento: apartamento?.trim() || null,
    })
    .eq('id', req.user.id)
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json({ perfil: data });
});

// ============================================================
// PUSH NOTIFICATIONS
// ============================================================
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

// ============================================================
// MORADOR - avisos de visita
// ============================================================

// Lista os avisos do proprio morador (incluindo historico da portaria se for pro seu lote)
app.get('/api/morador/avisos', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const { data: avisosData, error: errAvisos } = await req.supabase
      .from('avisos_visitas')
      .select('*')
      .order('criado_em', { ascending: false });
    if (errAvisos) throw errAvisos;

    let historico = [...(avisosData || [])];

    if (req.perfil && req.perfil.bloco) {
      const numeroBloco = req.perfil.bloco.replace(/lote\s*/i, '').trim();
      const { data: regData, error: errReg } = await supabaseAdmin
        .from('registros_portaria')
        .select('*')
        .ilike('destino_bloco', `%${numeroBloco}%`)
        .is('aviso_id', null)
        .order('entrada', { ascending: false });

      if (!errReg && regData) {
        const diretos = regData.map(p => ({
          id: `p_${p.id}`,
          nome_visitante: p.nome_pessoa === 'Encomenda' ? p.observacao : p.nome_pessoa,
          documento_visitante: p.documento,
          veiculo_placa: p.veiculo_placa,
          tipo: p.nome_pessoa === 'Encomenda' ? 'Encomenda' : p.tipo,
          data_prevista: p.entrada,
          status: p.saida ? 'Finalizada' : 'Entrada Realizada',
          criado_em: p.entrada
        }));
        historico = historico.concat(diretos);
      }
    }

    historico.sort((a, b) => new Date(b.criado_em) - new Date(a.criado_em));
    res.json({ avisos: historico });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Busca visitas frequentes agregadas por nome/documento para o morador
app.get('/api/morador/visitas-frequentes', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  try {
    const { data: avisosData } = await req.supabase
      .from('avisos_visitas')
      .select('*')
      .order('criado_em', { ascending: false });

    let regData = [];
    if (req.perfil && req.perfil.bloco) {
      const { data } = await supabaseAdmin
        .from('registros_portaria')
        .select('*')
        .eq('destino_bloco', req.perfil.bloco)
        .is('aviso_id', null)
        .order('entrada', { ascending: false });
      regData = data || [];
    }

    // Agrupar por nome (ou documento)
    const map = {};

    (avisosData || []).forEach(a => {
      const nome = a.nome_visitante.trim().toLowerCase();
      if (!map[nome]) {
        map[nome] = { count: 0, ultimo: a };
      }
      map[nome].count++;
    });

    regData.forEach(r => {
      const nome = r.nome_pessoa.trim().toLowerCase();
      if (!map[nome]) {
        map[nome] = {
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
      map[nome].count++;
    });

    const frequentes = Object.values(map)
      .sort((a, b) => b.count - a.count)
      .map(x => ({ ...x.ultimo, count: x.count }))
      .filter(x => x.tipo !== 'Entregador');

    res.json({ frequentes });
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

  const { data, error } = await req.supabase
    .from('avisos_visitas')
    .insert({
      morador_id: req.user.id,
      nome_visitante,
      documento_visitante: documento_visitante || null,
      veiculo_placa: veiculo_placa || null,
      tipo: tipo || 'Visitante',
      data_prevista: data_prevista || null,
      endereco_visitante: endereco_visitante || null,
      cep_visitante: cep_visitante || null,
      observacao: observacao || null,
      status: 'Pendente',
    })
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ aviso: data });
});

// Criar aviso via link publico (visitante se cadastra)
app.post('/api/public/avisos', async (req, res) => {
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
  } = req.body || {};

  if (!morador_id || !nome_visitante) {
    return res.status(400).json({ error: 'Morador e nome do visitante são obrigatórios.' });
  }

  const { data: morador, error: errMorador } = await supabaseAdmin
    .from('perfis')
    .select('id')
    .eq('id', morador_id)
    .single();

  if (errMorador || !morador) {
    return res.status(400).json({ error: 'Morador não encontrado.' });
  }

  const { data, error } = await supabaseAdmin
    .from('avisos_visitas')
    .insert({
      morador_id,
      nome_visitante,
      documento_visitante: documento_visitante || null,
      veiculo_placa: veiculo_placa || null,
      tipo: tipo || 'Visitante',
      data_prevista: data_prevista || null,
      endereco_visitante: endereco_visitante || null,
      cep_visitante: cep_visitante || null,
      observacao: observacao || null,
      status: 'Pendente',
    })
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ aviso: data });
});

// Informacoes basicas do morador para exibicao publica (cadastro de visita)
app.get('/api/public/moradores/:id', async (req, res) => {
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

// Lista de encomendas pendentes para o morador logado
app.get('/api/morador/encomendas', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const { data: perfil } = await req.supabase.from('perfis').select('bloco, nome').eq('id', req.user.id).single();
  const bloco = perfil?.bloco;
  const nome = perfil?.nome;

  if (!bloco) return res.json({ encomendas: [] });

  const numeroBloco = bloco.replace(/lote\s*/i, '').trim();

  const { data, error } = await req.supabase
    .from('registros_portaria')
    .select('*')
    .eq('nome_pessoa', 'Encomenda')
    .ilike('destino_bloco', `%${numeroBloco}%`)
    .ilike('observacao', `%${nome}%`)
    .is('saida', null)
    .order('entrada', { ascending: false });

  if (error) return res.status(400).json({ error: error.message });
  res.json({ encomendas: await comPorteiros(data || []) });
});

// ============================================================
// PORTEIRO - visitas previstas, entradas e saidas
// ============================================================

// Avisos pendentes/autorizados que a portaria deve esperar
app.get('/api/portaria/avisos', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { data, error } = await req.supabase
    .from('avisos_visitas')
    .select('*, morador:perfis!avisos_visitas_morador_id_fkey(nome, bloco, apartamento, telefone)')
    .in('status', ['Pendente', 'Autorizada'])
    .order('data_prevista', { ascending: true, nullsFirst: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ avisos: data });
});

// Marca um aviso como "Nao compareceu" (vai direto para o historico, sem entrada)
app.post('/api/portaria/avisos/:id/nao-veio', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { id } = req.params;
  const { data, error } = await req.supabase
    .from('avisos_visitas')
    .update({ status: 'Nao compareceu', nao_veio_por: req.user.id })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ aviso: data });
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
    .order('entrada', { ascending: false });

  if (req.query.de) query = query.gte('entrada', req.query.de);
  if (req.query.ate) query = query.lte('entrada', req.query.ate);
  if (req.query.cpf) query = query.ilike('documento', `%${req.query.cpf}%`);
  if (req.query.lote) query = query.ilike('destino_bloco', `%${req.query.lote}%`);

  query = query.limit(40);

  const { data, error } = await query;
  if (error) return res.status(400).json({ error: error.message });

  // Avisos que nao compareceram, no mesmo intervalo de data (por data_prevista).
  let qAvisos = req.supabase
    .from('avisos_visitas')
    .select('*, morador:perfis!avisos_visitas_morador_id_fkey!inner(bloco, apartamento)')
    .eq('status', 'Nao compareceu');

  if (req.query.de) qAvisos = qAvisos.gte('data_prevista', req.query.de);
  if (req.query.ate) qAvisos = qAvisos.lte('data_prevista', req.query.ate);
  if (req.query.cpf) qAvisos = qAvisos.ilike('documento_visitante', `%${req.query.cpf}%`);
  if (req.query.lote) qAvisos = qAvisos.ilike('perfis.bloco', `%${req.query.lote}%`);

  qAvisos = qAvisos.limit(40);

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

  const registros = [...registrosNormalizados, ...naoCompareceu].sort(
    (x, y) => new Date(y.entrada) - new Date(x.entrada)
  ).slice(0, 40);

  res.json({ registros });
});

// ------------------------------------------------------------
// Observações cadastrais fixas de visitantes e prestadores
// ------------------------------------------------------------
const OBS_VISITANTES_FILE = path.join(__dirname, 'scratch', 'observacoes_visitantes.json');
let cacheObsVisitantes = new Map();

function carregarCacheObsVisitantes() {
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
  try {
    const dir = path.dirname(OBS_VISITANTES_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const obj = Object.fromEntries(cacheObsVisitantes);
    fs.writeFileSync(OBS_VISITANTES_FILE, JSON.stringify(obj, null, 2), 'utf8');
  } catch (e) {
    // Silencioso se fs for somente leitura
  }
}

carregarCacheObsVisitantes();

async function obterTodasObservacoesVisitantes() {
  const mapa = new Map(cacheObsVisitantes);
  try {
    const { data, error } = await supabaseAdmin
      .from('observacoes_visitantes')
      .select('chave, nome, documento, observacao, atualizado_em, atualizado_por');
    if (!error && Array.isArray(data)) {
      data.forEach((item) => {
        if (item.chave) {
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
  if (chave && todas.has(chave)) return todas.get(chave);
  if (docLimpo && todas.has(docLimpo)) return todas.get(docLimpo);
  if (nomeNorm && todas.has('nome:' + nomeNorm)) return todas.get('nome:' + nomeNorm);

  const docPuro = (docLimpo || '').replace(/\D/g, '');
  const chavePura = (chave || '').replace(/\D/g, '');

  for (const item of todas.values()) {
    const itemDoc = (item.documento || '').replace(/\D/g, '');
    const itemChave = (item.chave || '').replace(/\D/g, '');
    if (docPuro && ((itemDoc && itemDoc === docPuro) || (itemChave && itemChave === docPuro))) {
      return item;
    }
    const itemNome = (item.nome || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    if (nomeNorm && itemNome && itemNome === nomeNorm) {
      return item;
    }
  }
  return null;
}

async function salvarObservacaoVisitante(chave, nome, documento, observacao, userId) {
  const agora = new Date().toISOString();
  const docLimpo = (documento || '').replace(/\D/g, '');
  const nomeLimpo = (nome || '').trim();
  const nomeNorm = nomeLimpo.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const finalChave = (chave || '').trim() || docLimpo || ('nome:' + nomeNorm);

  const registro = {
    chave: finalChave,
    nome: nomeLimpo,
    documento: documento ? (documento || '').trim() : null,
    observacao: (observacao || '').trim(),
    atualizado_em: agora,
    atualizado_por: userId || null,
  };

  cacheObsVisitantes.set(finalChave, registro);
  if (docLimpo && docLimpo !== finalChave) {
    cacheObsVisitantes.set(docLimpo, registro);
  }
  if (nomeNorm) {
    cacheObsVisitantes.set('nome:' + nomeNorm, registro);
  }
  salvarCacheObsVisitantes();

  try {
    await supabaseAdmin
      .from('observacoes_visitantes')
      .upsert(registro, { onConflict: 'chave' });
  } catch (err) {
    console.warn('[Obs Visitantes] Erro ao sincronizar com Supabase:', err.message);
  }

  return registro;
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

  // SE FOR MORADOR: Unifica o cadastro pelo perfil oficial do morador
  if (moradorEncontrado) {
    return res.json({
      encontrado: true,
      eh_morador: true,
      origem: 'morador',
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
    veiculo_placa,
    endereco_visitante,
    cep_visitante,
    observacao,
  } = req.body || {};

  if (!nome_pessoa) {
    return res.status(400).json({ error: 'Informe o nome da pessoa.' });
  }

  const docLimpo = (documento || '').replace(/\D/g, '');
  if (docLimpo.length === 11 && !cpfValido(docLimpo)) {
    return res.status(400).json({ error: 'O CPF informado no documento é inválido.' });
  }

  const tipoFinal = tipo || 'Visitante';
  const isMorador = tipoFinal === 'Morador';
  const agora = new Date().toISOString();
  const insertPayload = {
    aviso_id: aviso_id || null,
    nome_pessoa,
    documento: documento || null,
    tipo: tipoFinal,
    destino_bloco: destino_bloco || null,
    destino_apto: destino_apto || null,
    veiculo_placa: veiculo_placa || null,
    endereco_visitante: endereco_visitante || null,
    cep_visitante: cep_visitante || null,
    observacao: observacao || null,
    registrado_por: req.user.id,
    saida: isMorador ? agora : null,
    saida_por: isMorador ? req.user.id : null,
  };

  let { data, error } = await req.supabase
    .from('registros_portaria')
    .insert(insertPayload)
    .select()
    .single();

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

  // Se veio de um aviso, atualiza o status dele
  if (aviso_id) {
    await req.supabase
      .from('avisos_visitas')
      .update({ status: 'Entrada Realizada' })
      .eq('id', aviso_id);
  }

  // Disparar notificação push se for encomenda
  if (nome_pessoa === 'Encomenda') {
    notificarLote(destino_bloco, '📦 Nova Encomenda', 'Você tem uma encomenda na portaria!');
  } else {
    notificarLote(destino_bloco, '🛎️ Nova Visita', `O visitante ${nome_pessoa} chegou na portaria.`);
  }

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
  const { data, error } = await req.supabase
    .from('registros_portaria')
    .update({ saida: new Date().toISOString(), saida_por: req.user.id })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });

  if (data?.aviso_id) {
    await req.supabase
      .from('avisos_visitas')
      .update({ status: 'Finalizada' })
      .eq('id', data.aviso_id);
  }

  res.json({ registro: data });
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
    novaObs = `[ENCOMENDA] de : ${nomeDestino} retirado por ${retiradoPor || 'Morador'}`;
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
  const msgCancelamento = `[Cancelado]: ${motivo || 'Sem motivo'}`;

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

// Lista moradores de um lote especifico (usado para entregas rapidas como iFood)
app.get('/api/portaria/moradores', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  let lote = req.query.lote;
  if (!lote) return res.status(400).json({ error: 'Lote não informado.' });

  // Se o porteiro digitou apenas um numero, formata para "Lote XX"
  if (/^\d+$/.test(lote.trim())) {
    lote = `Lote ${String(lote.trim()).padStart(2, '0')}`;
  } else if (/^lote\s*\d+$/i.test(lote.trim())) {
    // Caso tenha digitado "lote 1" vira "Lote 01"
    const num = lote.replace(/\D/g, '');
    lote = `Lote ${String(num).padStart(2, '0')}`;
  }

  const { data, error } = await req.supabase
    .from('perfis')
    .select('id, nome, bloco, telefone')
    .eq('bloco', lote)
    .order('nome', { ascending: true });

  if (error) return res.status(400).json({ error: error.message });
  res.json({ moradores: data });
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
  let { email, password, nome, tipo, bloco, telefone, cpf, morador_id } = req.body || {};

  nome = (nome || '').trim();
  tipo = (tipo || '').trim();
  email = (email || '').trim().toLowerCase();
  const cpfLimpo = (cpf || '').replace(/\D/g, '') || null;

  if (cpfLimpo && !cpfValido(cpfLimpo)) {
    return res.status(400).json({ error: 'CPF inválido.' });
  }

  if (!nome || !tipo) {
    return res.status(400).json({ error: 'Preencha o nome e o perfil.' });
  }
  if (!['admin', 'porteiro', 'morador'].includes(tipo)) {
    return res.status(400).json({ error: 'Tipo inválido.' });
  }

  // Se morador_id foi fornecido (ou seja, selecionou morador existente para admin)
  if (morador_id && tipo === 'admin') {
    const { data: moradorPerfil } = await supabaseAdmin
      .from('perfis')
      .select('id, nome, bloco, telefone, cpf')
      .eq('id', morador_id)
      .single();

    if (moradorPerfil) {
      await supabaseAdmin.from('perfis').update({
        nome: nome || moradorPerfil.nome,
        tipo: 'admin',
        bloco: bloco || moradorPerfil.bloco,
        telefone: telefone || moradorPerfil.telefone,
        cpf: cpfLimpo || moradorPerfil.cpf || null,
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
    ativo: true,
    aprovado: true,
  });

  res.status(201).json({ id: data.user.id });
});

// Atualiza usuario existente
app.put('/api/admin/usuarios/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { nome, tipo, bloco, telefone, cpf, password } = req.body || {};

  if (!['admin', 'porteiro', 'morador'].includes(tipo)) {
    return res.status(400).json({ error: 'Tipo inválido.' });
  }

  const nomeLimpo = (nome || '').trim();
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

  // Atualiza metadados no Auth
  const authUpdates = {
    user_metadata: { nome: nomeLimpo, tipo, bloco, telefone, ...(cpfLimpo !== undefined ? { cpf: cpfLimpo } : {}) }
  };
  // Se informou nova senha, atualiza tambem
  if (password && password.trim().length >= 6) {
    authUpdates.password = password.trim();
  }

  await supabaseAdmin.auth.admin.updateUserById(id, authUpdates);

  const updatesPerfil = {
    nome: nomeLimpo,
    tipo,
    bloco: bloco || null,
    telefone: telefone || null,
  };
  if (cpfLimpo !== undefined) {
    updatesPerfil.cpf = cpfLimpo;
  }

  const { data, error } = await supabaseAdmin
    .from('perfis')
    .update(updatesPerfil)
    .eq('id', id)
    .select()
    .single();

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
      .select('nome_visitante, documento_visitante, veiculo_placa, tipo, criado_em')
      .order('criado_em', { ascending: false })
      .limit(2000);
    if (errAv) throw errAv;

    // Registros reais da portaria (entradas) - ignora encomendas
    const { data: registros, error: errReg } = await supabaseAdmin
      .from('registros_portaria')
      .select('nome_pessoa, documento, veiculo_placa, tipo, entrada')
      .neq('nome_pessoa', 'Encomenda')
      .order('entrada', { ascending: false })
      .limit(2000);
    if (errReg) throw errReg;

    // Agrega por chave (documento quando houver; senao, nome normalizado).
    const mapa = new Map();

    const adicionar = (nome, documento, placa, tipo, quando) => {
      if (!nome || !nome.trim()) return;
      if (nome === 'Entregador iFood') return; // entregas automaticas nao sao visitantes cadastrados
      const nomeLimpo = nome.trim();
      const docLimpo = (documento || '').replace(/\D/g, '');
      const chave = docLimpo || ('nome:' + nomeLimpo.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, ''));

      const existente = mapa.get(chave);
      if (!existente) {
        mapa.set(chave, {
          chave,
          nome: nomeLimpo,
          documento: documento || null,
          veiculo_placa: placa || null,
          tipo: tipo || 'Visitante',
          vezes: 1,
          ultima_vez: quando || null,
        });
      } else {
        existente.vezes += 1;
        if (!existente.documento && documento) existente.documento = documento;
        if (!existente.veiculo_placa && placa) existente.veiculo_placa = placa;
        if (quando && (!existente.ultima_vez || new Date(quando) > new Date(existente.ultima_vez))) {
          existente.ultima_vez = quando;
        }
      }
    };

    (avisos || []).forEach((a) =>
      adicionar(a.nome_visitante, a.documento_visitante, a.veiculo_placa, a.tipo, a.criado_em)
    );
    (registros || []).forEach((r) =>
      adicionar(r.nome_pessoa, r.documento, r.veiculo_placa, r.tipo, r.entrada)
    );

    const mapaObs = await obterTodasObservacoesVisitantes();
    let visitantes = Array.from(mapa.values()).map((v) => {
      const docLimpo = (v.documento || '').replace(/\D/g, '');
      const nomeNorm = v.nome.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      const obsObj = (v.chave && mapaObs.get(v.chave)) || (docLimpo && mapaObs.get(docLimpo)) || mapaObs.get('nome:' + nomeNorm);
      return {
        ...v,
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
    const docFinal = doc || registrosPessoa[0]?.documento || avisosPessoa[0]?.documento_visitante || null;
    const tipoFinal = registrosPessoa[0]?.tipo || avisosPessoa[0]?.tipo || 'Visitante';

    res.json({
      visitante: {
        chave: chave || docLimpo || ('nome:' + nomeNorm),
        nome: nomeFinal,
        documento: docFinal,
        tipo: tipoFinal,
        observacao_cadastro: obsObj ? (obsObj.observacao || '') : '',
        observacao_atualizada_em: obsObj ? obsObj.atualizado_em : null,
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

// Salva observação cadastral fixa de um visitante
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


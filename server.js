require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
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

app.post('/api/public/cadastro', async (req, res) => {
  const { nome, bloco, telefone, email, password } = req.body || {};
  if (!nome?.trim() || !bloco || !telefone?.trim() || !email?.trim() || !password) {
    return res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
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
    return res.status(400).json({ error: jaExiste ? 'Este e-mail ja esta cadastrado.' : error.message });
  }

  await supabaseAdmin.from('perfis').upsert({
    id: data.user.id,
    nome: meta.nome,
    tipo: 'morador',
    bloco,
    telefone: meta.telefone,
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

// Quem esta dentro do condominio agora (saida nula)
app.get('/api/portaria/presentes', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { data, error } = await req.supabase
    .from('registros_portaria')
    .select('*')
    .neq('nome_pessoa', 'Encomenda')
    .is('saida', null)
    .order('entrada', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ presentes: await comPorteiros(data || []) });
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

  const registros = [...(await comPorteiros(data || [])), ...naoCompareceu].sort(
    (x, y) => new Date(y.entrada) - new Date(x.entrada)
  ).slice(0, 40);

  res.json({ registros });;
});

// Busca o cadastro mais recente de uma pessoa pelo documento (CPF).
// Usado na aba "Registrar entrada" para preencher dados de quem ja veio antes.
app.get('/api/portaria/buscar', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const doc = (req.query.documento || '').trim();
  if (!doc) return res.status(400).json({ error: 'Informe o documento para buscar.' });

  // Normaliza para comparar ignorando pontuacao (123.456.789-00 == 12345678900)
  const docLimpo = doc.replace(/\D/g, '');

  // Procura primeiro nos registros de portaria (quem ja entrou).
  const { data: registros, error: errReg } = await req.supabase
    .from('registros_portaria')
    .select('*')
    .not('documento', 'is', null)
    .order('entrada', { ascending: false })
    .limit(500);
  if (errReg) return res.status(400).json({ error: errReg.message });

  const achoReg = (registros || []).find(
    (r) => (r.documento || '').replace(/\D/g, '') === docLimpo
  );
  if (achoReg) {
    return res.json({
      encontrado: true,
      origem: 'registro',
      pessoa: {
        nome_pessoa: achoReg.nome_pessoa,
        documento: achoReg.documento,
        tipo: achoReg.tipo,
        veiculo_placa: achoReg.veiculo_placa,
        destino_bloco: achoReg.destino_bloco,
        destino_apto: achoReg.destino_apto,
        endereco_visitante: achoReg.endereco_visitante,
        cep_visitante: achoReg.cep_visitante,
      },
    });
  }

  // Se nao achou, procura nos avisos de visita cadastrados pelos moradores.
  const { data: avisos, error: errAv } = await req.supabase
    .from('avisos_visitas')
    .select('*, morador:perfis!avisos_visitas_morador_id_fkey(bloco, apartamento)')
    .not('documento_visitante', 'is', null)
    .order('criado_em', { ascending: false })
    .limit(500);
  if (errAv) return res.status(400).json({ error: errAv.message });

  const achoAviso = (avisos || []).find(
    (a) => (a.documento_visitante || '').replace(/\D/g, '') === docLimpo
  );
  if (achoAviso) {
    const m = achoAviso.morador || {};
    return res.json({
      encontrado: true,
      origem: 'aviso',
      pessoa: {
        nome_pessoa: achoAviso.nome_visitante,
        documento: achoAviso.documento_visitante,
        tipo: achoAviso.tipo,
        veiculo_placa: achoAviso.veiculo_placa,
        destino_bloco: m.bloco || null,
        destino_apto: m.apartamento || null,
        endereco_visitante: achoAviso.endereco_visitante || null,
        cep_visitante: achoAviso.cep_visitante || null,
      },
    });
  }

  res.json({ encontrado: false });
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

  const { data, error } = await req.supabase
    .from('registros_portaria')
    .insert({
      aviso_id: aviso_id || null,
      nome_pessoa,
      documento: documento || null,
      tipo: tipo || 'Visitante',
      destino_bloco: destino_bloco || null,
      destino_apto: destino_apto || null,
      veiculo_placa: veiculo_placa || null,
      endereco_visitante: endereco_visitante || null,
      cep_visitante: cep_visitante || null,
      observacao: observacao || null,
      registrado_por: req.user.id,
    })
    .select()
    .single();

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

// Lista todos os perfis
app.get('/api/admin/usuarios', requireAuth, requireRole('admin'), async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('perfis')
    .select('*')
    .order('criado_em', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ usuarios: data });
});

// Cria um novo usuario (porteiro, morador ou admin)
app.post('/api/admin/usuarios', requireAuth, requireRole('admin'), async (req, res) => {
  let { email, password, nome, tipo, bloco, telefone } = req.body || {};

  nome = (nome || '').trim();
  tipo = (tipo || '').trim();
  email = (email || '').trim().toLowerCase();

  if (!nome || !tipo || !password) {
    return res.status(400).json({ error: 'Preencha nome, tipo e senha.' });
  }
  if (!['admin', 'porteiro', 'morador'].includes(tipo)) {
    return res.status(400).json({ error: 'Tipo inválido.' });
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
        error: `Ja existe um porteiro cadastrado com o nome "${nome}". Por favor, utilize um sobrenome ou complemento para identifica-lo (ex: ${nome} Silva).`
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
    user_metadata: { nome, tipo, bloco, telefone },
  });

  if (error) {
    const jaExiste = /already|registered|exists/i.test(error.message);
    return res.status(400).json({ error: jaExiste ? 'Este e-mail/usuário já está cadastrado.' : error.message });
  }

  // Garante o perfil mesmo se o trigger nao rodar
  await supabaseAdmin.from('perfis').upsert({
    id: data.user.id,
    nome,
    tipo,
    bloco: bloco || null,
    telefone: telefone || null,
    ativo: true,
    aprovado: true,
  });

  res.status(201).json({ id: data.user.id });
});

// Atualiza usuario existente
app.put('/api/admin/usuarios/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { nome, tipo, bloco, telefone, password } = req.body || {};

  if (!['admin', 'porteiro', 'morador'].includes(tipo)) {
    return res.status(400).json({ error: 'Tipo inválido.' });
  }

  const nomeLimpo = (nome || '').trim();

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
        error: `Ja existe outro porteiro cadastrado com o nome "${nomeLimpo}". Escolha um complemento para diferencia-lo.`
      });
    }
  }

  // Atualiza metadados no Auth
  const authUpdates = {
    user_metadata: { nome: nomeLimpo, tipo, bloco, telefone }
  };
  // Se informou nova senha, atualiza tambem
  if (password && password.trim().length >= 6) {
    authUpdates.password = password.trim();
  }

  await supabaseAdmin.auth.admin.updateUserById(id, authUpdates);

  const { data, error } = await supabaseAdmin
    .from('perfis')
    .update({ nome: nomeLimpo, tipo, bloco: bloco || null, telefone: telefone || null })
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
app.use(express.static(path.join(__dirname, 'public')));

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`\n  Park Place Portaria rodando em http://localhost:${PORT}\n`);
  });
}


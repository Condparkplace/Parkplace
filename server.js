require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

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

// Login (todos os perfis usam a mesma rota)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Informe e-mail e senha.' });
  }

  const { data, error } = await supabaseAnon.auth.signInWithPassword({
    email,
    password,
  });
  if (error) {
    return res.status(401).json({ error: 'E-mail ou senha invalidos.' });
  }

  const { data: perfil, error: perfilErr } = await supabaseAdmin
    .from('perfis')
    .select('*')
    .eq('id', data.user.id)
    .single();

  if (perfilErr || !perfil) {
    return res.status(403).json({ error: 'Perfil nao encontrado.' });
  }
  if (!perfil.ativo) {
    return res.status(403).json({ error: 'Usuario desativado. Procure a administracao.' });
  }

  setSessionCookie(res, data.session);
  res.json({ perfil });
});

// Logout
app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

// Dados do usuario logado
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ perfil: req.perfil });
});

// ============================================================
// MORADOR - avisos de visita
// ============================================================

// Lista os avisos do proprio morador
app.get('/api/morador/avisos', requireAuth, requireRole('morador', 'admin'), async (req, res) => {
  const { data, error } = await req.supabase
    .from('avisos_visitas')
    .select('*')
    .order('criado_em', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ avisos: data });
});

// Cria um novo aviso de visita
app.post('/api/morador/avisos', requireAuth, requireRole('morador'), async (req, res) => {
  const {
    nome_visitante,
    documento_visitante,
    veiculo_placa,
    tipo,
    data_prevista,
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
      observacao: observacao || null,
      status: 'Pendente',
    })
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ aviso: data });
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

// Quem esta dentro do condominio agora (saida nula)
app.get('/api/portaria/presentes', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { data, error } = await req.supabase
    .from('registros_portaria')
    .select('*')
    .is('saida', null)
    .order('entrada', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ presentes: data });
});

// Historico completo (com filtro opcional por data)
app.get('/api/portaria/historico', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  let query = req.supabase
    .from('registros_portaria')
    .select('*')
    .order('entrada', { ascending: false })
    .limit(500);

  if (req.query.de) query = query.gte('entrada', req.query.de);
  if (req.query.ate) query = query.lte('entrada', req.query.ate);

  const { data, error } = await query;
  if (error) return res.status(400).json({ error: error.message });
  res.json({ registros: data });
});

// Busca o cadastro mais recente de uma pessoa pelo documento (CPF/RG).
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

  res.status(201).json({ registro: data });
});

// Registra saida
app.post('/api/portaria/saida/:id', requireAuth, requireRole('porteiro', 'admin'), async (req, res) => {
  const { id } = req.params;
  const { data, error } = await req.supabase
    .from('registros_portaria')
    .update({ saida: new Date().toISOString() })
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

// Cria um novo usuario (porteiro ou morador)
app.post('/api/admin/usuarios', requireAuth, requireRole('admin'), async (req, res) => {
  const { email, password, nome, tipo, bloco, apartamento, telefone } = req.body || {};

  if (!email || !password || !nome || !tipo) {
    return res.status(400).json({ error: 'Preencha e-mail, senha, nome e tipo.' });
  }
  if (!['admin', 'porteiro', 'morador'].includes(tipo)) {
    return res.status(400).json({ error: 'Tipo invalido.' });
  }

  const { data, error } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { nome, tipo, bloco, apartamento, telefone },
  });

  if (error) return res.status(400).json({ error: error.message });

  // Garante o perfil mesmo se o trigger nao rodar
  await supabaseAdmin.from('perfis').upsert({
    id: data.user.id,
    nome,
    tipo,
    bloco: bloco || null,
    apartamento: apartamento || null,
    telefone: telefone || null,
  });

  res.status(201).json({ id: data.user.id });
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
    return res.status(400).json({ error: 'Voce nao pode remover o proprio usuario.' });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  Park Place Portaria rodando em http://localhost:${PORT}\n`);
});

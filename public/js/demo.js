// ============================================================
// MODO DEMONSTRACAO (sem Supabase)
// Simula o backend no proprio navegador usando localStorage.
// Ativa quando a URL tem ?demo=1 OU quando ja existe sessao demo.
// Para desligar: logout, ou remover a tag <script> de demo.js.
// ============================================================
(function () {
  const LS_KEY = 'pp_demo_db';
  const SESS_KEY = 'pp_demo_sessao';

  const params = new URLSearchParams(location.search);
  if (params.get('demo') === '1') localStorage.setItem('pp_demo_on', '1');
  if (params.get('demo') === '0') {
    localStorage.removeItem('pp_demo_on');
    localStorage.removeItem(SESS_KEY);
  }

  const DEMO_ON = localStorage.getItem('pp_demo_on') === '1';
  if (!DEMO_ON) return; // modo real: nao faz nada, usa a API de verdade.

  window.PP_DEMO = true;

  // ---------- Base de dados simulada ----------
  const agora = Date.now();
  const iso = (ms) => new Date(ms).toISOString();

  function seed() {
    return {
      usuarios: [
        { id: 'u-admin', nome: 'Administrador Demo', tipo: 'admin', bloco: null, apartamento: null, telefone: '(11) 4601-2211', ativo: true, email: 'admin@parkplace.com', criado_em: iso(agora - 9e8) },
        { id: 'u-port', nome: 'Carlos Porteiro', tipo: 'porteiro', bloco: null, apartamento: null, telefone: '(11) 90000-0001', ativo: true, email: 'porteiro@parkplace.com', criado_em: iso(agora - 8e8) },
        { id: 'u-mor1', nome: 'Mariana Souza', tipo: 'morador', bloco: 'Bloco A', apartamento: '102', telefone: '(11) 90000-1002', ativo: true, email: 'mariana@parkplace.com', criado_em: iso(agora - 7e8) },
        { id: 'u-mor2', nome: 'Joao Pereira', tipo: 'morador', bloco: 'Bloco B', apartamento: '204', telefone: '(11) 90000-2004', ativo: true, email: 'joao@parkplace.com', criado_em: iso(agora - 6e8) },
      ],
      avisos: [
        { id: 1, morador_id: 'u-mor1', nome_visitante: 'Pedro Encanador', documento_visitante: '123.456.789-00', veiculo_placa: 'ABC-1D23', tipo: 'Prestador', data_prevista: iso(agora + 36e5), observacao: 'Conserto da pia', status: 'Pendente', criado_em: iso(agora - 72e5) },
        { id: 2, morador_id: 'u-mor1', nome_visitante: 'Ana Visita', documento_visitante: null, veiculo_placa: null, tipo: 'Visitante', data_prevista: iso(agora + 72e5), observacao: null, status: 'Pendente', criado_em: iso(agora - 36e5) },
        { id: 3, morador_id: 'u-mor2', nome_visitante: 'Entrega Mercado', documento_visitante: null, veiculo_placa: 'XYZ-9K88', tipo: 'Entregador', data_prevista: iso(agora + 18e5), observacao: 'Compras do mes', status: 'Pendente', criado_em: iso(agora - 18e5) },
      ],
      registros: [
        { id: 1, aviso_id: null, nome_pessoa: 'Lucas Tecnico', documento: '987.654.321-00', tipo: 'Prestador', destino_bloco: 'Bloco B', destino_apto: '204', veiculo_placa: 'JKL-4M55', endereco_visitante: 'Rua das Flores, 200, Centro, Jundiai/SP - CEP 13201-000', cep_visitante: '13201-000', entrada: iso(agora - 54e5), saida: null, registrado_por: 'u-port', observacao: 'Internet' },
        { id: 2, aviso_id: null, nome_pessoa: 'Correios', documento: null, tipo: 'Entregador', destino_bloco: 'Bloco A', destino_apto: '102', veiculo_placa: null, endereco_visitante: null, cep_visitante: null, entrada: iso(agora - 90e5), saida: iso(agora - 88e5), registrado_por: 'u-port', observacao: null },
      ],
      seqAviso: 4,
      seqRegistro: 3,
    };
  }

  function load() {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (raw) return JSON.parse(raw);
    } catch {}
    const db = seed();
    save(db);
    return db;
  }
  function save(db) { localStorage.setItem(LS_KEY, JSON.stringify(db)); }

  function getSessao() {
    try { return JSON.parse(localStorage.getItem(SESS_KEY)); } catch { return null; }
  }
  function setSessao(userId) { localStorage.setItem(SESS_KEY, JSON.stringify({ userId })); }
  function limparSessao() { localStorage.removeItem(SESS_KEY); }

  const ok = (body) => Promise.resolve(body);
  const erro = (msg) => Promise.reject(new Error(msg));

  function usuarioLogado(db) {
    const s = getSessao();
    if (!s) return null;
    return db.usuarios.find((u) => u.id === s.userId) || null;
  }

  // ---------- Roteador que imita o backend ----------
  async function demoApi(path, options = {}) {
    const db = load();
    const metodo = (options.method || 'GET').toUpperCase();
    const corpo = options.body ? JSON.parse(options.body) : {};
    const url = path.split('?')[0];
    const me = usuarioLogado(db);

    // ----- Auth -----
    if (url === '/api/login' && metodo === 'POST') {
      const u = db.usuarios.find((x) => x.email === (corpo.email || '').toLowerCase());
      if (!u) return erro('E-mail ou senha invalidos. (demo: use os botoes de acesso rapido)');
      setSessao(u.id);
      return ok({ perfil: u });
    }
    if (url === '/api/logout') { limparSessao(); return ok({ ok: true }); }
    if (url === '/api/me') {
      if (!me) return erro('Nao autenticado.');
      return ok({ perfil: me });
    }

    if (!me) return erro('Nao autenticado.');

    // ----- Morador -----
    if (url === '/api/morador/avisos' && metodo === 'GET') {
      const lista = db.avisos
        .filter((a) => me.tipo === 'admin' || a.morador_id === me.id)
        .sort((a, b) => new Date(b.criado_em) - new Date(a.criado_em));
      return ok({ avisos: lista });
    }
    if (url === '/api/morador/avisos' && metodo === 'POST') {
      const novo = {
        id: db.seqAviso++,
        morador_id: me.id,
        nome_visitante: corpo.nome_visitante,
        documento_visitante: corpo.documento_visitante || null,
        veiculo_placa: corpo.veiculo_placa || null,
        tipo: corpo.tipo || 'Visitante',
        data_prevista: corpo.data_prevista || null,
        observacao: corpo.observacao || null,
        status: 'Pendente',
        criado_em: iso(Date.now()),
      };
      db.avisos.push(novo);
      save(db);
      return ok({ aviso: novo });
    }
    const mCancel = url.match(/^\/api\/morador\/avisos\/(\d+)\/cancelar$/);
    if (mCancel && metodo === 'POST') {
      const a = db.avisos.find((x) => x.id === Number(mCancel[1]));
      if (a) { a.status = 'Cancelada'; save(db); }
      return ok({ aviso: a });
    }

    // ----- Portaria -----
    if (url === '/api/portaria/avisos' && metodo === 'GET') {
      const lista = db.avisos
        .filter((a) => ['Pendente', 'Autorizada'].includes(a.status))
        .map((a) => {
          const m = db.usuarios.find((u) => u.id === a.morador_id) || {};
          return { ...a, morador: { nome: m.nome, bloco: m.bloco, apartamento: m.apartamento, telefone: m.telefone } };
        });
      return ok({ avisos: lista });
    }
    if (url === '/api/portaria/presentes' && metodo === 'GET') {
      const lista = db.registros.filter((r) => !r.saida).sort((a, b) => new Date(b.entrada) - new Date(a.entrada));
      return ok({ presentes: lista });
    }
    if (url === '/api/portaria/historico') {
      let lista = [...db.registros].sort((a, b) => new Date(b.entrada) - new Date(a.entrada));
      const qp = new URLSearchParams(path.split('?')[1] || '');
      if (qp.get('de')) lista = lista.filter((r) => new Date(r.entrada) >= new Date(qp.get('de')));
      if (qp.get('ate')) lista = lista.filter((r) => new Date(r.entrada) <= new Date(qp.get('ate')));
      return ok({ registros: lista });
    }
    if (url === '/api/portaria/buscar') {
      const qp = new URLSearchParams(path.split('?')[1] || '');
      const docLimpo = (qp.get('documento') || '').replace(/\D/g, '');
      if (!docLimpo) return erro('Informe o documento para buscar.');

      // Procura nos registros de portaria (mais recente primeiro)
      const regs = [...db.registros]
        .filter((r) => r.documento)
        .sort((a, b) => new Date(b.entrada) - new Date(a.entrada));
      const achoReg = regs.find((r) => (r.documento || '').replace(/\D/g, '') === docLimpo);
      if (achoReg) {
        return ok({
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

      // Procura nos avisos de visita
      const avs = [...db.avisos]
        .filter((a) => a.documento_visitante)
        .sort((a, b) => new Date(b.criado_em) - new Date(a.criado_em));
      const achoAviso = avs.find((a) => (a.documento_visitante || '').replace(/\D/g, '') === docLimpo);
      if (achoAviso) {
        const m = db.usuarios.find((u) => u.id === achoAviso.morador_id) || {};
        return ok({
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

      return ok({ encontrado: false });
    }

    if (url === '/api/portaria/entrada' && metodo === 'POST') {
      const novo = {
        id: db.seqRegistro++,
        aviso_id: corpo.aviso_id || null,
        nome_pessoa: corpo.nome_pessoa,
        documento: corpo.documento || null,
        tipo: corpo.tipo || 'Visitante',
        destino_bloco: corpo.destino_bloco || null,
        destino_apto: corpo.destino_apto || null,
        veiculo_placa: corpo.veiculo_placa || null,
        endereco_visitante: corpo.endereco_visitante || null,
        cep_visitante: corpo.cep_visitante || null,
        entrada: iso(Date.now()),
        saida: null,
        registrado_por: me.id,
        observacao: corpo.observacao || null,
      };
      db.registros.push(novo);
      if (corpo.aviso_id) {
        const a = db.avisos.find((x) => x.id === Number(corpo.aviso_id));
        if (a) a.status = 'Entrada Realizada';
      }
      save(db);
      return ok({ registro: novo });
    }
    const mSaida = url.match(/^\/api\/portaria\/saida\/(\d+)$/);
    if (mSaida && metodo === 'POST') {
      const r = db.registros.find((x) => x.id === Number(mSaida[1]));
      if (r) {
        r.saida = iso(Date.now());
        if (r.aviso_id) {
          const a = db.avisos.find((x) => x.id === r.aviso_id);
          if (a) a.status = 'Finalizada';
        }
        save(db);
      }
      return ok({ registro: r });
    }

    // ----- Admin -----
    if (url === '/api/admin/usuarios' && metodo === 'GET') {
      const lista = [...db.usuarios].sort((a, b) => new Date(b.criado_em) - new Date(a.criado_em));
      return ok({ usuarios: lista });
    }
    if (url === '/api/admin/usuarios' && metodo === 'POST') {
      const novo = {
        id: 'u-' + Math.random().toString(36).slice(2, 8),
        nome: corpo.nome,
        tipo: corpo.tipo,
        bloco: corpo.bloco || null,
        apartamento: corpo.apartamento || null,
        telefone: corpo.telefone || null,
        ativo: true,
        email: (corpo.email || '').toLowerCase(),
        criado_em: iso(Date.now()),
      };
      db.usuarios.push(novo);
      save(db);
      return ok({ id: novo.id });
    }
    const mToggle = url.match(/^\/api\/admin\/usuarios\/([^/]+)\/toggle$/);
    if (mToggle && metodo === 'POST') {
      const u = db.usuarios.find((x) => x.id === mToggle[1]);
      if (u) { u.ativo = !!corpo.ativo; save(db); }
      return ok({ perfil: u });
    }
    const mDel = url.match(/^\/api\/admin\/usuarios\/([^/]+)$/);
    if (mDel && metodo === 'DELETE') {
      if (mDel[1] === me.id) return erro('Voce nao pode remover o proprio usuario.');
      db.usuarios = db.usuarios.filter((x) => x.id !== mDel[1]);
      save(db);
      return ok({ ok: true });
    }
    if (url === '/api/admin/resumo') {
      return ok({
        totalMoradores: db.usuarios.filter((u) => u.tipo === 'morador').length,
        totalPorteiros: db.usuarios.filter((u) => u.tipo === 'porteiro').length,
        presentes: db.registros.filter((r) => !r.saida).length,
        avisosPendentes: db.avisos.filter((a) => ['Pendente', 'Autorizada'].includes(a.status)).length,
      });
    }

    return erro('Rota demo nao encontrada: ' + path);
  }

  // Expoe o roteador para o api.js usar.
  window.__demoApi = demoApi;

  // Login rapido chamado pelos botoes da tela inicial.
  window.demoLoginRapido = async function (tipo) {
    const emails = { admin: 'admin@parkplace.com', porteiro: 'porteiro@parkplace.com', morador: 'mariana@parkplace.com' };
    await demoApi('/api/login', { method: 'POST', body: JSON.stringify({ email: emails[tipo] }) });
    const destino = tipo === 'admin' ? '/admin.html' : tipo === 'porteiro' ? '/porteiro.html' : '/morador.html';
    location.href = destino;
  };

  // Permite reiniciar os dados de exemplo.
  window.demoReset = function () {
    localStorage.removeItem(LS_KEY);
    location.reload();
  };
})();

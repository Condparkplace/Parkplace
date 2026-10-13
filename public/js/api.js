// Helpers compartilhados de API e sessao para o frontend.

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  let body = null;
  try {
    body = await res.json();
  } catch {
    body = {};
  }
  if (!res.ok) {
    throw new Error(body.error || `Erro ${res.status}`);
  }
  return body;
}

// Garante que o usuario esta logado e com o tipo esperado.
// Redireciona para a pagina correta caso contrario.
async function protegerPagina(tipoEsperado) {
  try {
    const { perfil } = await api('/api/me');
    if (tipoEsperado && perfil.tipo !== tipoEsperado && perfil.tipo !== 'admin') {
      redirecionarPorTipo(perfil.tipo);
      return null;
    }
    return perfil;
  } catch {
    window.location.href = '/login.html';
    return null;
  }
}

// Botoes de navegacao entre as paginas (apenas para administradores).
function navAdmin(perfil, atual) {
  if (!perfil || perfil.tipo !== 'admin') return;
  const topbar = document.querySelector('.topbar');
  if (!topbar || topbar.querySelector('.admin-nav')) return;
  const links = [
    { id: 'admin', href: '/admin.html', txt: '&#9881;&#65039; Administração' },
    { id: 'porteiro', href: '/porteiro.html', txt: '&#128682; Portaria' },
    { id: 'morador', href: '/morador.html', txt: '&#127968; Área do morador' },
    { id: 'cadastro', href: '/cadastro.html', txt: '&#128221; Cadastro de morador', novaAba: true },
    { id: 'site', href: '/', txt: '&#127760; Site' },
  ];
  const nav = document.createElement('nav');
  nav.className = 'admin-nav';
  nav.setAttribute('aria-label', 'Navegacao do administrador');
  nav.innerHTML = links
    .map((l) => `<a id="nav-${l.id}" href="${l.href}"${l.id === atual ? ' class="ativo" aria-current="page"' : ''}${l.novaAba ? ' target="_blank"' : ''}>${l.txt}</a>`)
    .join('');
  const userArea = topbar.querySelector('.user-area');
  topbar.insertBefore(nav, userArea);
}

// Para paginas sem barra superior (Site, Cadastro): se o admin estiver logado,
// cria uma barra fina no topo com o mesmo menu.
async function navAdminAuto(atual) {
  let perfil;
  try {
    ({ perfil } = await api('/api/me'));
  } catch {
    return; // nao logado: nao mostra nada
  }
  if (!perfil || perfil.tipo !== 'admin') return;
  if (!document.querySelector('.topbar')) {
    const bar = document.createElement('div');
    bar.className = 'topbar';
    bar.innerHTML = `
      <div class="brand">&#9881;&#65039; Park Place <span class="sub">&middot; Administração</span></div>
      <div class="user-area">
        <span>${escapeHtml(perfil.nome)}</span>
        <button class="secundario mini" onclick="logout()">Sair</button>
      </div>`;
    document.body.prepend(bar);
  }
  navAdmin(perfil, atual);
}

function redirecionarPorTipo(tipo) {
  if (tipo === 'admin') window.location.href = '/admin.html';
  else if (tipo === 'porteiro') window.location.href = '/porteiro.html';
  else window.location.href = '/morador.html';
}

async function logout() {
  try {
    await api('/api/logout', { method: 'POST' });
  } catch {}
  window.location.href = '/login.html';
}

function escapeHtml(valor) {
  if (valor === null || valor === undefined) return '';
  return String(valor)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatarData(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d)) return '-';
  return d.toLocaleString('pt-BR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function badgeStatus(status) {
  const mapa = {
    'Pendente': 'pendente',
    'Autorizada': 'autorizada',
    'Entrada Realizada': 'entrada',
    'Finalizada': 'finalizada',
    'Cancelada': 'cancelada',
    'Nao compareceu': 'cancelada',
  };
  const cls = mapa[status] || 'finalizada';
  return `<span class="badge ${cls}">${escapeHtml(status)}</span>`;
}

// Alterna a visibilidade da senha (olho aberto / fechado)
function toggleSenha(inputId, btn) {
  const inp = document.getElementById(inputId);
  if (!inp) return;
  const isPass = inp.type === 'password';
  inp.type = isPass ? 'text' : 'password';
  if (btn) {
    const eyeOpen = btn.querySelector('.eye-open');
    const eyeClosed = btn.querySelector('.eye-closed');
    if (eyeOpen && eyeClosed) {
      eyeOpen.classList.toggle('hidden', isPass);
      eyeClosed.classList.toggle('hidden', !isPass);
    }
    btn.setAttribute('aria-label', isPass ? 'Ocultar senha' : 'Ver senha');
    btn.title = isPass ? 'Ocultar senha' : 'Ver senha';
  }
}


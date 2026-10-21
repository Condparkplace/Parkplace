// Helpers compartilhados de API e sessao para o frontend.

async function api(path, options = {}) {
  const opts = { ...options };
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, {
    credentials: 'include',
    ...opts,
    headers,
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
  // Admin inicia na Área do morador; porteiro na Portaria; morador na sua área.
  if (tipo === 'admin') window.location.href = '/morador.html';
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
    'Visualizada': 'entrada',
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

// Formata CPF no padrao 000.000.000-00
function formatarCpf(v) {
  if (!v) return '';
  const d = String(v).replace(/\D/g, '').slice(0, 11);
  return d
    .replace(/^(\d{3})(\d)/, '$1.$2')
    .replace(/^(\d{3})\.(\d{3})(\d)/, '$1.$2.$3')
    .replace(/\.(\d{3})(\d)/, '.$1-$2');
}

// Formata CEP no padrao 00000-000
function formatarCep(v) {
  if (!v) return '';
  const d = String(v).replace(/\D/g, '').slice(0, 8);
  if (d.length <= 5) return d;
  return d.slice(0, 5) + '-' + d.slice(5);
}

// Formata documento (CPF ou CNPJ) com máscara padronizada
function formatarDocumento(v) {
  if (!v) return '';
  const d = String(v).replace(/\D/g, '');
  if (d.length === 11) {
    return d.replace(/^(\d{3})(\d{3})(\d{3})(\d{2})$/, '$1.$2.$3-$4');
  }
  if (d.length === 14) {
    return d.replace(/^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$/, '$1.$2.$3/$4-$5');
  }
  return String(v).trim();
}

// Validador oficial de CPF (dígitos verificadores matemáticos + bloqueio de sequências)
function validarCpf(v) {
  if (!v) return false;
  const d = String(v).replace(/\D/g, '');
  if (d.length !== 11 || /^(\d)\1{10}$/.test(d)) return false;

  let soma = 0;
  for (let i = 0; i < 9; i++) {
    soma += parseInt(d.charAt(i), 10) * (10 - i);
  }
  let resto = (soma * 10) % 11;
  if (resto === 10 || resto === 11) resto = 0;
  if (resto !== parseInt(d.charAt(9), 10)) return false;

  soma = 0;
  for (let i = 0; i < 10; i++) {
    soma += parseInt(d.charAt(i), 10) * (11 - i);
  }
  resto = (soma * 10) % 11;
  if (resto === 10 || resto === 11) resto = 0;
  return resto === parseInt(d.charAt(10), 10);
}

// Vincula máscara e feedback visual em tempo real para qualquer campo de CPF
function vincularValidadorCpf(input, msgContainer) {
  if (!input) return;
  input.addEventListener('input', () => {
    // Limita sempre a 11 dígitos (tamanho do CPF) e aplica a máscara.
    const raw = input.value.replace(/\D/g, '').slice(0, 11);
    input.value = formatarCpf(raw);
    if (raw.length === 11) {
      const valido = validarCpf(raw);
      if (valido) {
        input.style.borderColor = 'var(--verde, #16a34a)';
        if (msgContainer) {
          msgContainer.textContent = '✓ CPF válido';
          msgContainer.style.color = 'var(--verde, #16a34a)';
          msgContainer.classList.remove('hidden');
        }
      } else {
        input.style.borderColor = 'var(--vermelho, #dc2626)';
        if (msgContainer) {
          msgContainer.textContent = '⚠ CPF inválido. Verifique os números digitados.';
          msgContainer.style.color = 'var(--vermelho, #dc2626)';
          msgContainer.classList.remove('hidden');
        }
      }
    } else {
      input.style.borderColor = '';
      if (msgContainer) {
        msgContainer.textContent = '';
        msgContainer.classList.add('hidden');
      }
    }
  });
}




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

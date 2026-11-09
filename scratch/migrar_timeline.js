// Migra observacoes_visitantes para o MODELO TIMELINE limpo, TANTO no Supabase
// QUANTO no arquivo de cache local (scratch/observacoes_visitantes.json) — este
// último é lido no boot do servidor e estava ressuscitando dados legados.
//
// DRY-RUN por padrão. Para aplicar: node scratch/migrar_timeline.js aplicar
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { supabaseAdmin } = require('../src/supabase');
const APLICAR = process.argv[2] === 'aplicar';
const CACHE_FILE = path.join(__dirname, 'observacoes_visitantes.json');

function limparTexto(t) {
  let s = (t || '').trim();
  if (!s) return '';
  const linhas = s.split('\n').map((l) => l.trim()).filter(Boolean);
  if (linhas.length && linhas[0].startsWith('•')) s = linhas[0];
  const prefixo = /^•?\s*\d{1,2}\/\d{1,2}(\/\d{2,4})?,?\s*\d{1,2}:\d{2}\s*\([^)]*\):\s*/;
  let ant;
  do { ant = s; s = s.replace(prefixo, '').trim(); } while (s !== ant && s.length);
  return s.trim();
}
const ehAuditoria = (t) => { const u = (t || '').trim().toUpperCase(); return u.startsWith('[OBSERVAÇÃO') || u.startsWith('[OBSERVACAO') || u.startsWith('[ALERTA'); };
const ehBloqueioTexto = (t) => { const u = (t || '').trim().toUpperCase(); return u.startsWith('[BLOQUEADO]') || u.startsWith('[DESBLOQUEADO]'); };
const novoId = () => 'obs_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);

// Reconstrói um registro no formato timeline limpo.
function reconstruir(item) {
  const historicoOrig = Array.isArray(item.historico) ? item.historico : [];
  const candidatos = [];
  for (const h of historicoOrig) {
    if (!h) continue;
    const texto = (h.texto || '').trim();
    if (!texto || ehAuditoria(texto) || ehBloqueioTexto(texto)) continue;
    const limpo = limparTexto(texto);
    if (!limpo) continue;
    const ativoLegado = (h.ativo !== undefined) ? !!h.ativo : (h.exibir_alerta !== undefined ? !!h.exibir_alerta : false);
    candidatos.push({ data: h.data || item.atualizado_em || new Date().toISOString(), autor_id: h.autor_id || null, autor_nome: h.autor_nome || null, texto: limpo, ativo: ativoLegado });
  }
  const porTexto = new Map();
  for (const c of candidatos) {
    const k = c.texto.toUpperCase();
    const ex = porTexto.get(k);
    if (!ex) porTexto.set(k, { ...c });
    else { ex.ativo = ex.ativo || c.ativo; if (new Date(c.data) > new Date(ex.data)) { ex.data = c.data; ex.autor_id = c.autor_id; ex.autor_nome = c.autor_nome; } }
  }
  let timeline = Array.from(porTexto.values());
  const obsLimpa = limparTexto(item.observacao);
  if (!timeline.length && obsLimpa) timeline.push({ data: item.atualizado_em || new Date().toISOString(), autor_id: item.atualizado_por || null, autor_nome: null, texto: obsLimpa, ativo: item.alerta_ativo !== false });
  if (timeline.length && !timeline.some((t) => t.ativo) && obsLimpa) { const m = timeline.find((t) => t.texto.toUpperCase() === obsLimpa.toUpperCase()); if (m) m.ativo = true; }
  timeline.sort((a, b) => new Date(b.data) - new Date(a.data));
  timeline = timeline.map((t) => ({ id: novoId(), data: t.data, autor_id: t.autor_id, autor_nome: t.autor_nome, texto: t.texto, ativo: t.ativo, origem: 'migracao' }));
  const ativos = timeline.filter((t) => t.ativo && t.texto).sort((a, b) => new Date(b.data) - new Date(a.data));
  const alertaAtivo = ativos.length ? ativos[0].texto : '';
  return {
    chave: item.chave,
    nome: item.nome,
    documento: item.documento,
    observacao: alertaAtivo || null,
    alerta_ativo: !!alertaAtivo,
    bloqueado: item.bloqueado === true,
    bloqueio_motivo: item.bloqueado === true ? (item.bloqueio_motivo || null) : null,
    bloqueado_por: item.bloqueado === true ? (item.bloqueado_por || null) : null,
    historico: timeline,
    atualizado_em: new Date().toISOString(),
    atualizado_por: item.atualizado_por || null,
  };
}

(async () => {
  // 1) Supabase
  const { data, error } = await supabaseAdmin.from('observacoes_visitantes').select('*');
  if (error) { console.error('Erro ao ler Supabase:', error.message); process.exit(1); }
  console.log(`SUPABASE: ${data.length} registros. Modo: ${APLICAR ? 'APLICAR' : 'DRY-RUN'}`);
  for (const item of data) {
    const novo = reconstruir(item);
    console.log(`  - ${novo.nome} [${novo.chave}]: ${item.historico?.length || 0} -> ${novo.historico.length} itens | alerta=${JSON.stringify((novo.observacao||'').slice(0,40))} | bloq=${novo.bloqueado}`);
    if (APLICAR) {
      const { error: e2 } = await supabaseAdmin.from('observacoes_visitantes').upsert(novo, { onConflict: 'chave' });
      if (e2) console.error(`      ERRO Supabase: ${e2.message}`);
    }
  }

  // 2) Cache local (reconstruído por CHAVE; remove duplicatas por nome, mantém só a chave canônica)
  console.log(`\nCACHE LOCAL: ${CACHE_FILE}`);
  if (fs.existsSync(CACHE_FILE)) {
    const raw = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    const porChave = new Map();
    for (const k of Object.keys(raw)) {
      const it = raw[k];
      if (!it || !it.chave) continue;
      // Usa a reconstrução; dedup por chave canônica (prefere a que tem mais itens).
      const novo = reconstruir(it);
      const ex = porChave.get(novo.chave);
      if (!ex || (novo.historico.length > ex.historico.length)) porChave.set(novo.chave, novo);
    }
    const novoCache = {};
    for (const [chave, novo] of porChave) {
      novoCache[chave] = novo;
      const docLimpo = (novo.documento || '').replace(/\D/g, '');
      if (docLimpo && docLimpo !== chave) novoCache[docLimpo] = novo;
      const nomeNorm = (novo.nome || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      if (nomeNorm) novoCache['nome:' + nomeNorm] = novo;
      console.log(`  - ${novo.nome} [${chave}]: ${novo.historico.length} itens`);
    }
    if (APLICAR) {
      fs.writeFileSync(CACHE_FILE, JSON.stringify(novoCache, null, 2), 'utf8');
      console.log('  cache reescrito.');
    }
  } else {
    console.log('  (arquivo de cache não existe; nada a fazer)');
  }

  console.log(`\n${APLICAR ? 'APLICADO.' : 'DRY-RUN. Rode: node scratch/migrar_timeline.js aplicar'}`);
})();

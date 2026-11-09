// Migra os registros de observacoes_visitantes do modelo ANTIGO (observacao =
// concatenação "• data (autor): texto" + estado no historico) para o NOVO
// (observacao = texto único limpo, alerta_ativo, bloqueado).
//
// POR PADRÃO roda em DRY-RUN (não grava). Para aplicar de verdade:
//   node scratch/migrar_observacoes.js aplicar
//
// ATENÇÃO: mexe no banco de PRODUÇÃO (localhost usa o .env de prod).
require('dotenv').config();
const { supabaseAdmin } = require('../src/supabase');

const APLICAR = process.argv[2] === 'aplicar';

// Extrai o texto "limpo" de uma observação concatenada antiga.
// Formato antigo por linha: "• DD/MM/AAAA HH:MM (AUTOR): TEXTO"
// Pega o TEXTO mais interno (remove prefixos aninhados repetidos).
function extrairTextoLimpo(observacao) {
  let t = (observacao || '').trim();
  if (!t) return '';
  // Se tem várias linhas no formato "• ...: ...", pega a primeira linha (mais recente).
  const linhas = t.split('\n').map((l) => l.trim()).filter(Boolean);
  if (linhas.length && linhas[0].startsWith('•')) {
    t = linhas[0];
  }
  // Remove repetidamente o prefixo "• data (autor): " (inclui aninhamentos).
  // Ex.: "• 09/11, 13:54 (FABIO): 09/11, 13:41 (FABIO): AVISAR..." -> "AVISAR..."
  const prefixo = /^•?\s*\d{1,2}\/\d{1,2}(\/\d{2,4})?,?\s*\d{1,2}:\d{2}\s*\([^)]*\):\s*/;
  let anterior;
  do {
    anterior = t;
    t = t.replace(prefixo, '').trim();
  } while (t !== anterior && t.length);
  return t.trim();
}

(async () => {
  const { data, error } = await supabaseAdmin.from('observacoes_visitantes').select('*');
  if (error) { console.error('Erro ao ler:', error.message); process.exit(1); }
  console.log(`${data.length} registros. Modo: ${APLICAR ? 'APLICAR' : 'DRY-RUN'}\n`);

  let mudados = 0;
  for (const item of data) {
    const historico = Array.isArray(item.historico) ? item.historico : [];
    const textoLimpo = extrairTextoLimpo(item.observacao);

    // Deriva alerta_ativo: se tinha texto e algum item ativo no legado.
    const algumAtivo = historico.some((h) => h && h.exibir_alerta && (h.texto || '').trim());
    const alertaAtivo = (item.alerta_ativo !== undefined && item.alerta_ativo !== null)
      ? item.alerta_ativo
      : (!!textoLimpo && (algumAtivo || true));

    // Deriva bloqueado.
    let bloqueado = (item.bloqueado === true);
    let motivo = item.bloqueio_motivo || null;
    let por = item.bloqueado_por || null;
    if (item.bloqueado === undefined || item.bloqueado === null) {
      const bloq = historico.find((h) => h && h.exibir_alerta && (h.texto || '').trim().toUpperCase().startsWith('[BLOQUEADO]'));
      if (bloq) {
        bloqueado = true;
        const tt = (bloq.texto || '').trim();
        const mMot = tt.match(/motivo:\s*(.+)$/i);
        const mPor = tt.match(/solicitado por\s*([^.]+)\./i);
        motivo = mMot ? mMot[1].trim() : tt.replace(/^\[bloqueado\]\s*/i, '');
        por = mPor ? mPor[1].trim() : (bloq.autor_nome || null);
      }
    }

    const precisaMudar =
      (item.observacao || '') !== (textoLimpo || '') ||
      item.alerta_ativo !== alertaAtivo ||
      item.bloqueado !== bloqueado;

    if (!precisaMudar) continue;
    mudados++;
    console.log(`- ${item.nome} [${item.chave}]`);
    console.log(`    obs: ${JSON.stringify(item.observacao)} -> ${JSON.stringify(textoLimpo)}`);
    console.log(`    alerta_ativo: ${item.alerta_ativo} -> ${alertaAtivo} | bloqueado: ${item.bloqueado} -> ${bloqueado}`);

    if (APLICAR) {
      const payload = {
        chave: item.chave,
        nome: item.nome,
        documento: item.documento,
        observacao: textoLimpo || null,
        alerta_ativo: alertaAtivo,
        bloqueado,
        bloqueio_motivo: bloqueado ? motivo : null,
        bloqueado_por: bloqueado ? por : null,
        atualizado_em: new Date().toISOString(),
        atualizado_por: item.atualizado_por || null,
        historico, // preserva auditoria
      };
      const { error: e2 } = await supabaseAdmin.from('observacoes_visitantes').upsert(payload, { onConflict: 'chave' });
      if (e2) console.error(`    ERRO ao gravar: ${e2.message}`);
    }
  }

  console.log(`\n${mudados} registro(s) ${APLICAR ? 'atualizados' : 'seriam atualizados'}.`);
  if (!APLICAR) console.log('Rode com "aplicar" para gravar: node scratch/migrar_observacoes.js aplicar');
})();

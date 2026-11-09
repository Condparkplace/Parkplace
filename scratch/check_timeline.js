require('dotenv').config();
const { supabaseAdmin } = require('../src/supabase');

(async () => {
  const { data, error } = await supabaseAdmin
    .from('observacoes_visitantes')
    .select('chave, nome, observacao, alerta_ativo, historico');
  if (error) { console.error(error.message); process.exit(1); }
  for (const r of data) {
    const h = Array.isArray(r.historico) ? r.historico : [];
    console.log(`\n[${r.chave}] ${r.nome}`);
    console.log(`  observacao: ${JSON.stringify(r.observacao)}`);
    console.log(`  alerta_ativo: ${r.alerta_ativo} | historico itens: ${h.length}`);
    h.forEach((it, i) => console.log(`    #${i} id=${it.id} ativo=${it.ativo} exibir_alerta=${it.exibir_alerta} origem=${it.origem} texto=${JSON.stringify((it.texto||'').slice(0,45))}`));
  }
})();

require('dotenv').config();
const { supabaseAdmin } = require('../src/supabase');

(async () => {
  const { data, error } = await supabaseAdmin
    .from('observacoes_visitantes')
    .select('chave, observacao, alerta_ativo, bloqueado, bloqueio_motivo, bloqueado_por')
    .limit(1);
  if (error) {
    console.log('FALTAM_COLUNAS');
    console.log(error.message);
  } else {
    console.log('COLUNAS_OK');
    console.log(JSON.stringify(data, null, 2));
  }
})();

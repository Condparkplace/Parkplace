// Define ativo do único item do IRAILDO. Uso: node scratch/set_ativo.js true|false
require('dotenv').config();
const { supabaseAdmin } = require('../src/supabase');
const CHAVE = '90107594404';
const ATIVO = process.argv[2] === 'true';

(async () => {
  const { data: reg } = await supabaseAdmin.from('observacoes_visitantes').select('*').eq('chave', CHAVE).single();
  const historico = (reg.historico||[]).map(h => ({...h, ativo: ATIVO}));
  const alerta = ATIVO ? (historico[0]?.texto || null) : null;
  await supabaseAdmin.from('observacoes_visitantes').upsert({ ...reg, historico, observacao: alerta, alerta_ativo: ATIVO, atualizado_em:new Date().toISOString() }, { onConflict:'chave' });
  console.log(`IRAILDO -> ativo=${ATIVO}, observacao=${JSON.stringify(alerta)}`);
})();

// Padroniza perfis.telefone para o formato (11) 9 9999-9999 / (11) 3333-4444.
// DRY-RUN por padrão. Para gravar: node scratch/padronizar_telefones.js aplicar
// Só altera quando o número tem 10/11 dígitos (com ou sem +55). Números que não dá
// para padronizar com segurança (ex.: sem DDD) NÃO são alterados e são listados.
require('dotenv').config();
const { supabaseAdmin } = require('../src/supabase');
const { formatarTelefone, telefoneJaPadronizado } = require('../src/telefone');
const APLICAR = process.argv[2] === 'aplicar';

(async () => {
  const { data, error } = await supabaseAdmin.from('perfis').select('id, nome, telefone');
  if (error) { console.error('Erro ao ler:', error.message); process.exit(1); }

  const mudar = [], jaOk = [], semTel = [], naoPadronizaveis = [];
  for (const p of data) {
    const atual = (p.telefone || '').trim();
    if (!atual) { semTel.push(p); continue; }
    if (telefoneJaPadronizado(atual)) { jaOk.push(p); continue; }
    const novo = formatarTelefone(atual);
    if (telefoneJaPadronizado(novo)) mudar.push({ ...p, novo });
    else naoPadronizaveis.push(p);
  }

  console.log(`Modo: ${APLICAR ? 'APLICAR' : 'DRY-RUN'} | perfis: ${data.length}`);
  console.log(`  já no padrão: ${jaOk.length} | a padronizar: ${mudar.length} | sem telefone: ${semTel.length} | não padronizáveis: ${naoPadronizaveis.length}\n`);

  mudar.forEach((p) => console.log(`  ${p.nome.padEnd(36)} ${String(p.telefone).padEnd(20)} -> ${p.novo}`));

  if (naoPadronizaveis.length) {
    console.log('\nNÃO alterados (precisam de conferência manual):');
    naoPadronizaveis.forEach((p) => console.log(`  ${p.nome.padEnd(36)} "${p.telefone}"  (${p.telefone.replace(/\D/g, '').length} dígitos)`));
  }

  if (APLICAR) {
    let ok = 0, falhas = 0;
    for (const p of mudar) {
      const { error: e } = await supabaseAdmin.from('perfis').update({ telefone: p.novo }).eq('id', p.id);
      if (e) { falhas++; console.error(`  ERRO ${p.nome}: ${e.message}`); } else ok++;
    }
    console.log(`\nGravado: ${ok} | falhas: ${falhas}`);
  } else {
    console.log('\nDRY-RUN: nada foi gravado. Para aplicar: node scratch/padronizar_telefones.js aplicar');
  }
})();

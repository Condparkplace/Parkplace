// Lista os telefones gravados hoje (somente leitura) para planejar a padronização.
require('dotenv').config();
const { supabaseAdmin } = require('../src/supabase');

(async () => {
  const { data, error } = await supabaseAdmin.from('perfis').select('id, nome, tipo, telefone');
  if (error) { console.error(error.message); process.exit(1); }
  const comTel = data.filter((p) => p.telefone && p.telefone.trim());
  console.log(`perfis: ${data.length} | com telefone: ${comTel.length} | sem telefone: ${data.length - comTel.length}\n`);
  const padroes = {};
  for (const p of comTel) {
    const dig = p.telefone.replace(/\D/g, '');
    const molde = p.telefone.replace(/\d/g, '9');
    const chave = `${molde}  (${dig.length} dígitos)`;
    (padroes[chave] = padroes[chave] || []).push(p.nome);
  }
  Object.entries(padroes).sort((a, b) => b[1].length - a[1].length).forEach(([k, v]) => {
    console.log(`${String(v.length).padStart(3)}x  ${k}   ex: ${v.slice(0, 2).join(', ')}`);
  });
})();

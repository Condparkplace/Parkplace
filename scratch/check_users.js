require('dotenv').config();
const { supabaseAdmin } = require('../src/supabase');

async function test() {
  const { data, error } = await supabaseAdmin.from('perfis').select('*');
  console.log('Perfis count:', data?.length);
  if (data) {
    data.forEach(p => console.log({ id: p.id, nome: p.nome, tipo: p.tipo, bloco: p.bloco }));
  }
  if (error) console.error('Error:', error);
}
test();

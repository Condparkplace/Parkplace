require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

async function main() {
  console.log('Buscando usuario Fabio Camargo...');
  const { data, error } = await supabase
    .from('perfis')
    .select('*')
    .ilike('nome', '%Fabio Camargo%');
    
  if (error) {
    console.error('Erro ao buscar:', error);
    return;
  }
  
  if (!data || data.length === 0) {
    console.log('Usuario nao encontrado.');
    return;
  }
  
  const usuario = data[0];
  console.log(`Encontrado: ${usuario.nome} (ID: ${usuario.id})`);
  
  console.log('Atualizando tipo para admin...');
  const { error: updateError } = await supabase
    .from('perfis')
    .update({ tipo: 'admin' })
    .eq('id', usuario.id);
    
  if (updateError) {
    console.error('Erro ao atualizar:', updateError);
  } else {
    console.log('Usuario atualizado com sucesso para Administrador!');
  }
}

main();

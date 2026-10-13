require('dotenv').config();
const { supabaseAdmin } = require('../src/supabase');

async function test() {
  const { data: perfis } = await supabaseAdmin.from('perfis').select('*').limit(1);
  if (!perfis || !perfis.length) {
    console.log('No profiles');
    return;
  }
  const id = perfis[0].id;
  const { data: userAuth, error } = await supabaseAdmin.auth.admin.getUserById(id);
  console.log('User auth email:', userAuth?.user?.email, 'Error:', error);
}
test();

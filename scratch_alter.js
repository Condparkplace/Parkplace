const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_KEY;

const supabase = createClient(url, key);

async function run() {
  const { data, error } = await supabase.rpc('exec_sql', {
    query: "ALTER TABLE public.perfis ADD COLUMN IF NOT EXISTS push_subscription JSONB;"
  });
  
  if (error) {
    console.error('RPC failed, trying raw query if possible or we might not have a way to alter table easily via JS API without direct postgres connection.', error);
  } else {
    console.log('Success:', data);
  }
}
run();

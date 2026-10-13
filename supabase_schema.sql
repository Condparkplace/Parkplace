-- ============================================================
-- Park Place Residencial - Esquema do banco (Supabase/Postgres)
-- Execute este script no SQL Editor do Supabase.
-- ============================================================

-- ------------------------------------------------------------
-- 1) Tipos
-- ------------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_type where typname = 'tipo_perfil') then
    create type tipo_perfil as enum ('admin', 'porteiro', 'morador');
  end if;
  if not exists (select 1 from pg_type where typname = 'tipo_acesso') then
    create type tipo_acesso as enum ('Morador', 'Visitante', 'Prestador', 'Entregador', 'Outro');
  end if;
  if not exists (select 1 from pg_type where typname = 'status_visita') then
    create type status_visita as enum ('Pendente', 'Autorizada', 'Entrada Realizada', 'Finalizada', 'Cancelada', 'Nao compareceu');
  end if;
end$$;

-- Migracao: garante o valor 'Nao compareceu' caso o enum ja exista.
alter type status_visita add value if not exists 'Nao compareceu';

-- Migracao: garante o valor 'Morador' no tipo de acesso.
alter type tipo_acesso add value if not exists 'Morador';

-- ------------------------------------------------------------
-- 2) Tabela de perfis (liga auth.users ao tipo de usuario)
-- ------------------------------------------------------------
create table if not exists public.perfis (
  id          uuid primary key references auth.users(id) on delete cascade,
  nome        text not null,
  tipo        tipo_perfil not null default 'morador',
  bloco       text,
  apartamento text,
  telefone    text,
  ativo       boolean not null default true,
  aprovado    boolean not null default true,
  criado_em   timestamptz not null default now()
);

-- Migracao: cadastro de morador via link precisa de aprovacao do admin.
alter table public.perfis add column if not exists aprovado boolean not null default true;

-- Migracao: CPF do morador (somente numeros, unico).
alter table public.perfis add column if not exists cpf text;
create unique index if not exists idx_perfis_cpf on public.perfis(cpf) where cpf is not null;

-- ------------------------------------------------------------
-- 3) Avisos de visita (morador avisa a portaria)
-- ------------------------------------------------------------
create table if not exists public.avisos_visitas (
  id                  bigint generated always as identity primary key,
  morador_id          uuid not null references public.perfis(id) on delete cascade,
  nome_visitante      text not null,
  documento_visitante text,
  veiculo_placa       text,
  tipo                tipo_acesso not null default 'Visitante',
  data_prevista       timestamptz,
  endereco_visitante  text,
  cep_visitante       text,
  observacao          text,
  status              status_visita not null default 'Pendente',
  criado_em           timestamptz not null default now()
);

-- Migracao: adiciona colunas de endereco caso a tabela ja exista.
alter table public.avisos_visitas add column if not exists endereco_visitante text;
alter table public.avisos_visitas add column if not exists cep_visitante text;

-- ------------------------------------------------------------
-- 4) Registros de portaria (log real de entrada/saida)
-- ------------------------------------------------------------
create table if not exists public.registros_portaria (
  id             bigint generated always as identity primary key,
  aviso_id       bigint references public.avisos_visitas(id) on delete set null,
  nome_pessoa    text not null,
  documento      text,
  tipo           tipo_acesso not null default 'Visitante',
  destino_bloco  text,
  destino_apto   text,
  veiculo_placa  text,
  endereco_visitante text,
  cep_visitante  text,
  entrada        timestamptz not null default now(),
  saida          timestamptz,
  registrado_por uuid references public.perfis(id),
  observacao     text
);

-- Migracao: porteiro responsavel por cada acao.
--   registrado_por = quem deu a ENTRADA (ja existia)
--   saida_por      = quem registrou a SAIDA
--   nao_veio_por   = quem marcou o aviso como "Nao compareceu"
alter table public.registros_portaria add column if not exists saida_por uuid references public.perfis(id) on delete set null;
alter table public.avisos_visitas add column if not exists nao_veio_por uuid references public.perfis(id) on delete set null;

create index if not exists idx_avisos_morador on public.avisos_visitas(morador_id);
create index if not exists idx_avisos_status on public.avisos_visitas(status);
create index if not exists idx_registros_saida on public.registros_portaria(saida);

-- ------------------------------------------------------------
-- 5) Funcao auxiliar: retorna o tipo do usuario logado
-- ------------------------------------------------------------
create or replace function public.meu_tipo()
returns tipo_perfil
language sql
security definer
set search_path = public
as $$
  select tipo from public.perfis where id = auth.uid();
$$;

-- ------------------------------------------------------------
-- 6) Row Level Security
-- ------------------------------------------------------------
alter table public.perfis enable row level security;
alter table public.avisos_visitas enable row level security;
alter table public.registros_portaria enable row level security;

-- ---------- PERFIS ----------
drop policy if exists perfis_self_select on public.perfis;
create policy perfis_self_select on public.perfis
  for select using (
    id = auth.uid()
    or public.meu_tipo() in ('admin', 'porteiro')
  );

drop policy if exists perfis_self_update on public.perfis;
create policy perfis_self_update on public.perfis
  for update using (id = auth.uid() or public.meu_tipo() = 'admin');

drop policy if exists perfis_admin_all on public.perfis;
create policy perfis_admin_all on public.perfis
  for all using (public.meu_tipo() = 'admin')
  with check (public.meu_tipo() = 'admin');

-- ---------- AVISOS DE VISITA ----------
-- Morador enxerga/gerencia apenas os proprios avisos;
-- porteiro e admin enxergam todos.
drop policy if exists avisos_select on public.avisos_visitas;
create policy avisos_select on public.avisos_visitas
  for select using (
    morador_id = auth.uid()
    or public.meu_tipo() in ('admin', 'porteiro')
  );

drop policy if exists avisos_insert on public.avisos_visitas;
create policy avisos_insert on public.avisos_visitas
  for insert with check (morador_id = auth.uid());

drop policy if exists avisos_update on public.avisos_visitas;
create policy avisos_update on public.avisos_visitas
  for update using (
    morador_id = auth.uid()
    or public.meu_tipo() in ('admin', 'porteiro')
  );

drop policy if exists avisos_delete on public.avisos_visitas;
create policy avisos_delete on public.avisos_visitas
  for delete using (
    morador_id = auth.uid()
    or public.meu_tipo() = 'admin'
  );

-- ---------- REGISTROS DE PORTARIA ----------
-- Somente porteiro e admin manipulam o log da portaria.
drop policy if exists registros_rw on public.registros_portaria;
create policy registros_rw on public.registros_portaria
  for all using (public.meu_tipo() in ('admin', 'porteiro'))
  with check (public.meu_tipo() in ('admin', 'porteiro'));

-- ------------------------------------------------------------
-- 7) Trigger: cria perfil automaticamente ao criar usuario
--    (le os metadados enviados no cadastro)
-- ------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.perfis (id, nome, tipo, bloco, apartamento, telefone, ativo, aprovado)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'nome', new.email),
    coalesce((new.raw_user_meta_data->>'tipo')::tipo_perfil, 'morador'),
    new.raw_user_meta_data->>'bloco',
    new.raw_user_meta_data->>'apartamento',
    new.raw_user_meta_data->>'telefone',
    coalesce((new.raw_user_meta_data->>'pendente')::boolean, false) = false,
    coalesce((new.raw_user_meta_data->>'pendente')::boolean, false) = false
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ============================================================
-- Dica: crie o PRIMEIRO admin manualmente.
-- 1. Crie o usuario em Authentication > Users (Add user).
-- 2. Rode (troque o email):
--    update public.perfis set tipo = 'admin'
--    where id = (select id from auth.users where email = 'admin@parkplace.com');
-- ============================================================

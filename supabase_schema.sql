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

-- Migracao: permissao do morador para ver as visitas de TODOS os moradores do
-- mesmo lote (liberada pelo admin). Padrao: false (so ve as proprias).
alter table public.perfis add column if not exists ver_lote boolean not null default false;

-- Migracao: endereco do morador (preenchido por busca de CEP / ViaCEP).
alter table public.perfis add column if not exists cep text;
alter table public.perfis add column if not exists endereco_logradouro text;
alter table public.perfis add column if not exists endereco_numero text;
alter table public.perfis add column if not exists endereco_bairro text;
alter table public.perfis add column if not exists endereco_cidade text;
alter table public.perfis add column if not exists endereco_uf text;
alter table public.perfis add column if not exists endereco_complemento text;

-- Migracao: inscricao de Web Push (VAPID) do morador. Guarda o objeto de
-- subscription do navegador (endpoint + chaves) como JSONB. Necessaria para
-- as notificacoes push funcionarem (/api/push/subscribe e notificarLote).
alter table public.perfis add column if not exists push_subscription jsonb;

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
  destino_morador uuid references public.perfis(id) on delete set null, -- morador específico destinatário
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

-- Migracao: morador especifico destinatario de uma entrada/encomenda (quando o
-- porteiro seleciona o morador no modal). Permite que cada morador veja apenas
-- os registros direcionados a ele, em vez de todos do mesmo lote.
alter table public.registros_portaria add column if not exists destino_morador uuid references public.perfis(id) on delete set null;

create index if not exists idx_avisos_morador on public.avisos_visitas(morador_id);
create index if not exists idx_avisos_status on public.avisos_visitas(status);
create index if not exists idx_registros_saida on public.registros_portaria(saida);
create index if not exists idx_registros_destino_morador on public.registros_portaria(destino_morador);

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

-- ------------------------------------------------------------
-- 7) Observações cadastrais de visitantes e prestadores
-- ------------------------------------------------------------
create table if not exists public.observacoes_visitantes (
  chave          text primary key, -- CPF limpo ou 'nome:...'
  nome           text not null,
  documento      text,
  observacao     text,
  historico      jsonb not null default '[]'::jsonb, -- histórico de observações/bloqueios
  atualizado_em  timestamptz not null default now(),
  atualizado_por uuid references public.perfis(id) on delete set null
);

-- Migracao: garante a coluna historico (JSON) caso a tabela ja exista sem ela.
-- Essencial para persistir bloqueios e observações em produção (Cloudflare
-- Workers tem filesystem efêmero/somente leitura; o Supabase é a fonte real).
alter table public.observacoes_visitantes add column if not exists historico jsonb not null default '[]'::jsonb;

alter table public.observacoes_visitantes enable row level security;

drop policy if exists observacoes_visitantes_all on public.observacoes_visitantes;
create policy observacoes_visitantes_all on public.observacoes_visitantes
  for all using (public.meu_tipo() in ('admin', 'porteiro'))
  with check (public.meu_tipo() in ('admin', 'porteiro'));


-- ------------------------------------------------------------
-- 8) Notificações do admin para moradores
-- ------------------------------------------------------------
-- O admin envia uma notificação a um morador (título, texto e validade em dias).
-- Ao fazer login, o morador vê um aviso que trava a tela até confirmar
-- ("Recebi a notificação"); a confirmação grava a data/hora em visualizado_em.
-- Depois de confirmada, aparece como card até expira_em.
create table if not exists public.notificacoes_morador (
  id            bigint generated always as identity primary key,
  morador_id    uuid not null references public.perfis(id) on delete cascade,
  titulo        text not null,
  texto         text not null,
  dias          integer not null default 7,
  visualizado_em timestamptz,            -- quando o morador confirmou o recebimento
  expira_em     timestamptz not null,    -- até quando a notificação fica visível
  criado_por    uuid references public.perfis(id) on delete set null,
  criado_em     timestamptz not null default now()
);

create index if not exists idx_notif_morador on public.notificacoes_morador(morador_id);
create index if not exists idx_notif_expira on public.notificacoes_morador(expira_em);

alter table public.notificacoes_morador enable row level security;

-- Morador vê/atualiza (confirmar leitura) apenas as próprias; admin gerencia todas.
drop policy if exists notif_morador_select on public.notificacoes_morador;
create policy notif_morador_select on public.notificacoes_morador
  for select using (morador_id = auth.uid() or public.meu_tipo() = 'admin');

drop policy if exists notif_morador_update on public.notificacoes_morador;
create policy notif_morador_update on public.notificacoes_morador
  for update using (morador_id = auth.uid() or public.meu_tipo() = 'admin');

drop policy if exists notif_morador_admin_all on public.notificacoes_morador;
create policy notif_morador_admin_all on public.notificacoes_morador
  for all using (public.meu_tipo() = 'admin')
  with check (public.meu_tipo() = 'admin');

-- ------------------------------------------------------------
-- 9) Visitas recorrentes (frequência semanal)
-- ------------------------------------------------------------
-- O morador programa um visitante/prestador para dias fixos da semana.
-- A lista da portaria calcula dinamicamente: se hoje é um dos dias marcados,
-- a pessoa aparece como "visita avisada" (recorrente), sem precisar aviso manual.
-- dias_semana: array de inteiros 0=Domingo ... 6=Sábado (padrão JS getDay()).
create table if not exists public.visitas_recorrentes (
  id             bigint generated always as identity primary key,
  morador_id     uuid not null references public.perfis(id) on delete cascade,
  nome_visitante text not null,
  documento_visitante text,
  tipo           tipo_acesso not null default 'Visitante',
  veiculo_placa  text,
  dias_semana    integer[] not null default '{}',
  ativo          boolean not null default true,
  criado_em      timestamptz not null default now()
);

create index if not exists idx_recorrentes_morador on public.visitas_recorrentes(morador_id);
create index if not exists idx_recorrentes_ativo on public.visitas_recorrentes(ativo);

alter table public.visitas_recorrentes enable row level security;

-- Morador gerencia as próprias; porteiro e admin podem ler todas.
drop policy if exists recorrentes_select on public.visitas_recorrentes;
create policy recorrentes_select on public.visitas_recorrentes
  for select using (morador_id = auth.uid() or public.meu_tipo() in ('admin', 'porteiro'));

drop policy if exists recorrentes_insert on public.visitas_recorrentes;
create policy recorrentes_insert on public.visitas_recorrentes
  for insert with check (morador_id = auth.uid() or public.meu_tipo() = 'admin');

drop policy if exists recorrentes_update on public.visitas_recorrentes;
create policy recorrentes_update on public.visitas_recorrentes
  for update using (morador_id = auth.uid() or public.meu_tipo() = 'admin');

drop policy if exists recorrentes_delete on public.visitas_recorrentes;
create policy recorrentes_delete on public.visitas_recorrentes
  for delete using (morador_id = auth.uid() or public.meu_tipo() = 'admin');

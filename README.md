# Park Place Residencial — Sistema de Controle de Portaria

Site de controle de portaria com três perfis de acesso (login e senha):

- **Administrador** — cadastra porteiros e moradores, ativa/desativa e remove usuários, vê o resumo do condomínio.
- **Porteiro** — vê visitas avisadas pelos moradores, registra entradas e saídas, acompanha quem está no condomínio e consulta o histórico.
- **Morador** — avisa a portaria sobre visitas esperadas e acompanha o status de cada uma.

Stack: **Node.js + Express** no backend, **Supabase (PostgreSQL + Auth)** para banco de dados, autenticação e segurança por linha (RLS). Frontend em HTML/CSS/JS puro.

---

## 1. Pré-requisitos

- [Node.js](https://nodejs.org/) 18 ou superior
- Uma conta gratuita no [Supabase](https://supabase.com/)

## 2. Criar o projeto no Supabase

1. Acesse o painel do Supabase e crie um novo projeto.
2. No menu lateral, abra **SQL Editor** e cole todo o conteúdo do arquivo [`supabase_schema.sql`](./supabase_schema.sql). Clique em **Run**. Isso cria as tabelas (`perfis`, `avisos_visitas`, `registros_portaria`), as políticas de segurança (RLS) e o gatilho que cria o perfil automaticamente.
3. Em **Settings > API**, copie:
   - **Project URL**
   - **anon public** key
   - **service_role** key (secreta — fica só no servidor)

## 3. Configurar o backend

Na pasta do projeto:

```powershell
npm install
Copy-Item .env.example .env
```

Edite o arquivo `.env` e preencha com os valores do Supabase:

```
SUPABASE_URL=https://SEU-PROJETO.supabase.co
SUPABASE_ANON_KEY=sua-anon-key
SUPABASE_SERVICE_ROLE_KEY=sua-service-role-key
PORT=3000
SESSION_SECRET=um-texto-aleatorio-bem-longo

# Push Notifications (gere com: npx web-push generate-vapid-keys)
VAPID_PUBLIC_KEY=sua-chave-publica-vapid
VAPID_PRIVATE_KEY=sua-chave-privada-vapid
VAPID_SUBJECT=mailto:contato@parkplace.com
```

> As chaves VAPID são opcionais no desenvolvimento local (há um fallback embutido só para testes). Em produção, **gere e configure as suas** com `npx web-push generate-vapid-keys`.

## 4. Criar o primeiro administrador

Como todo cadastro é feito pelo admin, crie o primeiro manualmente:

1. No Supabase, vá em **Authentication > Users > Add user**. Informe e-mail e senha e confirme.
2. No **SQL Editor**, rode (trocando o e-mail):

```sql
update public.perfis set tipo = 'admin'
where id = (select id from auth.users where email = 'admin@parkplace.com');
```

> Dica: se o perfil ainda não existir, rode primeiro o `INSERT` abaixo e depois o `UPDATE`:
> ```sql
> insert into public.perfis (id, nome, tipo)
> select id, 'Administrador', 'admin' from auth.users where email = 'admin@parkplace.com'
> on conflict (id) do update set tipo = 'admin';
> ```

## 5. Rodar o site

```powershell
npm start
```

Acesse **http://localhost:3000** e faça login com o administrador. A partir daí, cadastre porteiros e moradores pela própria tela de administração.

## 6. Deploy no Cloudflare Workers

O projeto roda como um **Cloudflare Worker** (Express via `cloudflare:node`) servindo os arquivos estáticos de `public/` pelo binding de Assets. A configuração está em [`wrangler.jsonc`](./wrangler.jsonc) (`main: worker.js`).

1. Faça login na sua conta do Cloudflare:
```bash
npx wrangler login
```
2. Faça o deploy:
```bash
npm run deploy
```
3. Configure as variáveis/segredos. Como são valores sensíveis, use **secrets** (não ficam no código):
```bash
npx wrangler secret put SUPABASE_URL
npx wrangler secret put SUPABASE_ANON_KEY
npx wrangler secret put SUPABASE_SERVICE_ROLE_KEY
npx wrangler secret put SESSION_SECRET
npx wrangler secret put VAPID_PUBLIC_KEY
npx wrangler secret put VAPID_PRIVATE_KEY
npx wrangler secret put VAPID_SUBJECT
```
   Alternativamente, defina-os pelo painel: **Workers & Pages > seu Worker > Settings > Variables and Secrets**.

> **Persistência (importante):** o Worker tem filesystem efêmero/somente leitura. Toda a persistência de dados — inclusive observações e **bloqueios de visitantes** — é feita no **Supabase**. Por isso é obrigatório ter rodado o `supabase_schema.sql` atualizado (que inclui a tabela `observacoes_visitantes` com a coluna `historico`). Sem essa coluna, os bloqueios não persistem em produção.

---

## Fluxo de uso


1. **Admin** cadastra os porteiros e moradores (cada um recebe e-mail e senha).
2. **Morador** entra, vai em "Avisar a portaria" e registra a visita esperada.
3. **Porteiro** vê a visita na aba "Visitas previstas", clica em "Registrar entrada" (os dados já vêm preenchidos) e confirma.
4. Quando a pessoa sai, o porteiro clica em "Registrar saída" na aba "No condomínio".
5. Tudo fica no **Histórico**, com filtro por período.

## Estrutura dos arquivos

```
Parkplace/
├── server.js              # Servidor Express + rotas da API
├── worker.js              # Entrada do Cloudflare Worker (roda o Express)
├── wrangler.jsonc         # Configuração de deploy (Workers + Assets)
├── supabase_schema.sql    # Script do banco (rodar no Supabase)
├── .env.example           # Modelo de variáveis de ambiente
├── src/
│   ├── supabase.js        # Clientes Supabase (admin, anon, por-token)
│   └── auth.js            # Sessão por cookie e middlewares de acesso
└── public/
    ├── index.html         # Login único / landing
    ├── cadastro.html      # Cadastro público de morador
    ├── cadastro-visita.html # Cadastro de visita/prestador (link com validade de 2h)
    ├── morador.html       # Painel do morador
    ├── porteiro.html      # Painel da portaria
    ├── admin.html         # Painel administrativo
    ├── css/style.css      # Estilos (desktop + mobile)
    ├── js/api.js          # Helpers de API/sessão do frontend
    └── sw.js              # Service worker (push notifications)
```

## Segurança

- As senhas são gerenciadas pelo **Supabase Auth** (hash + salt), nunca ficam no banco em texto puro.
- O **RLS** garante no banco que o morador só vê os próprios avisos e que apenas porteiro/admin acessam o log da portaria.
- A `service_role` key fica apenas no servidor (nunca é enviada ao navegador).
- A sessão do usuário trafega em um cookie `httpOnly`.

## Próximos passos sugeridos

- Notificar o morador por WhatsApp/Telegram quando a visita chegar.
- Leitura de QR Code / documento para agilizar o cadastro na portaria.
- Exportar o histórico em PDF/Excel.

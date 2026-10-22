# Guia: ativar notificações por WhatsApp (Park Place)

Este guia te leva do zero até o aviso de WhatsApp funcionando quando o porteiro
registra uma entrada. A parte de código já está pronta no sistema; aqui é só a
parte que precisa ser feita no painel da Meta (login humano) e o preenchimento
do `.env`.

> Regra importante: o aviso é "iniciado pelo sistema", então a Meta exige um
> **template aprovado** da categoria **utility**. Sem o template aprovado, o
> envio não funciona fora da janela de 24h.

---

## Passo 1 — Criar o App no Meta for Developers

1. Acesse https://developers.facebook.com/ e faça login (ou crie a conta).
2. Em **My Apps > Create App**. Escolha o tipo **Business**.
3. Dê um nome (ex.: "Park Place Portaria") e crie.
4. No painel do App, em **Add products**, adicione **WhatsApp**.

## Passo 2 — Pegar as credenciais (modo de teste, grátis)

1. No menu lateral: **WhatsApp > API Setup**.
2. A Meta já cria um **número de teste** e um **token temporário** (24h).
   - Copie o **Temporary access token** → vai em `WHATSAPP_TOKEN`.
   - Copie o **Phone number ID** → vai em `WHATSAPP_PHONE_NUMBER_ID`.
3. Em **"To"**, adicione o(s) número(s) de celular que vão **receber** os testes
   (no modo de teste só esses números autorizados recebem). Você vai confirmar
   um código enviado por WhatsApp para cada número.

> O token temporário expira em 24h. Serve para testar. Para produção, gere um
> token permanente com um **System User** (Passo 6).

## Passo 3 — Criar o template utility (homologação)

1. Acesse o **WhatsApp Manager**: https://business.facebook.com/wa/manage/
   (ou pelo painel do App em **WhatsApp > Message Templates**).
2. **Create template**:
   - **Category:** Utility
   - **Name:** `aviso_entrada_portaria`  (tem que bater com `WHATSAPP_TEMPLATE_ENTRADA`)
   - **Language:** Portuguese (BR) — `pt_BR`
3. No **corpo (Body)**, cole exatamente este texto (com as 3 variáveis):

   ```
   {{1}} chegou na portaria do Park Place.
   Destino: {{2}}.
   Horário: {{3}}.
   ```

4. Em **Body – Sample content** (exemplos pedidos para aprovação), preencha:
   - `{{1}}` → `🛎️ Visitante JOÃO SILVA`
   - `{{2}}` → `Lote 12`
   - `{{3}}` → `13/10 às 14:32`
5. Envie para revisão. A aprovação costuma sair em minutos a algumas horas.
   O status precisa ficar **Approved**.

> A ordem das variáveis é obrigatória: {{1}} = o que chegou, {{2}} = destino,
> {{3}} = horário. O código envia nessa ordem.

## Passo 4 — Preencher o `.env`

No arquivo `.env` do projeto, ajuste:

```
WHATSAPP_ATIVO=true
WHATSAPP_TOKEN=<token copiado no Passo 2>
WHATSAPP_PHONE_NUMBER_ID=<phone number id do Passo 2>
WHATSAPP_TEMPLATE_ENTRADA=aviso_entrada_portaria
WHATSAPP_TEMPLATE_LANG=pt_BR
WHATSAPP_API_VERSION=v21.0
```

## Passo 5 — Testar o envio (sem mexer na portaria)

Com o template **aprovado** e o `.env` preenchido, rode (PowerShell):

```
node scratch/test_whatsapp.js 5511999999999
```

Troque pelo número que você autorizou no Passo 2. Você deve **receber a
mensagem no WhatsApp**. O script imprime o ID da mensagem em caso de sucesso,
ou o motivo do erro.

Depois disso, qualquer entrada registrada pelo porteiro para um morador que
tenha telefone cadastrado já dispara o aviso automaticamente.

## Passo 6 — Produção (quando for pra valer)

1. **Token permanente:** em **Business Settings > Users > System Users**, crie um
   System User, gere um token com as permissões `whatsapp_business_messaging` e
   `whatsapp_business_management`. Use esse token no lugar do temporário.
2. **Número oficial:** registre o número real da portaria (em vez do número de
   teste) e verifique o negócio para liberar limites maiores.
3. **Secrets no Cloudflare:** NÃO comite o token. Configure como secret:
   ```
   npx wrangler secret put WHATSAPP_TOKEN
   npx wrangler secret put WHATSAPP_PHONE_NUMBER_ID
   ```
   E deixe `WHATSAPP_ATIVO`, `WHATSAPP_TEMPLATE_ENTRADA`, `WHATSAPP_TEMPLATE_LANG`
   como variáveis no `wrangler.jsonc`/painel.

---

## Como funciona por dentro (resumo técnico)

- Módulo: `src/whatsapp.js` (envio via Meta Cloud API, no-op se desativado).
- Gatilho: dentro de `POST /api/portaria/entrada`, após gravar o registro, chama
  `notificarWhatsappEntrada(registro)` em "dispara e esquece" (nunca bloqueia nem
  derruba o registro se o WhatsApp falhar).
- Quem recebe:
  - se o porteiro selecionou um morador (`destino_morador`) → só ele;
  - senão, todos os moradores do lote (`destino_bloco`) com telefone.
- Tipos de aviso: 📦 Encomenda, 🛵 Entregador (iFood), 🛎️ Visitante/Prestador.
- Entrada do próprio morador **não** gera aviso.

## Custos (resumo)

- Modo de teste: grátis (números autorizados).
- Produção: cada aviso é um template **utility** (categoria mais barata). O tier
  grátis de 1.000/mês da Meta é para mensagens de *serviço* dentro da janela de
  24h — o nosso aviso é business-initiated, então é cobrado por mensagem (fração
  de centavo). Para poucos envios o custo é mínimo.
- Confirme valores atuais em https://developers.facebook.com/docs/whatsapp/pricing/

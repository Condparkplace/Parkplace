// ============================================================
// Envio de notificações por WhatsApp (Meta Cloud API)
// ------------------------------------------------------------
// Dispara um aviso ao morador quando o porteiro registra uma entrada
// (visita, encomenda, iFood). Como a mensagem é iniciada pelo sistema
// (business-initiated), fora da janela de 24h a Meta só permite enviar
// um TEMPLATE pré-aprovado (categoria "utility").
//
// Toda a configuração vem de variáveis de ambiente. Se não estiver
// configurado, o módulo fica DESATIVADO e todas as funções viram no-op
// (nunca lançam erro), espelhando o comportamento do push (VAPID).
// ============================================================

// Lê a configuração de forma preguiçosa (as envs podem ser carregadas depois
// do require, e no Cloudflare Workers chegam em runtime).
function lerConfig() {
  const ativoFlag = String(process.env.WHATSAPP_ATIVO || '').trim().toLowerCase();
  const ativoPorFlag = ativoFlag === 'true' || ativoFlag === '1' || ativoFlag === 'sim';

  const token = (process.env.WHATSAPP_TOKEN || '').trim();
  const phoneNumberId = (process.env.WHATSAPP_PHONE_NUMBER_ID || '').trim();
  const templateEntrada = (process.env.WHATSAPP_TEMPLATE_ENTRADA || 'aviso_entrada_portaria').trim();
  const templateLang = (process.env.WHATSAPP_TEMPLATE_LANG || 'pt_BR').trim();
  const apiVersion = (process.env.WHATSAPP_API_VERSION || 'v21.0').trim();

  // Só consideramos ativo se a flag estiver ligada E as credenciais existirem.
  const ativo = ativoPorFlag && !!token && !!phoneNumberId;

  return { ativo, ativoPorFlag, token, phoneNumberId, templateEntrada, templateLang, apiVersion };
}

function whatsappAtivo() {
  return lerConfig().ativo;
}

// Normaliza um telefone brasileiro para o formato E.164 sem o "+"
// (a Cloud API aceita o número só com dígitos, com DDI). Reaproveita a mesma
// lógica do linkWhatsapp do frontend: assume DDI 55 quando faltar.
function normalizarTelefone(telefone) {
  let num = (telefone || '').toString().replace(/\D/g, '');
  if (!num) return '';
  // Remove zeros à esquerda que às vezes aparecem em DDD digitado errado.
  if (!num.startsWith('55') && (num.length === 10 || num.length === 11)) {
    num = '55' + num;
  }
  return num;
}

// Trunca um parâmetro de template para um tamanho seguro e remove quebras de
// linha/abas (a Cloud API rejeita parâmetros com \n, \t ou 4+ espaços).
function paramSeguro(valor, max = 120) {
  let s = (valor === undefined || valor === null) ? '' : String(valor);
  s = s.replace(/[\r\n\t]+/g, ' ').replace(/ {4,}/g, '   ').trim();
  if (s.length > max) s = s.slice(0, max - 1).trim() + '…';
  return s || '-';
}

/**
 * Envia um template utility de aviso de entrada para UM telefone.
 *
 * O template na Meta deve ter 3 parâmetros de corpo, na ordem:
 *   {{1}} = o que chegou (ex.: "Visitante JOÃO", "Encomenda", "Entregador iFood")
 *   {{2}} = destino (ex.: "Lote 12")
 *   {{3}} = horário (ex.: "13/10 às 14:32")
 *
 * Retorna { ok:true, id } em sucesso, ou { ok:false, motivo, detalhe }.
 * NUNCA lança: em erro de rede/API devolve ok:false.
 */
async function enviarTemplateEntrada({ telefone, oQueChegou, destino, horario }) {
  const cfg = lerConfig();
  if (!cfg.ativo) {
    return { ok: false, motivo: 'desativado' };
  }

  const to = normalizarTelefone(telefone);
  if (!to) {
    return { ok: false, motivo: 'sem_telefone' };
  }

  const url = `https://graph.facebook.com/${cfg.apiVersion}/${cfg.phoneNumberId}/messages`;
  const corpo = {
    messaging_product: 'whatsapp',
    to,
    type: 'template',
    template: {
      name: cfg.templateEntrada,
      language: { code: cfg.templateLang },
      components: [
        {
          type: 'body',
          parameters: [
            { type: 'text', text: paramSeguro(oQueChegou) },
            { type: 'text', text: paramSeguro(destino) },
            { type: 'text', text: paramSeguro(horario, 40) },
          ],
        },
      ],
    },
  };

  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${cfg.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(corpo),
    });

    let dados = null;
    try { dados = await resp.json(); } catch { dados = null; }

    if (!resp.ok) {
      const detalhe = (dados && dados.error && (dados.error.message || dados.error.type)) || `HTTP ${resp.status}`;
      return { ok: false, motivo: 'erro_api', detalhe, status: resp.status };
    }

    const id = dados && dados.messages && dados.messages[0] && dados.messages[0].id;
    return { ok: true, id: id || null };
  } catch (err) {
    return { ok: false, motivo: 'erro_rede', detalhe: err.message };
  }
}

/**
 * Monta o texto do parâmetro {{1}} ("o que chegou") a partir do tipo/nome
 * de uma entrada registrada na portaria.
 */
function descreverEntrada({ nome_pessoa, tipo }) {
  const nome = (nome_pessoa || '').trim();
  if (nome === 'Encomenda') return '📦 Encomenda';
  if (/entregador\s+ifood/i.test(nome) || tipo === 'Entregador') {
    return '🛵 ' + (nome || 'Entregador');
  }
  const prefixo = tipo === 'Prestador' ? 'Prestador' : 'Visitante';
  return `🛎️ ${prefixo} ${nome}`.trim();
}

module.exports = {
  whatsappAtivo,
  normalizarTelefone,
  enviarTemplateEntrada,
  descreverEntrada,
};

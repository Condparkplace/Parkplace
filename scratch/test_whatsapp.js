// ============================================================
// Teste isolado do envio de WhatsApp (Fase 1 do plano)
// ------------------------------------------------------------
// Envia UMA mensagem de teste usando o template de entrada, sem tocar
// no fluxo da portaria. Use enquanto valida as credenciais da Meta.
//
// Pré-requisitos no .env:
//   WHATSAPP_ATIVO=true
//   WHATSAPP_TOKEN=...            (token da Cloud API)
//   WHATSAPP_PHONE_NUMBER_ID=...  (número remetente)
//   WHATSAPP_TEMPLATE_ENTRADA=aviso_entrada_portaria  (template APROVADO)
//   WHATSAPP_TEMPLATE_LANG=pt_BR
//
// No modo de teste da Meta, o número de destino precisa estar na lista
// de números autorizados do App (API Setup > "To").
//
// Como rodar (PowerShell):
//   node scratch/test_whatsapp.js 5511999999999
//   node scratch/test_whatsapp.js 11999999999   (DDI 55 é adicionado sozinho)
// ============================================================

require('dotenv').config();
const { whatsappAtivo, normalizarTelefone, enviarTemplateEntrada } = require('../src/whatsapp');

async function main() {
  const telefoneArg = process.argv[2];

  if (!telefoneArg) {
    console.error('Uso: node scratch/test_whatsapp.js <telefone>');
    console.error('Ex.: node scratch/test_whatsapp.js 5511999999999');
    process.exit(1);
  }

  console.log('WhatsApp ativo?         ', whatsappAtivo());
  console.log('Telefone normalizado:   ', normalizarTelefone(telefoneArg));
  console.log('Template:               ', process.env.WHATSAPP_TEMPLATE_ENTRADA || 'aviso_entrada_portaria');
  console.log('Idioma:                 ', process.env.WHATSAPP_TEMPLATE_LANG || 'pt_BR');
  console.log('----------------------------------------------');

  if (!whatsappAtivo()) {
    console.error('\n[ERRO] WhatsApp está DESATIVADO.');
    console.error('Verifique no .env: WHATSAPP_ATIVO=true e preencha WHATSAPP_TOKEN e WHATSAPP_PHONE_NUMBER_ID.');
    process.exit(1);
  }

  const resultado = await enviarTemplateEntrada({
    telefone: telefoneArg,
    oQueChegou: '🛎️ Visitante TESTE DE SISTEMA',
    destino: 'Lote 00',
    horario: 'agora (teste)',
  });

  console.log('\nResultado do envio:', resultado);

  if (resultado.ok) {
    console.log('\n✅ Mensagem enviada. Confira o WhatsApp do número informado.');
    console.log('   ID da mensagem:', resultado.id);
  } else {
    console.error('\n❌ Falhou. Motivo:', resultado.motivo, resultado.detalhe || '');
    console.error('   Dicas: verifique se o template está APROVADO, se o idioma bate (pt_BR)');
    console.error('   e se o número de destino está autorizado no modo de teste da Meta.');
    process.exit(1);
  }
}

main();

// Padronização de telefones brasileiros para gravação no banco.
//
// Formato salvo:
//   celular (11 dígitos) -> (11) 9 9906-5508
//   fixo    (10 dígitos) -> (11) 3333-4444
//
// Aceita qualquer entrada: só dígitos, com máscara, com +55 / 55, com 0 antes do DDD.
// Se não der para padronizar com segurança (ex.: número sem DDD), devolve o texto
// original SEM alterar, para nunca corromper nem inventar um DDD.
function formatarTelefone(valor) {
  if (valor === null || valor === undefined) return null;
  const bruto = String(valor).trim();
  if (!bruto) return null;

  let d = bruto.replace(/\D/g, '');
  if (!d) return bruto;

  // Remove o DDI do Brasil (+55) quando sobra um número de 10 ou 11 dígitos.
  if ((d.length === 12 || d.length === 13) && d.startsWith('55')) d = d.slice(2);
  // Remove o zero à esquerda do DDD (ex.: 011...).
  if ((d.length === 11 || d.length === 12) && d.startsWith('0')) d = d.slice(1);

  if (d.length === 11) {
    return `(${d.slice(0, 2)}) ${d[2]} ${d.slice(3, 7)}-${d.slice(7)}`;
  }
  // Fixo: 10 dígitos e o número começa com 2-5. Um número de 10 dígitos que começa
  // com 9 é um celular ao qual falta o nono dígito: não adivinhamos, fica como veio.
  if (d.length === 10 && d[2] !== '9') {
    return `(${d.slice(0, 2)}) ${d.slice(2, 6)}-${d.slice(6)}`;
  }
  return bruto; // não padronizável (ex.: 9 dígitos sem DDD, celular sem o 9)
}

// Indica se o valor já está no formato padrão.
function telefoneJaPadronizado(valor) {
  const v = String(valor || '').trim();
  return /^\(\d{2}\) 9 \d{4}-\d{4}$/.test(v) || /^\(\d{2}\) [2-5]\d{3}-\d{4}$/.test(v);
}

module.exports = { formatarTelefone, telefoneJaPadronizado };

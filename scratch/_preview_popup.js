// Temporário: monta uma página de teste só com o CSS + o pop-up reais do porteiro.html,
// para tirar um screenshot em tela baixa (headless) e conferir se o pop-up cabe.
const fs = require('fs');
const path = require('path');
const h = fs.readFileSync(path.join(__dirname, '..', 'public', 'porteiro.html'), 'utf8');

const css = h.match(/<style>([\s\S]*?)<\/style>/)[1];
const ini = h.indexOf('<div id="modal-entrada-visitante-encontrado"');
const fim = h.indexOf('<!-- Modal Cancelar -->');
let popup = h.slice(ini, fim);

// 1) Balanço de <div>
const abre = (popup.match(/<div[\s>]/g) || []).length;
const fecha = (popup.match(/<\/div>/g) || []).length;
console.log(`div abre=${abre} fecha=${fecha} ->`, abre === fecha ? 'BALANCEADO' : 'DESBALANCEADO');

// 2) Página de teste (popup visível, com a tarja de observação aberta = pior caso)
popup = popup.replace('class="hidden"', '').replace('id="popup-vis-alerta-obs" class="hidden"', 'id="popup-vis-alerta-obs"');
const trecho = h.slice(h.indexOf('const LOTES_GRADE'), h.indexOf('function renderGradeLotes'));
const render = h.slice(h.indexOf('function renderGradeLotes'), h.indexOf('// Mensagem de status do destino'));
const html = `<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="../public/css/style.css"><style>${css}</style></head>
<body style="margin:0;background:#64748b">${popup}
<script>
${trecho}
${render}
renderGradeLotes('grade-lotes-popup','popup-vis-destino','status-lote-popup','',{condominio:true});
document.getElementById('popup-vis-nome').textContent='WILLIAN';
document.getElementById('popup-vis-doc').textContent='Documento: 123.456.789-00';
document.getElementById('popup-vis-destino').value='Lote 07';
document.querySelector('[data-lote="Lote 07"]').classList.add('selecionado');
document.getElementById('popup-vis-alerta-obs-texto').textContent=${JSON.stringify(process.argv[2] === 'obs' ? 'AVISAR QUE NÃO PODE JOGAR SUJEIRA DE PODA NO BOSQUE' : '')};
${process.argv[2] === 'obs' ? '' : "document.getElementById('popup-vis-alerta-obs').style.display='none';"}
document.getElementById('modal-entrada-visitante-encontrado').style.display='flex';
</script></body></html>`;
fs.writeFileSync(path.join(__dirname, '_preview_popup.html'), html, 'utf8');
console.log('preview gerado');

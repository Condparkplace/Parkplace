// Temporário: página de teste só com o CSS + o pop-up reais do porteiro.html (para screenshot headless).
const fs = require('fs');
const path = require('path');
const h = fs.readFileSync(path.join(__dirname, '..', 'public', 'porteiro.html'), 'utf8');

const css = h.match(/<style>([\s\S]*?)<\/style>/)[1];
const ini = h.indexOf('<div id="modal-entrada-visitante-encontrado"');
const fim = h.indexOf('<!-- Modal Cancelar -->');
let popup = h.slice(ini, fim);

const abre = (popup.match(/<div[\s>]/g) || []).length;
const fecha = (popup.match(/<\/div>/g) || []).length;
console.log(`div abre=${abre} fecha=${fecha} ->`, abre === fecha ? 'BALANCEADO' : 'DESBALANCEADO');

const comObs = process.argv[2] === 'obs';
popup = popup.replace('class="hidden"', '').replace('id="popup-vis-alerta-obs" class="hidden"', 'id="popup-vis-alerta-obs"');
const trecho = h.slice(h.indexOf('const LOTES_GRADE'), h.indexOf('function renderGradeLotes'));
const render = h.slice(h.indexOf('function renderGradeLotes'), h.indexOf('// Mensagem de status do destino'));
const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="../public/css/style.css"><style>${css}</style></head>
<body style="margin:0;background:#64748b">${popup}
<script>
${trecho}
${render}
renderGradeLotes('grade-lotes-popup','popup-vis-destino','status-lote-popup','',{condominio:true});
document.getElementById('popup-vis-nome').textContent='ADILSON';
document.getElementById('popup-vis-doc').textContent='Documento: 217.686.468-99';
document.getElementById('popup-vis-tipo').value='Prestador';
document.getElementById('popup-vis-destino').value='Lote 07';
document.querySelector('[data-lote="Lote 07"]').classList.add('selecionado');
${comObs
  ? "document.getElementById('popup-vis-alerta-obs-texto').textContent='AVISAR QUE NÃO PODE JOGAR SUJEIRA DE PODA NO BOSQUE';"
  : "document.getElementById('popup-vis-alerta-obs').style.display='none';"}
document.getElementById('modal-entrada-visitante-encontrado').style.display='flex';
</script></body></html>`;
fs.writeFileSync(path.join(__dirname, '_preview_popup.html'), html, 'utf8');

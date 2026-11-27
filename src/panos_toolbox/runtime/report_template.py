"""Page template of the runtime report (HTML, CSS and JavaScript).

Placeholders (replaced in ONE pass by ``analyzer.render``, so substituted text is never
scanned again): ``__KIND__``, ``__TITLE__``, ``__DATA__`` (JSON blob), and ``__HB_<id>__`` /
``__HP_<id>__`` (help button and collapsible help text, see report_help.py).

Safety: the blob holds firewall output. The script writes data into the page only with
``textContent`` / text nodes (helper ``E``) and sets attributes only from fixed vocabularies
or with ``setAttribute``; there is no ``innerHTML``, ``eval`` or inline handler. Charts are
hand-written SVG built with ``createElementNS``.
"""
from __future__ import annotations

from panos_toolbox.common.credits import CREDITS_CSS, CREDITS_HTML, CREDITS_PLACEHOLDER

from .report_dataplane import DP_CSS, JS_DATAPLANE
from .report_help import SECTION_TITLES

TEMPLATE_HEAD = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__KIND__ - __TITLE__</title>
<style>
"""

TEMPLATE_CSS = r"""
:root{--ink:#1c2530;--mute:#5d6b7a;--line:#d8dde3;--bg:#f4f6f8;--card:#fff;--acc:#1f6f8b;--warn-bg:#fff4d6;--warn-bd:#c98a00}
*{box-sizing:border-box}
body{margin:0;min-width:1100px;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:3200px;margin:0 auto;padding:20px 24px 48px}
h1{font-size:20px;margin:0 0 2px}
h2{font-size:15px;margin:0 0 10px}
h3{font-size:14px;margin:14px 0 6px}
.sub{color:var(--mute);margin:0 0 10px}
.utc{background:var(--warn-bg);border-left:4px solid var(--warn-bd);padding:8px 14px;margin:0 0 14px;border-radius:2px}
section.panel{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px 16px;margin-bottom:16px;overflow-x:auto}
section.panel[hidden]{display:none}
.subpanel{border:1px solid var(--line);border-radius:4px;padding:10px 14px;margin:0 0 14px;background:#fff;min-width:0}
select,input,button{font:inherit;color:inherit;border:1px solid var(--line);border-radius:3px;padding:4px 8px;background:#fff}
button{cursor:pointer}
button:hover{border-color:var(--acc)}
button:focus-visible,select:focus-visible,input:focus-visible,th:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
label{color:var(--mute)}
.bar{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;margin:0 0 10px}
.seg{display:inline-flex}
.seg button{border-radius:0;margin-left:-1px}
.seg button:first-child{border-radius:3px 0 0 3px;margin-left:0}
.seg button:last-child{border-radius:0 3px 3px 0}
.seg button[aria-pressed=true]{background:var(--acc);border-color:var(--acc);color:#fff}
.tabs{display:flex;flex-wrap:wrap;gap:2px;border-bottom:1px solid var(--line);margin:0}
.tabs button{border:1px solid transparent;border-bottom:none;border-radius:4px 4px 0 0;background:transparent;color:var(--mute);padding:8px 16px}
.tabs button:hover{color:var(--ink)}
.tabs button[aria-selected=true]{background:var(--card);border-color:var(--line);color:var(--ink);font-weight:600;position:relative;top:1px}
.tabs .n{margin-left:6px}
table{border-collapse:collapse;width:100%}
th,td{padding:5px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:#eef1f4;position:sticky;top:0;white-space:nowrap;z-index:1}
th.sortable{cursor:pointer}
th[aria-sort=ascending]::after{content:" \25B2";font-size:10px}
th[aria-sort=descending]::after{content:" \25BC";font-size:10px}
td.nw,th.nw{white-space:nowrap}
td.r,th.r{text-align:right;font-variant-numeric:tabular-nums}
td.wrap{white-space:pre-wrap;overflow-wrap:anywhere}
table.auto{width:auto}
.scroll{max-height:clamp(320px,calc(100vh - 380px),1000px);overflow:auto;border:1px solid var(--line)}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.dim,.hint{color:var(--mute)}
.hint{font-size:12px}
.badge{display:inline-block;color:#fff;border-radius:3px;padding:0 6px;margin:0 3px 2px 0;font-size:11px;line-height:17px;white-space:nowrap}
.b-critical,.b-crit,.b-drop,.b-error{background:#b42318}
.b-warning,.b-warn{background:#b7791f}
.b-info{background:#5d6b7a}
.b-ok{background:#2f855a}
.sechead{display:flex;align-items:center;gap:10px;margin:0 0 8px;flex-wrap:wrap}
.sechead h2,.sechead h3{margin:0;font-size:15px}
.sechead h3{font-size:14px}
.sechead .meta{color:var(--mute);font-size:12px}
.helpbtn{font-size:12px;padding:1px 8px;border-radius:10px;color:var(--mute)}
.helpbtn[aria-expanded=true]{color:var(--ink);border-color:var(--acc)}
.help{max-width:980px;line-height:1.5;background:#f7f9fb;border-left:3px solid var(--acc);padding:6px 14px;margin:0 0 12px;font-size:13px}
.help[hidden]{display:none}
.help p,.help ul{margin:6px 0}
.help code{background:#eef1f4;border-radius:2px;padding:0 4px;font-size:12.5px}
#helpstore{display:none}
details{margin-top:8px}
summary{cursor:pointer}
.kv{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:3px 14px;margin:0}
.kv dt{color:var(--mute)}.kv dd{margin:0;overflow-wrap:anywhere}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(520px,1fr));gap:0 20px;align-items:start}
.cols.two{grid-template-columns:repeat(2,minmax(0,1fr))}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 10px}
.chip{border:1px solid var(--line);border-radius:4px;padding:4px 12px;background:#f7f9fb;min-width:92px}
.chip b{display:block;font-size:20px;line-height:1.2;font-variant-numeric:tabular-nums}
.chip span{font-size:12px;color:var(--mute)}
.chip.c-critical{border-left:4px solid #b42318}.chip.c-warning{border-left:4px solid #b7791f}.chip.c-info{border-left:4px solid #5d6b7a}
.alarm{background:#fdecea;border:2px solid #b42318;color:#7a1109;border-radius:4px;padding:10px 16px;margin:0 0 14px;font-weight:600}
.alarm ul{margin:6px 0 0;padding-left:20px;font-weight:400}
.okbox{background:#eaf6ee;border:1px solid #2f855a;border-radius:4px;padding:8px 14px;margin:0 0 14px}
.msg{padding:10px 14px;background:#f7f9fb;border:1px dashed var(--line);margin:6px 0}
.msg.na{border-style:solid;border-color:var(--warn-bd);background:var(--warn-bg)}
.emp{color:var(--mute);font-style:italic}
pre.det{margin:4px 0;padding:8px 12px;background:#f7f9fb;border:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto;font:12.5px/1.4 ui-monospace,Consolas,monospace}
.chart svg{display:block;max-width:100%}
.chart .ax{fill:var(--mute);font-size:11px}
.chart .gl{stroke:#e3e7ec;stroke-width:1}
.chart .axl{stroke:#9aa5b1;stroke-width:1}
.leg{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12px;margin:4px 0 0}
.leg button{border:none;background:none;padding:1px 4px;display:inline-flex;align-items:center;gap:5px;border-radius:3px}
.leg button[aria-pressed=false]{opacity:.4;text-decoration:line-through}
.leg .sw{display:inline-block;width:12px;height:4px;border-radius:2px}
#tip{position:fixed;z-index:50;pointer-events:none;background:#1c2530;color:#fff;font-size:12px;padding:5px 9px;border-radius:3px;max-width:420px;white-space:pre-wrap;box-shadow:0 2px 8px rgba(0,0,0,.25)}
#tip[hidden]{display:none}
.bars{display:grid;grid-template-columns:max-content minmax(120px,1fr) 52px;gap:4px 10px;align-items:center}
.bars .trk{background:#eef1f4;border-radius:3px;height:12px;overflow:hidden}
.bars .fil{height:12px;background:#1f6f8b}
.bars .fil.hot{background:#b42318}.bars .fil.mid{background:#b7791f}
.strip{display:flex;flex-wrap:wrap;gap:6px}
.sbox{border:1px solid var(--line);border-radius:4px;padding:4px 10px;background:#f7f9fb;font-size:12px;min-width:150px}
.sbox b{display:block;font-size:13px}
.sbox.foreign{border:2px solid #b42318;background:#fdecea}
.picker{margin:0 0 6px}
.picklist{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:1px 14px;max-height:220px;overflow:auto;border:1px solid var(--line);padding:6px 10px;font-size:12.5px}
.picklist label{color:var(--ink);overflow-wrap:anywhere}
.picked{display:flex;flex-wrap:wrap;gap:4px;margin:0 0 8px}
.picked .pk{font-size:12px;padding:1px 8px;border-radius:10px;background:#f7f9fb}
.xp{padding:0 6px;line-height:16px;font-size:12px;min-width:22px}
@media print{
  body{min-width:0;background:#fff}
  .tabs,.bar,.helpbtn,.help{display:none!important}
  section.panel[hidden]{display:block!important}
  section.panel{break-inside:auto;border:none;overflow:visible}
  .scroll{max-height:none;overflow:visible}
  th{position:static}
}
"""

_TABS = [("overview", "Overview"), ("findings", "Findings"), ("pow", "POW"),
         ("counters", "Counters"), ("dataplane", "Dataplane Analysis"), ("sessions", "Sessions")]

_TABS_HTML = "\n".join(
    f'<button type="button" role="tab" id="tab-{i}" aria-controls="p-{i}" '
    f'aria-selected="{"true" if n == 0 else "false"}">{t}</button>'
    for n, (i, t) in enumerate(_TABS))
_PANELS_HTML = "\n".join(
    f'<section class="panel" id="p-{i}" role="tabpanel" aria-labelledby="tab-{i}"'
    f'{"" if n == 0 else " hidden"}><div class="sechead" data-help="{i}"><h2>{t}</h2></div>'
    f'<div id="b-{i}"></div></section>'
    for n, (i, t) in enumerate(_TABS))

TEMPLATE_BODY = r"""</style>
</head>
<body>
<main>
__CREDITS__
<h1 id="title">__TITLE__</h1>
<p class="sub" id="sub"></p>
<div class="utc">All times in this report are UTC, as stored in the capture. No time zone conversion is applied.</div>
<div class="tabs" id="tabs" role="tablist">
__TABS__
</div>
__PANELS__
</main>
<div id="tip" role="tooltip" hidden></div>
<div id="helpstore">
__HELPSTORE__
</div>
"""

JS_CORE = r'''<script>
const D = __DATA__;
const META = D.meta || {}, SS = (D.session || {}).series || [], SD = D.sessions_dump || {}, LOAD = D.load || [], DL = D.delta || {samples:[], counters:[], top:{t:[], series:{}}};
const POW = D.pow || {intervals:[], groups:{}, funcs:{}, banner:[]}, BL = D.backlog || {available:false, series:[], special_tags:[], offenders:[]};
const PBP = D.pbp || {available:false, series:[], latency:[], entries:[]}, RM = D.resmon || {available:false, series:[], last_groups:{}, last_util:{}};
const FMODE = ((D.delta || {}).mode || {}).effective || 'exclude';
function foreignNote(){
  const m = DL.mode || {}, n = DL.foreign || 0;
  const why = m.reason ? ' (' + m.reason + ')' : '';
  if(FMODE === 'include') return n + ' delta sample(s) were cut short by another client reading the global counters; they are kept as printed by the firewall' + why + '.';
  if(FMODE === 'rescale') return n + ' delta sample(s) were cut short by another client reading the global counters; they are kept and their counts are scaled to the whole gap since our previous read (rates per second are unchanged)' + why + '. Samples that would need a factor above ' + (TH.foreign_scale_max || 10) + ' are left out.';
  return n + ' delta sample(s) were cut short by another client reading the global counters; they are left out of the statistics (' + DL.valid + ' samples used)' + why + '.';
}
const TP = D.throughput || {available:false, t:[], total:{rx_bps:[], tx_bps:[]}, interfaces:{}};
const CAP = D.capture || {commands:[], cycles:[]}, FND = D.findings || [], TH = D.thresholds || {}, FH = D.flag_help || {};
const TABS = ['overview','findings','pow','counters','dataplane','sessions'];
const LEVELS = ['critical','warning','info'];
const PALETTE = ['#1f6f8b','#d9822b','#2f855a','#8e44ad','#b42318','#5d6b7a','#b59a00','#0e7490','#d1478a','#6b8e23'];
const $ = s => document.querySelector(s);

function E(tag, a, ...kids){
  const e = document.createElement(tag);
  if(a) for(const n in a){ const v = a[n]; if(v == null || v === false) continue;
    if(n === 'text') e.textContent = v; else if(n === 'class') e.className = v; else e.setAttribute(n, v === true ? '' : String(v)); }
  for(const c of kids){ if(c == null || c === false) continue; e.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c); }
  return e;
}
const NS = 'http://www.w3.org/2000/svg';
function S(tag, a, ...kids){
  const e = document.createElementNS(NS, tag);
  if(a) for(const n in a){ if(a[n] == null) continue; if(n === 'text') e.textContent = String(a[n]); else e.setAttribute(n, String(a[n])); }
  for(const c of kids) if(c) e.appendChild(c);
  return e;
}
function clear(e){ while(e.firstChild) e.removeChild(e.firstChild); return e; }
const pick = (v, list) => list.includes(v) ? v : null;
const badge = (cls, text, title) => E('span', {class:'badge b-' + cls, text, title});
const sevBadge = s => badge(pick(s, ['critical','warning','info','drop','warn','error','ok']) || 'info', String(s));
const emptyVal = () => E('span', {class:'emp', text:'(none)'});
const isNum = v => typeof v === 'number' && isFinite(v);

// ---- time (UTC ISO strings)
function ms(s){
  if(!s) return NaN;
  const m = /^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d)(?:\.(\d+))?)?/.exec(s);
  if(!m) return NaN;
  return Date.UTC(+m[1], +m[2]-1, +m[3], +m[4], +m[5], +(m[6]||0), Math.round(+('0.' + (m[7]||'0')) * 1000));
}
const pad = n => (n < 10 ? '0' : '') + n;
function isoOf(t){ const d = new Date(t); return d.getUTCFullYear() + '-' + pad(d.getUTCMonth()+1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()); }
function sec(s){ return s ? String(s).replace('T',' ').replace('Z','').slice(0,19) : ''; }
function hms(s){ return s ? String(s).slice(11,19) : ''; }
function fmtN(v){
  if(!isNum(v)) return '';
  const a = Math.abs(v);
  if(a >= 1e6) return +(v/1e6).toFixed(2) + 'M';
  if(a >= 1e4) return +(v/1e3).toFixed(1) + 'k';
  return String(+v.toFixed(a < 10 ? 3 : 1));
}
function fmtX(v){ return isNum(v) ? String(+v.toFixed(3)) : ''; }
function fmtDur(s){
  if(!isNum(s)) return '';
  s = Math.round(s); const h = Math.floor(s/3600), m = Math.floor(s%3600/60);
  return h ? h + ' h ' + pad(m) + ' min' : m ? m + ' min ' + pad(s%60) + ' s' : s + ' s';
}
const tsOf = list => list.map(x => ms(x.t));

// ---- tooltip (text only)
const TIP = $('#tip');
function tipShow(ev, lines){
  clear(TIP); TIP.textContent = lines.join('\n'); TIP.hidden = false;
  const w = TIP.offsetWidth, h = TIP.offsetHeight;
  let x = ev.clientX + 14, y = ev.clientY + 14;
  if(x + w > window.innerWidth - 4) x = ev.clientX - w - 14;
  if(y + h > window.innerHeight - 4) y = ev.clientY - h - 14;
  TIP.style.left = Math.max(2, x) + 'px'; TIP.style.top = Math.max(2, y) + 'px';
}
function tipHide(){ TIP.hidden = true; }

// ---- per-section help (the store holds the server-rendered button and text of every id)
let helpN = 0;
function addHelp(head, id){
  const s = document.querySelector('#helpstore [data-hid="' + id + '"]'); if(!s) return;
  const b = s.querySelector('.helpbtn').cloneNode(true), p = s.querySelector('.help').cloneNode(true);
  p.id = 'help-' + id + '-' + (++helpN); b.setAttribute('aria-controls', p.id);
  head.appendChild(b); head.parentNode.insertBefore(p, head.nextSibling);
}
document.addEventListener('click', e => {
  const b = e.target.closest ? e.target.closest('.helpbtn') : null; if(!b) return;
  const p = document.getElementById(b.getAttribute('aria-controls')); if(!p) return;
  const open = p.hidden; p.hidden = !open; b.setAttribute('aria-expanded', String(open));
});
document.querySelectorAll('.sechead[data-help]').forEach(h => addHelp(h, h.getAttribute('data-help')));
function sub(title, helpId, ...kids){
  const head = E('div', {class:'sechead'}, E('h3', {text:title}));
  const box = E('div', {class:'subpanel'}, head);
  if(helpId) addHelp(head, helpId);
  for(const k of kids) if(k) box.appendChild(k);
  return box;
}
const noData = txt => E('p', {class:'msg', text:txt || 'No data in this capture.'});
const naMsg = what => E('p', {class:'msg na', text:'Not available on this firewall: ' + what + ' did not run here (the firewall answered "Invalid syntax", or no samples were stored). Platform or software version does not provide it. See the Overview tab.'});
function kvList(rows){
  const dl = E('dl', {class:'kv'});
  for(const [k, v] of rows){ dl.appendChild(E('dt', {text:k})); dl.appendChild(E('dd', null, v == null || v === '' ? emptyVal() : (typeof v === 'object' ? v : String(v)))); }
  return dl;
}

// ---- sortable table
function dataTable(cols, rows, o){
  o = o || {};
  let sortK = o.sort || null, dir = o.dir || 1, pred = null, all = rows;
  const limit = o.limit || 1000;
  const thead = E('tr'), tbody = E('tbody'), note = E('p', {class:'hint'});
  const t = E('table', {class: o.cls || ''}, E('thead', null, thead), tbody);
  cols.forEach(c => {
    const th = E('th', {class:(c.cls || '').replace('mono', '') + ' sortable', tabindex:'0', text:c.label, scope:'col'});
    const go = () => { if(sortK === c.k) dir = -dir; else { sortK = c.k; dir = c.num ? -1 : 1; } paint(); };
    th.addEventListener('click', go);
    th.addEventListener('keydown', e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); go(); } });
    c.th = th; thead.appendChild(th);
  });
  function paint(){
    cols.forEach(c => { if(c.k === sortK) c.th.setAttribute('aria-sort', dir > 0 ? 'ascending' : 'descending'); else c.th.removeAttribute('aria-sort'); });
    let list = pred ? all.filter(pred) : all.slice();
    const col = cols.find(c => c.k === sortK);
    if(col){ const g = col.get || (r => r[col.k]); list.sort((a, b) => { let x = g(a), y = g(b);
      if(x == null) x = col.num ? -Infinity : ''; if(y == null) y = col.num ? -Infinity : '';
      return (x < y ? -1 : x > y ? 1 : 0) * dir; }); }
    const total = list.length; list = list.slice(0, limit);
    clear(tbody);
    for(const r of list){ const tr = E('tr'); for(const c of cols){ const v = c.cell ? c.cell(r) : r[c.k]; tr.appendChild(E('td', {class:c.cls || ''}, v == null || v === '' ? null : (typeof v === 'number' ? fmtN(v) : v))); } tbody.appendChild(tr); }
    note.textContent = total > limit ? 'Showing the first ' + limit + ' of ' + total + ' rows.' : total + (total === 1 ? ' row' : ' rows');
    if(!total) tbody.appendChild(E('tr', null, E('td', {colspan:String(cols.length), class:'dim', text:'No rows.'})));
  }
  paint();
  return {el: E('div', null, E('div', {class:'scroll'}, t), note), setFilter: p => { pred = p; paint(); }};
}

// ---- line chart (SVG, text only)
const CHARTS = [];
function niceCeil(v){
  if(!(v > 0)) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v))), f = v / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}
function timeLabel(t, span){
  const s = isoOf(t);
  if(span >= 36 * 3600e3) return s.slice(5, 16);
  if(span >= 15 * 60e3) return s.slice(11, 16);
  return s.slice(11, 19);
}
let clipN = 0;
function nearestIdx(T, t){
  let best = -1, bd = Infinity; T.forEach((u, i) => { const d = Math.abs(u - t); if(d < bd){ bd = d; best = i; } });
  return best;
}
const STEPS = new WeakMap();  // cached: asked on every mouse move, one time list per series
function medianStep(T){
  if(!STEPS.has(T)){
    const d = []; for(let i = 1; i < T.length; i++) if(T[i] > T[i - 1]) d.push(T[i] - T[i - 1]);
    d.sort((a, b) => a - b); STEPS.set(T, d.length ? d[Math.floor(d.length / 2)] : 60e3);
  }
  return STEPS.get(T);
}
// A sync group makes several charts share the time window, the cursor, the drag-to-zoom and the
// finding markers: every chart registers a function that moves its own cursor line.
function syncGroup(t0, t1, onZoom){
  const g = {full:[t0, t1], zoom:null, markers:[], showMarkers:true, members:[]};
  g.domain = () => g.zoom || g.full;
  g.add = (el, move) => g.members.push({el, move});
  g.cursor = t => { g.members = g.members.filter(m => m.el.isConnected); g.members.forEach(m => m.move(t)); };
  g.setZoom = (a, b) => {
    if(a == null) g.zoom = null;
    else { const lo = Math.max(g.full[0], Math.min(a, b)), hi = Math.min(g.full[1], Math.max(a, b)); if(hi - lo < 2000) return; g.zoom = [lo, hi]; }
    tipHide(); onZoom();
  };
  return g;
}
function markerLines(g, t, tol){
  if(!g || !g.showMarkers) return [];
  const l = g.markers.filter(m => Math.abs(m.t - t) <= tol).map(m => String(m.level).toUpperCase() + ' ' + m.code + ': ' + m.title);
  return l.length > 6 ? l.slice(0, 6).concat('... ' + (l.length - 6) + ' more') : l;
}
function drawMarkers(svg, g, X, d0, d1, y, h){
  if(!g || !g.showMarkers) return;
  for(const m of g.markers){
    if(m.t < d0 || m.t > d1) continue;
    const x = X(m.t), c = m.level === 'critical' ? '#b42318' : m.level === 'warning' ? '#b7791f' : '#5d6b7a';
    svg.appendChild(S('line', {x1:x, x2:x, y1:y, y2:y + h, stroke:c, 'stroke-width':1, 'stroke-dasharray':'1 3', opacity:.8}));
    svg.appendChild(S('path', {d:'M' + (x - 4) + ' ' + (y - 6) + 'L' + (x + 4) + ' ' + (y - 6) + 'L' + x + ' ' + y + 'Z', fill:c}));
  }
}
// Pointer handling of a synced chart: moving sets the shared cursor, dragging zooms, double click resets.
function syncPointer(ov, svg, g, W, toTime, left, right, y, h, tip){
  let from = null;
  const sel = S('rect', {y, height:h, fill:'#1f6f8b', opacity:.18, visibility:'hidden', 'pointer-events':'none'});
  svg.appendChild(sel);
  const px = ev => { const r = svg.getBoundingClientRect(); return Math.max(left, Math.min(right, (ev.clientX - r.left) * (W / r.width))); };
  ov.addEventListener('mousedown', ev => {
    if(ev.button !== 0) return; ev.preventDefault(); from = px(ev);
    const up = e => { window.removeEventListener('mouseup', up); const to = px(e), a = from; from = null; sel.setAttribute('visibility', 'hidden');
      if(Math.abs(to - a) > 5) g.setZoom(toTime(a), toTime(to)); };
    window.addEventListener('mouseup', up);
  });
  ov.addEventListener('mousemove', ev => {
    const x = px(ev), t = toTime(x);
    if(from != null){ sel.setAttribute('x', Math.min(from, x)); sel.setAttribute('width', Math.abs(x - from)); sel.setAttribute('visibility', 'visible'); }
    g.cursor(t); tipShow(ev, tip(ev, t));
  });
  ov.addEventListener('mouseleave', () => { g.cursor(null); tipHide(); });
  ov.addEventListener('dblclick', () => g.setZoom(null));
}
function lineChart(host, o){
  const wrap = E('div', {class:'chart'}), box = E('div'), leg = E('div', {class:'leg'});
  const hidden = new Set(), series = (o.series || []).map((s, i) => Object.assign({color:PALETTE[i % PALETTE.length]}, s));
  const G = o.sync || null, timesOf = s => s.t || o.t || [];
  const hasData = series.some(s => timesOf(s).length && (s.values || []).some(isNum));
  host.appendChild(wrap);
  if(!hasData){ wrap.appendChild(noData(o.empty || 'No data points to draw.')); return null; }
  wrap.appendChild(box);
  if(series.length > 1 || o.legend){
    series.forEach((s, i) => {
      const b = E('button', {type:'button', 'aria-pressed':'true', title:'Show or hide this series'}, E('span', {class:'sw', style:'background:' + s.color}), s.name);
      b.addEventListener('click', () => {
        if(hidden.has(i)){ hidden.delete(i); b.setAttribute('aria-pressed', 'true'); }
        else if(hidden.size < series.length - 1){ hidden.add(i); b.setAttribute('aria-pressed', 'false'); }
        draw();
      });
      leg.appendChild(b);
    });
    wrap.appendChild(leg);
  }
  function draw(){
    clear(box);
    const W = Math.max(480, Math.floor(wrap.clientWidth || host.clientWidth || 1000)), H = o.height || 260;
    const L = 62, R = G ? 62 : 16, Tp = 22, B = 34, pw = W - L - R, ph = H - Tp - B;
    const all = series.flatMap(s => timesOf(s).filter(isFinite));
    let t0 = Infinity, t1 = -Infinity;
    if(G) [t0, t1] = G.domain();
    else for(const t of all){ if(t < t0) t0 = t; if(t > t1) t1 = t; }
    if(!(t1 > t0)){ t0 -= 30e3; t1 += 30e3; }
    const inWin = t => t >= t0 && t <= t1;
    const vis0 = series.filter((s, i) => !hidden.has(i));
    // Logarithmic scale (o.log): values <= 0 cannot be drawn and become gaps.
    const LOG = !!o.log && vis0.some(s => s.values.some(v => isNum(v) && v > 0));
    const vis = LOG ? vis0.map(s => Object.assign({}, s, {src:s, values:s.values.map(v => isNum(v) && v > 0 ? v : null)})) : vis0;
    let mx = 0, mn = Infinity; vis.forEach(s => { const T = timesOf(s); s.values.forEach((v, i) => { if(isNum(v) && inWin(T[i])){ if(v > mx) mx = v; if(v > 0 && v < mn) mn = v; } }); });
    if(!isFinite(mn)) mn = 1;
    const lo = LOG ? Math.floor(Math.log10(mn)) : 0, hi = LOG ? Math.max(lo + 1, Math.ceil(Math.log10(mx || 1))) : 0;
    const ymax = LOG ? Math.pow(10, hi) : (o.yMax != null ? Math.max(o.yMax, mx) : niceCeil(mx || 1));
    const ymin = LOG ? Math.pow(10, lo) : (o.yMin != null ? o.yMin : 0), yr = (ymax - ymin) || 1;
    const span = t1 - t0, X = t => L + (t - t0) / span * pw;
    const Y = LOG ? (v => Tp + ph - (Math.log10(v) - lo) / (hi - lo) * ph) : (v => Tp + ph - (v - ymin) / yr * ph);
    const svg = S('svg', {width:W, height:H, viewBox:'0 0 ' + W + ' ' + H, role:'img', 'aria-label':o.title || 'chart'});
    const clip = 'clip' + (++clipN);
    svg.appendChild(S('defs', null, S('clipPath', {id:clip}, S('rect', {x:L - 3, y:Tp - 6, width:pw + 6, height:ph + 9}))));
    const ticks = [];
    if(LOG){ const st = Math.max(1, Math.ceil((hi - lo) / 6)); for(let e = lo; e <= hi; e += st) ticks.push(Math.pow(10, e)); }
    else for(let i = 0; i <= 4; i++) ticks.push(ymin + yr * i / 4);
    for(const v of ticks){
      const y = Y(v);
      svg.appendChild(S('line', {x1:L, x2:W - R, y1:y, y2:y, class:'gl'}));
      svg.appendChild(S('text', {x:L - 6, y:y + 4, 'text-anchor':'end', class:'ax', text:fmtN(v)}));
    }
    const nt = Math.max(2, Math.min(8, Math.floor(pw / 110)));
    for(let i = 0; i <= nt; i++){
      const t = t0 + span * i / nt, x = X(t);
      svg.appendChild(S('line', {x1:x, x2:x, y1:Tp + ph, y2:Tp + ph + 4, class:'axl'}));
      svg.appendChild(S('text', {x:x, y:H - 16, 'text-anchor':i === 0 ? 'start' : i === nt ? 'end' : 'middle', class:'ax', text:timeLabel(t, span)}));
    }
    svg.appendChild(S('text', {x:W - R, y:H - 3, 'text-anchor':'end', class:'ax', text:'UTC'}));
    if(o.unit || LOG) svg.appendChild(S('text', {x:4, y:12, class:'ax', text:(o.unit || '') + (LOG ? ' (log)' : '')}));
    svg.appendChild(S('line', {x1:L, x2:L, y1:Tp, y2:Tp + ph, class:'axl'}));
    svg.appendChild(S('line', {x1:L, x2:W - R, y1:Tp + ph, y2:Tp + ph, class:'axl'}));
    drawMarkers(svg, G, X, t0, t1, Tp, ph);
    const plot = S('g', {'clip-path':'url(#' + clip + ')'});
    for(const s of vis){
      const T = timesOf(s);
      let d = '', run = 0, shown = 0;
      const dots = [];
      s.values.forEach((v, i) => {
        if(!isNum(v) || !isFinite(T[i])){ if(run === 1) dots.push(i - 1); run = 0; return; }
        d += (run ? 'L' : 'M') + X(T[i]).toFixed(1) + ' ' + Y(v).toFixed(1); run++; if(inWin(T[i])) shown++;
        if(i === s.values.length - 1 && run === 1) dots.push(i);
      });
      if(d) plot.appendChild(S('path', {d, fill:'none', stroke:s.color, 'stroke-width':1.8, 'stroke-linejoin':'round', 'stroke-dasharray':s.dash || null}));
      const many = shown > 90;
      s.values.forEach((v, i) => { if(isNum(v) && inWin(T[i]) && (dots.includes(i) || !many)) plot.appendChild(S('circle', {cx:X(T[i]), cy:Y(v), r:many ? 2 : 2.6, fill:s.color})); });
    }
    (o.marks || []).forEach(i => { const v = vis[0] && vis[0].values[i], T = vis[0] ? timesOf(vis[0]) : []; if(isNum(v) && inWin(T[i])) plot.appendChild(S('circle', {cx:X(T[i]), cy:Y(v), r:5, fill:'none', stroke:'#b42318', 'stroke-width':2})); });
    svg.appendChild(plot);
    const guide = S('line', {y1:Tp, y2:Tp + ph, stroke:'#1c2530', 'stroke-width':1, 'stroke-dasharray':'3 3', visibility:'hidden'});
    svg.appendChild(guide);
    const move = t => { if(t == null || !inWin(t)){ guide.setAttribute('visibility', 'hidden'); return; }
      guide.setAttribute('x1', X(t)); guide.setAttribute('x2', X(t)); guide.setAttribute('visibility', 'visible'); };
    const valueText = (s, i) => {
      const src = s.src || s, v = src.raw ? src.raw[i] : s.values[i], unit = src.raw ? src.unit : o.unit;
      return isNum(v) ? fmtX(v) + (unit ? ' ' + unit : '') : 'n/a';
    };
    const ov = S('rect', {x:L, y:Tp, width:pw, height:ph, fill:'transparent', style:G ? 'cursor:crosshair' : null});
    if(G){
      G.add(svg, move);
      syncPointer(ov, svg, G, W, x => t0 + (x - L) / pw * span, L, L + pw, Tp, ph, (ev, t) => {
        const lines = [isoOf(t) + ' UTC'];
        for(const s of vis){
          const T = timesOf(s), i = nearestIdx(T, t);
          if(i < 0 || Math.abs(T[i] - t) > Math.max(medianStep(T) * 1.5, span / 200)){ lines.push(s.name + ': n/a'); continue; }
          lines.push(s.name + ': ' + valueText(s, i) + (Math.abs(T[i] - t) >= 1000 ? '  (' + isoOf(T[i]).slice(11) + ')' : ''));
        }
        if(o.extra){ const i = nearestIdx(o.t || [], t); if(i >= 0) lines.push(...o.extra(i)); }
        return lines.concat(markerLines(G, t, span * 5 / pw));
      });
    } else {
      const T = o.t || [];
      ov.addEventListener('mousemove', ev => {
        const r = svg.getBoundingClientRect(), x = (ev.clientX - r.left) * (W / r.width);
        const best = nearestIdx(T, t0 + (x - L) / pw * span); if(best < 0) return;
        move(T[best]);
        const lines = [isoOf(T[best]) + ' UTC'];
        for(const s of vis) lines.push(s.name + ': ' + valueText(s, best));
        if(o.extra) lines.push(...o.extra(best));
        tipShow(ev, lines);
      });
      ov.addEventListener('mouseleave', () => { move(null); tipHide(); });
    }
    svg.appendChild(ov); box.appendChild(svg);
  }
  const api = {draw, wrap};
  CHARTS.push(api); draw();
  return api;
}
function redrawCharts(){ CHARTS.forEach(c => { if(c.wrap.isConnected && c.wrap.clientWidth > 0) c.draw(); }); }
let rzT = null;
window.addEventListener('resize', () => { clearTimeout(rzT); rzT = setTimeout(redrawCharts, 150); });

// items: [{id, name, group}]; sel: a Set of ids, changed in place; changed() redraws the caller
function seriesPicker(items, sel, changed, o){
  o = o || {};
  const byId = new Map(items.map(it => [it.id, it])), groups = Array.from(new Set(items.map(it => it.group).filter(Boolean)));
  const chips = E('div', {class:'picked'}), list = E('div', {class:'picklist'}), note = E('p', {class:'hint'});
  const count = E('summary'), det = E('details', {class:'picker'}, count);
  let q = '', grp = '';
  const MAX = 300;
  const matches = () => items.filter(it => (!grp || it.group === grp) && (!q || (it.name + ' ' + (it.group || '')).toLowerCase().includes(q)));
  function update(){ refresh(); changed(); }
  function refresh(){
    clear(chips); clear(list);
    for(const id of sel){ const it = byId.get(id); if(!it) continue;
      const b = E('button', {type:'button', class:'pk', title:'Remove from the chart', 'aria-label':'Remove ' + it.name}, it.name + ' ×');
      b.addEventListener('click', () => { sel.delete(id); update(); }); chips.appendChild(b); }
    count.textContent = 'Add or remove ' + (o.what || 'series') + ' (' + sel.size + ' of ' + items.length + ' selected)';
    const m = matches();
    m.slice(0, MAX).forEach(it => { const cb = E('input', {type:'checkbox', checked:sel.has(it.id)});
      cb.addEventListener('change', () => { if(cb.checked) sel.add(it.id); else sel.delete(it.id); update(); });
      list.appendChild(E('label', null, cb, ' ' + it.name)); });
    note.textContent = m.length > MAX ? 'Listing the first ' + MAX + ' of ' + m.length + ' matches: search to narrow them down.' : m.length + ' match(es).';
  }
  const inp = E('input', {type:'search', size:'30', placeholder:'Search ' + (o.what || 'series'), 'aria-label':'Search ' + (o.what || 'series')});
  inp.addEventListener('input', () => { q = inp.value.trim().toLowerCase(); refresh(); });
  const bar = E('div', {class:'bar'}, inp);
  if(groups.length > 1) bar.appendChild(selectBox('Category', [['', '(all)'], ...groups.map(g => [g, g])], v => { grp = v; refresh(); }));
  const btn = (text, fn) => { const b = E('button', {type:'button', text}); b.addEventListener('click', () => { fn(); update(); }); bar.appendChild(b); };
  btn('Add all matching', () => matches().forEach(it => sel.add(it.id)));
  (o.buttons || []).forEach(([text, ids]) => btn(text, () => { sel.clear(); ids().forEach(id => sel.add(id)); }));
  btn('Clear', () => sel.clear());
  det.appendChild(bar); det.appendChild(list); det.appendChild(note);
  refresh();
  return {el:E('div', null, det, chips), refresh};
}
const lineStyle = i => ({color:PALETTE[i % PALETTE.length], dash:[null, '7 3', '2 3'][Math.floor(i / PALETTE.length) % 3]});

function bars(map, hotAt, midAt){
  const g = E('div', {class:'bars'});
  const names = Object.keys(map || {});
  if(!names.length) return noData();
  for(const n of names){
    const v = map[n], w = isNum(v) ? Math.max(0, Math.min(100, v)) : 0;
    g.appendChild(E('div', {class:'mono', text:n}));
    g.appendChild(E('div', {class:'trk'}, E('div', {class:'fil' + (v >= hotAt ? ' hot' : v >= midAt ? ' mid' : ''), style:'width:' + w + '%'})));
    g.appendChild(E('div', {class:'r mono', text:fmtX(v) + '%'}));
  }
  return g;
}
function chartBox(title, helpId, build){
  const b = sub(title, helpId);
  build(b);
  return b;
}
function selectBox(label, options, onchange){
  const sel = E('select', {'aria-label':label});
  options.forEach(([v, t]) => sel.appendChild(E('option', {value:v, text:t})));
  sel.addEventListener('change', () => onchange(sel.value));
  return E('label', null, label + ' ', sel);
}
'''

JS_OVERVIEW = r'''
// ================= Overview
function cmdTable(){
  const rows = (CAP.commands || []).map(c => Object.assign({}, c));
  if(!rows.length) return noData('No command samples were stored.');
  return dataTable([
    {k:'slug', label:'Command', cls:'mono', get:r => r.slug},
    {k:'n', label:'Samples', cls:'r', num:true},
    {k:'failed', label:'Failed', cls:'r', num:true, cell:r => r.failed ? badge('warning', String(r.failed)) : '0'},
    {k:'dur_avg', label:'Avg (s)', cls:'r', num:true, cell:r => fmtX(r.dur_avg)},
    {k:'dur_max', label:'Max (s)', cls:'r', num:true, cell:r => fmtX(r.dur_max)}], rows, {sort:'dur_max', dir:-1, cls:'auto'}).el;
}
function renderOverview(){
  const root = clear($('#b-overview')), fw = META.firewall || {}, inf = META.inflight || {};
  const warns = META.warnings || [];
  if(warns.length){
    const ul = E('ul'); warns.forEach(w => ul.appendChild(E('li', {text:w})));
    root.appendChild(E('div', {class:'alarm', role:'alert'}, 'INFLIGHT MONITORING MAY STILL BE ON. Check the firewall and switch it off by hand.', ul));
  } else {
    root.appendChild(E('div', {class:'okbox'}, 'Inflight monitoring: ' + (inf.note || 'unknown') + ' (state before the capture: ' + (inf.before || 'unknown') + ').'));
  }
  const counts = {critical:0, warning:0, info:0}; FND.forEach(f => { if(counts[f.level] != null) counts[f.level]++; });
  const total = Object.values(META.sample_counts || {}).reduce((a, b) => a + b, 0);
  const chips = E('div', {class:'chips'});
  [['Cycles', META.cycles, ''], ['Fast ticks', META.fast_ticks, ''], ['Samples', total, ''], ['Critical', counts.critical, 'c-critical'], ['Warning', counts.warning, 'c-warning'], ['Info', counts.info, 'c-info']]
    .forEach(([l, v, c]) => chips.appendChild(E('div', {class:'chip ' + c}, E('b', {text:v == null ? '-' : String(v)}), E('span', {text:l}))));
  root.appendChild(chips);
  const params = sub('Capture parameters', null, kvList([
    ['Capture folder', META.folder], ['Tool', META.tool],
    ['Started (UTC)', sec(META.started_utc)], ['Finished (UTC)', sec(META.finished_utc)],
    ['First / last sample (UTC)', META.first_t ? sec(META.first_t) + ' / ' + sec(META.last_t) : ''],
    ['Duration', META.duration_s != null ? fmtDur(META.duration_s) + ' (' + META.duration_s + ' s)' : ''],
    ['Cycle interval', META.interval_s != null ? META.interval_s + ' s' : ''], ['Backlog / packet buffer tick', META.backlog_interval_s != null ? META.backlog_interval_s + ' s' : ''],
    ['Skipped ticks', META.skipped_ticks], ['Stopped by user', META.stopped_by_user ? 'yes' : 'no'],
    ['Manifest', META.has_manifest ? 'present' : 'missing (figures come from the stored samples)']]));
  const fwb = sub('Firewall', null, kvList([['Model', fw.model], ['Software version', fw.sw_version], ['Family', fw.family]]));
  root.appendChild(E('div', {class:'cols'}, params, fwb));
  const av = META.available || {}, un = Object.keys(av).filter(k => av[k] === false);
  const ub = sub('Unavailable commands', 'ov_inflight');
  if(warns.length || inf.note) ub.appendChild(E('p', {class:'hint', text:'Inflight monitoring is switched on during the capture and always left OFF. Outcome: ' + (inf.note || 'unknown') + '.'}));
  if(un.length){ const ul = E('ul'); un.forEach(k => ul.appendChild(E('li', {class:'mono', text:k + ': the firewall answered "Invalid syntax"'}))); ub.appendChild(ul); }
  else ub.appendChild(E('p', {text:'All optional commands were available on this firewall.'}));
  root.appendChild(ub);
  const cy = CAP.cycles || [];
  const cd = sub('Cycle durations', 'cap_cycles');
  root.appendChild(cd);
  lineChart(cd, {t:tsOf(cy), unit:'s', title:'Cycle durations', series:[{name:'total command time per cycle', values:cy.map(x => x.total_s)}], extra:i => ['cycle #' + cy[i].n]});
  if(META.interval_s) cd.appendChild(E('p', {class:'hint', text:'Interval: ' + META.interval_s + ' s. Slow-cycle level: ' + (TH.cycle_slow_share != null ? Math.round(TH.cycle_slow_share * 100) : 50) + '% of the interval.' + (CAP.fast_tick_max_s != null ? ' Longest fast tick: ' + CAP.fast_tick_max_s + ' s.' : '')}));
  root.appendChild(sub('Per-command timing', 'ov_commands', cmdTable()));
}
'''

JS_FINDINGS = r'''
// ================= Findings
const LVR = {critical:0, warning:1, info:2};
function renderFindings(){
  const root = clear($('#b-findings'));
  const rows = FND.slice().sort((a, b) => (LVR[a.level] - LVR[b.level]) || String(a.code).localeCompare(String(b.code)) || String(a.t).localeCompare(String(b.t)));
  let lvl = 'all';
  const tab = dataTable([
    {k:'level', label:'Level', cls:'nw', get:r => LVR[r.level], num:true, cell:r => badge(pick(r.level, LEVELS) || 'info', String(r.level).toUpperCase())},
    {k:'code', label:'Code', cls:'nw mono'}, {k:'title', label:'Title'},
    {k:'detail', label:'Detail', cls:'wrap'}, {k:'t', label:'Time (UTC)', cls:'nw', cell:r => sec(r.t)}], rows, {sort:'level', dir:1});
  const seg = E('div', {class:'seg', role:'group', 'aria-label':'Filter by level'});
  const counts = {all:rows.length}; LEVELS.forEach(l => { counts[l] = rows.filter(r => r.level === l).length; });
  ['all', ...LEVELS].forEach(l => {
    const b = E('button', {type:'button', 'aria-pressed':String(l === lvl), text:(l === 'all' ? 'All' : l[0].toUpperCase() + l.slice(1)) + ' (' + counts[l] + ')'});
    b.addEventListener('click', () => { lvl = l; seg.querySelectorAll('button').forEach(x => x.setAttribute('aria-pressed', String(x === b))); tab.setFilter(l === 'all' ? null : r => r.level === l); });
    seg.appendChild(b);
  });
  root.appendChild(E('div', {class:'bar'}, seg));
  if(!rows.length) root.appendChild(E('p', {class:'msg', text:'No findings: none of the checks fired for this capture.'}));
  root.appendChild(tab.el);
  const hd = E('div', {class:'sechead', style:'margin-top:18px'}, E('h3', {text:'Flag reference'})); root.appendChild(hd); addHelp(hd, 'flagref');
  const raised = {}; FND.forEach(f => { raised[f.code] = (raised[f.code] || 0) + 1; });
  const codes = Object.keys(FH).sort();
  const det = E('details');
  det.appendChild(E('summary', {text:'Meaning of all ' + codes.length + ' codes, thresholds used and what to check next'}));
  const t = E('table', null, E('thead', null, E('tr', null, ...['Code','Title','Meaning','Threshold keys (value used)','Check next'].map(h => E('th', {text:h})), E('th', {class:'r', text:'Raised'}))));
  const tb = E('tbody'); t.appendChild(tb);
  codes.forEach(c => { const h = FH[c];
    const keys = (h[3] || []).map(k => k + (TH[k] != null ? ' = ' + TH[k] : '')).join(', ');
    tb.appendChild(E('tr', null, E('td', {class:'nw mono', text:c}), E('td', {text:h[0]}), E('td', {text:h[1]}), E('td', {class:'mono', text:keys || '-'}), E('td', {text:h[2]}), E('td', {class:'r', text:String(raised[c] || 0)}))); });
  det.appendChild(t); root.appendChild(det);
}
'''

JS_POW = r'''
// ================= POW
function renderPow(){
  const root = clear($('#b-pow'));
  const iv = POW.intervals || [], T = iv.map(ms), groups = POW.groups || {}, funcs = POW.funcs || {};
  const names = Object.keys(groups);
  const ban = POW.banner || [];
  if(ban.length){
    const ul = E('ul'); ban.forEach(b => ul.appendChild(E('li', null, badge(b.level === 'crit' ? 'critical' : b.level === 'warn' ? 'warning' : 'info', String(b.level || 'info').toUpperCase()), ' ' + (b.text || ''))));
    root.appendChild(sub('Evaluation of the last sample', null, ul));
  }
  const gb = sub('Average time per call by group', 'pow_groups');
  if(!iv.length || !names.length){
    gb.appendChild(noData('POW needs at least two samples with data to compute per-interval figures.'));
  } else {
    const holder = E('div');
    let cur = '*', scale = 'auto';
    const show = key => {
      cur = key; clear(holder);
      const sel = key === '*' ? names : [key];
      const log = scale === 'log' || (scale === 'auto' && sel.length > 1);
      lineChart(holder, {t:T, unit:'us', log, title:'POW average microseconds per call', legend:sel.length > 1,
        series:sel.map(n => ({name:n, values:groups[n].avg_us})),
        extra:i => sel.length === 1 ? ['calls in interval: ' + fmtN(groups[sel[0]].count[i]), 'max-us (reported): ' + fmtN(groups[sel[0]].max_us[i])] : []});
    };
    gb.appendChild(E('div', {class:'bar'}, selectBox('Group', [['*', '(all groups)'], ...names.map(n => [n, n])], show),
      selectBox('Scale', [['auto', 'Auto (log for all groups)'], ['log', 'Logarithmic'], ['linear', 'Linear']], v => { scale = v; show(cur); })));
    gb.appendChild(holder); show('*');
  }
  root.appendChild(gb);
  const fn = Object.keys(funcs).map(n => {
    const f = funcs[n], v = f.avg_us.filter(isNum), c = f.count.filter(isNum);
    return {name:n, max_avg:v.length ? Math.max(...v) : null, mean_avg:v.length ? v.reduce((a, b) => a + b, 0) / v.length : null,
      calls:c.reduce((a, b) => a + b, 0), max_us:Math.max(...f.max_us.filter(isNum), 0)};
  });
  root.appendChild(sub('Top functions by total time', 'pow_funcs', fn.length ? dataTable([
    {k:'name', label:'Function', cls:'mono'}, {k:'max_avg', label:'Max avg-us', cls:'r', num:true, cell:r => fmtX(r.max_avg)},
    {k:'mean_avg', label:'Mean avg-us', cls:'r', num:true, cell:r => fmtX(r.mean_avg)},
    {k:'calls', label:'Calls (sum of intervals)', cls:'r', num:true, cell:r => String(r.calls)},
    {k:'max_us', label:'Max-us (reported)', cls:'r', num:true, cell:r => String(r.max_us)}], fn, {sort:'calls', dir:-1, cls:'auto'}).el : noData()));
}
'''

JS_COUNTERS = r'''
// ================= Counters
function renderCounters(){
  const root = clear($('#b-counters'));
  const cs = DL.counters || [], top = DL.top || {t:[], series:{}}, rates = DL.rates || {}, sm = DL.samples || [];
  const T = (top.t || []).map(ms), busiest = Object.keys(top.series || {}), sel = new Set(busiest), boxes = new Map();
  const holder = E('div');
  let how = 'stats', scale = 'linear';
  const draw = () => {
    clear(holder);
    const keep = i => how === 'all' || (how === 'none' ? !(top.foreign || [])[i] : (top.used || [])[i] !== false);
    const marks = how === 'none' ? [] : (top.foreign || []).map((f, i) => f && keep(i) ? i : -1).filter(i => i >= 0);
    lineChart(holder, {t:T, unit:'/s', title:'Counter rates', legend:true, marks, height:320, log:scale === 'log',
      series:Array.from(sel).map((n, k) => Object.assign({name:n, values:T.map((_, i) => keep(i) ? (rates[n] || {})[i] || 0 : null)}, lineStyle(k))),
      empty:sel.size ? 'No counter rates to draw.' : 'No counter selected: add one below or tick it in the table.'});
  };
  const syncBoxes = () => boxes.forEach((cb, n) => { cb.checked = sel.has(n); });
  const picker = seriesPicker(cs.map(c => ({id:c.name, name:c.name, group:c.severity})), sel, () => { syncBoxes(); draw(); },
    {what:'counters', buttons:[['Busiest', () => busiest]]});
  const bar = E('div', {class:'bar'}, selectBox('Scale', [['linear', 'Linear'], ['log', 'Logarithmic']], v => { scale = v; draw(); }));
  if((top.foreign || []).some(Boolean)) bar.appendChild(selectBox('Foreign samples', [['stats', 'As in the statistics (' + FMODE + ')'], ['none', 'Hide'], ['all', 'Show all (red rings)']], v => { how = v; draw(); }));
  const chart = sub('Counter rates', 'ct_rates', bar, picker.el, holder);
  root.appendChild(chart); draw();
  const tb = sub('Aggregated counters', 'ct_table');
  if(!cs.length) tb.appendChild(noData('No delta counter samples were parsed.'));
  else {
    const sevs = Array.from(new Set(cs.map(c => c.severity))).sort();
    let q = '', sv = 'all';
    const plot = r => { let cb = boxes.get(r.name);
      if(!cb){ cb = E('input', {type:'checkbox', 'aria-label':'Plot ' + r.name}); boxes.set(r.name, cb);
        cb.addEventListener('change', () => { if(cb.checked) sel.add(r.name); else sel.delete(r.name); picker.refresh(); draw(); }); }
      cb.checked = sel.has(r.name); return cb; };
    const tab = dataTable([
      {k:'plot', label:'Plot', cls:'nw', num:true, get:r => sel.has(r.name) ? 1 : 0, cell:plot},
      {k:'name', label:'Counter', cls:'mono'}, {k:'severity', label:'Severity', cls:'nw', cell:r => sevBadge(r.severity)},
      {k:'category', label:'Category', cls:'nw'}, {k:'aspect', label:'Aspect', cls:'nw'},
      {k:'samples', label:'Samples', cls:'r', num:true}, {k:'max_rate', label:'Max rate/s', cls:'r', num:true},
      {k:'mean_rate', label:'Mean rate/s', cls:'r', num:true}, {k:'last_rate', label:'Last rate/s', cls:'r', num:true},
      {k:'sum_value', label:'Sum of deltas', cls:'r', num:true}, {k:'description', label:'Description'}], cs, {sort:'max_rate', dir:-1});
    const apply = () => tab.setFilter(r => (sv === 'all' || r.severity === sv) && (!q || (r.name + ' ' + r.description + ' ' + r.category + ' ' + r.aspect).toLowerCase().includes(q)));
    const inp = E('input', {type:'search', size:'36', placeholder:'Search name or description', 'aria-label':'Search counters in the table'});
    inp.addEventListener('input', () => { q = inp.value.trim().toLowerCase(); apply(); });
    const seg = E('div', {class:'seg', role:'group', 'aria-label':'Filter by severity'});
    ['all', ...sevs].forEach(s => {
      const b = E('button', {type:'button', 'aria-pressed':String(s === sv), text:s === 'all' ? 'All (' + cs.length + ')' : s + ' (' + cs.filter(c => c.severity === s).length + ')'});
      b.addEventListener('click', () => { sv = s; seg.querySelectorAll('button').forEach(x => x.setAttribute('aria-pressed', String(x === b))); apply(); });
      seg.appendChild(b);
    });
    tb.appendChild(E('div', {class:'bar'}, inp, seg));
    if(DL.foreign) tb.appendChild(E('p', {class:'hint', text:foreignNote()}));
    tb.appendChild(tab.el);
  }
  root.appendChild(tb);
  const strip = E('div', {class:'strip'});
  sm.forEach((s, i) => strip.appendChild(E('div', {class:'sbox' + (s.foreign ? ' foreign' : ''), title:s.foreign ? 'Another client reset the delta baseline during this window (mode: ' + FMODE + ')' : ''},
    E('b', {text:'#' + (i + 1) + '  ' + hms(s.t) + ' UTC'}), E('span', {text:'elapsed ' + (isNum(s.elapsed) ? fmtX(s.elapsed) + ' s' : 'n/a') + ', ' + s.n_counters + ' counters'}),
    s.foreign ? E('div', null, badge('critical', 'FOREIGN SAMPLER'), s.used ? (FMODE === 'rescale' && isNum(s.scale) ? ' scaled x' + fmtX(s.scale) : ' included') : ' excluded') : null)));
  const nf = sm.filter(s => s.foreign).length;
  root.appendChild(sub('Delta samples', 'ct_samples', sm.length ? strip : noData(),
    nf ? E('p', {class:'hint', text:foreignNote()}) : null));
}
'''

JS_SESSIONS = r'''
// ================= Sessions
function renderSessionDump(root){
  const box = sub('Session dump', 'ss_dump');
  if(!SD.available){
    box.appendChild(E('p', {class:'msg', text: SD.requested ? 'The session dump was requested but no page was stored.' : 'No session dump in this capture (capture option --dump-sessions).'}));
    root.appendChild(box); return;
  }
  box.appendChild(kvList([['Sessions read', fmtN(SD.sessions) + (SD.truncated ? ' (INCOMPLETE: ' + (SD.reason || 'stopped') + ')' : '')],
    ['Pages (1K sessions each)', fmtN(SD.pages) + (SD.failed_pages ? ', failed: ' + SD.failed_pages : '')],
    ['Duplicates skipped', fmtN(SD.duplicates)], ['Sessions with NAT', fmtN(SD.nat)],
    ['Read between (UTC)', sec(SD.t) + ' - ' + sec(SD.t_end)], ['Command time', fmtX(SD.dump_s) + ' s']]));
  const g = E('div', {class:'cols'});
  const table = (title, key) => {
    const rows = (SD.top || {})[key] || [], tot = SD.sessions || 1;
    const h = E('div', null, E('h4', {text:title + ' (' + fmtN((SD.distinct || {})[key] || 0) + ' distinct)', style:'margin:6px 0'}));
    h.appendChild(dataTable([{k:'name', label:'Value', cls:'mono'}, {k:'n', label:'Sessions', cls:'r', num:true},
      {k:'pct', label:'%', cls:'r', num:true, get:r => r.n * 100 / tot, cell:r => fmtX(Math.round(r.n * 1000 / tot) / 10)}], rows, {sort:'n', dir:-1, cls:'auto'}).el);
    g.appendChild(h);
  };
  [['Application', 'app'], ['State', 'state'], ['Type', 'type'], ['IP protocol', 'proto'], ['Source zone', 'src_zone'], ['Destination zone', 'dst_zone'],
   ['Zone pair', 'zones'], ['Flag', 'flags'], ['Vsys', 'vsys'], ['Source address', 'src_ip'], ['Destination address', 'dst_ip'], ['Destination port/protocol', 'dst_port']].forEach(([t, k]) => table(t, k));
  box.appendChild(g); root.appendChild(box);
}
function renderSessions(){
  const root = clear($('#b-sessions'));
  renderSessionDump(root);
  if(!SS.length){ root.appendChild(noData('No session info samples could be parsed.')); return; }
  const T = tsOf(SS), col = k => SS.map(x => x[k]);
  const a = sub('Session table usage', 'ss_table');
  lineChart(a, {t:T, title:'Allocated and supported sessions', series:[{name:'allocated', values:col('allocated')}, {name:'supported', values:col('supported'), dash:'5 4'}],
    extra:i => ['utilization: ' + fmtX(SS[i].util_pct) + ' %']});
  const ub = E('div', null, E('h4', {text:'Utilization', style:'margin:8px 0 0'})); lineChart(ub, {t:T, unit:'%', yMax:100, title:'Session table utilization', height:180, series:[{name:'utilization %', values:col('util_pct'), color:'#b42318'}]});
  a.appendChild(ub);
  root.appendChild(a);
  const b = sub('Active sessions by protocol', 'ss_active');
  lineChart(b, {t:T, title:'Active sessions', series:[{name:'tcp', values:col('tcp')}, {name:'udp', values:col('udp')}, {name:'icmp', values:col('icmp')}]});
  root.appendChild(b);
  const c = sub('Connection, packet and throughput rates', 'ss_rates'), g = E('div', {class:'cols'});
  [['cps', 'connections/s', 'Connection rate (cps)'], ['pps', 'packets/s', 'Packet rate (pps)'], ['kbps', 'kbps', 'Throughput (kbps)']].forEach(([k, u, ttl], i) => {
    const h = E('div', null, E('h4', {text:ttl, style:'margin:6px 0'})); lineChart(h, {t:T, unit:u, title:ttl, height:200, series:[{name:k, values:col(k), color:PALETTE[i]}]}); g.appendChild(h);
  });
  c.appendChild(g); root.appendChild(c);
}
'''

JS_MAIN = r'''
// ================= Tabs and start
const built = {};
const RENDER = {overview:renderOverview, findings:renderFindings, pow:renderPow, counters:renderCounters, dataplane:renderDataplane, sessions:renderSessions};
let cur = 'overview';
function showTab(id, noHash){
  if(!TABS.includes(id)) id = 'overview';
  cur = id; tipHide();
  TABS.forEach(t => { const on = t === id; $('#p-' + t).hidden = !on; $('#tab-' + t).setAttribute('aria-selected', String(on)); $('#tab-' + t).tabIndex = on ? 0 : -1; });
  if(!built[id]){ built[id] = true; try{ RENDER[id](); redrawCharts(); }catch(err){ $('#b-' + id).appendChild(E('p', {class:'msg na', text:'This tab could not be drawn: ' + err.message})); } }
  else redrawCharts();
  if(!noHash){ try{ history.replaceState(null, '', '#tab=' + id); }catch(e){} }
}
function tabFromHash(){ const m = /^#tab=([a-z]+)$/.exec(location.hash || ''); return m && TABS.includes(m[1]) ? m[1] : null; }
TABS.forEach(t => $('#tab-' + t).addEventListener('click', () => showTab(t)));
$('#tabs').addEventListener('keydown', e => {
  if(e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
  const i = TABS.indexOf(cur), n = TABS[(i + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length]; showTab(n); $('#tab-' + n).focus();
});
window.addEventListener('hashchange', () => { const h = tabFromHash(); if(h && h !== cur) showTab(h, true); });
(function head(){
  $('#sub').textContent = 'Capture ' + (META.folder || '') + ' | ' + (META.firewall && META.firewall.hostname ? META.firewall.hostname + ' | ' : '') + (META.firewall && META.firewall.model ? META.firewall.model + ' ' + (META.firewall.sw_version || '') + ' | ' : '') + (META.first_t ? sec(META.first_t) + ' to ' + sec(META.last_t) + ' UTC' : 'no samples') + (META.generated_utc ? ' | Report generated ' + META.generated_utc + ' UTC' : '');
  const nf = FND.filter(f => f.level !== 'info').length;
  if(nf) $('#tab-findings').appendChild(E('span', {class:'badge n b-' + (FND.some(f => f.level === 'critical') ? 'critical' : 'warning'), text:String(nf)}));
  if((META.warnings || []).length) $('#tab-overview').appendChild(E('span', {class:'badge n b-critical', text:'!'}));
})();
showTab(tabFromHash() || 'overview', true);
</script>
</body>
</html>
'''

_STORE = "\n".join(f'<div data-hid="{i}">__HB_{i}__ __HP_{i}__</div>' for i in SECTION_TITLES)

TEMPLATE = (TEMPLATE_HEAD + TEMPLATE_CSS + DP_CSS + CREDITS_CSS
            + TEMPLATE_BODY.replace("__TABS__", _TABS_HTML).replace("__PANELS__", _PANELS_HTML)
            .replace("__HELPSTORE__", _STORE).replace(CREDITS_PLACEHOLDER, CREDITS_HTML)
            + JS_CORE + JS_OVERVIEW + JS_FINDINGS + JS_POW + JS_COUNTERS + JS_SESSIONS
            + JS_DATAPLANE + JS_MAIN)

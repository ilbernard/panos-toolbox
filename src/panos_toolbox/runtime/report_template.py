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
         ("counters", "Counters"), ("backlog", "Ingress backlogs"), ("pbp", "Packet buffer"),
         ("sessions", "Sessions"), ("throughput", "Throughput"), ("resources", "Resources"), ("capture", "Capture log")]

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
const META = D.meta || {}, SS = (D.session || {}).series || [], LOAD = D.load || [], DL = D.delta || {samples:[], counters:[], top:{t:[], series:{}}};
const POW = D.pow || {intervals:[], groups:{}, funcs:{}, banner:[]}, BL = D.backlog || {available:false, series:[], special_tags:[], offenders:[]};
const PBP = D.pbp || {available:false, series:[], latency:[], entries:[]}, RM = D.resmon || {available:false, series:[], last_groups:{}, last_util:{}};
const TP = D.throughput || {available:false, t:[], total:{rx_bps:[], tx_bps:[]}, interfaces:{}};
const CAP = D.capture || {commands:[], cycles:[]}, FND = D.findings || [], TH = D.thresholds || {}, FH = D.flag_help || {};
const TABS = ['overview','findings','pow','counters','backlog','pbp','sessions','throughput','resources','capture'];
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
function lineChart(host, o){
  const wrap = E('div', {class:'chart'}), box = E('div'), leg = E('div', {class:'leg'});
  const hidden = new Set(), T = o.t || [], series = (o.series || []).map((s, i) => Object.assign({color:PALETTE[i % PALETTE.length]}, s));
  const hasData = T.length && series.some(s => (s.values || []).some(isNum));
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
    const L = 62, R = 16, Tp = 22, B = 34, pw = W - L - R, ph = H - Tp - B;
    const vis0 = series.filter((s, i) => !hidden.has(i));
    // Logarithmic scale (o.log): values <= 0 cannot be drawn and become gaps.
    const LOG = !!o.log && vis0.some(s => s.values.some(v => isNum(v) && v > 0));
    const vis = LOG ? vis0.map(s => Object.assign({}, s, {values:s.values.map(v => isNum(v) && v > 0 ? v : null)})) : vis0;
    let mx = 0, mn = Infinity; vis.forEach(s => s.values.forEach(v => { if(isNum(v)){ if(v > mx) mx = v; if(v > 0 && v < mn) mn = v; } }));
    const lo = LOG ? Math.floor(Math.log10(mn)) : 0, hi = LOG ? Math.max(lo + 1, Math.ceil(Math.log10(mx))) : 0;
    const ymax = LOG ? Math.pow(10, hi) : (o.yMax != null ? Math.max(o.yMax, mx) : niceCeil(mx || 1));
    const ymin = LOG ? Math.pow(10, lo) : (o.yMin != null ? o.yMin : 0), yr = (ymax - ymin) || 1;
    let t0 = Math.min(...T), t1 = Math.max(...T);
    if(t1 === t0){ t0 -= 30e3; t1 += 30e3; }
    const span = t1 - t0, X = t => L + (t - t0) / span * pw;
    const Y = LOG ? (v => Tp + ph - (Math.log10(v) - lo) / (hi - lo) * ph) : (v => Tp + ph - (v - ymin) / yr * ph);
    const svg = S('svg', {width:W, height:H, viewBox:'0 0 ' + W + ' ' + H, role:'img', 'aria-label':o.title || 'chart'});
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
    if(o.unit || LOG) svg.appendChild(S('text', {x:L, y:12, 'text-anchor':'end', class:'ax', text:(o.unit || '') + (LOG ? ' (log)' : '')}));
    svg.appendChild(S('line', {x1:L, x2:L, y1:Tp, y2:Tp + ph, class:'axl'}));
    svg.appendChild(S('line', {x1:L, x2:W - R, y1:Tp + ph, y2:Tp + ph, class:'axl'}));
    for(const s of vis){
      let d = '', run = 0;
      const dots = [];
      s.values.forEach((v, i) => {
        if(!isNum(v) || !isFinite(T[i])){ if(run === 1) dots.push(i - 1); run = 0; return; }
        d += (run ? 'L' : 'M') + X(T[i]).toFixed(1) + ' ' + Y(v).toFixed(1); run++;
        if(i === s.values.length - 1 && run === 1) dots.push(i);
      });
      if(d) svg.appendChild(S('path', {d, fill:'none', stroke:s.color, 'stroke-width':1.8, 'stroke-linejoin':'round', 'stroke-dasharray':s.dash || null}));
      const many = s.values.length > 90;
      s.values.forEach((v, i) => { if(isNum(v) && (dots.includes(i) || !many)) svg.appendChild(S('circle', {cx:X(T[i]), cy:Y(v), r:many ? 2 : 2.6, fill:s.color})); });
    }
    (o.marks || []).forEach(i => { const v = vis[0] && vis[0].values[i]; if(isNum(v)) svg.appendChild(S('circle', {cx:X(T[i]), cy:Y(v), r:5, fill:'none', stroke:'#b42318', 'stroke-width':2})); });
    const guide = S('line', {y1:Tp, y2:Tp + ph, stroke:'#1c2530', 'stroke-width':1, 'stroke-dasharray':'3 3', visibility:'hidden'});
    svg.appendChild(guide);
    const ov = S('rect', {x:L, y:Tp, width:pw, height:ph, fill:'transparent'});
    ov.addEventListener('mousemove', ev => {
      const r = svg.getBoundingClientRect(), px = (ev.clientX - r.left) * (W / r.width);
      let best = 0, bd = Infinity; T.forEach((t, i) => { const dd = Math.abs(X(t) - px); if(dd < bd){ bd = dd; best = i; } });
      guide.setAttribute('x1', X(T[best])); guide.setAttribute('x2', X(T[best])); guide.setAttribute('visibility', 'visible');
      const lines = [isoOf(T[best]) + ' UTC'];
      for(const s of vis) lines.push(s.name + ': ' + (isNum(s.values[best]) ? fmtX(s.values[best]) + (o.unit ? ' ' + o.unit : '') : 'n/a'));
      if(o.extra) lines.push(...o.extra(best));
      tipShow(ev, lines);
    });
    ov.addEventListener('mouseleave', () => { guide.setAttribute('visibility', 'hidden'); tipHide(); });
    svg.appendChild(ov); box.appendChild(svg);
  }
  const api = {draw, wrap};
  CHARTS.push(api); draw();
  return api;
}
function redrawCharts(){ CHARTS.forEach(c => { if(c.wrap.isConnected && c.wrap.clientWidth > 0) c.draw(); }); }
let rzT = null;
window.addEventListener('resize', () => { clearTimeout(rzT); rzT = setTimeout(redrawCharts, 150); });

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
  const cb = sub('Per-command timing', 'ov_commands', cmdTable());
  const sc = META.sample_counts || {}, names = Object.keys(sc).sort();
  const cnt = sub('Samples per command', null, names.length ? E('table', {class:'auto'}, E('tbody', null, ...names.map(n => E('tr', null, E('td', {class:'mono', text:n}), E('td', {class:'r', text:String(sc[n])}))))) : noData());
  root.appendChild(E('div', {class:'cols'}, ub, cnt));
  root.appendChild(cb);
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
  const det = E('details'); det.open = true;
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
  const cs = DL.counters || [];
  const tb = sub('Aggregated counters', 'ct_table');
  if(!cs.length) tb.appendChild(noData('No delta counter samples were parsed.'));
  else {
    const sevs = Array.from(new Set(cs.map(c => c.severity))).sort();
    let q = '', sv = 'all';
    const tab = dataTable([
      {k:'name', label:'Counter', cls:'mono'}, {k:'severity', label:'Severity', cls:'nw', cell:r => sevBadge(r.severity)},
      {k:'category', label:'Category', cls:'nw'}, {k:'aspect', label:'Aspect', cls:'nw'},
      {k:'samples', label:'Samples', cls:'r', num:true}, {k:'max_rate', label:'Max rate/s', cls:'r', num:true},
      {k:'mean_rate', label:'Mean rate/s', cls:'r', num:true}, {k:'last_rate', label:'Last rate/s', cls:'r', num:true},
      {k:'sum_value', label:'Sum of deltas', cls:'r', num:true}, {k:'description', label:'Description'}], cs, {sort:'max_rate', dir:-1});
    const apply = () => tab.setFilter(r => (sv === 'all' || r.severity === sv) && (!q || (r.name + ' ' + r.description + ' ' + r.category + ' ' + r.aspect).toLowerCase().includes(q)));
    const inp = E('input', {type:'search', size:'36', placeholder:'Search name or description', 'aria-label':'Search counters'});
    inp.addEventListener('input', () => { q = inp.value.trim().toLowerCase(); apply(); });
    const seg = E('div', {class:'seg', role:'group', 'aria-label':'Filter by severity'});
    ['all', ...sevs].forEach(s => {
      const b = E('button', {type:'button', 'aria-pressed':String(s === sv), text:s === 'all' ? 'All (' + cs.length + ')' : s + ' (' + cs.filter(c => c.severity === s).length + ')'});
      b.addEventListener('click', () => { sv = s; seg.querySelectorAll('button').forEach(x => x.setAttribute('aria-pressed', String(x === b))); apply(); });
      seg.appendChild(b);
    });
    tb.appendChild(E('div', {class:'bar'}, inp, seg));
    if(DL.excluded) tb.appendChild(E('p', {class:'hint', text:'Statistics use the ' + DL.valid + ' valid delta sample(s); ' + DL.excluded + ' sample(s) in which another client reset the delta counters are left out.'}));
    tb.appendChild(tab.el);
  }
  root.appendChild(tb);
  const top = DL.top || {t:[], series:{}}, names = Object.keys(top.series || {});
  const sm = DL.samples || [];
  root.appendChild(sub('Rate of the busiest counters', 'ct_rates', (function(){
    const h = E('div');
    lineChart(h, {t:(top.t || []).map(ms), unit:'/s', title:'Counter rates', legend:true, series:names.map(n => ({name:n, values:top.series[n]})), empty:'No counter rates to draw.'});
    return h;
  })()));
  const strip = E('div', {class:'strip'});
  sm.forEach((s, i) => strip.appendChild(E('div', {class:'sbox' + (s.foreign ? ' foreign' : ''), title:s.foreign ? 'Another client reset the delta baseline during this window: left out of the charts and statistics' : ''},
    E('b', {text:'#' + (i + 1) + '  ' + hms(s.t) + ' UTC'}), E('span', {text:'elapsed ' + (isNum(s.elapsed) ? fmtX(s.elapsed) + ' s' : 'n/a') + ', ' + s.n_counters + ' counters'}),
    s.foreign ? E('div', null, badge('critical', 'FOREIGN SAMPLER'), ' excluded') : null)));
  const nf = sm.filter(s => s.foreign).length;
  root.appendChild(sub('Delta samples', 'ct_samples', sm.length ? strip : noData(),
    nf ? E('p', {class:'hint', text:nf + ' sample(s) were shortened by another client that reset the delta counters. They are shown as gaps in the rate chart and are left out of the counter statistics.'}) : null));
}
'''

JS_BACKLOG = r'''
// ================= Ingress backlogs and packet buffer
function renderBacklog(){
  const root = clear($('#b-backlog'));
  if(!BL.available){ root.appendChild(naMsg('the ingress-backlogs command')); return; }
  const ser = BL.series || [], keys = [];
  const by = {}; ser.forEach(x => { const k = x.slot + ' / ' + x.dp; if(!by[k]){ by[k] = []; keys.push(k); } by[k].push(x); });
  keys.sort((a, b) => Math.max(...by[b].map(x => x.total || 0)) - Math.max(...by[a].map(x => x.total || 0)));
  const cb = sub('Backlog usage', 'bl_chart');
  if(!keys.length) cb.appendChild(noData());
  else {
    const holder = E('div');
    const show = k => { clear(holder); const l = by[k];
      lineChart(holder, {t:l.map(x => ms(x.t)), unit:'%', yMax:100, title:'Ingress backlog usage', series:[{name:'atomic %', values:l.map(x => x.atomic)}, {name:'total %', values:l.map(x => x.total)}],
        extra:i => ['sessions in list: ' + l[i].real + ', special tags: ' + l[i].special]}); };
    cb.appendChild(E('div', {class:'bar'}, selectBox('Slot / data plane', keys.map(k => [k, k]), show)));
    cb.appendChild(holder); show(keys[0]);
  }
  root.appendChild(cb);
  const tags = BL.special_tags || [];
  root.appendChild(sub('Special tags (not sessions)', 'bl_tags', tags.length ? dataTable([
    {k:'name', label:'Tag', cls:'mono'}, {k:'pct_max', label:'Max %', cls:'r', num:true}, {k:'count_max', label:'Max count', cls:'r', num:true},
    {k:'samples', label:'Samples', cls:'r', num:true}], tags, {sort:'pct_max', dir:-1, cls:'auto'}).el : E('p', {text:'No special tags were seen.'})));
  const off = BL.offenders || [], ob = sub('Offending sessions', 'bl_offenders');
  if(!off.length) ob.appendChild(E('p', {text:'No session held a large share of the backlog.'}));
  else {
    const t = E('table', null, E('thead', null, E('tr', null, ...['', 'Session id', 'First seen (UTC)', 'Max %', 'Group', 'Count', 'Slot / DP'].map(h => E('th', {text:h})))));
    const tbd = E('tbody'); t.appendChild(tbd);
    off.forEach((o, i) => {
      const pre = E('pre', {class:'det'}); pre.textContent = o.detail || '(no show session id output was stored)';
      const dr = E('tr', null, E('td', {colspan:'7'}, pre)); dr.hidden = i > 0;
      const b = E('button', {type:'button', class:'xp', 'aria-expanded':String(i === 0), 'aria-label':'Detail of session ' + o.id, text:i === 0 ? '-' : '+'});
      b.addEventListener('click', () => { dr.hidden = !dr.hidden; b.textContent = dr.hidden ? '+' : '-'; b.setAttribute('aria-expanded', String(!dr.hidden)); });
      tbd.appendChild(E('tr', null, E('td', null, b), E('td', {class:'mono', text:String(o.id)}), E('td', {class:'nw', text:sec(o.first_seen)}), E('td', {class:'r', text:fmtX(o.pct)}),
        E('td', {text:String(o.grp_id == null ? '' : o.grp_id)}), E('td', {class:'r', text:fmtN(o.count)}), E('td', {text:o.slot + ' / ' + o.dp})));
      tbd.appendChild(dr);
    });
    ob.appendChild(E('div', {class:'scroll'}, t));
  }
  root.appendChild(ob);
}
function renderPbp(){
  const root = clear($('#b-pbp'));
  if(!PBP.available){ root.appendChild(naMsg('the packet buffer protection commands')); return; }
  const ser = PBP.series || [];
  const act = []; ser.forEach((x, i) => { if(x.active) act.push(i); });
  const c1 = sub('Packet buffer congestion', 'pbp_congestion');
  lineChart(c1, {t:tsOf(ser), unit:'%', yMax:100, title:'Packet buffer congestion', series:[{name:'congestion %', values:ser.map(x => x.congestion_pct)}], marks:act.length <= 40 ? act : [],
    extra:i => ['used / total: ' + fmtN(ser[i].used) + ' / ' + fmtN(ser[i].total), 'protection active: ' + (ser[i].active ? 'yes' : 'no')]});
  if(act.length) c1.appendChild(E('p', {class:'hint', text:(act.length <= 40 ? 'Red rings mark the ' : 'Protection was active in ') + act.length + ' sample(s)' + (act.length <= 40 ? ' where protection was active.' : ' (too many to mark).')}));
  if(PBP.basis) c1.appendChild(E('p', {class:'hint', text:'Basis: ' + PBP.basis}));
  root.appendChild(c1);
  const lat = PBP.latency || [];
  const c2 = sub('Packet buffer latency', 'pbp_latency');
  lineChart(c2, {t:tsOf(lat), unit:'ms', title:'Packet buffer latency', series:[{name:'latest ms', values:lat.map(x => x.latest_ms)}, {name:'max ms', values:lat.map(x => x.max_ms)}]});
  root.appendChild(c2);
  const en = PBP.entries || [], keys = [];
  en.forEach(e => Object.keys(e).forEach(k => { if(!keys.includes(k)) keys.push(k); }));
  root.appendChild(sub('Last packet buffer protection table' + (PBP.entries_t ? ' (' + sec(PBP.entries_t) + ' UTC)' : ''), 'pbp_entries',
    en.length ? dataTable(keys.map(k => ({k, label:k.replace(/_/g, ' '), cls:'mono' + (/^(pcs|percentage|packets_total|dropped|time_till_discard)$/.test(k) ? ' r' : ''), num:/^(pcs|percentage|packets_total|dropped|time_till_discard)$/.test(k),
      get:r => /^(pcs|percentage|packets_total|dropped|time_till_discard)$/.test(k) ? Number(r[k]) : String(r[k] == null ? '' : r[k]), cell:r => String(r[k] == null ? '' : r[k])})), en, {cls:'auto'}).el : E('p', {text:'The table was empty in every sample.'})));
}
'''

JS_SESSIONS = r'''
// ================= Sessions and resources
function renderSessions(){
  const root = clear($('#b-sessions'));
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
// ---- CPU heatmap: one row per core, one cell per second (see analysis._cpu_heat)
const heatColor = v => isNum(v) ? 'rgba(180,35,24,' + (0.06 + 0.94 * v / 100).toFixed(2) + ')' : '';
function cpuHeat(host, H){
  const ids = (H.cores || []).map(String), n = ids.length, stepMs = (H.step_s || 1) * 1000;
  const ncell = n ? H.cells[ids[0]].length : 0;
  if(!n || !ncell){ host.appendChild(noData('No per-second CPU data in this capture.')); return; }
  const t0 = H.t0_ms, span = ncell * stepMs, thr = +(TH.cpu_core_warn || 80);
  const wrap = E('div', {class:'chart'}), box = E('div'); wrap.appendChild(box); host.appendChild(wrap);
  function draw(){
    clear(box);
    const W = Math.max(480, Math.floor(wrap.clientWidth || host.clientWidth || 1000));
    const L = 62, PK = 46, Rr = 16 + PK, T = 16, B = 28, LEG = 26, pw = W - L - Rr;
    const rp = Math.min(18, Math.max(8, Math.floor(420 / n))), ph = n * rp;
    const nb = Math.max(1, Math.floor(pw / 2)), bw = pw / nb, bt = span / nb;
    const svg = S('svg', {width:W, height:T + ph + B + LEG, viewBox:'0 0 ' + W + ' ' + (T + ph + B + LEG), role:'img', 'aria-label':'CPU per core heatmap'});
    svg.appendChild(S('rect', {x:L, y:T, width:pw, height:ph, fill:'#eef1f4'}));
    const cols = [];  // per row: value per pixel column
    ids.forEach((id, k) => {
      const row = H.cells[id], vals = new Array(nb).fill(null), y = T + k * rp;
      let pk = null;
      for(let j = 0; j < row.length; j++){
        const v = row[j]; if(!isNum(v)) continue;
        if(pk === null || v > pk) pk = v;
        const a = Math.floor(j * stepMs / bt), b = Math.max(a, Math.ceil((j + 1) * stepMs / bt) - 1);
        for(let c = a; c <= Math.min(b, nb - 1); c++) if(vals[c] === null || v > vals[c]) vals[c] = v;
      }
      cols.push(vals);
      let i = 0;
      while(i < nb){
        const v = vals[i]; if(v === null){ i++; continue; }
        let j = i; while(j + 1 < nb && vals[j + 1] === v) j++;
        const hot = v >= thr;
        svg.appendChild(S('rect', {x:L + i * bw, y, width:(j - i + 1) * bw, height:rp + 0.3, fill:heatColor(v), stroke:hot ? '#1c2530' : null, 'stroke-width':hot ? 1 : null}));
        i = j + 1;
      }
      const fs = Math.max(8, Math.min(11, rp - 1)), yc = y + rp / 2 + fs * 0.35;
      svg.appendChild(S('text', {x:L - 6, y:yc, 'text-anchor':'end', class:'ax', 'font-size':fs, text:'core ' + id}));
      if(pk !== null){
        svg.appendChild(S('rect', {x:W - Rr + 4, y, width:PK - 8, height:rp + 0.3, fill:heatColor(pk)}));
        if(rp >= 8) svg.appendChild(S('text', {x:W - Rr + 4 + (PK - 8) / 2, y:yc, 'text-anchor':'middle', 'font-size':fs, fill:pk >= 55 ? '#fff' : '#1c2530', text:String(pk)}));
      }
    });
    svg.appendChild(S('text', {x:W - Rr + 4 + (PK - 8) / 2, y:T - 3, 'text-anchor':'middle', class:'ax', text:'peak'}));
    const nt = Math.max(2, Math.min(8, Math.floor(pw / 110)));
    for(let i = 0; i <= nt; i++){
      const t = t0 + span * i / nt, x = L + pw * i / nt;
      svg.appendChild(S('line', {x1:x, x2:x, y1:T + ph, y2:T + ph + 4, class:'axl'}));
      svg.appendChild(S('text', {x, y:T + ph + 17, 'text-anchor':i === 0 ? 'start' : i === nt ? 'end' : 'middle', class:'ax', text:timeLabel(t, span)}));
    }
    svg.appendChild(S('text', {x:W - Rr, y:T + ph + 17 + 9, 'text-anchor':'end', class:'ax', text:'UTC'}));
    svg.appendChild(S('line', {x1:L, x2:L + pw, y1:T + ph, y2:T + ph, class:'axl'}));
    const ly = T + ph + B + 4, gid = 'hmg' + Math.random().toString(36).slice(2, 8);
    svg.appendChild(S('defs', null, S('linearGradient', {id:gid, x1:0, x2:1, y1:0, y2:0}, S('stop', {offset:0, 'stop-color':heatColor(0)}), S('stop', {offset:1, 'stop-color':heatColor(100)}))));
    svg.appendChild(S('text', {x:L, y:ly + 9, class:'ax', text:'0%'}));
    svg.appendChild(S('rect', {x:L + 26, y:ly, width:140, height:11, fill:'url(#' + gid + ')', stroke:'#d8dde3'}));
    svg.appendChild(S('text', {x:L + 172, y:ly + 9, class:'ax', text:'100%'}));
    svg.appendChild(S('rect', {x:L + 226, y:ly, width:14, height:11, fill:'#eef1f4', stroke:'#d8dde3'}));
    svg.appendChild(S('text', {x:L + 246, y:ly + 9, class:'ax', text:'no data'}));
    svg.appendChild(S('rect', {x:L + 316, y:ly + 0.5, width:14, height:10, fill:heatColor(thr), stroke:'#1c2530', 'stroke-width':1}));
    svg.appendChild(S('text', {x:L + 336, y:ly + 9, class:'ax', text:'at or above ' + thr + '% (cpu_core_warn)'}));
    const ov = S('rect', {x:L, y:T, width:pw, height:ph, fill:'transparent'});
    ov.addEventListener('mousemove', ev => {
      const r = svg.getBoundingClientRect(), px = (ev.clientX - r.left) * (W / r.width), py = (ev.clientY - r.top) * (W / r.width);
      const k = Math.max(0, Math.min(n - 1, Math.floor((py - T) / rp))), c = Math.max(0, Math.min(nb - 1, Math.floor((px - L) / bw)));
      const a = t0 + c * bt, b = a + bt, v = cols[k][c];
      tipShow(ev, ['core ' + ids[k], isoOf(a) + ' - ' + isoOf(b) + ' UTC', isNum(v) ? 'max ' + v + ' %' : 'no data']);
    });
    ov.addEventListener('mouseleave', tipHide);
    svg.appendChild(ov); box.appendChild(svg);
  }
  CHARTS.push({draw, wrap}); draw();
  const um = H.unmeasured || [];
  if(um.length) host.appendChild(E('p', {class:'hint', text:'Not measured by the firewall (printed as *): core ' + um.join(', core ') + '. Not drawn.'}));
  if((H.step_s || 1) > 1) host.appendChild(E('p', {class:'hint', text:'Long capture: every cell is the maximum of ' + H.step_s + ' seconds.'}));
}
function renderResources(){
  const root = clear($('#b-resources'));
  const ser = RM.series || [];
  if(!RM.available){ root.appendChild(naMsg('the resource-monitor command')); }
  else {
    const T = tsOf(ser);
    const a = sub('Data plane CPU per cycle', 'res_cpu');
    lineChart(a, {t:T, unit:'%', yMax:100, title:'Core CPU', series:[{name:'busiest core (max 60 s)', values:ser.map(x => x.core_max)}, {name:'highest core average (60 s)', values:ser.map(x => x.core_avg)}]});
    root.appendChild(a);
    const hm = sub('CPU per core (heatmap)', 'res_heat');
    if(RM.heat) cpuHeat(hm, RM.heat); else hm.appendChild(noData('No per-second CPU table could be parsed.'));
    root.appendChild(hm);
    const g = sub('CPU per group', 'res_groups'), cols = E('div', {class:'cols two'});
    const l = E('div', null, E('h4', {text:'Busiest group per cycle', style:'margin:6px 0'}));
    lineChart(l, {t:T, unit:'%', yMax:100, title:'Busiest group', height:220, series:[{name:'busiest group %', values:ser.map(x => x.group_max_pct)}], extra:i => ['group: ' + (ser[i].group_max_name || 'n/a')]});
    const r = E('div', null, E('h4', {text:'Last sample, every group', style:'margin:6px 0'}), bars(RM.last_groups, +(TH.cpu_group_warn || 80), 50));
    cols.appendChild(l); cols.appendChild(r); g.appendChild(cols); root.appendChild(g);
    const um = {}; ser.forEach(x => Object.keys(x.util_max || {}).forEach(k => { um[k] = Math.max(um[k] || 0, x.util_max[k]); }));
    root.appendChild(sub('Resource utilization, maximum over the capture (60 s figures)', 'res_util', bars(um, 90, 70)));
  }
  const ld = sub('Management plane load average', 'res_mgmt');
  lineChart(ld, {t:tsOf(LOAD), title:'Load average', series:[{name:'1 min', values:LOAD.map(x => x.load1)}, {name:'5 min', values:LOAD.map(x => x.load5)}, {name:'15 min', values:LOAD.map(x => x.load15)}]});
  root.appendChild(ld);
}
// ================= Throughput (from "show counter interface all" in every fast tick)
const bpsM = v => isNum(v) ? v / 1e6 : null;
function renderThroughput(){
  const root = clear($('#b-throughput'));
  if(!TP.available){ root.appendChild(naMsg('the interface counters (show counter interface all)')); return; }
  const T = (TP.t || []).map(ms), rx = (TP.total.rx_bps || []).map(bpsM), tx = (TP.total.tx_bps || []).map(bpsM);
  const sum = rx.map((v, i) => isNum(v) && isNum(tx[i]) ? v + tx[i] : null);
  // the figure the firewall reports in "show session info" (kbps), once per cycle, put on the nearest interval
  const ref = T.map(() => null), half = (TP.dt || []).map(d => d * 500);
  SS.forEach(x => { const t = ms(x.t); if(!isNum(x.kbps) || !isFinite(t)) return;
    let best = -1, bd = Infinity; T.forEach((u, i) => { const dd = Math.abs(u - t); if(dd < bd){ bd = dd; best = i; } });
    if(best >= 0 && bd <= Math.max(half[best] || 0, 1000)) ref[best] = x.kbps / 1000; });
  const a = sub('Total throughput', 'tp_total');
  lineChart(a, {t:T, unit:'Mbit/s', title:'Total throughput of the physical ports', legend:true, series:[
    {name:'received (all physical ports)', values:rx}, {name:'transmitted (all physical ports)', values:tx},
    {name:'received + transmitted', values:sum, dash:'5 4', color:PALETTE[5]},
    {name:'firewall figure (show session info, per cycle)', values:ref, color:PALETTE[4]}],
    extra:i => ['interval: ' + fmtX((TP.dt || [])[i]) + ' s']});
  const peak = Math.max(0, ...sum.filter(isNum)), ok = sum.filter(isNum);
  a.appendChild(E('p', {class:'hint', text:'Peak received + transmitted ' + fmtX(peak) + ' Mbit/s, mean ' + fmtX(ok.length ? ok.reduce((p, q) => p + q, 0) / ok.length : 0) +
    ' Mbit/s over ' + ok.length + ' interval(s); average interval ' + fmtX((TP.dt || []).reduce((p, q) => p + q, 0) / Math.max(1, (TP.dt || []).length)) + ' s.' +
    ((TP.total.rx_bps || []).some(v => v == null) ? ' Some intervals have no total (a port counter went backwards).' : '')}));
  root.appendChild(a);

  const names = Object.keys(TP.interfaces || {});
  const rows = names.map(n => { const f = TP.interfaces[n], r = f.rx_bps.map(bpsM), t = f.tx_bps.map(bpsM);
    const s2 = r.map((v, i) => (isNum(v) ? v : 0) + (isNum(t[i]) ? t[i] : 0));
    return {name:n, f, r, t, peak:Math.max(0, ...s2), mean:s2.length ? s2.reduce((p, q) => p + q, 0) / s2.length : 0}; });
  const b = sub('Throughput per interface', 'tp_ifaces');
  if(!rows.length) b.appendChild(noData('No interface counters were parsed.'));
  else {
    let q = '', busy = true, order = 'peak';
    const grid = E('div', {class:'cols two'}), note = E('p', {class:'hint'});
    const LIMIT = 60;
    const paint = () => {
      clear(grid);
      let list = rows.filter(r => (!busy || r.peak > 0) && (!q || r.name.toLowerCase().includes(q)));
      list.sort((x, y) => order === 'name' ? x.name.localeCompare(y.name, undefined, {numeric:true}) : y.peak - x.peak);
      const total = list.length; list = list.slice(0, LIMIT);
      list.forEach(r => { const h = E('div', null, E('h4', {text:r.name + '   peak ' + fmtX(r.peak) + ' Mbit/s, mean ' + fmtX(r.mean) + ' Mbit/s', style:'margin:8px 0 0'}));
        lineChart(h, {t:T, unit:'Mbit/s', title:'Throughput of ' + r.name, height:170, series:[{name:'received', values:r.r, color:PALETTE[0]}, {name:'transmitted', values:r.t, color:PALETTE[1]}], legend:true});
        grid.appendChild(h); });
      note.textContent = (total > LIMIT ? 'Showing the first ' + LIMIT + ' of ' + total + ' interfaces. ' : total + ' interface(s). ') +
        (TP.skipped_idle ? TP.skipped_idle + ' physical port(s) without configuration and without traffic are not listed. ' : '') + (TP.resets ? TP.resets + ' counter reset(s) left a gap.' : '');
      if(!total) grid.appendChild(noData('No interface matches.'));
      redrawCharts();
    };
    const inp = E('input', {type:'search', size:'24', placeholder:'Filter by name', 'aria-label':'Filter interfaces'});
    inp.addEventListener('input', () => { q = inp.value.trim().toLowerCase(); paint(); });
    const cb = E('input', {type:'checkbox', checked:true, 'aria-label':'Only interfaces with traffic'});
    cb.addEventListener('change', () => { busy = cb.checked; paint(); });
    b.appendChild(E('div', {class:'bar'}, inp, E('label', null, cb, ' only interfaces with traffic'),
      selectBox('Sort by', [['peak', 'peak throughput'], ['name', 'name']], v => { order = v; paint(); })));
    b.appendChild(note); b.appendChild(grid); paint();
  }
  root.appendChild(b);
}
function renderCapture(){
  const root = clear($('#b-capture'));
  const cy = CAP.cycles || [];
  const a = sub('Cycle durations', 'cap_cycles');
  lineChart(a, {t:tsOf(cy), unit:'s', title:'Cycle durations', series:[{name:'total command time per cycle', values:cy.map(x => x.total_s)}], extra:i => ['cycle #' + cy[i].n]});
  if(META.interval_s) a.appendChild(E('p', {class:'hint', text:'Interval: ' + META.interval_s + ' s. Slow-cycle level: ' + (TH.cycle_slow_share != null ? Math.round(TH.cycle_slow_share * 100) : 50) + '% of the interval.' + (CAP.fast_tick_max_s != null ? ' Longest fast tick: ' + CAP.fast_tick_max_s + ' s.' : '')}));
  root.appendChild(a);
  root.appendChild(sub('Commands', 'cap_commands', cmdTable()));
}
'''

JS_MAIN = r'''
// ================= Tabs and start
const built = {};
const RENDER = {overview:renderOverview, findings:renderFindings, pow:renderPow, counters:renderCounters, backlog:renderBacklog, pbp:renderPbp, sessions:renderSessions, throughput:renderThroughput, resources:renderResources, capture:renderCapture};
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

TEMPLATE = (TEMPLATE_HEAD + TEMPLATE_CSS + CREDITS_CSS
            + TEMPLATE_BODY.replace("__TABS__", _TABS_HTML).replace("__PANELS__", _PANELS_HTML)
            .replace("__HELPSTORE__", _STORE).replace(CREDITS_PLACEHOLDER, CREDITS_HTML)
            + JS_CORE + JS_OVERVIEW + JS_FINDINGS + JS_POW + JS_COUNTERS + JS_BACKLOG
            + JS_SESSIONS + JS_MAIN)

"""Page template of the GlobalProtect report (HTML, CSS and JavaScript).

Placeholders (replaced in ONE pass by ``analyzer.render``, so substituted text is never
scanned again): ``__KIND__``, ``__TITLE__``, ``__DATA__`` (JSON blob), and ``__HB_<id>__`` /
``__HP_<id>__`` (help button and collapsible help text, see report_help.py).
The pieces are concatenated in TEMPLATE; the script is one block that ends in JS_MAIN.

Safety: the blob holds raw log text. The script writes data into the page only with
``textContent`` / text nodes (helper ``E``) and sets attributes only from fixed vocabularies
or with ``setAttribute``; there is no ``innerHTML``, ``eval`` or inline handler.
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
:root{--ink:#1c2530;--mute:#5d6b7a;--line:#d8dde3;--bg:#f4f6f8;--card:#fff;--acc:#1f6f8b;--warn-bg:#fff4d6;--warn-bd:#c98a00;
--c-ok:#2f855a;--c-fail:#b42318;--c-warn:#b7791f;--c-mute:#5d6b7a;--c-exp:#2b6cb0}
*{box-sizing:border-box}
body{margin:0;min-width:1200px;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:3200px;margin:0 auto;padding:20px 24px 48px}
h1{font-size:20px;margin:0 0 2px}
h2{font-size:15px;margin:0 0 10px}
h3{font-size:14px;margin:14px 0 6px}
.sub{color:var(--mute);margin:0 0 10px}
.utc{background:var(--warn-bg);border-left:4px solid var(--warn-bd);padding:8px 14px;margin:0 0 14px;border-radius:2px}
section.panel{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px 16px;margin-bottom:16px;overflow-x:auto}
section.panel[hidden]{display:none}
.subpanel{border:1px solid var(--line);border-radius:4px;padding:10px 14px;margin:0 0 14px;background:#fff}
select,input,button{font:inherit;color:inherit;border:1px solid var(--line);border-radius:3px;padding:4px 8px;background:#fff}
button{cursor:pointer}
button:hover{border-color:var(--acc)}
button:focus-visible,select:focus-visible,input:focus-visible,th:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
label{color:var(--mute)}
.bar{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;margin:0 0 10px}
.bar label.ck{color:var(--ink);display:flex;align-items:center;gap:5px;cursor:pointer}
.bar input[type=checkbox]{margin:0;padding:0}
.seg{display:inline-flex}
.seg button{border-radius:0;margin-left:-1px}
.seg button:first-child{border-radius:3px 0 0 3px;margin-left:0}
.seg button:last-child{border-radius:0 3px 3px 0}
.seg button[aria-pressed=true]{background:var(--acc);border-color:var(--acc);color:#fff}
.tabs{display:flex;flex-wrap:wrap;gap:2px;border-bottom:1px solid var(--line);margin:0}
.tabs button{border:1px solid transparent;border-bottom:none;border-radius:4px 4px 0 0;background:transparent;color:var(--mute);padding:8px 18px}
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
td.r,th.r{text-align:right}
.scroll{max-height:clamp(420px,calc(100vh - 360px),1100px);overflow:auto;border:1px solid var(--line)}
.scroll.tall{max-height:none;overflow-y:visible}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.dim,.hint{color:var(--mute)}
.hint{font-size:12px}
.badge{display:inline-block;color:#fff;border-radius:3px;padding:0 6px;margin:0 3px 2px 0;font-size:11px;line-height:17px;white-space:nowrap}
.b-critical,.b-crit,.b-failed{background:#b42318}
.b-warning,.b-warn,.b-cancelled,.b-last_seen{background:#b7791f}
.b-info,.b-abandoned,.b-no_data{background:#5d6b7a}
.b-ok,.b-connected,.b-current{background:#2f855a}
.b-expired{background:#2b6cb0}
.b-internal{background:#0e7490}
.b-historical{background:#fff;color:#5d6b7a;border:1px solid #5d6b7a;line-height:15px}
.astatus{display:inline-block;font-size:12px;line-height:20px;padding:0 10px;border-radius:10px;margin:0 0 12px;cursor:pointer;color:#fff}
.astatus.complete{background:#2f855a}.astatus.partial{background:#b7791f}
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
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(480px,1fr));gap:0 20px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 8px}
.chip{border:1px solid var(--line);border-radius:4px;padding:4px 12px;background:#f7f9fb;min-width:92px}
.chip b{display:block;font-size:20px;line-height:1.2;font-variant-numeric:tabular-nums}
.chip span{font-size:12px;color:var(--mute)}
.chip.o-connected{border-left:4px solid var(--c-ok)}.chip.o-failed{border-left:4px solid var(--c-fail)}
.chip.o-cancelled{border-left:4px solid var(--c-warn)}.chip.o-abandoned{border-left:4px solid var(--c-mute)}.chip.o-expired{border-left:4px solid var(--c-exp)}.chip.o-internal{border-left:4px solid #0e7490}
.lnk{color:var(--acc);cursor:pointer;text-decoration:underline;background:none;border:none;padding:0;font:inherit}
.fnd{border-left:4px solid var(--line);background:#f7f9fb;padding:6px 10px;margin:0 0 6px;border-radius:2px}
.fnd.s-critical{border-color:#b42318;background:#fdecea}.fnd.s-warning{border-color:var(--warn-bd);background:var(--warn-bg)}
.fnd .t{font-weight:600}
.fnd .w{color:var(--mute);font-size:12px}
.fnd .refs{margin-top:3px;font-size:12px}
.fnd .refs .lnk{margin-right:8px}
.cfgnav{display:flex;flex-wrap:wrap;gap:4px 12px;margin:0 0 10px;font-size:13px}
table.cfg td.k{color:var(--mute);width:26%}
table.cfg td.key{width:20%}
table.cfg td.val{overflow-wrap:anywhere;white-space:pre-wrap}
table.keyt td.k{width:14%;white-space:nowrap}
table.keyt td.val{width:44%;min-width:16em;overflow-wrap:break-word}
table.keyt td.src{width:24%;min-width:9em;color:var(--mute);overflow-wrap:break-word}
.cols.sumcols{grid-template-columns:minmax(0,2fr) minmax(0,3fr)}
@media(max-width:1100px){.cols.sumcols{grid-template-columns:minmax(0,1fr)}}
.cfgtog{font:inherit;font-size:12px;padding:1px 8px;cursor:pointer}
.cfgbody[hidden]{display:none}
.emp{color:var(--mute);font-style:italic}
.hl{background:#fff2a8}
.cfgp{border:1px solid var(--line);border-radius:4px;margin:0 0 12px;padding:8px 12px}
.cfgp>.sechead h3{font-size:15px}
.cfgp .note{color:var(--mute);font-size:12px;margin:0 0 6px}
.xp{padding:0 6px;line-height:16px;font-size:12px;min-width:22px}
tr.att{cursor:pointer}
tr.att:hover td{background:#f4f9fb}
tr.att.o-failed td:first-child{box-shadow:inset 4px 0 0 var(--c-fail)}
tr.att.o-connected td:first-child{box-shadow:inset 4px 0 0 var(--c-ok)}
tr.att.o-cancelled td:first-child{box-shadow:inset 4px 0 0 var(--c-warn)}
tr.att.o-abandoned td:first-child{box-shadow:inset 4px 0 0 var(--c-mute)}
tr.att.o-expired td:first-child{box-shadow:inset 4px 0 0 var(--c-exp)}
tr.att.o-internal td:first-child{box-shadow:inset 4px 0 0 #0e7490}
.ecat{color:var(--mute);font-size:12px;margin-left:6px}
tr.att.in-grp td:nth-child(2){padding-left:26px}
tr.grp td{background:#fdf6e3;cursor:pointer;font-weight:600}
tr.flash td{animation:flash 2.2s}
@keyframes flash{0%,60%{background:#fff2a8}100%{background:transparent}}
tr.det>td{background:#fafbfc;padding:8px 14px 12px 40px;white-space:normal}
.det .steps{width:auto;min-width:60%;max-width:100%;margin-top:6px}
.det .steps td,.det .steps th{padding:2px 10px;white-space:normal}
.det .steps td.nw{white-space:nowrap}
.det .steps tr.lv-error td:nth-child(4){color:#b42318;font-weight:600}
.det .steps tr.lv-warn td:nth-child(4){color:#8a5a00}
.nodet{color:var(--mute);font-style:italic;margin:6px 0}
#strip{width:100%;height:auto;display:block}
#strip .ax{fill:var(--mute);font-size:11px}
#strip .ln{stroke:#e3e7ec}
#strip .mk{cursor:pointer}
#strip .mk:hover{stroke:#1c2530;stroke-width:1.5}
.leg{display:flex;flex-wrap:wrap;gap:4px 18px;font-size:12px;margin:4px 0 0;color:var(--ink)}
.leg i{font-style:normal;font-size:14px;margin-right:4px}
.msg{padding:10px 14px;background:#f7f9fb;border:1px dashed var(--line);margin:6px 0}
.pg{display:flex;gap:10px;align-items:center;margin:8px 0 0}
@media print{
  body{min-width:0;background:#fff}
  .tabs,.bar,.helpbtn,.help,.pg,.xp,.cfgnav,.astatus{display:none!important}
  section.panel[hidden]{display:block!important}
  .cfgbody[hidden]{display:block!important}
  .cfgtog{display:none}
  section.panel{break-inside:auto;border:none;overflow:visible}
  .scroll{max-height:none;overflow:visible}
  th{position:static}
}
"""

TEMPLATE_BODY = r"""</style>
</head>
<body>
<main>
__CREDITS__
<h1 id="title">__TITLE__</h1>
<p class="sub" id="sub"></p>
<div><span class="astatus" id="astatus" role="button" tabindex="0"></span></div>
<div class="utc">Times are the local wall-clock time of the client, as written in the logs. No time zone conversion is applied. "Newest log record" anchors every relative period (not today's date).</div>
<div class="tabs" id="tabs" role="tablist">
<button type="button" role="tab" id="tab-summary" aria-controls="p-summary" aria-selected="true">Summary</button>
<button type="button" role="tab" id="tab-config" aria-controls="p-config" aria-selected="false">Client configuration</button>
<button type="button" role="tab" id="tab-timeline" aria-controls="p-timeline" aria-selected="false">Connection timeline</button>
<button type="button" role="tab" id="tab-findings" aria-controls="p-findings" aria-selected="false">Findings</button>
<button type="button" role="tab" id="tab-coverage" aria-controls="p-coverage" aria-selected="false">Source coverage</button>
</div>
<section class="panel" id="p-summary" role="tabpanel" aria-labelledby="tab-summary"><div class="sechead" data-help="summary"><h2>Summary</h2></div><div id="b-summary"></div></section>
<section class="panel" id="p-config" role="tabpanel" aria-labelledby="tab-config" hidden><div class="sechead" data-help="config"><h2>Client configuration</h2></div><div id="b-config"></div></section>
<section class="panel" id="p-timeline" role="tabpanel" aria-labelledby="tab-timeline" hidden><div class="sechead" data-help="timeline"><h2>Connection timeline</h2></div><div id="b-timeline"></div></section>
<section class="panel" id="p-findings" role="tabpanel" aria-labelledby="tab-findings" hidden><div class="sechead" data-help="findings"><h2>Findings</h2></div><div id="b-findings"></div></section>
<section class="panel" id="p-coverage" role="tabpanel" aria-labelledby="tab-coverage" hidden><div class="sechead" data-help="coverage"><h2>Source coverage</h2></div><div id="b-coverage"></div></section>
</main>
<div id="helpstore">
__HELPSTORE__
</div>
"""

JS_CORE = r'''<script>
const D = __DATA__;
const META = D.meta, CF = D.config, TL = D.timeline, FND = D.findings || [], ATT = TL.attempts || [];
const OUTS = ['connected','internal','failed','cancelled','abandoned','expired'], KINDS = ['login','pre-logon','auto-reconnect','auto-restore'];
const OUTLBL = {connected:'Connected',internal:'Internal',failed:'Failed',cancelled:'Cancelled',abandoned:'Abandoned',expired:'Expired'};
const OUTCOL = {connected:'#2f855a',internal:'#0e7490',failed:'#b42318',cancelled:'#b7791f',abandoned:'#5d6b7a',expired:'#2b6cb0'};
const KINDLBL = {login:'Login','pre-logon':'Pre-logon','auto-reconnect':'Auto-reconnect','auto-restore':'Auto-restore'};
const KINDSHAPE = {login:'circle','pre-logon':'square','auto-reconnect':'triangle','auto-restore':'diamond'};
const KINDSYM = {login:'\u25cf','pre-logon':'\u25a0','auto-reconnect':'\u25b2','auto-restore':'\u25c6'};
const FRESHLBL = {current:'At collection',last_seen:'Last seen in logs',historical:'Historical'};
const LEVELS = ['critical','warning','info'];
const TABS = ['summary','config','timeline','findings','coverage'];
const STORE_KEY = 'panosToolbox.gpReport.v2';
const PRESETS = {'24h':864e5,'7d':7*864e5,'30d':30*864e5,'all':null,'custom':null};
const $ = s => document.querySelector(s);

function E(tag, a, ...kids){
  const e = document.createElement(tag);
  if(a) for(const n in a){ const v = a[n]; if(v == null || v === false) continue;
    if(n === 'text') e.textContent = v; else if(n === 'class') e.className = v; else e.setAttribute(n, v === true ? '' : String(v)); }
  for(const c of kids){ if(c == null || c === false) continue; e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); }
  return e;
}
const NS = 'http://www.w3.org/2000/svg';
function S(tag, a, ...kids){
  const e = document.createElementNS(NS, tag);
  if(a) for(const n in a) if(a[n] != null) e.setAttribute(n, String(a[n]));
  for(const c of kids) if(c) e.appendChild(c);
  return e;
}
function clear(e){ while(e.firstChild) e.removeChild(e.firstChild); return e; }
const pick = (v, list) => list.includes(v) ? v : null;
const badge = (cls, text, title) => E('span', {class:'badge b-' + cls, text, title});

// ---- time helpers (naive local times; Date.UTC is used for arithmetic only)
function ms(s){
  if(!s) return NaN;
  const m = /^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d)(?:\.(\d+))?)?/.exec(s);
  if(!m) return NaN;
  return Date.UTC(+m[1], +m[2]-1, +m[3], +m[4], +m[5], +(m[6]||0), Math.round(+('0.' + (m[7]||'0')) * 1000));
}
const pad = n => (n < 10 ? '0' : '') + n;
function isoOf(t){ const d = new Date(t); return d.getUTCFullYear() + '-' + pad(d.getUTCMonth()+1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()); }
function sec(s){ return s ? String(s).replace('T',' ').slice(0,19) : ''; }
function fmtMs(n){
  if(n == null) return '';
  if(n < 1000) return n + ' ms';
  if(n < 60000) return (n/1000).toFixed(1) + ' s';
  const s = Math.round(n/1000), h = Math.floor(s/3600), m = Math.floor(s%3600/60);
  if(h) return h + ' h ' + pad(m) + ' min';
  return m + ' min ' + pad(s%60) + ' s';
}
function fmtBytes(n){ if(n == null) return ''; if(n < 1024) return n + ' B'; if(n < 1048576) return (n/1024).toFixed(1) + ' KB'; return (n/1048576).toFixed(1) + ' MB'; }
const emptyVal = () => E('span', {class:'emp', text:'(empty)'});

// ---- persisted UI state (localStorage may be unavailable)
const ST = {tab:'summary', cfg:'', tl:{preset:'7d', from:'', to:'', out:OUTS.slice(), kind:KINDS.slice(), q:'', sort:'start', dir:-1, page:100}};
const SORTS = ['start','kind','outcome','dur','portal','gateway','protocol','trigger','cycles','error'];
function loadState(){
  try{
    const o = JSON.parse(localStorage.getItem(STORE_KEY) || 'null'); if(!o || typeof o !== 'object') return;
    if(pick(o.tab, TABS)) ST.tab = o.tab;
    if(typeof o.cfg === 'string') ST.cfg = o.cfg.slice(0, 200);
    const t = o.tl; if(!t || typeof t !== 'object') return;
    if(pick(t.preset, Object.keys(PRESETS))) ST.tl.preset = t.preset;
    for(const k of ['from','to','q']) if(typeof t[k] === 'string') ST.tl[k] = t[k].slice(0, 200);
    if(Array.isArray(t.out)) ST.tl.out = t.out.filter(x => OUTS.includes(x));
    if(Array.isArray(t.kind)) ST.tl.kind = t.kind.filter(x => KINDS.includes(x));
    if(pick(t.sort, SORTS)) ST.tl.sort = t.sort;
    if(t.dir === 1 || t.dir === -1) ST.tl.dir = t.dir;
    if([50,100,250,500,1e9].includes(t.page)) ST.tl.page = t.page;
  }catch(e){}
}
function saveState(){ try{ localStorage.setItem(STORE_KEY, JSON.stringify(ST)); }catch(e){} }
loadState();

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

// ---- derived data
const byId = {}; ATT.forEach((a, i) => { byId[a.id] = a; a._i = i; a._t = ms(a.start); a._e = ms(a.end);
  a._q = [a.id, a.portal, a.gateway, a.user, a.trigger, a.protocol, a.kind, a.outcome, a.tunnel_ip, a.error && a.error.text, a.error && a.error.raw].join(' ').toLowerCase(); });
const stormById = {}; (TL.storms || []).forEach(s => { stormById[s.id] = s; });
const secById = {}; (CF.sections || []).forEach(s => { secById[s.id] = s; });
let ANCHOR = ms(META.anchor);
if(isNaN(ANCHOR)) ANCHOR = ATT.length ? Math.max(...ATT.map(a => a._t)) : Date.now();

function refLink(r){
  if(byId[r]){ const b = E('button', {type:'button', class:'lnk', text:r, title:'Open this attempt in the timeline'}); b.addEventListener('click', () => gotoAttempt(r)); return b; }
  if(secById[r]){ const b = E('button', {type:'button', class:'lnk', text:secById[r].title, title:'Open this configuration section'}); b.addEventListener('click', () => gotoSection(r)); return b; }
  return E('span', {class:'dim', text:r});
}
function freshBadge(f){ return badge(pick(f, Object.keys(FRESHLBL)) || 'historical', FRESHLBL[f] || String(f)); }
'''

JS_SUMMARY = r'''
// ================= Summary
function keyTable(){
  const rows = D.key_settings || [];
  if(!rows.length) return E('p', {class:'hint', text:'No key settings were found in the bundle.'});
  const t = E('table', {class:'cfg keyt'}, E('thead', null, E('tr', null, E('th', {text:'Setting'}), E('th', {text:'Value'}), E('th', {text:'Currency'}), E('th', {text:'Source'}))));
  const tb = E('tbody'); t.appendChild(tb);
  for(const r of rows){
    tb.appendChild(E('tr', null, E('td', {class:'k', text:r.label}),
      E('td', {class:'val'}, r.value === '' ? emptyVal() : r.value), E('td', {class:'nw'}, freshBadge(r.freshness)),
      E('td', {class:'src', text:r.source || ''})));
  }
  return t;
}
function periodList(preset){ const w = PRESETS[preset]; return ATT.filter(a => w == null || a._t >= ANCHOR - w); }
function countBy(list){
  const c = {total:list.length, storm:0, o:{}, k:{}};
  OUTS.forEach(o => { c.o[o] = 0; KINDS.forEach(k => { c.k[k + '|' + o] = 0; }); });
  for(const a of list){ if(c.o[a.outcome] != null){ c.o[a.outcome]++; c.k[a.kind + '|' + a.outcome]++; } if(a.storm != null) c.storm++; }
  return c;
}
function counters(list){
  const c = countBy(list), wrap = E('div');
  const chips = E('div', {class:'chips'}, E('div', {class:'chip'}, E('b', {text:String(c.total)}), E('span', {text:'Attempts'})));
  OUTS.forEach(o => chips.appendChild(E('div', {class:'chip o-' + o}, E('b', {text:String(c.o[o])}), E('span', {text:OUTLBL[o]}))));
  wrap.appendChild(chips);
  const t = E('table', {style:'width:auto'}, E('thead', null, E('tr', null, E('th', {text:'Kind'}), ...OUTS.map(o => E('th', {class:'r', text:OUTLBL[o]})))));
  const tb = E('tbody'); t.appendChild(tb);
  KINDS.forEach(k => tb.appendChild(E('tr', null, E('td', {text:KINDLBL[k]}), ...OUTS.map(o => E('td', {class:'r', text:String(c.k[k + '|' + o])})))));
  wrap.appendChild(t);
  if(c.storm) wrap.appendChild(E('p', {class:'hint', text:c.storm + ' of these attempts belong to a retry storm (already counted above).'}));
  return wrap;
}
function renderSummary(){
  const root = clear($('#b-summary'));
  const st = D.state || {};
  const left = E('div', {class:'subpanel'}, E('h3', {text:'Identity and state at collection'}));
  const dl = E('dl', {class:'kv'});
  for(const r of (D.identity || [])){ dl.appendChild(E('dt', {text:r.label})); dl.appendChild(E('dd', null, r.value === '' ? emptyVal() : r.value)); }
  const conn = st.connected === true ? 'Connected' : st.connected === false ? 'Not connected' : 'Unknown (no collection snapshot)';
  dl.appendChild(E('dt', {text:'Connection at collection'}));
  dl.appendChild(E('dd', null, E('b', {text:conn}), st.conclusion ? ' - ' + st.conclusion : ''));
  if(st.last_state){ dl.appendChild(E('dt', {text:'Last service state'})); dl.appendChild(E('dd', {text:st.last_state + (st.last_state_at ? ' (' + sec(st.last_state_at) + ')' : '')})); }
  dl.appendChild(E('dt', {text:'Newest log record'})); dl.appendChild(E('dd', {text:sec(META.anchor)}));
  dl.appendChild(E('dt', {text:'Findings status'})); dl.appendChild(E('dd', null, badge(pick(D.status, ['ok','warning','critical','no_data']) || 'no_data', String(D.status))));
  left.appendChild(dl);
  const right = E('div', {class:'subpanel'}, E('div', {class:'sechead'}, E('h3', {text:'Key settings'})));
  addHelp(right.firstChild, 'keysettings'); right.appendChild(keyTable());
  root.appendChild(E('div', {class:'cols sumcols'}, left, right));
  const lo = ANCHOR - PRESETS['7d'];
  const cp = E('div', {class:'subpanel'}, E('div', {class:'sechead'}, E('h3', {text:'Attempts in the last 7 days'}), E('span', {class:'meta', text:sec(isoOf(lo)) + ' to ' + sec(META.anchor) + ' (7 days before the newest log record)'})));
  addHelp(cp.firstChild, 'sum_counters');
  cp.appendChild(counters(periodList('7d')));
  const go = E('button', {type:'button', text:'Open in the Connection timeline'});
  go.addEventListener('click', () => { Object.assign(ST.tl, {preset:'7d', from:'', to:'', out:OUTS.slice(), kind:KINDS.slice(), q:''}); syncControls(); showTab('timeline'); });
  cp.appendChild(go);
  const fp = E('div', {class:'subpanel'}, E('div', {class:'sechead'}, E('h3', {text:'Findings'})));
  addHelp(fp.firstChild, 'sum_findings');
  if(!FND.length) fp.appendChild(E('p', {text:'No findings.'}));
  for(const lv of LEVELS){
    const items = FND.filter(f => f.level === lv); if(!items.length) continue;
    fp.appendChild(E('div', null, badge(lv, lv.toUpperCase()), ' ' + items.length + (items.length === 1 ? ' finding' : ' findings')));
    items.slice(0, 5).forEach(f => fp.appendChild(findingBox(f, 3)));
    if(items.length > 5) fp.appendChild(E('p', {class:'hint', text:'+' + (items.length - 5) + ' more in the Findings tab.'}));
  }
  root.appendChild(E('div', {class:'cols'}, cp, fp));
}
'''

JS_CONFIG = r'''
// ================= Client configuration
const cfgPanels = [];
const CFG_COLLAPSE_ROWS = 40;
function paintCfgPanel(p, forced){
  const show = forced || p.open;
  p.body.hidden = !show;
  p.tog.textContent = show ? 'Collapse' : 'Expand (' + p.nrows + ' rows)';
  p.tog.setAttribute('aria-expanded', show ? 'true' : 'false');
  p.tog.title = forced && !p.open ? 'Shown because it contains matches of the filter' : '';
}
function longVal(v){ return v.length > 200 || v.split('\n').length > 3; }
function valueCell(v){
  const td = E('td', {class:'val'});
  if(v === '' || v == null){ td.appendChild(emptyVal()); return td; }
  if(!longVal(v)){ td.textContent = v; return td; }
  const short = v.split('\n').slice(0, 3).join('\n').slice(0, 160) + '...';
  const txt = E('span', {text:short}), btn = E('button', {type:'button', class:'lnk', text:'expand'});
  let open = false;
  btn.addEventListener('click', () => { open = !open; txt.textContent = open ? v : short; btn.textContent = open ? 'collapse' : 'expand'; });
  td.appendChild(txt); td.appendChild(document.createTextNode(' ')); td.appendChild(btn);
  td.appendChild(E('span', {class:'hint', text:' (' + v.length + ' characters)'}));
  return td;
}
function buildCfgPanel(cs){
  const head = E('div', {class:'sechead'}, E('h3', {text:cs.title}), freshBadge(cs.freshness),
    E('span', {class:'meta', text:'Source: ' + (cs.sources && cs.sources.length ? cs.sources.join(', ') : 'n/a') + ' | Data time: ' + (cs.timestamp ? sec(cs.timestamp) : 'none')}));
  const box = E('section', {class:'cfgp'}, head);
  addHelp(head, 'cfg_' + cs.id);
  const body = E('div', {class:'cfgbody'});
  const nrows = cs.groups.reduce((n, g) => n + g.rows.length, 0);
  const tog = E('button', {type:'button', class:'cfgtog'});
  head.insertBefore(tog, head.firstChild.nextSibling);
  if(cs.note) body.appendChild(E('p', {class:'note', text:cs.note}));
  const groups = [];
  for(const g of cs.groups){
    const gt = E('div', null, E('h4', {text:g.title, style:'margin:8px 0 4px'}));
    const tb = E('tbody');
    const rows = [];
    for(const r of g.rows){
      const tr = E('tr', null, E('td', {class:'k'}, r.label, r.hint ? E('div', {class:'hint', text:r.hint}) : null), valueCell(r.value), E('td', {class:'key mono dim', text:r.key || ''}));
      tb.appendChild(tr);
      rows.push({tr, s:(r.label + ' ' + r.value + ' ' + r.key + ' ' + r.hint).toLowerCase()});
    }
    if(!g.rows.length) gt.appendChild(E('p', {class:'hint', text:'(no rows)'}));
    else gt.appendChild(E('table', {class:'cfg'}, E('thead', null, E('tr', null, E('th', {text:'Setting'}), E('th', {text:'Value'}), E('th', {text:'Raw key'}))), tb));
    body.appendChild(gt); groups.push({gt, rows});
  }
  box.appendChild(body);
  const p = {sec:cs, box, body, tog, groups, title:(cs.title + ' ' + cs.id).toLowerCase(), nrows, open:nrows <= CFG_COLLAPSE_ROWS};
  tog.addEventListener('click', () => { p.open = !p.open; paintCfgPanel(p, false); });
  return p;
}
function applyCfgFilter(){
  const q = ST.cfg.trim().toLowerCase(); let total = 0;
  for(const p of cfgPanels){
    let vis = 0;
    for(const g of p.groups){
      let gv = 0;
      for(const r of g.rows){ const show = !q || p.title.includes(q) || r.s.includes(q); r.tr.hidden = !show; if(show) gv++; }
      g.gt.hidden = gv === 0 && !!q; vis += gv;
    }
    p.box.hidden = !!q && vis === 0; total += vis; paintCfgPanel(p, !!q && vis > 0);
  }
  $('#cfg-count').textContent = q ? total + ' matching setting(s)' : cfgPanels.reduce((n, p) => n + p.nrows, 0) + ' settings in ' + cfgPanels.length + ' sections';
}
function renderConfig(){
  const root = clear($('#b-config'));
  const kb = E('div', {class:'subpanel'}, E('div', {class:'sechead'}, E('h3', {text:'Key settings'})));
  addHelp(kb.firstChild, 'keysettings'); kb.appendChild(keyTable()); root.appendChild(kb);
  const inp = E('input', {type:'search', size:'44', placeholder:'Filter all settings (name, value, raw key)', 'aria-label':'Filter settings', value:ST.cfg});
  inp.addEventListener('input', () => { ST.cfg = inp.value; applyCfgFilter(); saveState(); });
  root.appendChild(E('div', {class:'bar'}, inp, E('span', {class:'hint', id:'cfg-count'})));
  const nav = E('div', {class:'cfgnav'});
  for(const sec of (CF.sections || [])){
    const p = buildCfgPanel(sec); cfgPanels.push(p);
    const b = E('button', {type:'button', class:'lnk', text:sec.title}); b.addEventListener('click', () => { if(p.box.hidden){ ST.cfg = ''; inp.value = ''; applyCfgFilter(); } p.open = true; paintCfgPanel(p, false); p.box.scrollIntoView({block:'start'}); });
    nav.appendChild(b);
  }
  root.appendChild(nav);
  cfgPanels.forEach(p => root.appendChild(p.box));
  if(!cfgPanels.length) root.appendChild(E('p', {class:'msg', text:'No configuration data in the bundle.'}));
  applyCfgFilter();
}
function gotoSection(id){
  showTab('config');
  const p = cfgPanels.find(x => x.sec.id === id); if(!p) return;
  if(p.box.hidden){ ST.cfg = ''; const i = $('#b-config input[type=search]'); if(i) i.value = ''; applyCfgFilter(); saveState(); }
  p.open = true; paintCfgPanel(p, false);
  p.box.scrollIntoView({block:'start'});
}
'''

JS_TIMELINE = r'''
// ================= Connection timeline
const COLS = [['start','Time',a=>a._t,'nw'],['kind','Kind',a=>KINDS.indexOf(a.kind),'nw'],['outcome','Outcome',a=>OUTS.indexOf(a.outcome),'nw'],
  ['dur','Duration',a=>a.duration_ms == null ? -1 : a.duration_ms,'nw r'],['portal','Portal',a=>a.portal || ''],['gateway','Gateway',a=>a.gateway || ''],
  ['protocol','Protocol',a=>a.protocol || '','nw'],['trigger','Trigger',a=>a.trigger || '','nw'],['cycles','Cycles',a=>a.cycles || 0,'nw r'],['error','Error',a=>a.error ? a.error.text : '']];
const NCOL = COLS.length + 1;
const expanded = new Set(), openStorms = new Set();
let CUR = {list:[], items:[], shown:0};
let tlBuilt = false, ui = {};

function win(){
  const f = ST.tl;
  if(f.preset === 'custom'){ const lo = ms(f.from), hi = ms(f.to); return [isNaN(lo) ? -Infinity : lo, isNaN(hi) ? Infinity : hi]; }
  const w = PRESETS[f.preset]; return w == null ? [-Infinity, Infinity] : [ANCHOR - w, Infinity];
}
function passes(a, skipOut){
  const f = ST.tl, [lo, hi] = win();
  if(a._t < lo || a._t > hi) return false;
  if(!f.kind.includes(a.kind)) return false;
  if(!skipOut && !f.out.includes(a.outcome)) return false;
  if(f.q && !a._q.includes(f.q.trim().toLowerCase())) return false;
  return true;
}
function sortedList(){
  const col = COLS.find(c => c[0] === ST.tl.sort) || COLS[0], d = ST.tl.dir;
  return ATT.filter(a => passes(a)).sort((x, y) => { const p = col[2](x), q = col[2](y); return (p < q ? -1 : p > q ? 1 : x._t - y._t) * d; });
}
function buildItems(list){
  const items = [], groups = new Map();
  for(const a of list){
    if(a.storm != null && stormById[a.storm]){ let g = groups.get(a.storm); if(!g){ g = {type:'storm', id:a.storm, atts:[]}; groups.set(a.storm, g); items.push(g); } g.atts.push(a); }
    else items.push({type:'att', a});
  }
  return items.map(it => it.type === 'storm' && it.atts.length < 2 ? {type:'att', a:it.atts[0]} : it);
}
function attRow(a, inGrp){
  const oc = pick(a.outcome, OUTS) || 'x';
  const x = E('button', {type:'button', class:'xp', 'aria-expanded':String(expanded.has(a.id)), 'aria-label':'Details of attempt ' + a.id, text:expanded.has(a.id) ? '-' : '+'});
  const tr = E('tr', {class:'att o-' + oc + (inGrp ? ' in-grp' : ''), 'data-id':a.id},
    E('td', null, x), E('td', {class:'nw', title:a.id + ' | ' + a.start}, sec(a.start)), E('td', {class:'nw', text:KINDLBL[a.kind] || a.kind}),
    E('td', {class:'nw'}, badge(oc, OUTLBL[a.outcome] || a.outcome)), E('td', {class:'nw r', text:fmtMs(a.duration_ms)}),
    E('td', {text:a.portal || ''}), E('td', {text:a.gateway || ''}), E('td', {class:'nw', text:a.protocol || ''}), E('td', {class:'nw', text:a.trigger || ''}),
    E('td', {class:'nw r', text:a.cycles > 1 ? String(a.cycles) : (a.cycles ? '1' : '')}), E('td', null, a.error ? a.error.text : '', a.error_category ? E('span', {class:'ecat', text:'[' + a.error_category + ']'}) : ''));
  return tr;
}
function kvRow(dl, k, v){ if(v == null || v === '') return; dl.appendChild(E('dt', {text:k})); dl.appendChild(E('dd', {text:String(v)})); }
function stepsTable(a){
  const t = E('table', {class:'steps'}, E('thead', null, E('tr', null, E('th', {text:'Time'}), E('th', {class:'r', text:'Offset'}), E('th', {text:'Phase'}), E('th', {text:'Step'}), E('th', {text:'Source'}))));
  const tb = E('tbody'); t.appendChild(tb);
  const d0 = (a.start || '').slice(0, 10);
  for(const s of a.steps){
    const off = ms(s.ts) - a._t, txt = s.text + (s.count > 1 ? ' (x' + s.count + (s.until ? ' until ' + String(s.until).slice(11, 23) : '') + ')' : '');
    const lv = pick(s.level, ['error','warn','info','ok']) || 'info';
    tb.appendChild(E('tr', {class:'lv-' + lv}, E('td', {class:'nw mono', text:String(s.ts || '').slice(0, 10) === d0 ? String(s.ts).slice(11, 23) : sec(s.ts)}),
      E('td', {class:'nw r mono', text:isNaN(off) ? '' : (off < 0 ? '-' : '+') + (Math.abs(off) / 1000).toFixed(3) + ' s'}),
      E('td', {class:'nw', text:s.phase}), E('td', {text:txt}), E('td', {class:'nw dim', text:s.source || ''})));
  }
  return t;
}
function detRow(a){
  const box = E('div', {class:'det'}), dl = E('dl', {class:'kv'});
  kvRow(dl, 'Attempt', a.id + ' (' + (KINDLBL[a.kind] || a.kind) + ')'); kvRow(dl, 'Start', a.start); kvRow(dl, 'End', a.end);
  kvRow(dl, 'User', a.user); kvRow(dl, 'Tunnel IP', a.tunnel_ip); kvRow(dl, 'Sources', (a.sources || []).join(', '));
  if(a.outcome === 'cancelled'){ const ce = (a.details || {}).cancel_evidence; kvRow(dl, 'Cancelled', ce === 'explicit' ? 'explicit user cancel (the log has a cancel line)' : ce === 'inferred' ? 'inferred from a user disconnect during the attempt (no explicit cancel line)' : 'evidence not recorded'); }
  if(a.outcome === 'expired') kvRow(dl, 'Expired', (a.details || {}).expired_reason === 'saml-timeout' ? 'the SAML sign-in was not completed before the portal SAML timeout' + ((a.details || {}).saml_timeout_s ? ' (' + a.details.saml_timeout_s + ' s)' : '') : 'downtime over the retry grace period; no reconnection was attempted' + ((a.details || {}).modern_standby ? ' (the PC waited in modern standby)' : ''));
  if(a.outcome === 'internal') kvRow(dl, 'Internal', 'the client detected the internal network and created no tunnel on purpose; counted as a success');
  if(a.error_category) kvRow(dl, 'Error category', a.error_category);
  if(a.error){ kvRow(dl, 'Error', a.error.text); kvRow(dl, 'Logged message', a.error.raw); kvRow(dl, a.outcome === 'failed' ? 'Failed at stage' : 'Stage', a.error.stage); }
  const dc = a.disconnect;
  if(dc){ kvRow(dl, 'Disconnect', sec(dc.time) + (dc.reason ? ' - ' + dc.reason : '') + (dc.by_user ? ' (by the user)' : ''));
    if(dc.session_ms != null) kvRow(dl, 'Session duration', fmtMs(dc.session_ms));
    if(dc.restored_by) kvRow(dl, 'Restored by', dc.restored_by); }
  else if(a.outcome === 'connected') kvRow(dl, 'Disconnect', 'not found in the logs (still connected, or logs end first)');
  if(a.storm != null) kvRow(dl, 'Retry storm', '#' + a.storm);
  const dd = a.details || {};
  const sw = Array.isArray(dd.gateway_switches) ? dd.gateway_switches : [];
  if(sw.length) kvRow(dl, 'Manual gateway switches', sw.length + ' in this session: ' + sw.map(g => sec(g.time) + ' ' + (g.gateway || '?') + (g.protocol ? ' (' + g.protocol + ')' : '')).join('; '));
  for(const k of Object.keys(dd)){ if(k === 'gateway_switches' || k === 'cancel_evidence') continue; const v = dd[k]; kvRow(dl, k.replace(/_/g, ' '), v !== null && typeof v === 'object' ? JSON.stringify(v) : v); }
  box.appendChild(dl);
  if(a.has_detail && a.steps && a.steps.length){ box.appendChild(E('h4', {text:'Phase steps (' + a.steps.length + ')', style:'margin:10px 0 0'})); box.appendChild(stepsTable(a)); }
  else { const w = (TL.coverage || {}).detail_window;
    box.appendChild(E('p', {class:'nodet', text:'No detailed logs for this period (service/agent logs cover ' + (w ? sec(w.first) + ' - ' + sec(w.last) : 'nothing: no service or agent log in the bundle') + ').'})); }
  return E('tr', {class:'det', 'data-did':a.id}, E('td', {colspan:String(NCOL)}, box));
}
function grpRow(g){
  const s = stormById[g.id] || {}, open = openStorms.has(g.id);
  const errs = Object.keys(s.by_error || {}).slice(0, 3).map(k => k + ' (' + s.by_error[k] + ')').join('; ');
  const x = E('button', {type:'button', class:'xp', 'aria-expanded':String(open), 'aria-label':'Retry storm ' + g.id, text:open ? '-' : '+'});
  return E('tr', {class:'grp', 'data-sid':String(g.id)}, E('td', null, x), E('td', {colspan:String(NCOL - 1)},
    'Retry storm #' + g.id + ': ' + g.atts.length + ' attempts' + (g.atts.length !== s.count ? ' shown of ' + s.count : '') + ', ' + sec(s.start) + ' - ' + sec(s.end) +
    (s.median_interval_ms != null ? ', median interval ' + fmtMs(s.median_interval_ms) : '') + (errs ? ' | ' + errs : '')));
}
function renderRows(){
  const tb = clear(ui.tbody), n = Math.min(CUR.shown, CUR.items.length);
  for(let i = 0; i < n; i++){
    const it = CUR.items[i];
    if(it.type === 'att'){ tb.appendChild(attRow(it.a, false)); if(expanded.has(it.a.id)) tb.appendChild(detRow(it.a)); }
    else { tb.appendChild(grpRow(it)); if(openStorms.has(it.id)) for(const a of it.atts){ tb.appendChild(attRow(a, true)); if(expanded.has(a.id)) tb.appendChild(detRow(a)); } }
  }
  clear(ui.pg);
  ui.pg.appendChild(E('span', {text:'Showing ' + n + ' of ' + CUR.items.length + ' rows' + (CUR.items.length !== CUR.list.length ? ' (' + CUR.list.length + ' attempts, retry storms grouped)' : '')}));
  if(n < CUR.items.length){
    const more = E('button', {type:'button', text:'Show ' + Math.min(ST.tl.page, CUR.items.length - n) + ' more'}), all = E('button', {type:'button', text:'Show all'});
    more.addEventListener('click', () => { CUR.shown += ST.tl.page; renderRows(); }); all.addEventListener('click', () => { CUR.shown = CUR.items.length; renderRows(); });
    ui.pg.appendChild(more); ui.pg.appendChild(all);
  }
  if(!CUR.items.length) ui.tbody.appendChild(E('tr', null, E('td', {colspan:String(NCOL)}, E('div', {class:'msg', text: ATT.length ? 'No attempts match the filters. Widen the period (30 d or All) or reset the filters.' : 'No connection attempts were found in the bundle.'}))));
  ui.thead.querySelectorAll('th[data-sort]').forEach(th => { const on = th.getAttribute('data-sort') === ST.tl.sort; if(on) th.setAttribute('aria-sort', ST.tl.dir > 0 ? 'ascending' : 'descending'); else th.removeAttribute('aria-sort'); });
}
function toggleAtt(id){ if(expanded.has(id)) expanded.delete(id); else expanded.add(id); renderRows(); }
function onTableClick(e){
  const tr = e.target.closest('tr'); if(!tr || e.target.closest('a')) return;
  if(tr.classList.contains('att')) toggleAtt(tr.getAttribute('data-id'));
  else if(tr.classList.contains('grp')){ const id = +tr.getAttribute('data-sid'); if(openStorms.has(id)) openStorms.delete(id); else openStorms.add(id); renderRows(); }
}

// ---- strip chart
const LANE = 30, PL = 86, PR = 16, PT = 8, PB = 30;
function tickStep(range){
  const M = 6e4, H = 36e5, Dd = 864e5, steps = [M, 5*M, 15*M, 30*M, H, 3*H, 6*H, 12*H, Dd, 2*Dd, 7*Dd, 14*Dd, 30*Dd, 60*Dd, 91*Dd, 182*Dd];
  return steps.find(s => range / s <= 12) || steps[steps.length - 1];
}
function drawStrip(){
  const host = clear(ui.stripHost), list = CUR.list;
  if(!list.length){ host.appendChild(E('p', {class:'hint', text:'No attempts to draw for these filters.'})); return; }
  const W = Math.max(640, host.clientWidth || 1100), H = PT + LANE * OUTS.length + PB, [wl, wh] = win();
  let lo = Math.min(...list.map(a => a._t)), hi = Math.max(...list.map(a => a._t));
  if(isFinite(wl)) lo = wl; if(isFinite(wh)) hi = wh; else if(ST.tl.preset !== 'all' && ST.tl.preset !== 'custom') hi = ANCHOR;
  if(hi - lo < 36e5){ const c = (hi + lo) / 2; lo = c - 18e5; hi = c + 18e5; }
  const x = t => PL + (t - lo) / (hi - lo) * (W - PL - PR), svg = S('svg', {id:'strip', viewBox:'0 0 ' + W + ' ' + H, role:'img', 'aria-label':'Attempts over time, one row per outcome'});
  OUTS.forEach((o, i) => { const y = PT + i * LANE + LANE / 2;
    svg.appendChild(S('line', {x1:PL, x2:W - PR, y1:y, y2:y, class:'ln'}));
    const t = S('text', {x:PL - 8, y:y + 4, 'text-anchor':'end', class:'ax'}); t.textContent = OUTLBL[o]; svg.appendChild(t); });
  const step = tickStep(hi - lo), long = step >= 864e5;
  for(let t = Math.ceil(lo / step) * step; t <= hi; t += step){
    const px = x(t); svg.appendChild(S('line', {x1:px, x2:px, y1:PT, y2:PT + LANE * OUTS.length + 4, class:'ln'}));
    const d = isoOf(t), tx = S('text', {x:px, y:H - 10, 'text-anchor':'middle', class:'ax'}); tx.textContent = long ? d.slice(0, 10) : d.slice(5, 16); svg.appendChild(tx); }
  list.forEach(a => {
    const oi = OUTS.indexOf(a.outcome); if(oi < 0) return;
    const cx = x(a._t), cy = PT + oi * LANE + LANE / 2, col = OUTCOL[a.outcome];
    const ttl = S('title'); ttl.textContent = sec(a.start) + ' | ' + (KINDLBL[a.kind] || a.kind) + ' | ' + (OUTLBL[a.outcome] || a.outcome) + (a.gateway ? ' | ' + a.gateway : '') + (a.error ? ' | ' + a.error.text : '');
    const sh = KINDSHAPE[a.kind] || 'circle', at = {fill:col, 'fill-opacity':'.7', stroke:'#fff', 'stroke-width':'.6', class:'mk', 'data-i':a._i};
    const m = sh === 'diamond' ? S('path', Object.assign({d:'M' + cx + ' ' + (cy - 6) + 'L' + (cx + 6) + ' ' + cy + 'L' + cx + ' ' + (cy + 6) + 'L' + (cx - 6) + ' ' + cy + 'Z'}, at), ttl)
      : sh === 'triangle' ? S('path', Object.assign({d:'M' + cx + ' ' + (cy - 6) + 'L' + (cx + 5.5) + ' ' + (cy + 4.5) + 'L' + (cx - 5.5) + ' ' + (cy + 4.5) + 'Z'}, at), ttl)
      : sh === 'square' ? S('rect', Object.assign({x:cx - 4.5, y:cy - 4.5, width:9, height:9}, at), ttl)
      : S('circle', Object.assign({cx, cy, r:4.5}, at), ttl);
    svg.appendChild(m);
  });
  host.appendChild(svg);
}
function legend(){
  const l = E('div', {class:'leg'});
  KINDS.forEach(k => l.appendChild(E('span', null, E('i', {text:KINDSYM[k]}), KINDLBL[k] + ' (' + KINDSHAPE[k] + ')')));
  OUTS.forEach(o => l.appendChild(E('span', null, E('i', {text:'■', style:'color:' + OUTCOL[o]}), OUTLBL[o] + ' (row ' + (OUTS.indexOf(o) + 1) + ')')));
  l.appendChild(E('span', {class:'dim', text:'Click a mark to open its row.'}));
  return l;
}

// ---- controls
function syncControls(){
  if(!tlBuilt) return;
  const f = ST.tl;
  ui.presets.forEach(b => b.setAttribute('aria-pressed', String(b.getAttribute('data-p') === f.preset)));
  ui.from.value = f.from; ui.to.value = f.to; ui.q.value = f.q;
  ui.outs.forEach(c => { c.cb.checked = f.out.includes(c.v); }); ui.kinds.forEach(c => { c.cb.checked = f.kind.includes(c.v); });
  ui.page.value = String(f.page);
}
function refreshTimeline(keepShown){
  if(!tlBuilt) return;
  CUR.list = sortedList(); CUR.items = buildItems(CUR.list); if(!keepShown) CUR.shown = ST.tl.page;
  const cnt = {}; OUTS.forEach(o => { cnt[o] = 0; }); let inPeriod = 0; const kc = {}; KINDS.forEach(k => { kc[k] = 0; });
  for(const a of ATT){ if(passes(a, true)){ cnt[a.outcome]++; } }
  const saveKind = ST.tl.kind; ST.tl.kind = KINDS;
  for(const a of ATT){ if(passes(a)){ kc[a.kind]++; } if(passes(a, true)) inPeriod++; }
  ST.tl.kind = saveKind;
  ui.outs.forEach(c => { c.cnt.textContent = ' (' + (cnt[c.v] || 0) + ')'; }); ui.kinds.forEach(c => { c.cnt.textContent = ' (' + (kc[c.v] || 0) + ')'; });
  const [lo] = win();
  ui.sum.textContent = CUR.list.length + ' of ' + ATT.length + ' attempts shown' + (isFinite(lo) ? ' | from ' + sec(isoOf(lo)) : ' | whole bundle') + ' | newest log record ' + sec(META.anchor);
  renderRows(); drawStrip(); saveState();
}
function focusAttempt(a){
  if(!a) return;
  if(!tlBuilt) buildTimeline();
  showTab('timeline');
  if(!passes(a)){ Object.assign(ST.tl, {preset:'all', from:'', to:'', out:OUTS.slice(), kind:KINDS.slice(), q:''}); syncControls(); refreshTimeline(); }
  let idx = CUR.items.findIndex(it => it.type === 'att' ? it.a === a : it.atts.includes(a));
  if(idx < 0) return;
  const it = CUR.items[idx]; if(it.type === 'storm') openStorms.add(it.id);
  expanded.add(a.id); if(CUR.shown <= idx) CUR.shown = idx + ST.tl.page;
  renderRows();
  const tr = ui.tbody.querySelector('tr.att[data-id="' + a.id + '"]');
  if(tr){ tr.scrollIntoView({block:'center'}); tr.classList.add('flash'); }
}
const gotoAttempt = id => focusAttempt(byId[id]);
function buildTimeline(){
  if(tlBuilt) return; tlBuilt = true;
  const root = clear($('#b-timeline')), f = ST.tl;
  ui.presets = [];
  const seg = E('div', {class:'seg', role:'group', 'aria-label':'Period'});
  [['24h','24 h'],['7d','7 d'],['30d','30 d'],['all','All'],['custom','Custom']].forEach(([p, lbl]) => {
    const b = E('button', {type:'button', 'data-p':p, text:lbl, 'aria-pressed':'false'});
    b.addEventListener('click', () => { f.preset = p; syncControls(); refreshTimeline(); }); seg.appendChild(b); ui.presets.push(b); });
  ui.from = E('input', {type:'datetime-local', 'aria-label':'From'}); ui.to = E('input', {type:'datetime-local', 'aria-label':'To'});
  [ui.from, ui.to].forEach(i => i.addEventListener('change', () => { f.from = ui.from.value; f.to = ui.to.value; f.preset = 'custom'; syncControls(); refreshTimeline(); }));
  root.appendChild(E('div', {class:'bar'}, E('b', {text:'Period'}), seg, E('label', null, 'from ', ui.from), E('label', null, 'to ', ui.to),
    E('span', {class:'hint', text:'Presets end at the newest log record (' + sec(META.anchor) + '), not at today.'})));
  ui.outs = []; ui.kinds = [];
  const mk = (list, key, labels, store) => list.map(v => { const cb = E('input', {type:'checkbox'}), cnt = E('span', {class:'dim'});
    cb.addEventListener('change', () => { f[key] = list.filter(x => (store.find(c => c.v === x).cb.checked)); refreshTimeline(); });
    store.push({v, cb, cnt}); return E('label', {class:'ck'}, cb, labels[v], cnt); });
  ui.q = E('input', {type:'search', size:'34', placeholder:'Search error, gateway, portal, user, id', 'aria-label':'Search attempts'});
  ui.q.addEventListener('input', () => { f.q = ui.q.value; refreshTimeline(); });
  ui.page = E('select', {'aria-label':'Rows per page'}, ...[50,100,250,500].map(n => E('option', {value:String(n), text:n + ' rows'})), E('option', {value:'1000000000', text:'All rows'}));
  ui.page.addEventListener('change', () => { f.page = +ui.page.value; refreshTimeline(); });
  const reset = E('button', {type:'button', text:'Reset filters'});
  reset.addEventListener('click', () => { Object.assign(f, {preset:'7d', from:'', to:'', out:OUTS.slice(), kind:KINDS.slice(), q:''}); syncControls(); refreshTimeline(); });
  root.appendChild(E('div', {class:'bar'}, E('b', {text:'Outcome'}), ...mk(OUTS, 'out', OUTLBL, ui.outs), E('b', {text:'Kind'}), ...mk(KINDS, 'kind', KINDLBL, ui.kinds), ui.q, ui.page, reset));
  ui.sum = E('div', {class:'hint', style:'margin:0 0 8px'}); root.appendChild(ui.sum);
  const ch = E('div', {class:'sechead'}, E('h3', {text:'Attempts over time'})); root.appendChild(ch); addHelp(ch, 'tl_chart');
  ui.stripHost = E('div'); root.appendChild(ui.stripHost); root.appendChild(legend());
  ui.stripHost.addEventListener('click', e => { const m = e.target.closest('.mk'); if(m) focusAttempt(ATT[+m.getAttribute('data-i')]); });
  const th = E('div', {class:'sechead', style:'margin-top:14px'}, E('h3', {text:'Attempts'})); root.appendChild(th); addHelp(th, 'tl_table');
  ui.thead = E('thead'); const hr = E('tr', null, E('th', {text:''})); ui.thead.appendChild(hr);
  COLS.forEach(c => { const h = E('th', {class:'sortable ' + (c[3] || ''), 'data-sort':c[0], tabindex:'0', text:c[1]});
    const go = () => { if(f.sort === c[0]) f.dir = -f.dir; else { f.sort = c[0]; f.dir = c[0] === 'start' ? -1 : 1; } refreshTimeline(); };
    h.addEventListener('click', go); h.addEventListener('keydown', e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); go(); } }); hr.appendChild(h); });
  ui.tbody = E('tbody'); ui.tbody.addEventListener('click', onTableClick);
  root.appendChild(E('div', {class:'scroll tall'}, E('table', null, ui.thead, ui.tbody)));
  ui.pg = E('div', {class:'pg'}); root.appendChild(ui.pg);
  syncControls(); refreshTimeline();
}
let rsz = null;
window.addEventListener('resize', () => { clearTimeout(rsz); rsz = setTimeout(() => { if(tlBuilt && !$('#p-timeline').hidden) drawStrip(); }, 150); });
'''

JS_REST = r'''
// ================= Findings
function findingBox(f, cap){
  const lv = pick(f.level, LEVELS) || 'info';
  const box = E('div', {class:'fnd s-' + lv}, E('div', null, badge(lv, lv.toUpperCase()), badge('info', f.code), E('span', {class:'t', text:f.title || f.code})));
  box.appendChild(E('div', {text:f.text}));
  const w = [f.scope, f.when ? 'time ' + sec(f.when) : '', f.count != null ? 'count ' + f.count : ''].filter(Boolean).join(' | ');
  if(w) box.appendChild(E('div', {class:'w', text:w}));
  const refs = f.refs || [];
  if(refs.length){
    const r = E('div', {class:'refs'}, 'Related: ');
    const lim = cap || 12;
    refs.slice(0, lim).forEach(x => r.appendChild(refLink(x)));
    if(refs.length > lim){
      const more = E('button', {type:'button', class:'lnk', text:'+' + (refs.length - lim) + ' more'});
      more.addEventListener('click', () => { more.remove(); refs.slice(lim).forEach(x => r.appendChild(refLink(x))); }); r.appendChild(more);
    }
    box.appendChild(r);
  }
  return box;
}
function renderFindings(){
  const root = clear($('#b-findings'));
  root.appendChild(E('p', null, 'Status: ', badge(pick(D.status, ['ok','warning','critical','no_data']) || 'no_data', String(D.status)), ' ' + FND.length + ' finding(s)'));
  if(!FND.length) root.appendChild(E('p', {class:'msg', text:'No findings: none of the checks fired for this bundle.'}));
  for(const lv of LEVELS){ const items = FND.filter(f => f.level === lv); if(!items.length) continue;
    root.appendChild(E('h3', null, badge(lv, lv.toUpperCase()), ' ' + items.length)); items.forEach(f => root.appendChild(findingBox(f, 12))); }
  const hd = E('div', {class:'sechead', style:'margin-top:18px'}, E('h3', {text:'Flag reference'})); root.appendChild(hd); addHelp(hd, 'flagref');
  const det = E('details'), codes = Object.keys(D.flag_help || {});
  det.appendChild(E('summary', {text:'Show the meaning of all ' + codes.length + ' codes and the thresholds used'}));
  const raised = {}; FND.forEach(f => { raised[f.code] = (raised[f.code] || 0) + 1; });
  const t = E('table', null, E('thead', null, E('tr', null, E('th', {text:'Code'}), E('th', {text:'Title'}), E('th', {text:'Explanation'}), E('th', {class:'r', text:'Raised'}))));
  const tb = E('tbody'); t.appendChild(tb);
  codes.forEach(c => { const h = D.flag_help[c]; tb.appendChild(E('tr', null, E('td', {class:'nw mono', text:c}), E('td', {text:h[0]}), E('td', {text:h[1]}), E('td', {class:'r', text:String(raised[c] || 0)}))); });
  det.appendChild(t);
  const th = E('table', {style:'width:auto;margin-top:12px'}, E('thead', null, E('tr', null, E('th', {text:'Threshold'}), E('th', {class:'r', text:'Used'}), E('th', {class:'r', text:'Default'}), E('th', {text:'Command-line option'}))));
  const tb2 = E('tbody'); th.appendChild(tb2);
  for(const k of Object.keys(D.thresholds || {})){ const v = D.thresholds[k];
    tb2.appendChild(E('tr', null, E('td', {class:'mono', text:k}), E('td', {class:'r', text:String(v.value) + (v.value !== v.default ? ' (changed)' : '')}), E('td', {class:'r', text:String(v.default)}), E('td', {class:'mono dim', text:'--gp-' + k.replace(/_/g, '-')}))); }
  det.appendChild(th); root.appendChild(det);
}

// ================= Source coverage
function renderCoverage(){
  const root = clear($('#b-coverage')), cov = TL.coverage || {};
  const reasons = (D.analysis && D.analysis.reasons) || [];
  root.appendChild(E('p', null, 'Analysis status: ', badge(D.analysis && D.analysis.status === 'complete' ? 'ok' : 'warning', D.analysis ? D.analysis.status : 'unknown')));
  if(reasons.length){ const ul = E('ul'); reasons.forEach(r => ul.appendChild(E('li', {text:r}))); root.appendChild(ul); }
  const h1 = E('div', {class:'sechead'}, E('h3', {text:'Time range of the logs'})); root.appendChild(h1); addHelp(h1, 'cov_ranges');
  const w = cov.detail_window;
  root.appendChild(E('p', {class:'msg', text:w ? 'Detailed phase steps exist only inside the detailed-log window: ' + sec(w.first) + ' - ' + sec(w.last) + '. Attempts outside it have an outcome but no steps.' : 'No detailed (service/agent) log in the bundle: no attempt has phase steps.'}));
  const t = E('table', {style:'width:auto'}, E('thead', null, E('tr', null, E('th', {text:'Log family'}), E('th', {text:'Files'}), E('th', {text:'First record'}), E('th', {text:'Last record'}), E('th', {class:'r', text:'Records'}))));
  const tb = E('tbody'); t.appendChild(tb);
  [['event_log','Event log (pan_gp_event)'],['service_log','Service log (PanGPS)'],['agent_log','Agent log (PanGPA)']].forEach(([k, lbl]) => {
    const c = cov[k]; tb.appendChild(c ? E('tr', null, E('td', {text:lbl}), E('td', {text:(c.files || []).length + ': ' + (c.files || []).join(', ')}), E('td', {class:'nw', text:sec(c.first)}), E('td', {class:'nw', text:sec(c.last)}), E('td', {class:'r', text:String(c.records)}))
      : E('tr', null, E('td', {text:lbl}), E('td', {class:'dim', colspan:'4', text:'not in the bundle'}))); });
  root.appendChild(t);
  if(cov.event_log_ends_before_detail_s != null && cov.event_log_ends_before_detail_s > 0) root.appendChild(E('p', {class:'hint', text:'The event log ends ' + fmtMs(Math.round(cov.event_log_ends_before_detail_s * 1000)) + ' before the detailed logs end.'}));
  if(cov.restores && cov.restores.note) root.appendChild(E('p', {class:'hint', text:'Auto-restores: ' + cov.restores.note}));
  const x = cov.crosscheck; if(x) root.appendChild(E('p', {class:'hint', text:'Cross-check of the event log and the detailed logs: ' + x.matched + ' attempts matched, ' + x.outcome_agree + ' agree on the outcome, ' + (x.outcome_differ || []).length + ' differ.'}));
  const lim = cov.limitations || []; if(lim.length){ const ul = E('ul'); lim.forEach(r => ul.appendChild(E('li', {text:r}))); root.appendChild(ul); }
  const wl = (D.warnings || []); if(wl.length){ root.appendChild(E('h4', {text:'Warnings'})); const ul = E('ul'); wl.forEach(r => ul.appendChild(E('li', {text:r}))); root.appendChild(ul); }
  const h2 = E('div', {class:'sechead', style:'margin-top:16px'}, E('h3', {text:'Bundle inventory'})); root.appendChild(h2); addHelp(h2, 'cov_inventory');
  const inv = D.inventory || [];
  const it = E('table', null, E('thead', null, E('tr', null, E('th', {text:'File'}), E('th', {text:'Family'}), E('th', {class:'r', text:'Size'}), E('th', {text:'Status'}), E('th', {text:'Reason'}), E('th', {text:'Used for'}))));
  const ib = E('tbody'); it.appendChild(ib);
  inv.forEach(m => ib.appendChild(E('tr', null, E('td', {class:'mono', text:m.name}), E('td', {text:m.family}), E('td', {class:'nw r', text:fmtBytes(m.size)}),
    E('td', {class:'nw'}, badge(m.status === 'read' ? 'ok' : (m.status === 'skipped' || m.status === 'truncated') ? 'warning' : 'info', m.status)), E('td', {text:m.reason || ''}), E('td', {class:'dim', text:m.used_for || ''}))));
  root.appendChild(E('div', {class:'scroll'}, it));
  root.appendChild(E('p', {class:'hint', text:inv.length + ' files.'}));
}

// ================= Tabs and start
const built = {};
function showTab(id){
  if(!TABS.includes(id)) id = 'summary';
  ST.tab = id;
  TABS.forEach(t => { const on = t === id; $('#p-' + t).hidden = !on; $('#tab-' + t).setAttribute('aria-selected', String(on)); $('#tab-' + t).tabIndex = on ? 0 : -1; });
  if(!built[id]){ built[id] = true; ({summary:renderSummary, config:renderConfig, timeline:buildTimeline, findings:renderFindings, coverage:renderCoverage})[id](); }
  else if(id === 'timeline') drawStrip();
  saveState();
}
TABS.forEach(t => $('#tab-' + t).addEventListener('click', () => showTab(t)));
$('#tabs').addEventListener('keydown', e => {
  const i = TABS.indexOf(ST.tab); if(e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
  const n = TABS[(i + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length]; showTab(n); $('#tab-' + n).focus();
});
(function head(){
  $('#sub').textContent = 'Bundle ' + META.bundle + ' | generated ' + META.generated + ' | panos-toolbox ' + META.tool_version;
  const a = D.analysis || {status:'unknown', reasons:[]}, el = $('#astatus');
  el.textContent = 'Analysis: ' + a.status + (a.reasons.length ? ' (' + a.reasons.length + ' note' + (a.reasons.length > 1 ? 's' : '') + ')' : '');
  el.classList.add(a.status === 'complete' ? 'complete' : 'partial'); el.title = a.reasons.join('\n') || 'All files were read';
  el.addEventListener('click', () => showTab('coverage')); el.addEventListener('keydown', e => { if(e.key === 'Enter') showTab('coverage'); });
  const nf = FND.filter(f => f.level !== 'info').length;
  if(nf) $('#tab-findings').appendChild(E('span', {class:'badge n b-' + (FND.some(f => f.level === 'critical') ? 'critical' : 'warning'), text:String(nf)}));
})();
showTab(ST.tab);
</script>
</body>
</html>
'''

_STORE = "\n".join(f'<div data-hid="{i}">__HB_{i}__ __HP_{i}__</div>' for i in SECTION_TITLES)

TEMPLATE = (TEMPLATE_HEAD + TEMPLATE_CSS + CREDITS_CSS
            + TEMPLATE_BODY.replace("__HELPSTORE__", _STORE).replace(CREDITS_PLACEHOLDER, CREDITS_HTML)
            + JS_CORE + JS_SUMMARY + JS_CONFIG + JS_TIMELINE + JS_REST)

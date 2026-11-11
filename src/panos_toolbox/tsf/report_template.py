"""Page template of the TSF report (HTML, CSS and JavaScript).

Placeholders: __KIND__, __TITLE__ and __DATA__ (JSON blob), and __HB_<id>__ / __HP_<id>__
(help button and collapsible help text of each section, see report_help.py).
The pieces are concatenated in TEMPLATE; edit one piece to change one part of the page.
"""

# Document start and opening of the style element.
TEMPLATE_HEAD = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__KIND__ - __TITLE__</title>
<style>
'''

# Stylesheet rules (CSS variables, layout, tabs, tables, badges).
TEMPLATE_CSS = r''':root{--ink:#1c2530;--mute:#5d6b7a;--line:#d8dde3;--bg:#f4f6f8;--card:#fff;--acc:#1f6f8b;--warn-bg:#fff4d6;--warn-bd:#c98a00}
*{box-sizing:border-box}
/* Layout: designed for Full HD (1920x1080) or larger; 1900 leaves room for a classic scrollbar. Below 1900 CSS px the page keeps
   its width and scrolls horizontally, so no layout reflows at smaller sizes. The main
   column grows with the window; it is capped at 3200px on ultrawide and 4K screens so
   that lines of tables and text do not run across the whole display. */
body{margin:0;min-width:1900px;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:3200px;margin:0 auto;padding:20px 24px 48px}
h1{font-size:20px;margin:0 0 2px}
h2{font-size:15px;margin:0 0 10px}
.sub{color:var(--mute);margin:0 0 14px}
.utc{background:var(--warn-bg);border-left:4px solid var(--warn-bd);padding:10px 14px;margin:0 0 16px;border-radius:2px}
section{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px 16px;margin-bottom:16px}
.bar{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;margin-bottom:10px}
label{color:var(--mute)}
select,input,button{font:inherit;color:inherit;border:1px solid var(--line);border-radius:3px;padding:4px 8px;background:#fff}
button{cursor:pointer}
button:hover{border-color:var(--acc)}
button:focus-visible,select:focus-visible,input:focus-visible,th:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
.leg{display:flex;flex-wrap:wrap;gap:6px 14px}
.leg label{display:flex;align-items:center;gap:5px;color:var(--ink);cursor:pointer}
.sw{width:12px;height:12px;border-radius:2px;display:inline-block}
.cw{position:relative}
svg{display:block;width:100%;height:auto;touch-action:none;user-select:none}
.tip{position:absolute;pointer-events:none;background:#1c2530;color:#fff;padding:6px 9px;border-radius:3px;font-size:12px;white-space:nowrap;display:none;max-height:340px;overflow:hidden}
table{border-collapse:collapse;width:100%}
th,td{padding:5px 10px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
th:first-child,td:first-child,th:nth-child(2),td:nth-child(2){text-align:left}
th{cursor:pointer;background:#eef1f4;position:sticky;top:0}
/* Scrollable tables: show more rows on taller screens (100vh minus room for the header and
   filters), between 460px and 1200px. */
.scroll{max-height:clamp(460px,calc(100vh - 400px),1200px);overflow:auto;border:1px solid var(--line)}
.pgrid>div+div{margin-top:16px}
.stats td,.stats th{cursor:default;position:static}
.stats th:nth-child(2),.stats td:nth-child(2){text-align:right}
.tabs{display:flex;flex-wrap:wrap;gap:2px;border-bottom:1px solid var(--line);margin:0}
.tabs button{border:1px solid transparent;border-bottom:none;border-radius:4px 4px 0 0;background:transparent;color:var(--mute);padding:8px 18px}
.tabs button:hover{color:var(--ink)}
.tabs button[aria-selected=true]{background:var(--card);border-color:var(--line);color:var(--ink);font-weight:600;position:relative;top:1px}
.panel{border-top-left-radius:0}
.sep{margin-top:22px;padding-top:16px;border-top:1px solid var(--line)}
details{margin-top:8px}
.hint{color:var(--mute);font-size:12px}
.banner{list-style:none;margin:0 0 12px;padding:0}
.banner li{border-left:4px solid var(--line);background:#f7f9fb;padding:6px 10px;margin:0 0 6px;border-radius:2px}
.banner li.lvl-crit{border-color:#b42318;background:#fdecea}
.banner li.lvl-warn{border-color:var(--warn-bd);background:var(--warn-bg)}
.badge{display:inline-block;color:#fff;border-radius:3px;padding:0 6px;margin:0 3px 2px 0;font-size:11px;line-height:17px;white-space:nowrap}
.b-crit{background:#b42318}.b-warn{background:#b7791f}.b-info{background:#5d6b7a}.b-ok{background:#2f855a}
.astatus{font-size:12px;line-height:20px;padding:0 10px;border-radius:10px;margin:0 0 12px;cursor:help}
.cov-sub{margin:6px 0 0 18px;padding:0;font-size:12px}.cov-sub li{margin:1px 0}
table.covt td.l,table.covt th.l{text-align:left}
table.hm{width:auto;margin:0 0 10px}
table.hm td,table.hm th{text-align:center;min-width:36px;padding:3px 5px;cursor:default;position:static}
table.hm th:first-child,table.hm td:first-child{text-align:left;min-width:150px}
table.hm td.hot{outline:2px solid #1c2530;outline-offset:-2px;font-weight:700}
table.dphs th,table.dphs td{text-align:right}
table.dphs th:first-child,table.dphs td:first-child{text-align:left}
tr.anom-crit td{background:#fdecea}
tr.anom-warn td{background:var(--warn-bg)}
tr.anom-crit td:first-child{box-shadow:inset 4px 0 0 #b42318}
tr.anom-warn td:first-child{box-shadow:inset 4px 0 0 var(--warn-bd)}
.meter{height:8px;min-width:120px;background:#e3e7ec;border-radius:2px}
.meter i{display:block;height:100%;background:var(--acc);border-radius:2px}
summary{cursor:pointer}
.help{max-width:920px;line-height:1.5}
/* Wide screens only (2560 px and up): two-column POW tables, larger text and a wider Help
   column. Below 2560 px every block stays single column, as on 1080p. */
@media (min-width:2560px){
  body{font-size:15px}
  .help{max-width:1100px}
  .pgrid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:0 24px;align-items:start}
  .pgrid>div+div{margin-top:0}
}
.help{background:#f7f9fb;border-left:3px solid var(--acc);padding:6px 14px;margin:0 0 12px;font-size:13px}
.help[hidden],#gltip[hidden]{display:none}
.help h3{font-size:14px;margin:14px 0 6px}
.help p,.help ul,.help ol{margin:6px 0}
.help code{background:#eef1f4;border-radius:2px;padding:0 4px;font-size:12.5px}
.help table{width:auto;max-width:100%}
.help th,.help td{white-space:normal;text-align:left;vertical-align:top;cursor:default;position:static}
.help details{margin:8px 0}
.help summary{font-weight:600}
.sechead{display:flex;align-items:center;gap:10px;margin:0 0 6px}
.sechead h2,.sechead h3{margin:0;font-size:15px}
.sechead h3{font-size:14px}
.helpbtn{font-size:12px;padding:1px 8px;border-radius:10px;color:var(--mute)}
.helpbtn[aria-expanded=true]{color:var(--ink);border-color:var(--acc)}
.gl{cursor:help;border-bottom:1px dotted var(--mute)}
.gl:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
.gl.unk{border-bottom:2px dotted #b42318;color:#b42318}
.gl.unk::after{content:" ?";font-weight:700}
#gltip{position:fixed;z-index:50;max-width:380px;background:#1c2530;color:#f1f4f7;padding:8px 11px;border-radius:4px;font-size:12px;line-height:1.4;box-shadow:0 3px 12px rgba(0,0,0,.35);pointer-events:none}
#gltip .gt-h{font-weight:600;font-size:13px}
#gltip .gt-c{opacity:.8;margin:1px 0 4px}
#gltip .gt-f{opacity:.85;margin-top:5px;font-size:11px}
#gltip .gt-bad{margin-top:5px;font-weight:600;color:#ff8b7e}
.cb{display:inline-block;min-width:16px;text-align:center;border-radius:3px;padding:0 4px;margin-left:6px;font-size:11px;font-weight:700;color:#fff}
.cb.c-D{background:#1a7f4b}.cb.c-G{background:#0e7490}.cb.c-I{background:#a15c00}.cb.c-U{background:#b42318}
.chartgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(520px,1fr));gap:12px 24px;margin-bottom:12px}
.axt{fill:var(--mute);font-size:11px}
.bl{fill:var(--ink);font-size:11px;font-family:ui-monospace,Consolas,monospace}
.vl{fill:var(--mute);font-size:11px}
.dim{color:var(--mute)}
.itbl th.g-phys{box-shadow:inset 0 3px 0 #b42318}
.itbl th.g-cpu{box-shadow:inset 0 3px 0 #a15c00}
.itbl th.g-logical{box-shadow:inset 0 3px 0 #1f6f8b}
.itbl td.nzc{font-weight:600;color:#b42318}
.itbl td.zc{color:#9aa5b1}
.itbl td.tl,.itbl th.tl{text-align:left}
.legsq{display:inline-block;width:14px;height:4px;margin:0 4px 2px 12px}
.isys td,.isys th{cursor:default;position:static;text-align:left}
'''

# Markup: closing head, header, tabs bar, tab panels.
TEMPLATE_BODY = r'''</style>
</head>
<body>
<main>
<div id="gltip" role="tooltip" hidden></div>
<h1 id="title"></h1>
<p class="sub" id="sub"></p>
<div><span class="badge astatus" id="astatus" style="display:none" tabindex="0"></span></div>
<div class="utc" id="utc"></div>
<details id="warn" style="display:none;margin:0 0 16px"><summary id="warnsum"></summary><ul id="warnlist"></ul></details>

<div class="tabs" id="tabs" role="tablist" aria-label="Report sections">
  <button type="button" role="tab" id="tab-chart" aria-controls="p-chart" aria-selected="true">Dataplane Throughput</button>
  <button type="button" role="tab" id="tab-cpu" aria-controls="p-cpu" aria-selected="false" tabindex="-1" style="display:none">CPU load by group</button>
  <button type="button" role="tab" id="tab-dph" aria-controls="p-dph" aria-selected="false" tabindex="-1" style="display:none">Dataplane health</button>
  <button type="button" role="tab" id="tab-mp" aria-controls="p-mp" aria-selected="false" tabindex="-1" style="display:none">Management plane</button>
  <button type="button" role="tab" id="tab-sys" aria-controls="p-sys" aria-selected="false" tabindex="-1" style="display:none">System health</button>
  <button type="button" role="tab" id="tab-pow" aria-controls="p-pow" aria-selected="false" tabindex="-1" style="display:none">POW performance</button>
  <button type="button" role="tab" id="tab-ifc" aria-controls="p-ifc" aria-selected="false" tabindex="-1" style="display:none">Interface Errors</button>
  <button type="button" role="tab" id="tab-cov" aria-controls="p-cov" aria-selected="false" tabindex="-1" style="display:none">Source coverage</button>
</div>

<section class="panel" id="p-chart" role="tabpanel" aria-labelledby="tab-chart">
  <div class="sechead"><h2>Dataplane throughput</h2>__HB_chart__</div>__HP_chart__
  <div class="bar">
    <label>Metric <select id="metric"></select></label>
    <div class="leg" id="leg"></div>
    <button id="reset" type="button">Reset zoom</button>
  </div>
  <div class="cw" id="chartwrap"><svg id="chart" role="img" aria-label="Metrics over time chart"></svg><div class="tip" id="tip"></div></div>
  <p class="hint">Drag on the chart to zoom into a range; the range also applies to the other charts and to the table.</p>
  <table class="stats" id="stats"></table>
  <div class="sep">
  <div class="sechead"><h3>Samples table</h3>__HB_table__</div>__HP_table__
  <div class="bar">
    <label>DP <select id="fdp"></select></label>
    <label>From (UTC) <input type="datetime-local" id="t0"></label>
    <label>To (UTC) <input type="datetime-local" id="t1"></label>
    <label>Search <input type="search" id="q" placeholder="free text"></label>
    <label id="gcolwrap" style="display:none"><input type="checkbox" id="gcol"> CPU by group columns</label>
    <button id="csv" type="button">Export CSV</button>
    <span class="hint" id="count"></span>
  </div>
  <div class="scroll"><table id="tbl"></table></div>
  <p class="hint" id="more"></p>
  </div>
</section>

<section class="panel" id="p-cpu" role="tabpanel" aria-labelledby="tab-cpu" hidden>
  <div class="sechead"><h2>CPU load by group</h2>__HB_cpu__</div>__HP_cpu__
  <div class="bar">
    <label>DP <select id="gdp"></select></label>
    <button id="greset" type="button">Reset zoom</button>
    <button id="gall" type="button">All</button>
    <button id="gnone" type="button">None</button>
  </div>
  <div class="leg" id="gleg" style="margin-bottom:10px"></div>
  <div class="cw" id="gwrap"><svg id="gchart" role="img" aria-label="CPU load by group over time"></svg><div class="tip" id="gtip"></div></div>
  <table class="stats" id="gstats"></table>
</section>

<section class="panel" id="p-dph" role="tabpanel" aria-labelledby="tab-dph" hidden>
  <div class="sechead"><h2>Dataplane health</h2>__HB_dph__</div>__HP_dph__
  <p class="hint" id="dphinfo"></p>
  <details id="dphwarn" style="display:none;margin:0 0 12px"><summary id="dphwarnsum"></summary><ul id="dphwarnlist"></ul></details>
  <div class="scroll"><table class="stats dphs" id="dphsum"></table></div>
  <div class="sechead" style="margin-top:12px"><h3>Findings</h3>__HB_dphflags__</div>__HP_dphflags__
  <ul class="banner" id="dphbanner"></ul>
  <div class="sep"><div class="sechead"><h2>Utilization over time</h2>__HB_dphchart__</div>__HP_dphchart__
  <div class="bar">
    <label>DP <select id="dphdp"></select></label>
    <button id="dphreset" type="button">Reset zoom</button>
    <div class="leg" id="dphleg"></div>
  </div>
  <div class="cw" id="dphwrap"><svg id="dphchart" role="img" aria-label="Dataplane health over time chart"></svg><div class="tip" id="dphtip"></div></div>
  <table class="stats" id="dphstats"></table></div>
  <div class="sep"><div class="sechead"><h2>CPU peak per core</h2>__HB_dphcores__</div>__HP_dphcores__
  <div id="dphcores"></div></div>
</section>

<section class="panel" id="p-mp" role="tabpanel" aria-labelledby="tab-mp" hidden>
  <div class="sechead"><h2>Management plane</h2>__HB_mp__</div>__HP_mp__
  <p class="hint" id="mpinfo"></p>
  <details id="mpwarn" style="display:none;margin:0 0 12px"><summary id="mpwarnsum"></summary><ul id="mpwarnlist"></ul></details>
  <div class="scroll"><table class="stats dphs" id="mpsum"></table></div>
  <div class="sechead" style="margin-top:12px"><h3>Findings</h3>__HB_mpflags__</div>__HP_mpflags__
  <ul class="banner" id="mpbanner"></ul>
  <div class="sep"><div class="sechead"><h2>Memory over time</h2>__HB_mpchart__</div>__HP_mpchart__
  <div class="bar">
    <button id="mpreset" type="button">Reset zoom</button>
    <div class="leg" id="mpleg"></div>
  </div>
  <div class="cw" id="mpwrap"><svg id="mpchart" role="img" aria-label="Management plane memory over time chart"></svg><div class="tip" id="mptip"></div></div>
  <table class="stats" id="mpstats"></table></div>
  <div class="sep"><div class="sechead"><h2>Processes</h2>__HB_mpprocs__</div>__HP_mpprocs__
  <div class="bar"><label>Show <select id="mpview"></select></label><span class="hint" id="mpcount"></span></div>
  <details id="mpproctab" open><summary>Process table</summary>
  <div class="scroll"><table class="stats dphs" id="mpprocs"></table></div></details></div>
</section>

<section class="panel" id="p-sys" role="tabpanel" aria-labelledby="tab-sys" hidden>
  <div class="sechead"><h2>System health</h2>__HB_sys__</div>__HP_sys__
  <p class="hint" id="sysinfo"></p>
  <div class="scroll"><table class="stats covt" id="syschecks"></table></div>
  <div class="sechead" style="margin-top:12px"><h3>Findings</h3>__HB_sysflags__</div>__HP_sysflags__
  <ul class="banner" id="sysbanner"></ul>
  <div class="sep"><div class="sechead"><h2>Details</h2>__HB_sysdetail__</div>__HP_sysdetail__
  <div id="sysdetails"></div></div>
</section>

<section class="panel" id="p-pow" role="tabpanel" aria-labelledby="tab-pow" hidden>
  <div class="sechead"><h2>POW performance</h2>__HB_pow__</div>__HP_pow__
  <p class="hint" id="pinfo"></p>
  <details id="pwarn" style="display:none;margin:0 0 12px"><summary id="pwarnsum"></summary><ul id="pwarnlist"></ul></details>
  <div class="sechead"><h3>Findings</h3>__HB_pflags__</div>__HP_pflags__
  <ul class="banner" id="pbanner"></ul>
  <div class="bar">
    <label>View <select id="pview"></select></label>
    <label>Search <input type="search" id="pq" placeholder="name or category"></label>
    <label><input type="checkbox" id="panom"> only anomalous rows</label>
    <label><input type="checkbox" id="pidle" checked> hide rows without calls</label>
    <button id="pcsv" type="button">Export CSV</button>
    <span class="hint" id="pmeta"></span>
  </div>
  <div class="sep"><div class="sechead"><h2>Top functions</h2>__HB_ptop__</div>__HP_ptop__
  <div class="bar"><label>Top <select id="ptopn"><option>10</option><option selected>15</option><option>25</option><option>40</option></select></label></div>
  <div class="chartgrid"><div><h4>By total-us (window)</h4><div id="ptopw"></div></div>
  <div id="ptopa-wrap"><h4>By ac-total-us (accumulated)</h4><div id="ptopa"></div></div></div></div>
  <div class="pgrid">
  <div><div class="sechead"><h2>Workgroups</h2>__HB_pgroups__</div>__HP_pgroups__
  <div class="scroll"><table id="pgt"></table></div></div>
  <div><div class="sechead"><h2>Functions</h2>__HB_pfuncs__</div>__HP_pfuncs__
  <div class="scroll"><table id="pft"></table></div></div>
  </div>
  <div class="sep"><div class="sechead"><h2>Function CPU share by category</h2>__HB_pcat__</div>__HP_pcat__
  <table class="stats" id="pcat"></table>
  <h4>Glossary families</h4><p class="hint" id="pgcat-hint"></p>
  <div class="scroll"><table id="pgcat"></table></div></div>
  <div class="sep"><div class="sechead"><h2>Histograms (processing time per call)</h2>__HB_phist__</div>__HP_phist__<div id="phist"></div></div>
  <div class="sep"><div class="sechead"><h2>Latency counters</h2>__HB_plat__</div>__HP_plat__<div class="scroll"><table id="plt"></table></div></div>
  <div class="sep"><div class="sechead"><h2>Workgroup total-us per core</h2>__HB_pmx__</div>__HP_pmx__<div class="scroll"><table id="pmx"></table></div></div>
</section>

<section class="panel" id="p-ifc" role="tabpanel" aria-labelledby="tab-ifc" hidden>
  <div class="sechead"><h2>Interface errors</h2>__HB_ifc__</div>__HP_ifc__
  <table class="stats isys" id="isys"></table>
  <details id="iwarn" style="display:none;margin:8px 0 12px"><summary id="iwarnsum"></summary><ul id="iwarnlist"></ul></details>
  <div class="sechead" style="margin-top:12px"><h3>Findings</h3>__HB_iflags__</div>__HP_iflags__
  <ul class="banner" id="ibanner"></ul>
  <p class="hint" id="idown"></p>
  <div class="sep"><div class="sechead"><h2>Interfaces</h2>__HB_itable__</div>__HP_itable__
  <div class="bar">
    <label>Search <input type="search" id="iq" placeholder="name, zone, address, flag"></label>
    <label>Type <select id="ikind"></select></label>
    <label><input type="checkbox" id="iissues" checked> only interfaces with issues</label>
    <button id="icsv" type="button">Export CSV</button>
    <span class="hint" id="imeta"></span>
  </div>
  <p class="hint" id="igleg"></p>
  <div class="scroll"><table class="itbl" id="itbl"></table></div></div>
  <div class="sep"><div class="sechead"><h2>Cross-check with the global counters</h2>__HB_ixchk__</div>__HP_ixchk__
  <p class="hint" id="ixmsg"></p>
  <table class="stats" id="ixchk"></table>
  <h4>Other drop-related global counters (no interface counter)</h4>
  <table class="stats" id="ictx"></table></div>
  <div id="iextra"></div>
</section>

<section class="panel" id="p-cov" role="tabpanel" aria-labelledby="tab-cov" hidden>
  <div class="sechead"><h2>Source coverage</h2>__HB_coverage__</div>__HP_coverage__
  <p class="hint" id="covmsg"></p>
  <div class="scroll"><table class="stats covt" id="covfam"></table></div>
  <div class="sep"><h3>Skipped members</h3><p class="hint" id="covskipmsg"></p><table class="stats covt" id="covskip"></table></div>
  <div class="sep"><h3>Limit notes</h3><ul id="covnotes"></ul></div>
  <div class="sep"><h3>Conflicting samples</h3><p class="hint" id="covconfmsg"></p><div class="scroll"><table class="stats covt" id="covconf"></table></div></div>
</section>

</main>

'''

# Shared glossary tooltip (counter, group and function names, column headers) and the
# collapsible per-section help buttons.
JS_GL = r'''// ===== shared: glossary tooltips and per-section help =====
const GL = D.gl || {names:{}, fields:{}, conf:{}};
const noMeaning = e => !!e && (e.f==='U' || e.c==='Unclassified');
function glTitle(key, field){
  const e = field ? GL.fields[key] : GL.names[key]; if(!e) return '';
  if(field) return key + ': ' + e.m;
  return key + ' [' + e.f + '] ' + e.c + ': ' + e.m + (noMeaning(e) ? ' (no known meaning)' : '');
}
function glTag(el, key, field){
  const e = field ? GL.fields[key] : GL.names[key]; if(!e) return el;
  el.classList.add('gl'); el.setAttribute(field ? 'data-gf' : 'data-gl', key);
  el.setAttribute('aria-describedby', 'gltip'); if(!el.hasAttribute('tabindex')) el.tabIndex = 0;
  if(!field && noMeaning(e)) el.classList.add('unk');
  el.setAttribute('title', glTitle(key, field)); return el;
}
function glName(name, tag){ const s = document.createElement(tag || 'span'); s.textContent = name; return glTag(s, name, false); }
(function(){
  const tip = document.getElementById('gltip'); let cur = null, savedTitle = null, savedChild = null;
  const div = (c, t) => { const d = document.createElement('div'); d.className = c; d.textContent = t; return d; };
  function build(el){
    const key = el.getAttribute('data-gl') || el.getAttribute('data-gf'), field = el.hasAttribute('data-gf');
    const e = field ? GL.fields[key] : GL.names[key]; tip.replaceChildren(); if(!e) return false;
    const h = div('gt-h', key), b = document.createElement('span'); b.className = 'cb c-' + e.f; b.textContent = e.f; h.appendChild(b); tip.appendChild(h);
    tip.appendChild(div('gt-c', field ? 'Column' : (e.c + ' - ' + (e.k === 'group' ? 'group' : (e.k === 'counter' ? 'counter' : 'function')))));
    tip.appendChild(div('gt-m', e.m));
    tip.appendChild(div('gt-f', 'Confidence ' + e.f + ': ' + (GL.conf[e.f] || '')));
    if(!field && noMeaning(e)) tip.appendChild(div('gt-bad', 'No known meaning. If this counter is active, please report it.'));
    return true;
  }
  function place(el){
    const r = el.getBoundingClientRect(), tw = tip.offsetWidth, th = tip.offsetHeight;
    let x = Math.min(Math.max(8, r.left), window.innerWidth - tw - 8), y = r.bottom + 8;
    if(y + th > window.innerHeight - 4) y = Math.max(4, r.top - th - 8);
    tip.style.left = x + 'px'; tip.style.top = y + 'px';
  }
  function hide(){
    if(!cur) return; tip.hidden = true;
    if(savedTitle !== null) cur.setAttribute('title', savedTitle);
    if(savedChild) cur.appendChild(savedChild);
    cur = savedTitle = savedChild = null;
  }
  function show(el){
    if(cur === el) return; hide();
    if(!build(el)) return;
    cur = el; savedTitle = el.getAttribute('title'); if(savedTitle !== null) el.removeAttribute('title');
    const t = el.querySelector(':scope > title'); if(t){ savedChild = t; el.removeChild(t); }
    tip.hidden = false; place(el);
  }
  const find = t => (t && t.closest) ? t.closest('[data-gl],[data-gf]') : null;
  document.addEventListener('mouseover', e => { const el = find(e.target); if(el) show(el); else if(cur) hide(); });
  document.addEventListener('focusin', e => { const el = find(e.target); if(el) show(el); else hide(); });
  document.addEventListener('focusout', hide);
  document.addEventListener('keydown', e => { if(e.key === 'Escape') hide(); });
  window.addEventListener('scroll', hide, true);
  document.querySelectorAll('.helpbtn').forEach(b => {
    b.onclick = () => { const p = document.getElementById(b.getAttribute('aria-controls')); const open = p.hidden; p.hidden = !open; b.setAttribute('aria-expanded', String(open)); };
  });
})();
'''

# Script start, data, dataplane throughput chart and table, CPU by group, CSV export.
_JS_CORE = r'''<script>
const D = __DATA__;
const $ = s => document.querySelector(s);
const NS = 'http://www.w3.org/2000/svg';
__GL_JS__
const METRICS = {
  kbps:{label:'Throughput'},
  pps:{label:'Packet rate', unit:'pkt/s'},
  cps:{label:'New connections', unit:'cps'},
  sess:{label:'Allocated sessions', unit:''},
  util:{label:'Session table utilization', unit:'%'}
};
const PALETTE = ['#1c2530','#1f6f8b','#c2410c','#2f855a','#7c3aed','#b7791f','#be185d','#0e7490','#4d7c0f'];
const colors = {}; D.series.forEach((s,i)=>colors[s]=PALETTE[i%PALETTE.length]);
const hasG = D.groups.length>0;
const hasSamples = D.samples.length>0;
const GCOL = D.groups.map((_,i)=>'hsl('+Math.round(i*360/D.groups.length)+',62%,40%)');
const state = {metric:'kbps', hidden:new Set(), range:[null,null], sort:{k:'t',dir:1}, dp:'', q:'', all:false, showG:false};
const gs = {dp:null, hidden:new Set()};
const maxOf = a => a.reduce((m,v)=>v>m?v:m,-Infinity);
const minOf = a => a.reduce((m,v)=>v<m?v:m,Infinity);
const ALLT = D.samples.map(s=>s.t);
const TMIN = minOf(ALLT), TMAX = maxOf(ALLT);

const pad = n => String(n).padStart(2,'0');
const iso = ms => new Date(ms).toISOString().replace('T',' ').slice(0,19);
const isoLocalInput = ms => new Date(ms).toISOString().slice(0,16);
const hasMetric = k => D.samples.some(s=>s[k]!==null && s[k]!==undefined);
const inRange = t => (state.range[0]===null||t>=state.range[0]) && (state.range[1]===null||t<=state.range[1]);

function scaleFor(vals){
  const m = vals.length?maxOf(vals):0;
  if(m>=1e6) return {div:1e6,unit:'Gbps'};
  if(m>=1e3) return {div:1e3,unit:'Mbps'};
  return {div:1,unit:'kbps'};
}
const fmt = (v,div) => (v/div).toLocaleString('en-US',{maximumFractionDigits: div===1&&Number.isInteger(v)?0:2});

// header
$('#title').textContent = D.kind + ' - ' + D.name;
$('#sub').textContent = hasSamples ? ('Period ' + iso(TMIN) + ' - ' + iso(TMAX) + ' UTC | dp-monitor files read: ' + D.files + ' | generated ' + D.generated + ' UTC') : (D.pow && D.pow.collected_at ? 'Collected at ' + D.pow.collected_at : (D.ifc && D.ifc.system.collected_at ? 'Collected at ' + D.ifc.system.collected_at : ''));
$('#utc').textContent = 'Reminder: all times in this report are in UTC. The original firewall timestamps' + (D.offsets.length ? ' (detected offsets: ' + D.offsets.join(', ') + ')' : '') + ' have been converted.' + (D.series[0]==='ALL' ? ' The ALL series is the sum across DPs (for session table utilization it is the maximum value).' : '');
$('#utc').style.display = hasSamples ? '' : 'none';
if (D.warnings.length){ $('#warn').style.display=''; $('#warnsum').textContent = D.warnings.length + ' warnings while reading'; D.warnings.forEach(w=>{const li=document.createElement('li'); li.textContent=w; $('#warnlist').appendChild(li);}); }

// reusable chart
// Chart height follows the window height: 360px (the 1080p size) up to 720px on 4K.
// The width comes from the container, so the viewBox ratio gives the drawn height.
const chartH = () => Math.round(Math.min(720, Math.max(360, 0.38*window.innerHeight)));
function makeChart(svg, tip, wrap){
  let view=null;
  const el=(n,a)=>{const e=document.createElementNS(NS,n); for(const k in a) e.setAttribute(k,a[k]); svg.appendChild(e); return e;};
  const niceMax=v=>{ if(v<=0) return 1; const p=Math.pow(10,Math.floor(Math.log10(v))), n=v/p; return (n<=1?1:n<=2?2:n<=2.5?2.5:n<=5?5:10)*p; };
  function draw(series,o){
    const W=Math.max(480,wrap.clientWidth), H=chartH(), L=70,R=16,T=12,B=34, u=o.u;
    svg.setAttribute('viewBox','0 0 '+W+' '+H); svg.replaceChildren();
    const all=series.flatMap(s=>s.d.map(p=>p.v));
    const x0=state.range[0]!==null?state.range[0]:(o.t0!==undefined?o.t0:TMIN), x1=state.range[1]!==null?state.range[1]:(o.t1!==undefined?o.t1:TMAX);
    let ymax=niceMax((all.length?maxOf(all):1)/u.div*1.05); if(o.top) ymax=Math.max(ymax,o.top); if(o.cap) ymax=Math.min(ymax,o.cap);
    const X=t=>L+(x1===x0?0.5:(t-x0)/(x1-x0))*(W-L-R), Y=v=>T+(1-v/u.div/ymax)*(H-T-B);
    view={W,L,R,T,B,x0,x1,X,u};
    for(let i=0;i<=5;i++){
      const v=ymax*i/5, y=T+(1-i/5)*(H-T-B);
      el('line',{x1:L,x2:W-R,y1:y,y2:y,stroke:'#e3e7ec'});
      const t=el('text',{x:L-8,y:y+4,'text-anchor':'end','font-size':11,fill:'#5d6b7a'}); t.textContent=v.toLocaleString('en-US',{maximumFractionDigits:2});
    }
    const yl=el('text',{x:12,y:T+10,'font-size':11,fill:'#5d6b7a'}); yl.textContent=o.label+(u.unit?' ('+u.unit+')':'');
    yl.setAttribute('transform','rotate(-90 12 '+(T+(H-T-B)/2)+') translate(-'+((H-T-B)/2-40)+' 0)');
    const span=x1-x0, multi=span>86400000;
    for(let i=0;i<=6;i++){
      const t=x0+span*i/6, x=X(t), d=new Date(t);
      const lab=multi?pad(d.getUTCMonth()+1)+'-'+pad(d.getUTCDate())+' '+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes()):pad(d.getUTCHours())+':'+pad(d.getUTCMinutes());
      el('line',{x1:x,x2:x,y1:H-B,y2:H-B+4,stroke:'#5d6b7a'});
      const tx=el('text',{x:x,y:H-B+17,'text-anchor':i===0?'start':i===6?'end':'middle','font-size':11,fill:'#5d6b7a'}); tx.textContent=lab;
    }
    el('line',{x1:L,x2:W-R,y1:H-B,y2:H-B,stroke:'#5d6b7a'});
    (o.lines||[]).forEach(l=>{ if(l.v>ymax*u.div) return; const y=Y(l.v*u.div); el('line',{x1:L,x2:W-R,y1:y,y2:y,stroke:l.color,'stroke-width':1.2,'stroke-dasharray':'6 4'}); const t=el('text',{x:W-R-4,y:y-4,'text-anchor':'end','font-size':11,fill:l.color}); t.textContent=l.label; });
    series.forEach(s=>{
      if(!s.d.length) return;
      el('polyline',{points:s.d.map(p=>X(p.t).toFixed(1)+','+Y(p.v).toFixed(1)).join(' '),fill:'none',stroke:s.color,'stroke-width':s.w||1.6,'stroke-linejoin':'round'});
      if(s.d.length<=80) s.d.forEach(p=>el('circle',{cx:X(p.t),cy:Y(p.v),r:2.6,fill:s.color}));
    });
    if(!all.length){ const t=el('text',{x:W/2,y:H/2,'text-anchor':'middle',fill:'#5d6b7a'}); t.textContent='No data to display'; }
    view.sel=el('rect',{y:T,height:H-T-B,fill:'rgba(31,111,139,.15)',stroke:'#1f6f8b',display:'none'});
    view.cur=el('line',{y1:T,y2:H-B,stroke:'#8a95a1','stroke-dasharray':'3 3',display:'none'});
    const h=el('rect',{x:L,y:T,width:W-L-R,height:H-T-B,fill:'transparent'});
    bind(h,series);
  }
  function bind(h,series){
    let drag=null;
    const px=e=>{const r=svg.getBoundingClientRect(); return (e.clientX-r.left)*view.W/r.width;};
    const tOf=x=>view.x0+(x-view.L)/(view.W-view.L-view.R)*(view.x1-view.x0);
    h.onpointerdown=e=>{drag=px(e); h.setPointerCapture(e.pointerId);};
    h.onpointermove=e=>{
      const x=px(e);
      if(drag!==null){ view.sel.setAttribute('display',''); view.sel.setAttribute('x',Math.min(drag,x)); view.sel.setAttribute('width',Math.abs(x-drag)); tip.style.display='none'; return; }
      const t=tOf(x); let best=null,bd=Infinity;
      series.forEach(s=>s.d.forEach(p=>{const d=Math.abs(p.t-t); if(d<bd){bd=d;best=p.t;}}));
      if(best===null){tip.style.display='none'; return;}
      const cx=view.X(best); view.cur.setAttribute('x1',cx); view.cur.setAttribute('x2',cx); view.cur.setAttribute('display','');
      const rows=series.map(s=>{const p=s.d.find(z=>z.t===best); return p?'<div><span class="sw" style="background:'+s.color+'"></span> '+s.name+': '+fmt(p.v,view.u.div)+' '+view.u.unit+'</div>':'';}).join('');
      tip.innerHTML='<div>'+iso(best)+' UTC</div>'+rows; tip.style.display='block';
      const r=svg.getBoundingClientRect(); let left=(cx/view.W)*r.width+12; if(left>r.width-190) left-=210;
      tip.style.left=left+'px'; tip.style.top='12px';
    };
    h.onpointerleave=()=>{ if(drag===null){tip.style.display='none'; view.cur.setAttribute('display','none');} };
    h.onpointerup=e=>{
      if(drag===null) return; const x=px(e), a=drag; drag=null;
      if(Math.abs(x-a)>6) setRange(Math.round(tOf(Math.min(a,x))),Math.round(tOf(Math.max(a,x)))); else view.sel.setAttribute('display','none');
    };
  }
  return {draw};
}
const chart=makeChart($('#chart'),$('#tip'),$('#chartwrap'));
const gchart=hasG?makeChart($('#gchart'),$('#gtip'),$('#gwrap')):null;

function statsTable(t, series, u){
  t.replaceChildren();
  const hd=t.createTHead().insertRow(); ['Series','Samples','Min','Avg','Max','Time of maximum (UTC)'].forEach(h=>{const c=document.createElement('th'); c.textContent=h; hd.appendChild(c);});
  const tb=t.createTBody();
  series.forEach(s=>{
    if(!s.d.length) return;
    const v=s.d.map(p=>p.v), mx=maxOf(v), at=s.d.find(p=>p.v===mx).t;
    const r=tb.insertRow(); [s.name,s.d.length,fmt(minOf(v),u.div)+' '+u.unit,fmt(v.reduce((a,b)=>a+b,0)/v.length,u.div)+' '+u.unit,fmt(mx,u.div)+' '+u.unit,iso(at)].forEach(x=>{r.insertCell().textContent=x;});
  });
}

// grafico principale
const visibleSeries=()=>D.series.filter(s=>!state.hidden.has(s));
function mainSeries(){
  return visibleSeries().map(s=>({name:s,color:colors[s],w:s==='ALL'?2.2:1.6,
    d:D.samples.filter(x=>x.dp===s&&x[state.metric]!==null&&x[state.metric]!==undefined&&inRange(x.t)).map(x=>({t:x.t,v:x[state.metric]}))}));
}
function mainUnit(ser){
  const vals=ser.flatMap(s=>s.d.map(p=>p.v));
  return state.metric==='kbps'?scaleFor(vals):{div:1,unit:METRICS[state.metric].unit};
}
function drawMain(){ const ser=mainSeries(), u=mainUnit(ser); chart.draw(ser,{label:METRICS[state.metric].label,u}); statsTable($('#stats'),ser,u); }

// CPU by group chart
function groupSeries(){
  return D.groups.map((n,i)=>({name:n,color:GCOL[i],w:1.5,i})).filter(s=>!gs.hidden.has(s.name)).map(s=>({name:s.name,color:s.color,w:s.w,
    d:D.samples.filter(x=>x.dp===gs.dp&&x.g&&x.g[s.i]!==null&&x.g[s.i]!==undefined&&inRange(x.t)).map(x=>({t:x.t,v:x.g[s.i]}))}));
}
function drawGroups(){
  if(!hasG) return;
  const ser=groupSeries(), u={div:1,unit:'%'};
  gchart.draw(ser,{label:'CPU load',u,cap:100}); statsTable($('#gstats'),ser,u);
}

let activeTab='chart';
function renderActive(){ if(activeTab==='chart'){ drawMain(); renderTable(); } else if(activeTab==='cpu') drawGroups(); else if(activeTab==='dph' && hasDph) renderDph(); else if(activeTab==='mp' && hasMp) renderMp(); else if(activeTab==='sys' && hasSys) renderSys(); else if(activeTab==='pow' && hasPow) renderPow(); else if(activeTab==='ifc' && hasIfc) renderIfc(); }
function showTab(n){
  activeTab=n;
  ['chart','cpu','dph','mp','sys','pow','ifc','cov'].forEach(k=>{ const tab=$('#tab-'+k), pan=$('#p-'+k); tab.setAttribute('aria-selected',String(k===n)); tab.tabIndex=k===n?0:-1; pan.hidden=k!==n; });
  renderActive();   // charts are drawn only when the panel is visible (the real width is needed)
}
function refresh(){ renderActive(); }
function setRange(a,b,fromInput){
  state.range=[a,b];
  if(!fromInput){ $('#t0').value=a?isoLocalInput(a):''; $('#t1').value=b?isoLocalInput(b):''; }
  state.all=false; refresh();
}

// controlli
const msel=$('#metric');
Object.keys(METRICS).filter(hasMetric).forEach(k=>{const o=document.createElement('option'); o.value=k; o.textContent=METRICS[k].label; msel.appendChild(o);});
msel.onchange=()=>{state.metric=msel.value; drawMain();};
const fdp=$('#fdp');
[''].concat(D.series).forEach(v=>{const o=document.createElement('option'); o.value=v; o.textContent=v||'All'; fdp.appendChild(o);});
fdp.onchange=()=>{state.dp=fdp.value; renderTable();};
function legendItem(host,name,color,hiddenSet,onchange){
  const l=document.createElement('label'), c=document.createElement('input'); c.type='checkbox'; c.checked=!hiddenSet.has(name);
  c.onchange=()=>{c.checked?hiddenSet.delete(name):hiddenSet.add(name); onchange();};
  const sw=document.createElement('span'); sw.className='sw'; sw.style.background=color;
  l.append(c,sw,GL.names[name]?glName(name):document.createTextNode(name)); host.appendChild(l); return c;
}
D.series.forEach(s=>legendItem($('#leg'),s,colors[s],state.hidden,drawMain));
$('#reset').onclick=()=>setRange(null,null);
$('#q').oninput=e=>{state.q=e.target.value.toLowerCase(); renderTable();};
$('#t0').onchange=()=>{const v=$('#t0').value; setRange(v?Date.parse(v+':00Z'):null,state.range[1],true);};
$('#t1').onchange=()=>{const v=$('#t1').value; setRange(state.range[0],v?Date.parse(v+':59Z'):null,true);};
if(hasG){
  $('#tab-cpu').style.display=''; $('#gcolwrap').style.display=''; $('#greset').onclick=()=>setRange(null,null);
  const gdps=D.series.filter(s=>s!=='ALL'&&D.samples.some(x=>x.dp===s&&x.g));
  gs.dp=gdps[0];
  gdps.forEach(v=>{const o=document.createElement('option'); o.value=v; o.textContent=v; $('#gdp').appendChild(o);});
  $('#gdp').onchange=()=>{gs.dp=$('#gdp').value; drawGroups();};
  const boxes=D.groups.map((n,i)=>legendItem($('#gleg'),n,GCOL[i],gs.hidden,drawGroups));
  $('#gall').onclick=()=>{gs.hidden.clear(); boxes.forEach(b=>b.checked=true); drawGroups();};
  $('#gnone').onclick=()=>{D.groups.forEach(n=>gs.hidden.add(n)); boxes.forEach(b=>b.checked=false); drawGroups();};
  $('#gcol').onchange=()=>{state.showG=$('#gcol').checked; renderTable();};
}

// table
const num=v=>v===null||v===undefined?'':v.toLocaleString('en-US');
function cols(){
  const c=[
    {k:'t',l:'Date/time (UTC)',get:s=>s.t,f:s=>iso(s.t)},
    {k:'dp',l:'DP',get:s=>s.dp,f:s=>s.dp},
    {k:'kbpsu',l:'Throughput',get:s=>s.kbps,f:(s,u)=>s.kbps===null?'':fmt(s.kbps,u.div)+' '+u.unit},
    {k:'kbps',l:'Throughput (kbps)',get:s=>s.kbps,f:s=>num(s.kbps)},
    {k:'pps',l:'Packet rate (pkt/s)',get:s=>s.pps,f:s=>num(s.pps)},
    {k:'cps',l:'New conn. (cps)',get:s=>s.cps,f:s=>num(s.cps)},
    {k:'sess',l:'Allocated sessions',get:s=>s.sess,f:s=>num(s.sess)},
    {k:'util',l:'Session utilization (%)',get:s=>s.util,f:s=>s.util===null?'':s.util}
  ];
  if(state.showG) D.groups.forEach((n,i)=>c.push({k:'g'+i,l:n+' (%)',get:s=>s.g?s.g[i]:null,f:s=>s.g&&s.g[i]!==null?s.g[i]:''}));
  c.push({k:'src',l:'Source file',get:s=>s.src,f:s=>s.src});
  return c;
}
function filtered(){
  const rows=D.samples.filter(s=>inRange(s.t)&&(!state.dp||s.dp===state.dp)&&(!state.q||(iso(s.t)+' '+s.dp+' '+s.src+' '+s.kbps).toLowerCase().includes(state.q)));
  const c=cols().find(x=>x.k===state.sort.k)||cols()[0], d=state.sort.dir;
  return rows.sort((a,b)=>{const x=c.get(a),y=c.get(b); if(x===y) return a.t-b.t; if(x===null||x===undefined) return 1; if(y===null||y===undefined) return -1; return (x<y?-1:1)*d;});
}
function renderTable(){
  const rows=filtered(), u=scaleFor(rows.map(r=>r.kbps).filter(v=>v!==null)), C=cols();
  const t=$('#tbl'); t.replaceChildren();
  const hr=t.createTHead().insertRow();
  C.forEach(c=>{const th=document.createElement('th'); th.textContent=c.l+(state.sort.k===c.k?(state.sort.dir>0?' \u25B2':' \u25BC'):''); th.tabIndex=0;
    const go=()=>{state.sort=state.sort.k===c.k?{k:c.k,dir:-state.sort.dir}:{k:c.k,dir:1}; renderTable();};
    th.onclick=go; th.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();go();}}; hr.appendChild(th);});
  const tb=t.createTBody(), lim=state.all?rows.length:500;
  rows.slice(0,lim).forEach(s=>{const r=tb.insertRow(); C.forEach(c=>{r.insertCell().textContent=c.f(s,u);});});
  $('#count').textContent=rows.length+' rows';
  const m=$('#more'); m.textContent='';
  if(rows.length>lim){ m.textContent='Showing the first '+lim+' rows. '; const b=document.createElement('button'); b.type='button'; b.textContent='Show all'; b.onclick=()=>{state.all=true; renderTable();}; m.appendChild(b); }
}
$('#csv').onclick=()=>{
  const rows=filtered(), q=v=>'"'+String(v).replace(/"/g,'""')+'"', nz=v=>v===null||v===undefined?'':v;
  const lines=[['datetime_utc','dp','throughput_kbps','packet_rate_pps','cps','allocated_sessions','session_utilization_pct'].concat(D.groups.map(n=>'cpu_'+n),['source_file']).join(',')];
  rows.forEach(s=>lines.push([q(iso(s.t)),q(s.dp),nz(s.kbps),nz(s.pps),nz(s.cps),nz(s.sess),nz(s.util)].concat(D.groups.map((n,i)=>s.g?nz(s.g[i]):''),[q(s.src)]).join(',')));
  const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob(['\uFEFF'+lines.join('\r\n')],{type:'text/csv;charset=utf-8'}));
  a.download=D.name+'_throughput.csv'; a.click(); URL.revokeObjectURL(a.href);
};

'''

JS_CORE = _JS_CORE.replace('__GL_JS__', JS_GL)

# POW performance tab (workgroups, functions, categories, histograms, core matrix).
JS_POW = r'''// POW performance tab (debug dataplane pow performance)
const P = D.pow || null;
const hasPow = !!P;
const powState = {view:'global', q:'', anom:false, idle:true, sort:{g:{k:'total',dir:-1}, f:{k:'share',dir:-1}, l:{k:'total',dir:-1}}};
// Text with tooltips on the counter names and pow column names it mentions.
function richText(text,names){
  const keys=names.concat(Object.keys(GL.fields).filter(k=>/-us$|^ac-|^count$|^avg-ticks$/.test(k))).filter((v,i,a)=>a.indexOf(v)===i).sort((a,b)=>b.length-a.length);
  if(!keys.length) return document.createTextNode(text);
  const esc=x=>x.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const rx=new RegExp('(?<![\\w-])('+keys.map(esc).join('|')+')(?![\\w-])','g');
  const f=document.createDocumentFragment(); let last=0, m;
  while((m=rx.exec(text))){
    if(m.index>last) f.appendChild(document.createTextNode(text.slice(last,m.index)));
    const k=m[1];
    f.appendChild(names.indexOf(k)>=0&&GL.names[k]?glName(k):(GL.fields[k]?glTag(Object.assign(document.createElement('span'),{textContent:k}),k,true):document.createTextNode(k)));
    last=m.index+k.length;
  }
  if(last<text.length) f.appendChild(document.createTextNode(text.slice(last)));
  return f;
}
const rowLevel = r => r.flags.some(f=>f.level==='crit') ? 'crit' : (r.flags.some(f=>f.level==='warn') ? 'warn' : '');
const avgTxt = v => v===null||v===undefined ? '' : v.toLocaleString('en-US',{maximumFractionDigits:1});
const POW_COLS = [
  {k:'name', l:'Name', fk:'name', get:r=>r.name, f:r=>r.name},
  {k:'category', l:'Category', fk:'category', get:r=>r.category, f:r=>r.category},
  {k:'max', l:'max-us', fk:'max-us', get:r=>r.max_us, f:r=>num(r.max_us)},
  {k:'avg', l:'avg-us', fk:'avg-us', get:r=>r.avg_us, f:r=>avgTxt(r.avg_us)},
  {k:'count', l:'count', fk:'count', get:r=>r.count, f:r=>num(r.count)},
  {k:'total', l:'total-us', fk:'total-us', get:r=>r.total_us, f:r=>num(r.total_us)},
  {k:'share', l:'share %', fk:'share', get:r=>r.share, f:r=>r.share.toFixed(2)},
  {k:'acmax', l:'ac-max-us', fk:'ac-max-us', ac:true, get:r=>r.ac_max_us, f:r=>num(r.ac_max_us)},
  {k:'acavg', l:'ac-avg-us', fk:'ac-avg-us', ac:true, get:r=>r.ac_avg_us, f:r=>avgTxt(r.ac_avg_us)},
  {k:'account', l:'ac-count', fk:'ac-count', ac:true, get:r=>r.ac_count, f:r=>num(r.ac_count)},
  {k:'actotal', l:'ac-total-us', fk:'ac-total-us', ac:true, get:r=>r.ac_total_us, f:r=>num(r.ac_total_us)},
  {k:'ratio', l:'count / ac-count', fk:'ratio', ac:true, get:r=>r.ratio, f:r=>r.ratio===null?'':r.ratio.toFixed(2)},
  {k:'flags', l:'Flags', fk:'flags', get:r=>r.flags.length, f:null}
];
const powCols = () => POW_COLS.filter(c=>!(c.ac && P.format==='legacy'));
const powView = () => powState.view==='global' ? P.global : P.cores[powState.view];
function powFilter(rows){
  const q=powState.q;
  return rows.filter(r=>(!powState.idle || r.count>0 || r.ac_count>0 || r.flags.length>0)
    && (!q || (r.name+' '+r.category).toLowerCase().includes(q))
    && (!powState.anom || rowLevel(r)!==''));
}
function flagCell(td,r){
  td.style.textAlign='left';
  r.flags.forEach(f=>{ const s=document.createElement('span'); s.className='badge b-'+f.level; s.textContent=f.code; s.title=f.text; td.appendChild(s); });
}
function powTable(t,key,rows){
  const st=powState.sort[key], C=powCols();
  t.replaceChildren();
  const hr=t.createTHead().insertRow();
  C.forEach(c=>{
    const th=document.createElement('th'); th.textContent=c.l+(st.k===c.k?(st.dir>0?' ▲':' ▼'):''); th.tabIndex=0; glTag(th,c.fk,true);
    const go=()=>{ powState.sort[key]=st.k===c.k?{k:c.k,dir:-st.dir}:{k:c.k,dir:(c.k==='name'||c.k==='category')?1:-1}; renderPow(); };
    th.onclick=go; th.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();go();}}; hr.appendChild(th);
  });
  const c=C.find(x=>x.k===st.k)||C[0];
  const sorted=rows.slice().sort((a,b)=>{
    const x=c.get(a), y=c.get(b);
    if(x===y) return a.name<b.name?-1:(a.name>b.name?1:0);
    if(x===null||x===undefined) return 1;
    if(y===null||y===undefined) return -1;
    return (x<y?-1:1)*st.dir;
  });
  const tb=t.createTBody();
  sorted.forEach(r=>{
    const tr=tb.insertRow(), lv=rowLevel(r);
    if(lv) tr.className='anom-'+lv;
    C.forEach(col=>{
      const td=tr.insertCell();
      if(col.k==='name') td.appendChild(glName(r.name)); else if(col.f) td.textContent=col.f(r); else flagCell(td,r);
    });
  });
}
function renderPowInfo(){
  $('#pinfo').textContent='Collected at '+(P.collected_at||'unknown (no show clock output)')+' | format: '+P.format+(P.format==='legacy'?' (pre-9.1: max-us, avg-us, count only)':' (total-us and ac-* columns present)')+' | cores with data: '+(Object.keys(P.cores).join(', ')||'none');
  const ul=$('#pbanner'); ul.replaceChildren();
  if(!P.banner.length){ const li=document.createElement('li'); li.textContent='No anomaly flags with the current thresholds.'; ul.appendChild(li); }
  P.banner.forEach(b=>{ const li=document.createElement('li'); li.className='lvl-'+b.level; li.appendChild(richText(b.text,b.names||[])); ul.appendChild(li); });
  if(P.warnings.length){
    $('#pwarn').style.display=''; $('#pwarnsum').textContent=P.warnings.length+' warnings while parsing the POW output';
    P.warnings.forEach(w=>{ const li=document.createElement('li'); li.textContent=w; $('#pwarnlist').appendChild(li); });
  }
}
function renderPowCats(V){
  const t=$('#pcat'); t.replaceChildren();
  const s=V.func_summary, hr=t.createTHead().insertRow();
  [['Category','category'],['total-us','total-us'],['share %','share'],['','']].forEach(([x,fk])=>{ const th=document.createElement('th'); th.textContent=x; if(fk){ th.tabIndex=0; glTag(th,fk,true); } hr.appendChild(th); });
  const tb=t.createTBody();
  if(!s.by_category.length){ const c=tb.insertRow().insertCell(); c.colSpan=4; c.textContent='No function CPU time in this view.'; return; }
  s.by_category.forEach(b=>{
    const r=tb.insertRow(); r.insertCell().textContent=b.category; r.insertCell().textContent=num(b.total_us); r.insertCell().textContent=b.share.toFixed(2);
    const m=document.createElement('div'); m.className='meter'; const i=document.createElement('i'); i.style.width=Math.min(100,b.share)+'%'; m.appendChild(i); r.insertCell().appendChild(m);
  });
}
function renderPowHist(list){
  const box=$('#phist'); box.replaceChildren();
  if(!list.length){ box.textContent='No histograms in this view.'; return; }
  const LV={crit:2,warn:1,info:0}, rank=h=>h.flags.reduce((m,f)=>Math.max(m,LV[f.level]),-1);
  list.map((h,i)=>({h,i})).sort((a,b)=>rank(b.h)-rank(a.h)||a.i-b.i).forEach(({h})=>{
    const d=document.createElement('details'), s=document.createElement('summary');
    s.appendChild(glName(h.name)); s.appendChild(document.createTextNode(' ('+h.kind+') | calls '+num(h.count)+' | p50 '+avgTxt(h.p50_us)+' us | p99 '+avgTxt(h.p99_us)+' us | max bin '+avgTxt(h.max_bin_us)+' us '));
    h.flags.forEach(f=>{ const b=document.createElement('span'); b.className='badge b-'+f.level; b.textContent=f.code; b.title=f.text; s.appendChild(b); });
    d.appendChild(s);
    const t=document.createElement('table'), hr=t.createTHead().insertRow();
    ['col','avg-ticks','avg-us','count','total-us'].forEach(x=>{ const th=document.createElement('th'); th.textContent=x; th.tabIndex=0; glTag(th,x,true); hr.appendChild(th); });
    const tb=t.createTBody();
    h.bins.forEach(b=>{ const r=tb.insertRow(); b.forEach((v,i)=>{ r.insertCell().textContent=i===2?avgTxt(v):num(v); }); });
    const wrap=document.createElement('div'); wrap.className='scroll'; wrap.appendChild(t);
    const cb=document.createElement('div'), sel=document.createElement('select');
    [['count','calls per bin'],['total','time per bin (total-us)']].forEach(([v,l])=>{ const o=document.createElement('option'); o.value=v; o.textContent=l; sel.appendChild(o); });
    const cw=document.createElement('div'); cw.className='cw';
    const draw=()=>histChart(cw,h,sel.value); sel.onchange=draw;
    cb.append(document.createTextNode('Chart: '),sel,cw); d.append(cb,wrap);
    d.addEventListener('toggle',()=>{ if(d.open) draw(); });
    box.appendChild(d);
  });
}
function renderPowMatrix(){
  const t=$('#pmx'); t.replaceChildren();
  const cores=Object.keys(P.cores).map(Number).sort((a,b)=>a-b);
  const names=P.global.groups.map(g=>g.name);
  const val=(c,g)=>{ const r=P.cores[c].groups.find(x=>x.name===g); return r&&r.total_us?r.total_us:0; };
  let mx=0; names.forEach(g=>cores.forEach(c=>{ mx=Math.max(mx,val(c,g)); }));
  const hr=t.createTHead().insertRow();
  ['Workgroup'].concat(cores.map(c=>'Core '+c)).forEach(x=>{ const th=document.createElement('th'); th.textContent=x; hr.appendChild(th); });
  const tb=t.createTBody(), tot=new Array(cores.length).fill(0);
  names.forEach(g=>{
    const r=tb.insertRow(); r.insertCell().textContent=g;
    cores.forEach((c,j)=>{ const v=val(c,g), td=r.insertCell(); tot[j]+=v; td.textContent=num(v); if(mx>0 && v>0) td.style.background='rgba(31,111,139,'+(0.08+0.6*v/mx).toFixed(3)+')'; });
  });
  const r=tb.insertRow(); r.insertCell().textContent='Total';
  tot.forEach(v=>{ r.insertCell().textContent=num(v); });
}
const fUs=v=>v>=1e8?num(Math.round(v/1e6))+' s':v>=1e6?(v/1e6).toFixed(2)+' s':v>=1e3?(v/1e3).toFixed(1)+' ms':(Math.round(v*10)/10)+' us';
const shortN=v=>v>=1e9?(v/1e9).toFixed(1)+'G':v>=1e6?(v/1e6).toFixed(1)+'M':v>=1e3?(v/1e3).toFixed(1)+'k':String(Math.round(v*10)/10);
const svg=(n,a,p)=>{ const e=document.createElementNS(NS,n); for(const k in a) e.setAttribute(k,a[k]); if(p) p.appendChild(e); return e; };
const noMeaningRow=n=>{ const e=GL.names[n]; return !!e && noMeaning(e); };
function hbar(host,items,title){
  host.replaceChildren();
  if(!items.length){ const p=document.createElement('p'); p.className='hint'; p.textContent='No counters with CPU time.'; host.appendChild(p); return; }
  const W=Math.max(360,host.clientWidth||560), rh=21, L=235, R=140, H=items.length*rh+6, mx=Math.max.apply(null,items.map(i=>i.v))||1;
  const el=svg('svg',{viewBox:'0 0 '+W+' '+H,role:'img','aria-label':title},host); el.style.height=H+'px';
  items.forEach((it,i)=>{
    const y=3+i*rh, w=Math.max(1,(W-L-R)*it.v/mx), unk=noMeaningRow(it.n), g=svg('g',{},el), lab=svg('g',{},g);
    svg('rect',{x:0,y:y,width:L-4,height:rh,fill:'transparent'},lab);
    const tx=svg('text',{x:L-8,y:y+14,'text-anchor':'end',class:'bl'},lab); tx.textContent=(it.n.length>34?it.n.slice(0,33)+'..':it.n)+(unk?' ?':'');
    if(GL.names[it.n]){ lab.setAttribute('data-gl',it.n); lab.setAttribute('class','gl'); lab.setAttribute('tabindex','0'); lab.setAttribute('aria-describedby','gltip'); svg('title',{},lab).textContent=glTitle(it.n,false); }
    svg('rect',{x:L,y:y+3,width:w,height:rh-7,rx:2,fill:unk?'#b42318':'#1f6f8b',opacity:.85},g);
    const vt=svg('text',{x:L+w+6,y:y+14,class:'vl'},g); vt.textContent=fUs(it.v)+'  '+it.share.toFixed(1)+'%';
  });
}
function histChart(host,h,metric){
  host.replaceChildren();
  if(!h.bins.length) return;
  const W=Math.max(420,host.clientWidth||700), H=250, L=64, R=12, T=14, B=50, ci=metric==='count'?3:4;
  const bins=h.bins.slice().sort((a,b)=>a[0]-b[0]), c0=bins[0][0], c1=bins[bins.length-1][0], n=c1-c0+1, by={};
  bins.forEach(b=>{ by[b[0]]=b; });
  const mx=Math.max.apply(null,bins.map(b=>b[ci]).concat([1])), bw=(W-L-R)/n;
  const el=svg('svg',{viewBox:'0 0 '+W+' '+H,role:'img','aria-label':'Histogram of '+h.name},host);
  for(let i=0;i<=4;i++){
    const y=T+(H-T-B)*(1-i/4); svg('line',{x1:L,x2:W-R,y1:y,y2:y,stroke:'#e3e7ec'},el);
    svg('text',{x:L-6,y:y+4,'text-anchor':'end',class:'axt'},el).textContent=metric==='count'?shortN(mx*i/4):fUs(mx*i/4);
  }
  for(let c=c0;c<=c1;c++){
    const b=by[c], x=L+(c-c0)*bw;
    if(b){ const hh=(H-T-B)*b[ci]/mx, r=svg('rect',{x:x+1,y:H-B-hh,width:Math.max(1,bw-2),height:hh,fill:'#1f6f8b',opacity:.85},el);
      svg('title',{},r).textContent='col '+c+': avg '+fUs(b[3]?b[4]/b[3]:b[2])+', '+num(b[3])+' calls, '+fUs(b[4])+' total'; }
    if(n<=40||(c-c0)%2===0){ svg('text',{x:x+bw/2,y:H-B+14,'text-anchor':'middle',class:'axt'},el).textContent=c;
      if(b) svg('text',{x:x+bw/2,y:H-B+27,'text-anchor':'middle',class:'axt'},el).textContent=shortN(b[3]?b[4]/b[3]:b[2]); }
  }
  svg('text',{x:L,y:H-6,class:'axt'},el).textContent='bin (col), and mean us per call in the bin';
}
function renderPowTop(V){
  const n=+$('#ptopn').value, cpu=V.funcs.filter(r=>r.category!=='latency'), ac=P.format!=='legacy';
  const top=(k,sk)=>cpu.filter(r=>r[k]>0).sort((a,b)=>b[k]-a[k]).slice(0,n).map(r=>({n:r.name,v:r[k],share:r[sk]}));
  hbar($('#ptopw'),top('total_us','share'),'Top functions by total-us');
  $('#ptopa-wrap').style.display=ac?'':'none';
  if(ac) hbar($('#ptopa'),top('ac_total_us','ac_share'),'Top functions by ac-total-us');
}
function renderPowGcat(V){
  const t=$('#pgcat'); t.replaceChildren();
  const all=V.gloss_summary, rows=all.filter(c=>!powState.idle||!c.zero), hid=all.filter(c=>powState.idle&&c.zero), legacy=P.format==='legacy';
  $('#pgcat-hint').textContent=hid.length?hid.length+' inactive famil'+(hid.length>1?'ies':'y')+' collapsed ('+hid.map(c=>c.category).join('; ')+'). Untick "hide rows without calls" to list them.':'';
  const cols=[['Family','gcategory'],['functions','funcs'],['active','active'],['total-us','total-us'],['share %','share']].concat(legacy?[]:[['ac-total-us','ac-total-us'],['ac-share','ac-share']],[['Top counter','name']]);
  const hr=t.createTHead().insertRow();
  cols.forEach(([x,fk])=>{ const th=document.createElement('th'); th.textContent=x; th.tabIndex=0; glTag(th,fk,true); hr.appendChild(th); });
  const tb=t.createTBody();
  rows.forEach(c=>{
    const r=tb.insertRow(); r.insertCell().textContent=c.category+(c.unknown?' *':''); r.insertCell().textContent=c.funcs; r.insertCell().textContent=c.active;
    r.insertCell().textContent=num(c.total_us); r.insertCell().textContent=c.share.toFixed(2);
    if(!legacy){ r.insertCell().textContent=num(c.ac_total_us); r.insertCell().textContent=c.ac_share.toFixed(2); }
    const td=r.insertCell(); if(c.top) td.appendChild(glName(c.top));
  });
}
function renderPowView(){
  const V=powView();
  renderPowCats(V); renderPowHist(V.hist);
}
function renderPowLat(V){
  const rows=powFilter(V.funcs.filter(r=>r.category==='latency'));
  if(!rows.length){ const t=$('#plt'); t.replaceChildren(); t.textContent='No latency counters with data in this view.'; return; }
  powTable($('#plt'),'l',rows);
}
function renderPow(){
  const V=powView(), g=powFilter(V.groups), f=powFilter(V.funcs.filter(r=>r.category!=='latency'));
  powTable($('#pgt'),'g',g); powTable($('#pft'),'f',f);
  renderPowTop(V); renderPowGcat(V); renderPowLat(V);
  $('#pmeta').textContent='Workgroups '+g.length+' of '+V.groups.length+' | functions '+f.length+' of '+V.funcs.filter(r=>r.category!=='latency').length+' (latency counters listed apart) | CPU share basis: '+(V.func_summary.basis||'n/a');
}
function powCsv(){
  const q=v=>'"'+String(v).replace(/"/g,'""')+'"', nz=v=>v===null||v===undefined?'':(typeof v==='string'?q(v):v);
  const V=powView(), lines=['table,name,category,max_us,avg_us,count,total_us,share_pct,ac_max_us,ac_avg_us,ac_count,ac_total_us,count_ratio,flags,description'];
  [['workgroups',powFilter(V.groups)],['functions',powFilter(V.funcs)]].forEach(([tn,rows])=>rows.forEach(r=>lines.push([tn,r.name,r.category,r.max_us,r.avg_us,r.count,r.total_us,r.share,r.ac_max_us,r.ac_avg_us,r.ac_count,r.ac_total_us,r.ratio,r.flags.map(f=>f.code+':'+f.level).join(';'),r.description].map(nz).join(','))));
  const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob(['﻿'+lines.join('\r\n')],{type:'text/csv;charset=utf-8'}));
  a.download=D.name+'_pow_'+powState.view+'.csv'; a.click(); URL.revokeObjectURL(a.href);
}
if(hasPow){
  const pv=$('#pview');
  ['global'].concat(Object.keys(P.cores)).forEach(v=>{ const o=document.createElement('option'); o.value=v; o.textContent=v==='global'?'Global':'Core '+v; pv.appendChild(o); });
  pv.onchange=()=>{ powState.view=pv.value; renderPowView(); renderPow(); };
  $('#pq').oninput=e=>{ powState.q=e.target.value.trim().toLowerCase(); renderPow(); };
  $('#panom').onchange=e=>{ powState.anom=e.target.checked; renderPow(); };
  $('#pidle').onchange=e=>{ powState.idle=e.target.checked; renderPow(); };
  $('#pcsv').onclick=powCsv;
  $('#ptopn').onchange=()=>renderPow();
  renderPowInfo(); renderPowMatrix(); renderPowView(); renderPow();
}

'''

# Interface Errors tab (show counter interface all, show interface ...).
JS_IFC = r'''// Interface Errors tab (interface counters, link state, cross-check with the global counters)
const IF = D.ifc || null;
const hasIfc = !!IF;
const ifState = {q:'', kind:'', issues:true, sort:{k:'order', dir:1}};
const ifLevel = r => r.flags.some(f=>f.level==='crit') ? 'crit' : (r.flags.some(f=>f.level==='warn') ? 'warn' : '');
const ifNum = v => v===null||v===undefined ? '' : v.toLocaleString('en-US');
function ifCols(){
  const c = [
    {k:'order', l:'Interface', fk:'if:interface', left:true, get:r=>r.order, f:r=>r.name, name:true},
    {k:'kind', l:'Type', fk:'if:type', left:true, get:r=>r.kind, f:r=>r.kind},
    {k:'link', l:'Link', fk:'if:link', left:true, get:r=>r.link_txt, f:r=>r.link_txt},
    {k:'zone', l:'Zone', fk:'if:zone', left:true, get:r=>r.zone, f:r=>r.zone},
    {k:'ip', l:'Address', fk:'if:ip', left:true, get:r=>r.ip, f:r=>r.ip},
    {k:'rx_pkts', l:'rx packets', fk:'if:rx_pkts', get:r=>r.rx_pkts, f:r=>ifNum(r.rx_pkts)},
    {k:'tx_pkts', l:'tx packets', fk:'if:tx_pkts', get:r=>r.tx_pkts, f:r=>ifNum(r.tx_pkts)},
    {k:'rx_bytes', l:'rx bytes', fk:'if:rx_bytes', get:r=>r.rx_bytes, f:r=>ifNum(r.rx_bytes)},
    {k:'tx_bytes', l:'tx bytes', fk:'if:tx_bytes', get:r=>r.tx_bytes, f:r=>ifNum(r.tx_bytes)}
  ];
  IF.groups.forEach(g=>g.cols.forEach(x=>c.push({k:g.id+':'+x.k, l:x.k, gl:x.gl, grp:g.id, counter:true, get:r=>(r[g.id]||{})[x.k]||0, f:r=>ifNum((r[g.id]||{})[x.k]||0)})));
  c.push({k:'drop_pct', l:'Drop %', fk:'if:drop_pct', get:r=>r.drop_pct, f:r=>r.drop_pct===null?'':r.drop_pct.toFixed(2)});
  c.push({k:'flags', l:'Flags', fk:'if:flags', left:true, get:r=>r.flags.length, f:null});
  return c;
}
function ifFiltered(){
  const q = ifState.q;
  return IF.rows.filter(r=>(!ifState.issues || r.issue)
    && (!ifState.kind || r.kind===ifState.kind)
    && (!q || (r.name+' '+r.zone+' '+r.ip+' '+r.kind+' '+r.flags.map(f=>f.code).join(' ')).toLowerCase().includes(q)));
}
function ifTable(){
  const C = ifCols(), t = $('#itbl'), st = ifState.sort;
  t.replaceChildren();
  const hr = t.createTHead().insertRow();
  C.forEach(c=>{
    const th = document.createElement('th'); th.textContent = c.l + (st.k===c.k ? (st.dir>0?' ▲':' ▼') : ''); th.tabIndex = 0;
    if(c.left) th.classList.add('tl');
    if(c.grp) th.classList.add('g-'+c.grp);
    if(c.counter) glTag(th, c.gl, false); else glTag(th, c.fk, true);
    const go = ()=>{ ifState.sort = st.k===c.k ? {k:c.k, dir:-st.dir} : {k:c.k, dir:(c.left?1:-1)}; renderIfc(); };
    th.onclick = go; th.onkeydown = e=>{ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); go(); } };
    hr.appendChild(th);
  });
  const sc = C.find(x=>x.k===st.k) || C[0];
  const rows = ifFiltered().sort((a,b)=>{
    const x = sc.get(a), y = sc.get(b);
    if(x===y) return a.order-b.order;
    if(x===null||x===undefined) return 1;
    if(y===null||y===undefined) return -1;
    return (x<y?-1:1)*st.dir;
  });
  const tb = t.createTBody();
  rows.forEach(r=>{
    const tr = tb.insertRow(), lv = ifLevel(r);
    if(lv) tr.className = 'anom-'+lv;
    C.forEach(c=>{
      const td = tr.insertCell();
      if(c.left) td.classList.add('tl');
      if(c.f===null){
        r.flags.forEach(f=>{ const s = document.createElement('span'); s.className = 'badge b-'+f.level; s.textContent = f.code; s.title = f.text; td.appendChild(s); });
      } else if(c.counter){
        const v = c.get(r); td.textContent = v ? ifNum(v) : '·'; td.classList.add(v ? 'nzc' : 'zc');
      } else td.textContent = c.f(r);
    });
  });
  $('#imeta').textContent = rows.length+' of '+IF.rows.length+' interfaces shown'+(ifState.issues?' (only those with issues)':'');
}
function ifSimpleTable(t, head, rows, fill){
  t.replaceChildren();
  const hr = t.createTHead().insertRow();
  head.forEach(h=>{ const th = document.createElement('th'); th.textContent = h; hr.appendChild(th); });
  const tb = t.createTBody();
  rows.forEach(r=>{ const tr = tb.insertRow(); fill(tr, r); });
}
function renderIfcStatic(){
  const S = IF.system;
  ifSimpleTable($('#isys'), ['Hostname','Model','PAN-OS','Uptime','Captured'], [S], (tr,s)=>{
    [s.hostname||'unknown', s.model||'unknown', s.sw_version||'unknown', s.uptime ? s.uptime+' ('+s.uptime_text+')' : 'unknown', s.collected_at||'unknown'].forEach(x=>{ tr.insertCell().textContent = x; });
  });
  const ul = $('#ibanner'); ul.replaceChildren();
  if(!IF.banner.length){ const li = document.createElement('li'); li.textContent = 'No interface flags with the current thresholds.'; ul.appendChild(li); }
  IF.banner.forEach(b=>{ const li = document.createElement('li'); li.className = 'lvl-'+b.level; li.textContent = b.text; ul.appendChild(li); });
  $('#idown').textContent = IF.down_ports.length ? 'Down ports with no traffic: '+IF.down_ports.join(', ')+'.' : '';
  if(IF.warnings.length){
    $('#iwarn').style.display = ''; $('#iwarnsum').textContent = IF.warnings.length+' warnings while parsing the interface output';
    IF.warnings.forEach(w=>{ const li = document.createElement('li'); li.textContent = w; $('#iwarnlist').appendChild(li); });
  }
  const leg = $('#igleg'); leg.replaceChildren();
  IF.groups.filter(g=>g.cols.length).forEach(g=>{
    const sq = document.createElement('span'); sq.className = 'legsq'; sq.style.background = g.id==='phys'?'#b42318':g.id==='cpu'?'#a15c00':'#1f6f8b';
    leg.append(sq, document.createTextNode(g.label+' counters'));
  });
  if(!leg.childNodes.length) leg.textContent = 'No non-zero error counters.';
  const ks = Array.from(new Set(IF.rows.map(r=>r.kind))), sel = $('#ikind');
  [''].concat(ks).forEach(v=>{ const o = document.createElement('option'); o.value = v; o.textContent = v||'All'; sel.appendChild(o); });
  // cross-check
  $('#ixmsg').textContent = IF.crosscheck.length ? '' : 'No cross-check available (the output has no show counter global, or all counters are zero).';
  ifSimpleTable($('#ixchk'), ['Counter','Sum over interfaces','Global counter(s)','Global value','Difference','Status'], IF.crosscheck, (tr,x)=>{
    tr.insertCell().appendChild(glName(x.counter));
    tr.insertCell().textContent = ifNum(x.interface_sum);
    const c = tr.insertCell(); c.style.textAlign = 'left'; x.globals.forEach((g,i)=>{ if(i) c.appendChild(document.createTextNode(' + ')); c.appendChild(glName(g.name)); });
    tr.insertCell().textContent = x.globals.map(g=>g.value===null?'n/a':ifNum(g.value)).join(' + ')+(x.globals.length>1?' = '+ifNum(x.global_sum):'');
    tr.insertCell().textContent = (x.diff>0?'+':'')+ifNum(x.diff);
    const s = tr.insertCell(); s.textContent = x.status; s.title = x.note; s.style.textAlign = 'left';
    if(x.status==='differs') tr.className = 'anom-warn';
  });
  ifSimpleTable($('#ictx'), ['Global counter','Value','Description'], IF.context, (tr,c)=>{
    tr.insertCell().appendChild(glName(c.name)); tr.insertCell().textContent = ifNum(c.value);
    const d = tr.insertCell(); d.textContent = c.description; d.style.textAlign = 'left';
  });
  const ex = $('#iextra'); ex.replaceChildren();
  if(IF.transceivers && IF.transceivers.rows.length){
    const d = document.createElement('details'); d.open = true; const sm = document.createElement('summary'); sm.textContent = 'Transceivers ('+IF.transceivers.rows.length+')'; d.appendChild(sm);
    const t = document.createElement('table'); t.className = 'stats'; d.appendChild(t); ex.appendChild(d);
    ifSimpleTable(t, IF.transceivers.header, IF.transceivers.rows, (tr,r)=>{ r.forEach(x=>{ tr.insertCell().textContent = x; }); });
  }
  if(IF.lacp.length){
    const d = document.createElement('details'); const sm = document.createElement('summary'); sm.textContent = 'LACP (show lacp aggregate-ethernet all, raw)'; d.appendChild(sm);
    const pre = document.createElement('pre'); pre.textContent = IF.lacp.join('\n'); d.appendChild(pre); ex.appendChild(d);
  }
}
function ifCsv(){
  const C = ifCols().filter(c=>c.f!==null), q = v=>'"'+String(v).replace(/"/g,'""')+'"';
  const head = C.map(c=>c.grp ? c.grp+': '+c.l : c.l).concat(['flags']);
  const lines = [head.map(q).join(',')];
  ifFiltered().sort((a,b)=>a.order-b.order).forEach(r=>{
    const cells = C.map(c=>{ const v = c.left ? c.f(r) : c.get(r); return typeof v==='number' ? v : q(v===null||v===undefined?'':v); });
    cells.push(q(r.flags.map(f=>f.code+':'+f.level).join(';')));
    lines.push(cells.join(','));
  });
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['﻿'+lines.join('\r\n')], {type:'text/csv;charset=utf-8'}));
  a.download = D.name+'_interfaces.csv'; a.click(); URL.revokeObjectURL(a.href);
}
function renderIfc(){ ifTable(); }
if(hasIfc){
  $('#iq').oninput = e=>{ ifState.q = e.target.value.trim().toLowerCase(); renderIfc(); };
  $('#ikind').onchange = e=>{ ifState.kind = e.target.value; renderIfc(); };
  $('#iissues').onchange = e=>{ ifState.issues = e.target.checked; renderIfc(); };
  $('#icsv').onclick = ifCsv;
  renderIfcStatic(); renderIfc();
}

'''

# Dataplane health tab (resource monitor of the panio sections: sessions, packet buffer, cores)
JS_DPH = r'''// Dataplane health tab (session / packet buffer / packet descriptor utilization, CPU per core)
const DH = D.dph || null;
const hasDph = !!DH;
const dphState = {dp:null, hidden:new Set()};
const DPH_SERIES = [
  {k:'sess', name:'Session utilization', color:'#1f6f8b', w:1.8},
  {k:'pb_avg', name:'Packet buffer (avg)', color:'#2f855a', w:1.4},
  {k:'pb_max', name:'Packet buffer (max)', color:'#c2410c', w:1.4},
  {k:'core_max', name:'Busiest core (per-second)', color:'#7c3aed', w:1.4},
  {k:'core_m_max', name:'Busiest core (per-minute max)', color:'#0e7490', w:1.4}
];
const dphChart = hasDph ? makeChart($('#dphchart'), $('#dphtip'), $('#dphwrap')) : null;
let DPH_T0 = 0, DPH_T1 = 0;
const dphPct = v => v===null||v===undefined ? '' : v+'%';
const dphAt = (v, t) => v===null||v===undefined ? '' : v+'% @ '+iso(t);
function dphWorst(dp){
  const fl = DH.findings.filter(f=>f.dp===dp);
  return fl.some(f=>f.level==='crit') ? 'crit' : (fl.some(f=>f.level==='warn') ? 'warn' : '');
}
function renderDphStatic(){
  const all = DH.dps.flatMap(d=>DH.series[d].t);
  DPH_T0 = minOf(all); DPH_T1 = maxOf(all);
  if(!hasSamples){
    $('#sub').textContent = 'Period '+iso(DPH_T0)+' - '+iso(DPH_T1)+' UTC | dp-monitor files read: '+D.files+' | generated '+D.generated+' UTC';
    $('#utc').style.display = '';
  }
  const dsc = DH.discarded;
  $('#dphinfo').textContent = DH.n_samples+' sample(s) on '+DH.dps.length+' DP(s). Discarded while reading: '+dsc.bad_rows+' CPU row(s) with a wrong column count, '+dsc.out_of_range+' value(s) outside 0-100; '+dsc.asterisks+' missing (*) CPU/utilization cell(s) ignored.';
  if(DH.warnings.length){ $('#dphwarn').style.display=''; $('#dphwarnsum').textContent = DH.warnings.length+' note(s)'; DH.warnings.forEach(w=>{ const li=document.createElement('li'); li.textContent=w; $('#dphwarnlist').appendChild(li); }); }
  const onchip = DH.dps.some(d=>DH.summary[d].pkt_desc_onchip.n>0);
  const metrics = [['session','Session util'],['pkt_buffer','Packet buffer'],['pkt_desc','Packet descriptor']]
    .concat(onchip?[['pkt_desc_onchip','Pkt desc on-chip']]:[], [['core','Busiest core (per-second)'],['core_minute','Busiest core (per-minute max)']]);
  const t = $('#dphsum'); t.replaceChildren();
  const h1 = t.createTHead().insertRow();
  ['DP','Samples','Period (UTC)'].forEach(x=>{ const th=document.createElement('th'); th.textContent=x; th.rowSpan=2; h1.appendChild(th); });
  metrics.forEach(m=>{ const th=document.createElement('th'); th.textContent=m[1]; th.colSpan=2; th.style.textAlign='center'; h1.appendChild(th); });
  const h2 = t.tHead.insertRow();
  metrics.forEach(()=>['Last','Peak'].forEach(x=>{ const th=document.createElement('th'); th.textContent=x; h2.appendChild(th); }));
  const tb = t.createTBody();
  DH.dps.forEach(dp=>{
    const S = DH.summary[dp], ts = DH.series[dp].t, r = tb.insertRow();
    r.insertCell().textContent = dp; r.insertCell().textContent = ts.length;
    r.insertCell().textContent = iso(ts[0])+' - '+iso(ts[ts.length-1]);
    metrics.forEach(m=>{
      const x = S[m[0]];
      const core = m[0]==='core' || m[0]==='core_minute';
      r.insertCell().textContent = x.last===null ? '' : x.last+'%'+(core && x.last_core!==null ? ' (core '+x.last_core+')' : '');
      r.insertCell().textContent = x.peak===null ? '' : x.peak+'% @ '+iso(x.peak_t)+(core && x.peak_core!==null ? ' (core '+x.peak_core+')' : '');
    });
    const lv = dphWorst(dp); if(lv) r.className = 'anom-'+lv;
  });
  const ul = $('#dphbanner'); ul.replaceChildren();
  if(!DH.findings.length){ const li=document.createElement('li'); li.textContent='No dataplane health flags with the current thresholds.'; ul.appendChild(li); }
  DH.findings.forEach(f=>{
    const li = document.createElement('li'); li.className = 'lvl-'+f.level;
    const b = document.createElement('span'); b.className = 'badge b-'+f.level; b.textContent = f.code;
    li.append(b, document.createTextNode(f.text)); ul.appendChild(li);
  });
  DH.dps.forEach(v=>{ const o=document.createElement('option'); o.value=v; o.textContent=v; $('#dphdp').appendChild(o); });
  dphState.dp = DH.dps[0];
  $('#dphdp').onchange = ()=>{ dphState.dp = $('#dphdp').value; renderDph(); };
  $('#dphreset').onclick = ()=>setRange(null,null);
  DPH_SERIES.forEach(s=>legendItem($('#dphleg'), s.name, s.color, dphState.hidden, renderDph));
}
function dphHeat(v){ return v===null||v===undefined ? '' : 'rgba(180,35,24,'+(0.06+0.94*v/100).toFixed(2)+')'; }
function renderDphCores(){
  const host = $('#dphcores'); host.replaceChildren();
  const C = DH.cores[dphState.dp];
  if(!C.ids.length){ const p=document.createElement('p'); p.className='hint'; p.textContent='No CPU load per core was found for this DP.'; host.appendChild(p); return; }
  const rows = [['Peak, per-second table', C.peak, true, DH.thresholds.core_peak_warn], ['Peak, per-minute max', C.peak_m, false, DH.thresholds.core_peak_minute_warn]];
  for(let i=0;i<C.ids.length;i+=16){
    const t = document.createElement('table'); t.className = 'hm';
    const hr = t.createTHead().insertRow(); hr.appendChild(document.createElement('th')).textContent = i===0 ? 'Core' : 'Core (cont.)';
    C.ids.slice(i,i+16).forEach(c=>{ const th=document.createElement('th'); th.textContent=c; hr.appendChild(th); });
    const tb = t.createTBody();
    rows.forEach(rw=>{
      const r = tb.insertRow(); r.insertCell().textContent = rw[0];
      rw[1].slice(i,i+16).forEach((v,j)=>{
        const td = r.insertCell(); td.textContent = v===null||v===undefined ? '' : v;
        if(v!==null&&v!==undefined){
          td.style.background = dphHeat(v); if(v>=55) td.style.color = '#fff';
          if(v>=rw[3]) td.classList.add('hot');
          if(rw[2]) td.title = 'Core '+C.ids[i+j]+': peak '+v+'% at '+iso(C.peak_t[i+j])+' UTC; last '+C.last[i+j]+'%';
          else td.title = 'Core '+C.ids[i+j]+': highest per-minute maximum '+v+'% in the 15 minutes before '+iso(C.peak_m_t[i+j])+' UTC; last '+C.last_m[i+j]+'%';
        }
      });
    });
    host.appendChild(t);
  }
}
function renderDph(){
  const S = DH.series[dphState.dp], u = {div:1, unit:'%'};
  const ser = DPH_SERIES.filter(s=>!dphState.hidden.has(s.name)).map(s=>({name:s.name, color:s.color, w:s.w,
    d:S.t.map((t,i)=>({t:t, v:S[s.k][i]})).filter(p=>p.v!==null&&p.v!==undefined&&inRange(p.t))}));
  dphChart.draw(ser, {label:'Utilization', u, cap:100, t0:DPH_T0, t1:DPH_T1});
  statsTable($('#dphstats'), ser, u);
  renderDphCores();
}
if(hasDph) renderDphStatic();

'''

# Management plane tab (mp-monitor memory and processes sections)
JS_MP = r'''// Management plane tab (memory used %, per-process CPU and Res+Swap)
const MP = D.mp || null;
const hasMp = !!MP;
const mpState = {hidden:new Set(), view:null};
const MP_SERIES = [
  {k:'used_pct', name:'Memory used', color:'#c2410c', w:1.8},
  {k:'swap_used_pct', name:'Swap used', color:'#0e7490', w:1.4}
];
const mpChart = hasMp ? makeChart($('#mpchart'), $('#mptip'), $('#mpwrap')) : null;
let MP_T0 = 0, MP_T1 = 0;
const mpKb = v => v===null||v===undefined ? '' : (v/1024).toLocaleString('en-US',{maximumFractionDigits:1})+' MB';
const mpGrowth = v => (v>0?'+':v<0?'-':'')+mpKb(Math.abs(v));
const mpPct = v => v===null||v===undefined ? '' : v+'%';
function mpRow(t, cells){ const r = t.insertRow(); cells.forEach(c=>{ r.insertCell().textContent = c; }); return r; }
function mpHead(t, names){ const r = t.createTHead().insertRow(); names.forEach(x=>{ const th=document.createElement('th'); th.textContent=x; r.appendChild(th); }); }
function mpWorst(){
  return MP.findings.some(f=>f.level==='crit') ? 'crit' : (MP.findings.some(f=>f.level==='warn') ? 'warn' : '');
}
function renderMpStatic(){
  const M = MP.memory, S = M.summary, P = MP.period;
  MP_T0 = M.t.length ? M.t[0] : P.first; MP_T1 = M.t.length ? M.t[M.t.length-1] : P.last;
  if(!hasSamples && !hasDph){
    $('#sub').textContent = 'Period '+iso(P.first)+' - '+iso(P.last)+' UTC | generated '+D.generated+' UTC';
  }
  if(!hasSamples) $('#utc').style.display = '';
  const dsc = MP.discarded;
  $('#mpinfo').textContent = MP.n_mem+' memory and '+MP.n_proc+' processes sample(s)'+(MP.interval_s!==null ? ' (processes about every '+MP.interval_s+' s)' : '')+'. Discarded while reading: '+dsc.bad_rows+' row(s), '+dsc.bad_values+' non-numeric memory value(s); '+dsc.duplicates+' duplicate section(s) from rotated files ignored.';
  if(MP.warnings.length){ $('#mpwarn').style.display=''; $('#mpwarnsum').textContent = MP.warnings.length+' note(s)'; MP.warnings.forEach(w=>{ const li=document.createElement('li'); li.textContent=w; $('#mpwarnlist').appendChild(li); }); }
  const t = $('#mpsum'); t.replaceChildren();
  mpHead(t, ['Memory samples','Processes samples','Period (UTC)','Total memory','Memory used, last','Memory used, peak','Lowest MemAvailable']);
  const tb = t.createTBody();
  const r = mpRow(tb, [MP.n_mem, MP.n_proc, iso(P.first)+' - '+iso(P.last),
    S ? mpKb(S.total_kb) : '', S ? S.last+'% @ '+iso(S.last_t) : '', S ? S.peak+'% @ '+iso(S.peak_t) : '', S ? mpKb(S.min_avail_kb) : '']);
  const lv = mpWorst(); if(lv) r.className = 'anom-'+lv;
  const ul = $('#mpbanner'); ul.replaceChildren();
  if(!MP.findings.length){ const li=document.createElement('li'); li.textContent='No management plane flags with the current thresholds.'; ul.appendChild(li); }
  MP.findings.forEach(f=>{
    const li = document.createElement('li'); li.className = 'lvl-'+f.level;
    const b = document.createElement('span'); b.className = 'badge b-'+f.level; b.textContent = f.code;
    li.append(b, document.createTextNode(f.text)); ul.appendChild(li);
  });
  $('#mpreset').onclick = ()=>setRange(null,null);
  MP_SERIES.filter(s=>M[s.k].some(v=>v!==null)).forEach(s=>legendItem($('#mpleg'), s.name, s.color, mpState.hidden, renderMp));
  const views = [['flagged','Processes with a PROC_CPU flag ('+MP.flagged.length+')'], ['cpu','Top '+MP.top_cpu.length+' by peak CPU'], ['rss','Top '+MP.top_rss.length+' by peak Res+Swap'], ['growth','Top '+MP.top_growth.length+' by Res+Swap growth'], ['all','All processes ('+MP.procs.length+')']];
  views.forEach(v=>{ const o=document.createElement('option'); o.value=v[0]; o.textContent=v[1]; $('#mpview').appendChild(o); });
  mpState.view = MP.flagged.length ? 'flagged' : 'rss';
  $('#mpview').value = mpState.view;
  $('#mpview').onchange = ()=>{ mpState.view = $('#mpview').value; renderMpProcs(); };
}
function renderMpProcs(){
  const by = {}; MP.procs.forEach(p=>{ by[p.name] = p; });
  const names = {flagged:MP.flagged, cpu:MP.top_cpu, rss:MP.top_rss, growth:MP.top_growth, all:MP.procs.map(p=>p.name)}[mpState.view];
  const t = $('#mpprocs'); t.replaceChildren();
  mpHead(t, ['Process','Samples','Peak CPU','Samples at/above '+MP.thresholds.proc_cpu_warn+'%','Longest run','Longest run period (UTC)','Runs (>= '+MP.thresholds.proc_cpu_min_samples+')','Peak Res+Swap','Last Res+Swap','Growth','State Z','Flag']);
  const tb = t.createTBody();
  names.forEach(n=>{
    const p = by[n];
    const r = mpRow(tb, [n+(p.ignored ? ' ('+p.ignored+', not flagged)' : ''), p.n, p.peak_cpu===null ? '' : p.peak_cpu+'% @ '+iso(p.peak_cpu_t), p.n_high, p.longest_run || '',
      p.run_start===null ? '' : iso(p.run_start)+' - '+iso(p.run_end), p.n_runs || '',
      p.peak_rss===null ? '' : mpKb(p.peak_rss)+' @ '+iso(p.peak_rss_t), mpKb(p.last_rss), p.n_rss>1 ? mpGrowth(p.growth) : '', p.zombie || '', '']);
    if(MP.flagged.includes(n)){
      r.className = 'anom-warn';
      const b = document.createElement('span'); b.className = 'badge b-warn'; b.textContent = 'PROC_CPU'; r.cells[r.cells.length-1].appendChild(b);
    }
  });
  $('#mpcount').textContent = names.length+' process(es) shown.';
}
function renderMp(){
  const M = MP.memory, u = {div:1, unit:'%'};
  const ser = MP_SERIES.filter(s=>!mpState.hidden.has(s.name) && M[s.k].some(v=>v!==null)).map(s=>({name:s.name, color:s.color, w:s.w,
    d:M.t.map((t,i)=>({t:t, v:M[s.k][i]})).filter(p=>p.v!==null&&p.v!==undefined&&inRange(p.t))}));
  mpChart.draw(ser, {label:'Memory', u, cap:100, top:100, t0:MP_T0, t1:MP_T1,
    lines:[{v:MP.thresholds.mem_warn, color:'#b7791f', label:'warn '+MP.thresholds.mem_warn+'%'}, {v:MP.thresholds.mem_crit, color:'#b42318', label:'crit '+MP.thresholds.mem_crit+'%'}]});
  statsTable($('#mpstats'), ser, u);
  renderMpProcs();
}
if(hasMp) renderMpStatic();

'''

# Tab wiring, keyboard handling, initial tab, closing script and document tags.
JS_TABS = r'''const TABS=[].concat(hasSamples?['chart']:[], hasG?['cpu']:[], hasDph?['dph']:[], hasMp?['mp']:[], hasSys?['sys']:[], hasPow?['pow']:[], hasIfc?['ifc']:[], hasCov?['cov']:[]);
['chart','cpu','dph','mp','sys','pow','ifc','cov'].forEach(k=>{ $('#tab-'+k).style.display=TABS.includes(k)?'':'none'; });
$('#tabs').style.display=TABS.length>1?'':'none';
TABS.forEach(k=>{ $('#tab-'+k).onclick=()=>showTab(k); });
$('#tabs').onkeydown=e=>{
  const i=TABS.indexOf(activeTab); let j=-1;
  if(e.key==='ArrowRight') j=(i+1)%TABS.length; else if(e.key==='ArrowLeft') j=(i+TABS.length-1)%TABS.length; else if(e.key==='Home') j=0; else if(e.key==='End') j=TABS.length-1;
  if(j<0) return; e.preventDefault(); showTab(TABS[j]); $('#tab-'+TABS[j]).focus();
};
// Debounced: re-draws the visible tab at the new size. Zoom range and selections are state, so they are kept.
let resizeTimer=null;
window.addEventListener('resize',()=>{ clearTimeout(resizeTimer); resizeTimer=setTimeout(renderActive,150); });
showTab(TABS[0]);
</script>
</body>
</html>
'''

# System health tab (CLI dump sections and core file names; more check groups can be added)
JS_SYS = r'''// System health tab: a checks table, the findings and one detail block per check
const SYS = D.sys || null;
const hasSys = !!SYS;
const SYS_BADGE = {ok:['ok','ok'], warning:['warning','warn'], critical:['critical','crit'], no_data:['no data','info']};
function sysEl(tag, text, cls){ const e = document.createElement(tag); if(text!==undefined && text!==null) e.textContent = text; if(cls) e.className = cls; return e; }
function sysBadge(st){ const d = SYS_BADGE[st] || [st,'info']; return sysEl('span', d[0], 'badge b-'+d[1]); }
function sysTable(head, rows, fill){
  const t = sysEl('table', null, 'stats covt'); const hr = t.createTHead().insertRow();
  head.forEach(h=>{ const th = sysEl('th', h); th.className = 'l'; hr.appendChild(th); });
  const tb = t.createTBody();
  rows.forEach(r=>{ const tr = tb.insertRow(); fill(tr, r); Array.from(tr.cells).forEach(c=>{ c.className = 'l'; }); });
  const w = sysEl('div', null, 'scroll'); w.appendChild(t); return w;
}
function sysCell(tr, v){ tr.insertCell().textContent = (v===null||v===undefined) ? '' : v; }
function sysFmtBytes(n){
  if(n===null||n===undefined) return 'unknown size';
  const u = ['bytes','KB','MB','GB']; let i = 0, v = n;
  while(v>=1024 && i<u.length-1){ v /= 1024; i++; }
  return (i ? v.toLocaleString('en-US',{maximumFractionDigits:1}) : v.toLocaleString('en-US'))+' '+u[i];
}
function sysBlock(host, title, body, note){
  const d = sysEl('div', null, 'sysblock'); d.style.margin = '0 0 16px';
  d.appendChild(sysEl('h3', title)); if(note) d.appendChild(sysEl('p', note, 'hint'));
  if(body) d.appendChild(body); host.appendChild(d); return d;
}
function sysNoData(host, check, title){
  sysBlock(host, title, null, 'No data: '+check.note);
}
function sysDetailSoftware(host, check){
  const S = SYS.software;
  if(check.status==='no_data'){ sysNoData(host, check, 'Software status'); return; }
  S.blocks.forEach(b=>{
    const msg = b.bad.length ? b.bad.length+' of '+b.total+' not running.' : 'All '+b.total+' running.';
    sysBlock(host, 'Software status - '+b.title, b.bad.length ? sysTable(['Type','Name','State','Info'], b.bad, (tr,r)=>{
      sysCell(tr, r.type); sysCell(tr, r.name); sysCell(tr, r.state); sysCell(tr, r.info); tr.className = 'anom-crit'; }) : null, msg);
  });
}
function sysDetailCfg(host, check){
  if(check.status==='no_data'){ sysNoData(host, check, 'Configuration memory'); return; }
  const rows = [];
  SYS.cfg.blocks.forEach(b=>{
    if(b.config) rows.push({label:b.label, name:'Config allocator', a:b.config});
    b.policies.forEach(p=>rows.push({label:b.label, name:'Policy cache'+(p.role ? ' ('+p.role+')' : ''), a:p}));
  });
  const th = SYS.thresholds;
  sysBlock(host, 'Configuration memory', sysTable(['Block','Allocator','Used','Total','Used %'], rows, (tr,r)=>{
    sysCell(tr, r.label); sysCell(tr, r.name); sysCell(tr, r.a.used_kb.toLocaleString('en-US')+' KB'); sysCell(tr, r.a.total_kb.toLocaleString('en-US')+' KB'); sysCell(tr, r.a.pct+'%');
    if(r.a.pct>=th.cfg_mem_crit) tr.className = 'anom-crit'; else if(r.a.pct>=th.cfg_mem_warn) tr.className = 'anom-warn';
  }), 'Limits: warn '+th.cfg_mem_warn+'%, crit '+th.cfg_mem_crit+'% (at or above).');
}
function sysRuleRow(tr, r, warn){
  sysCell(tr, r.vsys); sysCell(tr, r.rule); sysCell(tr, r.type); sysCell(tr, r.used.toLocaleString('en-US')); sysCell(tr, r.avail.toLocaleString('en-US'));
  sysCell(tr, r.pct===null ? '' : r.pct+'%'); sysCell(tr, r.mem); sysCell(tr, r.ratio); sysCell(tr, r.persistent); sysCell(tr, r.min); sysCell(tr, r.max);
  if(r.pct!==null && r.pct>=warn) tr.className = 'anom-warn';
}
function sysDetailNat(host, check){
  const N = SYS.nat, warn = SYS.thresholds.nat_pool_warn;
  if(check.status==='no_data'){ sysNoData(host, check, 'NAT pools'); return; }
  const g = [];
  if(N.shared) g.push({name:'Shared memory used', v:N.shared.used.toLocaleString('en-US')+(N.shared.usable ? ' of '+N.shared.usable.toLocaleString('en-US') : ''), pct:N.shared.pct});
  N.pools.forEach(p=>g.push({name:p.name+' NAT pool', v:p.count.toLocaleString('en-US'), pct:p.pct}));
  const d = sysBlock(host, 'NAT pools', null, 'Limit: warn '+warn+'% (at or above). '+(N.present_global ? '' : 'show running global-ippool not found. ')+(N.present_rules ? N.n_rules+' rule(s) in '+N.vsys.length+' VSYS block(s)' : 'show running ippool not found')+(N.present_rules ? ', '+N.n_over+' at or above the limit.' : '.'));
  if(g.length) d.appendChild(sysTable(['Global pool item','Value','Used %'], g, (tr,r)=>{ sysCell(tr, r.name); sysCell(tr, r.v); sysCell(tr, r.pct+'%'); if(r.pct>=warn) tr.className = 'anom-warn'; }));
  const head = ['VSYS','Rule','Type','Used','Available','Used %','Mem size','Ratio','Persistent','Min','Max'];
  if(N.rules.length){
    d.appendChild(sysEl('h4', 'Top '+N.top.length+' rules by used %'));
    d.appendChild(sysTable(head, N.top, (tr,r)=>sysRuleRow(tr, r, warn)));
    if(N.rules.length>N.top.length){
      const det = sysEl('details'); det.appendChild(sysEl('summary', 'All '+N.rules.length+' rules'+(N.n_rules>N.rules.length ? ' (worst '+N.rules.length+' of '+N.n_rules+')' : '')));
      det.appendChild(sysTable(head, N.rules, (tr,r)=>sysRuleRow(tr, r, warn))); d.appendChild(det);
    }
  }
}
function sysDetailCores(host, check){
  const C = SYS.cores;
  if(check.status==='no_data'){ sysNoData(host, check, 'Core files'); return; }
  const msg = C.state==='files' ? C.files.length+' core file(s). The content was not read.' : (C.state==='empty' ? 'Core directory present, empty: '+C.dirs.join(', ') : 'No core directory in the archive.');
  sysBlock(host, 'Core files', C.files.length ? sysTable(['File','Size'], C.files, (tr,f)=>{ sysCell(tr, f.name); sysCell(tr, sysFmtBytes(f.size)); tr.className = 'anom-crit'; }) : null, msg);
}
// Logs group: kernel crashes, repeated daemon errors, commit and job context
function sysUtc(ms){ return (ms===null||ms===undefined) ? '' : iso(ms)+' UTC'; }
function sysDetailKernel(host, check){
  const K = SYS.logs.kernel;
  if(check.status==='no_data'){ sysNoData(host, check, 'Kernel crashes'); return; }
  const crit = SYS.thresholds.crash_min;
  const note = K.lines.toLocaleString('en-US')+' kernel line(s) in '+K.files.join(', ')+'. Only segfault, general protection and out-of-memory kill lines are counted, per process and type; at or above '+crit+' is flagged. Times are the ones written in the log: device local time, no year, no offset (not used for correlation).'+(K.dropped ? ' '+K.dropped+' event(s) of further process/type pairs were not counted (limit reached).' : '');
  sysBlock(host, 'Kernel crashes', K.events.length ? sysTable(['Process','Type','Events','First (local, no year)','Last (local, no year)','PIDs','Files'], K.events, (tr,e)=>{
    sysCell(tr, e.process); sysCell(tr, e.type); sysCell(tr, e.count.toLocaleString('en-US')); sysCell(tr, e.first); sysCell(tr, e.last); sysCell(tr, e.pids.join(', ')); sysCell(tr, e.files.join(', '));
    tr.className = e.count>=crit ? 'anom-crit' : 'anom-warn'; }) : null, K.events.length ? note : 'No crash line found. '+note);
}
function sysDetailLogErrors(host, check){
  const L = SYS.logs.daemons, rep = SYS.thresholds.log_repeat_min;
  if(check.status==='no_data'){ sysNoData(host, check, 'Repeated daemon errors'); return; }
  const d = sysBlock(host, 'Repeated daemon errors', sysTable(['Daemon','Files','Lines','Error lines','Distinct messages','Repeated (>= '+rep+')'], L.rows, (tr,r)=>{
    sysCell(tr, r.daemon); sysCell(tr, r.files.join(', ')); sysCell(tr, r.lines.toLocaleString('en-US')); sysCell(tr, r.errors.toLocaleString('en-US')); sysCell(tr, r.distinct.toLocaleString('en-US'));
    const n = r.messages.filter(m=>m.flagged).length; sysCell(tr, n); if(n) tr.className = 'anom-warn'; }),
    'An error line starts (after the timestamp) with a level token ERROR/ERR/CRIT/CRITICAL/FATAL or Error:/error:/Crit:/fatal:. Messages are normalised (3+ digit numbers become N, 0x... becomes 0xH, bracketed or quoted paths are kept). Identical messages are counted per daemon; lines of rotated files are not de-duplicated. At most 50 messages per daemon are listed.');
  L.rows.forEach(r=>{
    if(!r.messages.length) return;
    const det = sysEl('details'); const nf = r.messages.filter(m=>m.flagged).length;
    det.appendChild(sysEl('summary', r.daemon+': '+r.errors.toLocaleString('en-US')+' error line(s), '+r.distinct.toLocaleString('en-US')+' distinct'+(nf ? ', '+nf+' repeated' : '')));
    if(nf) det.open = true;
    det.appendChild(sysTable(['Count','First (UTC)','Last (UTC)','Message','Files'], r.messages, (tr,m)=>{
      sysCell(tr, m.count.toLocaleString('en-US')); sysCell(tr, sysUtc(m.first)); sysCell(tr, sysUtc(m.last)); sysCell(tr, m.msg); sysCell(tr, m.files.join(', ')); if(m.flagged) tr.className = 'anom-warn'; }));
    if(r.omitted) det.appendChild(sysEl('p', r.omitted+' less frequent message(s) not listed (limit of 50 per daemon).', 'hint'));
    if(r.dropped) det.appendChild(sysEl('p', r.dropped+' error line(s) with a new message were not counted (limit of distinct messages reached).', 'hint'));
    d.appendChild(det);
  });
}
function sysDetailCommits(host, check){
  const C = SYS.logs.context;
  if(check.status==='no_data'){ sysNoData(host, check, 'Commit and job context'); return; }
  const d = sysBlock(host, 'Commit and job context', null, 'Informational only: it never changes a flag. Commit windows come from COMMIT lines of configd.log (explicit UTC offset; lines at most '+SYS.thresholds.commit_gap_s+' s apart form one window). Jobs come from "show jobs processed" in device local time WITHOUT offset: the offset is inferred from the explicit-offset log headers of the same TSF; a job with an ambiguous (DST change within a day) or unknown offset has no UTC time and is not correlated. A flag is near a window or job when it lies within '+SYS.thresholds.corr_window_s+' s of it. Running jobs have no end and are not correlated.');
  if(C.correlations.length){
    d.appendChild(sysEl('h4', 'Items near a commit or job ('+C.correlations.length+')'));
    const ul = sysEl('ul', null, 'banner');
    C.correlations.forEach(c=>{ const li = sysEl('li', null, 'lvl-info'); li.append(sysEl('span', 'NEAR_COMMIT', 'badge b-info'), document.createTextNode(c.text)); ul.appendChild(li); });
    d.appendChild(ul);
  } else d.appendChild(sysEl('p', 'No flagged item is near a commit window or a job.', 'hint'));
  const off = Object.entries(C.job_offsets).map(([k,v])=>v+' '+k).join(', ');
  if(off) d.appendChild(sysEl('p', 'Job offsets: '+off+'.'+(C.jobs_src ? ' Source: '+C.jobs_src+'.' : ''), 'hint'));
  const head = ['Kind','Item','Start (UTC)','End (UTC)','Offset','Detail','Near'];
  const fill = (tr,r)=>{
    sysCell(tr, r.kind); sysCell(tr, r.label); sysCell(tr, r.start===null ? '(no UTC: offset '+r.offset_state+')' : sysUtc(r.start)); sysCell(tr, r.running ? 'running' : sysUtc(r.end));
    sysCell(tr, r.kind==='commit' ? 'explicit' : (r.offset ? 'inferred '+r.offset : r.offset_state)); sysCell(tr, r.detail); sysCell(tr, r.near.join(', ')); if(r.near.length) tr.className = 'anom-warn'; };
  const tl = C.timeline;
  d.appendChild(sysEl('h4', 'Commit and job timeline'));
  d.appendChild(sysTable(head, tl.slice(0, 20), fill));
  if(tl.length>20){ const det = sysEl('details'); det.appendChild(sysEl('summary', 'All '+tl.length+' rows')); det.appendChild(sysTable(head, tl, fill)); d.appendChild(det); }
}
// check id -> detail renderer; a later step registers its own here.
const SYS_DETAIL = {software:sysDetailSoftware, cfg_mem:sysDetailCfg, nat:sysDetailNat, cores:sysDetailCores, kernel:sysDetailKernel, log_errors:sysDetailLogErrors, commits:sysDetailCommits};
function renderSysStatic(){
  if(!hasSamples && !hasDph && !hasMp && !hasPow && !hasIfc) $('#sub').textContent = 'Generated '+D.generated+' UTC';
  const n = SYS.checks.length, nd = SYS.checks.filter(c=>c.status==='no_data').length;
  $('#sysinfo').textContent = n+' check(s)'+(nd ? ', '+nd+' without data' : '')+'. Overall: '+(SYS_BADGE[SYS.status] || [SYS.status])[0]+'. Sources: the CLI dump of the TSF, the names of the core files in the archive'+(SYS.logs ? ', var/log/messages and the daemon logs.' : '.');
  if(SYS.logs && SYS.logs.budgets.length) $('#sysinfo').textContent += ' Limits reached: '+SYS.logs.budgets.join('; ')+'.';
  const t = $('#syschecks'); t.replaceChildren();
  const hr = t.createTHead().insertRow();
  ['Group','Check','Source','Status','Value','Note'].forEach(h=>{ const th = sysEl('th', h); th.className = 'l'; hr.appendChild(th); });
  const tb = t.createTBody();
  SYS.checks.forEach(c=>{
    const tr = tb.insertRow();
    sysCell(tr, c.group); sysCell(tr, c.title); sysCell(tr, c.source);
    tr.insertCell().appendChild(sysBadge(c.status));
    sysCell(tr, c.value); sysCell(tr, c.note);
    Array.from(tr.cells).forEach(x=>{ x.className = 'l'; });
    if(c.status==='critical') tr.className = 'anom-crit'; else if(c.status==='warning') tr.className = 'anom-warn';
  });
  const ul = $('#sysbanner'); ul.replaceChildren();
  if(!SYS.findings.length){ ul.appendChild(sysEl('li', 'No system health flags with the current thresholds.')); }
  SYS.findings.forEach(f=>{
    const li = sysEl('li', null, 'lvl-'+f.level);
    li.append(sysEl('span', f.code, 'badge b-'+f.level), document.createTextNode(f.text)); ul.appendChild(li);
  });
  const host = $('#sysdetails'); host.replaceChildren();
  SYS.checks.forEach(c=>{ if(SYS_DETAIL[c.id]) SYS_DETAIL[c.id](host, c); });
}
function renderSys(){}
if(hasSys) renderSysStatic();

'''

# Source coverage tab and analysis-status badge (what the analysis actually looked at).
JS_COV = r'''// Source coverage tab and analysis status badge
const CV = D.coverage || null;
const hasCov = !!CV;
const COV_STATE = {
  absent:['absent','info','No member of this family was found in the input.'],
  unread:['unread','warn','Members were found but none could be read.'],
  zero_samples:['0 samples','warn','Files were read but no sample could be extracted.'],
  truncated:['truncated','warn','At least one member exceeded the read limit: only its last part was analysed.'],
  error:['read error','crit','At least one member could not be read to the end.'],
  conflict:['conflict','warn','Samples with the same DP and time but different values were found; the first was kept.'],
  listed:['listed only','ok','Names and sizes were recorded; the content is never read.'],
  ok:['ok','ok','Everything found was read.']
};
function covBadge(host, st){
  const d = COV_STATE[st] || [st,'info','']; const b = document.createElement('span');
  b.className = 'badge b-'+d[1]; b.textContent = d[0]; b.title = d[2]; host.appendChild(b);
}
function covMemberState(m){
  const k = m.state.split(':')[0], b = document.createElement('span');
  b.className = 'badge b-'+(k==='read'||k==='listed'?'ok':k==='error'?'crit':'warn'); b.textContent = m.state; if(m.detail) b.title = m.detail;
  return b;
}
function covTable(t, head, rows, fill){
  t.replaceChildren();
  const hr = t.createTHead().insertRow();
  head.forEach(h=>{ const th = document.createElement('th'); th.textContent = h; th.className = 'l'; hr.appendChild(th); });
  const tb = t.createTBody();
  rows.forEach(r=>{ const tr = tb.insertRow(); fill(tr, r); Array.from(tr.cells).forEach(c=>{ c.className = 'l'; }); });
}
function covRange(f, l){ return f===null||f===undefined ? '' : iso(f)+' - '+iso(l)+' UTC'; }
function renderCov(){
  const ab = $('#astatus');
  ab.style.display = ''; ab.className = 'badge astatus b-'+(CV.status==='complete'?'ok':'warn');
  ab.textContent = 'Analysis: '+CV.status;
  ab.title = CV.status==='complete' ? 'Every member found was read in full and no samples conflicted.' :
    'Partial: '+(CV.summary.length ? CV.summary.join('; ') : 'see the Source coverage tab')+'. Results may miss data; see the Source coverage tab.';
  ab.onclick = ()=>{ if(TABS.includes('cov')) showTab('cov'); };
  $('#covmsg').textContent = CV.archive ? '' : 'Single-file input: source coverage is only meaningful for archives and directories.';
  covTable($('#covfam'), ['Family','State','Found','Read','Truncated','Skipped','Samples','Time range (UTC)','Conflicts','Members'], CV.families, (tr,f)=>{
    tr.insertCell().textContent = f.family;
    const sc = tr.insertCell(); f.states.forEach(s=>covBadge(sc, s));
    [f.found, f.read, f.truncated+f.errors, f.skipped].forEach(v=>{ tr.insertCell().textContent = v; });
    tr.insertCell().textContent = f.samples===null ? 'n/a' : f.samples;
    tr.insertCell().textContent = covRange(f.first, f.last);
    tr.insertCell().textContent = f.family==='dp-monitor' ? f.conflicts : 'n/a';
    const mc = tr.insertCell();
    if(f.members.length){
      const d = document.createElement('details'); const sm = document.createElement('summary'); sm.textContent = f.members.length+' member(s)'; d.appendChild(sm);
      const ul = document.createElement('ul'); ul.className = 'cov-sub';
      f.members.forEach(m=>{
        const li = document.createElement('li'); li.appendChild(covMemberState(m));
        let txt = ' '+m.name+(m.state==='listed' && m.detail ? ' ('+m.detail+')' : ''); if(m.samples!==null) txt += ' - '+m.samples+' samples'+(m.samples ? ', '+covRange(m.first, m.last) : '');
        li.appendChild(document.createTextNode(txt)); ul.appendChild(li);
      });
      d.appendChild(ul); mc.appendChild(d);
    } else if(f.dirs && f.dirs.length){
      mc.textContent = 'empty directory: '+f.dirs.join(', ');
    }
    if(f.states.some(s=>s!=='ok')) tr.className = 'anom-warn';
  });
  $('#covskipmsg').textContent = CV.skipped.length ? CV.skipped.length+' member(s) were rejected before reading.' : 'No member was rejected.';
  covTable($('#covskip'), ['Member','Reason'], CV.skipped, (tr,s)=>{ tr.insertCell().textContent = s.name; tr.insertCell().textContent = s.reason; });
  const ul = $('#covnotes');
  if(!CV.notes.length){ const li = document.createElement('li'); li.textContent = 'No limit was reached.'; ul.appendChild(li); }
  CV.notes.forEach(n=>{ const li = document.createElement('li'); li.textContent = n; ul.appendChild(li); });
  const C = CV.conflicts;
  $('#covconfmsg').textContent = C.total ? (C.total+' conflicting sample(s)'+(C.shown<C.total ? ', first '+C.shown+' shown' : '')+'. The first sample was kept.') : 'No conflicting samples.';
  covTable($('#covconf'), ['DP','Time (UTC)','Kept (source)','Dropped (source)'], C.items, (tr,c)=>{
    tr.insertCell().textContent = c.dp; tr.insertCell().textContent = iso(c.t);
    tr.insertCell().textContent = c.kept; tr.insertCell().textContent = c.dropped;
  });
}
if(hasCov) renderCov();

'''

TEMPLATE = (TEMPLATE_HEAD +
            TEMPLATE_CSS +
            TEMPLATE_BODY +
            JS_CORE +
            JS_POW +
            JS_IFC +
            JS_DPH +
            JS_MP +
            JS_SYS +
            JS_COV +
            JS_TABS)

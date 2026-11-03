"""Page template of the TSF report (HTML, CSS and JavaScript).

Placeholders: __KIND__, __TITLE__ and __DATA__ (JSON blob), __HELP__ (Help tab).
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
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1280px;margin:0 auto;padding:20px 16px 48px}
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
.scroll{max-height:460px;overflow:auto;border:1px solid var(--line)}
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
.b-crit{background:#b42318}.b-warn{background:#b7791f}.b-info{background:#5d6b7a}
tr.anom-crit td{background:#fdecea}
tr.anom-warn td{background:var(--warn-bg)}
tr.anom-crit td:first-child{box-shadow:inset 4px 0 0 #b42318}
tr.anom-warn td:first-child{box-shadow:inset 4px 0 0 var(--warn-bd)}
.meter{height:8px;min-width:120px;background:#e3e7ec;border-radius:2px}
.meter i{display:block;height:100%;background:var(--acc);border-radius:2px}
summary{cursor:pointer}
.help{max-width:920px;line-height:1.5}
.help h2{font-size:16px;margin:20px 0 8px}
.help h2:first-child{margin-top:0}
.help h3{font-size:14px;margin:14px 0 6px}
.help p,.help ul,.help ol{margin:6px 0}
.help code{background:#eef1f4;border-radius:2px;padding:0 4px;font-size:12.5px}
.help table{width:auto;max-width:100%}
.help th,.help td{white-space:normal;text-align:left;vertical-align:top;cursor:default;position:static}
.help details{margin:8px 0}
.help summary{font-weight:600}
'''

# Markup: closing head, header, tabs bar, tab panels.
TEMPLATE_BODY = r'''</style>
</head>
<body>
<main>
<h1 id="title"></h1>
<p class="sub" id="sub"></p>
<div class="utc" id="utc"></div>
<details id="warn" style="display:none;margin:0 0 16px"><summary id="warnsum"></summary><ul id="warnlist"></ul></details>

<div class="tabs" id="tabs" role="tablist" aria-label="Report sections">
  <button type="button" role="tab" id="tab-chart" aria-controls="p-chart" aria-selected="true">Dataplane Throughput</button>
  <button type="button" role="tab" id="tab-cpu" aria-controls="p-cpu" aria-selected="false" tabindex="-1" style="display:none">CPU load by group</button>
  <button type="button" role="tab" id="tab-pow" aria-controls="p-pow" aria-selected="false" tabindex="-1" style="display:none">POW performance</button>
  <button type="button" role="tab" id="tab-help" aria-controls="p-help" aria-selected="false" tabindex="-1">Help</button>
</div>

<section class="panel" id="p-chart" role="tabpanel" aria-labelledby="tab-chart">
  <div class="bar">
    <label>Metric <select id="metric"></select></label>
    <div class="leg" id="leg"></div>
    <button id="reset" type="button">Reset zoom</button>
  </div>
  <div class="cw" id="chartwrap"><svg id="chart" role="img" aria-label="Metrics over time chart"></svg><div class="tip" id="tip"></div></div>
  <p class="hint">Drag on the chart to zoom into a range; the range also applies to the other charts and to the table.</p>
  <table class="stats" id="stats"></table>
  <div class="sep">
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

<section class="panel" id="p-pow" role="tabpanel" aria-labelledby="tab-pow" hidden>
  <p class="hint" id="pinfo"></p>
  <details id="pwarn" style="display:none;margin:0 0 12px"><summary id="pwarnsum"></summary><ul id="pwarnlist"></ul></details>
  <ul class="banner" id="pbanner"></ul>
  <div class="bar">
    <label>View <select id="pview"></select></label>
    <label>Search <input type="search" id="pq" placeholder="name or category"></label>
    <label><input type="checkbox" id="panom"> only anomalous rows</label>
    <label><input type="checkbox" id="pidle" checked> hide rows without calls</label>
    <button id="pcsv" type="button">Export CSV</button>
    <span class="hint" id="pmeta"></span>
  </div>
  <h2>Workgroups</h2>
  <div class="scroll"><table id="pgt"></table></div>
  <h2 style="margin-top:16px">Functions</h2>
  <div class="scroll"><table id="pft"></table></div>
  <div class="sep"><h2>Function CPU share by category</h2><table class="stats" id="pcat"></table></div>
  <div class="sep"><h2>Histograms (processing time per call)</h2><div id="phist"></div></div>
  <div class="sep"><h2>Workgroup total-us per core</h2><p class="hint">Darker cell = more CPU time. Use the View selector to see one core's functions.</p><div class="scroll"><table id="pmx"></table></div></div>
</section>

<section class="panel help" id="p-help" role="tabpanel" aria-labelledby="tab-help" hidden>
__HELP__
</section>

</main>

'''

# Script start, data, dataplane throughput chart and table, CPU by group, CSV export.
JS_CORE = r'''<script>
const D = __DATA__;
const $ = s => document.querySelector(s);
const NS = 'http://www.w3.org/2000/svg';
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
$('#sub').textContent = hasSamples ? ('Period ' + iso(TMIN) + ' - ' + iso(TMAX) + ' UTC | dp-monitor files read: ' + D.files + ' | generated ' + D.generated + ' UTC') : (D.pow && D.pow.collected_at ? 'Collected at ' + D.pow.collected_at : '');
$('#utc').textContent = 'Reminder: all times in this report are in UTC. The original firewall timestamps' + (D.offsets.length ? ' (detected offsets: ' + D.offsets.join(', ') + ')' : '') + ' have been converted.' + (D.series[0]==='ALL' ? ' The ALL series is the sum across DPs (for session table utilization it is the maximum value).' : '');
$('#utc').style.display = hasSamples ? '' : 'none';
if (D.warnings.length){ $('#warn').style.display=''; $('#warnsum').textContent = D.warnings.length + ' warnings while reading'; D.warnings.forEach(w=>{const li=document.createElement('li'); li.textContent=w; $('#warnlist').appendChild(li);}); }

// reusable chart
function makeChart(svg, tip, wrap){
  let view=null;
  const el=(n,a)=>{const e=document.createElementNS(NS,n); for(const k in a) e.setAttribute(k,a[k]); svg.appendChild(e); return e;};
  const niceMax=v=>{ if(v<=0) return 1; const p=Math.pow(10,Math.floor(Math.log10(v))), n=v/p; return (n<=1?1:n<=2?2:n<=2.5?2.5:n<=5?5:10)*p; };
  function draw(series,o){
    const W=Math.max(480,wrap.clientWidth), H=360, L=70,R=16,T=12,B=34, u=o.u;
    svg.setAttribute('viewBox','0 0 '+W+' '+H); svg.replaceChildren();
    const all=series.flatMap(s=>s.d.map(p=>p.v));
    const x0=state.range[0]!==null?state.range[0]:TMIN, x1=state.range[1]!==null?state.range[1]:TMAX;
    let ymax=niceMax((all.length?maxOf(all):1)/u.div*1.05); if(o.cap) ymax=Math.min(ymax,o.cap);
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
function renderActive(){ if(activeTab==='chart'){ drawMain(); renderTable(); } else if(activeTab==='cpu') drawGroups(); else if(activeTab==='pow' && hasPow) renderPow(); }
function showTab(n){
  activeTab=n;
  ['chart','cpu','pow','help'].forEach(k=>{ const tab=$('#tab-'+k), pan=$('#p-'+k); tab.setAttribute('aria-selected',String(k===n)); tab.tabIndex=k===n?0:-1; pan.hidden=k!==n; });
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
  l.append(c,sw,document.createTextNode(name)); host.appendChild(l); return c;
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

# POW performance tab (workgroups, functions, categories, histograms, core matrix).
JS_POW = r'''// POW performance tab (debug dataplane pow performance)
const P = D.pow || null;
const hasPow = !!P;
const powState = {view:'global', q:'', anom:false, idle:true, sort:{g:{k:'total',dir:-1}, f:{k:'share',dir:-1}}};
const rowLevel = r => r.flags.some(f=>f.level==='crit') ? 'crit' : (r.flags.some(f=>f.level==='warn') ? 'warn' : '');
const avgTxt = v => v===null||v===undefined ? '' : v.toLocaleString('en-US',{maximumFractionDigits:1});
const POW_COLS = [
  {k:'name', l:'Name', get:r=>r.name, f:r=>r.name},
  {k:'category', l:'Category', get:r=>r.category, f:r=>r.category},
  {k:'max', l:'max-us', get:r=>r.max_us, f:r=>num(r.max_us)},
  {k:'avg', l:'avg-us', get:r=>r.avg_us, f:r=>avgTxt(r.avg_us)},
  {k:'count', l:'count', get:r=>r.count, f:r=>num(r.count)},
  {k:'total', l:'total-us', get:r=>r.total_us, f:r=>num(r.total_us)},
  {k:'share', l:'share %', get:r=>r.share, f:r=>r.share.toFixed(2)},
  {k:'acmax', l:'ac-max-us', ac:true, get:r=>r.ac_max_us, f:r=>num(r.ac_max_us)},
  {k:'acavg', l:'ac-avg-us', ac:true, get:r=>r.ac_avg_us, f:r=>avgTxt(r.ac_avg_us)},
  {k:'account', l:'ac-count', ac:true, get:r=>r.ac_count, f:r=>num(r.ac_count)},
  {k:'actotal', l:'ac-total-us', ac:true, get:r=>r.ac_total_us, f:r=>num(r.ac_total_us)},
  {k:'ratio', l:'count / ac-count', ac:true, get:r=>r.ratio, f:r=>r.ratio===null?'':r.ratio.toFixed(2)},
  {k:'flags', l:'Flags', get:r=>r.flags.length, f:null}
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
    const th=document.createElement('th'); th.textContent=c.l+(st.k===c.k?(st.dir>0?' ▲':' ▼'):''); th.tabIndex=0;
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
      if(col.f) td.textContent=col.f(r); else flagCell(td,r);
      if(col.k==='name' && r.description) td.title=r.description;
    });
  });
}
function renderPowInfo(){
  $('#pinfo').textContent='Collected at '+(P.collected_at||'unknown (no show clock output)')+' | format: '+P.format+(P.format==='legacy'?' (pre-9.1: max-us, avg-us, count only)':' (total-us and ac-* columns present)')+' | cores with data: '+(Object.keys(P.cores).join(', ')||'none');
  const ul=$('#pbanner'); ul.replaceChildren();
  if(!P.banner.length){ const li=document.createElement('li'); li.textContent='No anomaly flags with the current thresholds.'; ul.appendChild(li); }
  P.banner.forEach(b=>{ const li=document.createElement('li'); li.className='lvl-'+b.level; li.textContent=b.text; ul.appendChild(li); });
  if(P.warnings.length){
    $('#pwarn').style.display=''; $('#pwarnsum').textContent=P.warnings.length+' warnings while parsing the POW output';
    P.warnings.forEach(w=>{ const li=document.createElement('li'); li.textContent=w; $('#pwarnlist').appendChild(li); });
  }
}
function renderPowCats(V){
  const t=$('#pcat'); t.replaceChildren();
  const s=V.func_summary, hr=t.createTHead().insertRow();
  ['Category','total-us','share %',''].forEach(x=>{ const th=document.createElement('th'); th.textContent=x; hr.appendChild(th); });
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
    s.textContent=h.name+' ('+h.kind+') | calls '+num(h.count)+' | p50 '+avgTxt(h.p50_us)+' us | p99 '+avgTxt(h.p99_us)+' us | max bin '+avgTxt(h.max_bin_us)+' us ';
    h.flags.forEach(f=>{ const b=document.createElement('span'); b.className='badge b-'+f.level; b.textContent=f.code; b.title=f.text; s.appendChild(b); });
    d.appendChild(s);
    const t=document.createElement('table'), hr=t.createTHead().insertRow();
    ['col','avg-ticks','avg-us','count','total-us'].forEach(x=>{ const th=document.createElement('th'); th.textContent=x; hr.appendChild(th); });
    const tb=t.createTBody();
    h.bins.forEach(b=>{ const r=tb.insertRow(); b.forEach((v,i)=>{ r.insertCell().textContent=i===2?avgTxt(v):num(v); }); });
    const wrap=document.createElement('div'); wrap.className='scroll'; wrap.appendChild(t); d.appendChild(wrap);
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
function renderPowView(){
  const V=powView();
  renderPowCats(V); renderPowHist(V.hist);
}
function renderPow(){
  const V=powView(), g=powFilter(V.groups), f=powFilter(V.funcs);
  powTable($('#pgt'),'g',g); powTable($('#pft'),'f',f);
  $('#pmeta').textContent='Workgroups '+g.length+' of '+V.groups.length+' | functions '+f.length+' of '+V.funcs.length+' | CPU share basis: '+(V.func_summary.basis||'n/a');
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
  renderPowInfo(); renderPowMatrix(); renderPowView(); renderPow();
}

'''

# Tab wiring, keyboard handling, initial tab, closing script and document tags.
JS_TABS = r'''const TABS=[].concat(hasSamples?['chart']:[], hasG?['cpu']:[], hasPow?['pow']:[], ['help']);
['chart','cpu','pow','help'].forEach(k=>{ $('#tab-'+k).style.display=TABS.includes(k)?'':'none'; });
$('#tabs').style.display=TABS.length>1?'':'none';
TABS.forEach(k=>{ $('#tab-'+k).onclick=()=>showTab(k); });
$('#tabs').onkeydown=e=>{
  const i=TABS.indexOf(activeTab); let j=-1;
  if(e.key==='ArrowRight') j=(i+1)%TABS.length; else if(e.key==='ArrowLeft') j=(i+TABS.length-1)%TABS.length; else if(e.key==='Home') j=0; else if(e.key==='End') j=TABS.length-1;
  if(j<0) return; e.preventDefault(); showTab(TABS[j]); $('#tab-'+TABS[j]).focus();
};
window.addEventListener('resize',renderActive);
showTab(TABS[0]);
</script>
</body>
</html>
'''

TEMPLATE = (TEMPLATE_HEAD +
            TEMPLATE_CSS +
            TEMPLATE_BODY +
            JS_CORE +
            JS_POW +
            JS_TABS)

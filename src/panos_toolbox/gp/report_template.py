"""Single-file HTML page of the GlobalProtect client report (HTML, CSS, JS).

The data is embedded as JSON; the page works offline and loads nothing from
the network. Every value from the logs is written with ``textContent``.
"""
from __future__ import annotations

import html

TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ - GlobalProtect client report</title>
<style>
:root{--ink:#1c2530;--mute:#5d6b7a;--line:#d8dde3;--bg:#f4f6f8;--card:#fff;--acc:#1f6f8b;
--ok:#1b7f4b;--ok-bg:#e3f4ea;--bad:#b3261e;--bad-bg:#fbe6e4;--warn:#8a5a00;--warn-bg:#fff4d6;
--idle:#5d6b7a;--idle-bg:#e9edf1;--sys:#5b4b8a;--sys-bg:#eeeaf7}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,-apple-system,Arial,sans-serif}
header{background:#16232e;color:#fff;padding:14px 24px}
header h1{margin:0;font-size:19px;font-weight:600}
header .sub{color:#b9c6d2;font-size:12.5px;margin-top:3px;overflow-wrap:anywhere}
nav{display:flex;gap:4px;padding:0 24px;background:#16232e}
nav button{border:0;background:transparent;color:#b9c6d2;padding:9px 16px;font:inherit;cursor:pointer;border-radius:6px 6px 0 0}
nav button.on{background:var(--bg);color:var(--ink);font-weight:600}
nav button:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,tr.row:focus-visible{outline:2px solid #4aa3c2;outline-offset:1px}
main{padding:18px 24px 60px;max-width:1800px;margin:0 auto}
section.tab{display:none}section.tab.on{display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin-bottom:14px}
.card h2{margin:0 0 8px;font-size:15px}
.card h3{margin:14px 0 6px;font-size:13px;color:var(--mute);text-transform:uppercase;letter-spacing:.04em}
.mute{color:var(--mute)}.small{font-size:12.5px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.tile{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--idle);border-radius:8px;padding:10px 14px}
.tile b{display:block;font-size:24px;line-height:1.2}
.tile span{color:var(--mute);font-size:12.5px}
.tile.connected{border-left-color:var(--ok)}.tile.failed{border-left-color:var(--bad)}
.tile.cancelled{border-left-color:var(--warn)}.tile.total{border-left-color:var(--acc)}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--mute);font-weight:600;white-space:nowrap;background:var(--card);position:sticky;top:0;z-index:1}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.scroll{overflow-x:auto}
.kv td:first-child{width:320px;color:var(--mute);overflow-wrap:anywhere}
.kv td:last-child{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;white-space:pre-wrap;overflow-wrap:anywhere}
.kv .long{max-height:7.5em;overflow:auto;display:block}
.bar{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;margin-bottom:12px}
.bar label{font-size:12.5px;color:var(--mute);display:flex;align-items:center;gap:5px}
select,input[type=search]{font:inherit;padding:4px 7px;border:1px solid #b8c1ca;border-radius:5px;background:#fff;color:var(--ink)}
input[type=search]{min-width:260px}
.chip{border:1px solid #b8c1ca;background:#fff;border-radius:999px;padding:3px 11px;font:inherit;font-size:12.5px;cursor:pointer;color:var(--ink)}
.chip.on{background:#16232e;color:#fff;border-color:#16232e}
.badge{display:inline-block;border-radius:4px;padding:1px 7px;font-size:12px;font-weight:600;white-space:nowrap}
.b-connected{background:var(--ok-bg);color:var(--ok)}.b-failed{background:var(--bad-bg);color:var(--bad)}
.b-cancelled{background:var(--warn-bg);color:var(--warn)}.b-incomplete{background:var(--idle-bg);color:var(--idle)}
.b-system{background:var(--sys-bg);color:var(--sys)}
.steps{display:flex;gap:2px;white-space:nowrap}
.step{width:26px;height:18px;border-radius:3px;background:#e4e8ec;color:#8c98a4;font-size:10.5px;font-weight:700;
display:inline-flex;align-items:center;justify-content:center}
.step.ok{background:var(--ok);color:#fff}.step.fail{background:var(--bad);color:#fff}
.step.warn{background:#d99a00;color:#fff}.step.pending{background:#9fb3c2;color:#fff}
tr.row{cursor:pointer}tr.row:hover td{background:#eef3f6}
tr.row.sys td{color:var(--mute);background:#fafbfc}
tr.row.open td{background:#e8f1f5;border-bottom-color:transparent}
tr.det>td{background:#f8fafb;padding:10px 14px 16px 30px}
.tl td{white-space:nowrap;font-variant-numeric:tabular-nums}
.tl td.wrap{white-space:normal;overflow-wrap:anywhere;min-width:260px}
.ev{font-size:12.5px}
.ev td{padding:2px 8px;border-bottom:1px solid #edf0f3}
.ev td.t{font-family:ui-monospace,Consolas,monospace;white-space:nowrap;color:var(--mute)}
.ev td.m{overflow-wrap:anywhere;white-space:pre-wrap}
.ev tr.l-error td.m{color:var(--bad);font-weight:600}
.ev tr.l-warn td.m{color:var(--warn)}
.ev tr.l-ok td.m{color:var(--ok)}
.ev tr.l-logerr td.m{color:#8a5a00;font-style:italic}
.ev tr.detail td.m{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.ev tr.detail td.s{color:var(--acc)}
.ev tr.head td{font-weight:700;background:#eef1f4;color:var(--ink)}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:4px 18px;margin-bottom:10px;font-size:13px}
.facts div span{color:var(--mute)}
details.help{margin:0 0 12px;font-size:13px;color:#3a4652}
details.help summary{cursor:pointer;color:var(--acc);font-weight:600;width:max-content}
details.help ul{margin:6px 0 0 18px;padding:0}
details.sec{border-top:1px solid var(--line);padding:8px 0}
details.sec>summary{cursor:pointer;font-weight:600}
details.sec>summary .mute{font-weight:400}
.warnbox{background:var(--warn-bg);border:1px solid #c98a00;border-radius:8px;padding:8px 14px;margin-bottom:14px}
.warnbox ul{margin:4px 0 0 18px;padding:0}
button.link{border:0;background:none;color:var(--acc);font:inherit;cursor:pointer;padding:0;text-decoration:underline}
.more{margin:12px 0;text-align:center}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:12.5px;color:var(--mute);margin:6px 0 10px}
.legend .step{margin-right:4px}
</style>
</head>
<body>
<header><h1>GlobalProtect client report</h1><div class="sub" id="sub"></div></header>
<nav id="nav"></nav>
<main>
<div id="warn"></div>

<section class="tab" id="tab-summary">
  <div class="bar" id="bar-summary"></div>
  <div class="tiles" id="tiles"></div>
  <div class="card"><h2>Last connection attempt</h2><div id="last"></div></div>
  <div class="card"><h2>Why attempts did not connect</h2>
    <details class="help"><summary>How to read this</summary><ul>
      <li>One line per distinct stage and message, for the attempts in the selected period that did not bring the tunnel up.</li>
      <li>"No outcome logged" means the log has no result line for the attempt: typically the app was waiting for credentials, or a newer attempt replaced it. It is not proof of a failure.</li>
      <li>Click a message to open the matching attempts in the timeline.</li></ul></details>
    <div class="scroll" id="reasons"></div></div>
  <div class="card"><h2>Portals</h2><div class="scroll" id="portals"></div></div>
  <div class="card"><h2>Client overview</h2><table class="kv" id="overview"></table></div>
</section>

<section class="tab" id="tab-config">
  <div class="card">
    <h2>Current client configuration</h2>
    <details class="help"><summary>How to read this</summary><ul>
      <li>Each block is the newest copy of one configuration document found in the bundle; its source file and the time it was logged are shown in the title.</li>
      <li>"App configuration from portal" is what the service applied after the portal login. "Registry settings" is the registry dump taken when the logs were collected. A value can differ between the two when the portal was not contacted recently.</li>
      <li>"Gateway configuration" exists only if a gateway login succeeded inside the time span covered by PanGPS.log.</li>
      <li>Values are shown as logged. Empty means the element was present with no value.</li></ul></details>
    <div class="bar"><label>Filter settings <input type="search" id="cfgq" placeholder="name or value, e.g. timeout"></label>
      <button class="chip" id="cfgopen">Expand all</button><button class="chip" id="cfgclose">Collapse all</button>
      <span class="mute small" id="cfgcount"></span></div>
    <div id="config"></div>
  </div>
</section>

<section class="tab" id="tab-timeline">
  <div class="card">
    <h2>Connection attempts</h2>
    <details class="help"><summary>How to read this</summary><ul>
      <li>One row per connection attempt, newest first. An attempt starts at "Started the Portal pre-login" and collects every event until the next attempt starts; for a connected attempt this includes the whole VPN session.</li>
      <li>Steps: PP portal pre-login, PL portal login, PC portal configuration, GP gateway pre-login, GL gateway login, TU tunnel.</li>
      <li>A portal followed by * was not logged for that attempt: it is inferred because the nearest earlier and later attempts with a logged portal both used it.</li>
      <li>Click a row for its events. Rows marked "detail" also carry lines from PanGPS.log (shown in monospace), available only for the time span that log covers.</li>
      <li>Lines in italic are entries the service logged at error level that no rule classifies; they are shown for context and do not change the outcome.</li>
      <li>All times are the client's local time, as written in the logs.</li></ul></details>
    <div class="bar" id="bar-timeline"></div>
    <div class="legend" id="legend"></div>
    <div class="small mute" id="count"></div>
    <div class="scroll"><table class="tl" id="tl"></table></div>
    <div class="more" id="more"></div>
  </div>
</section>

<section class="tab" id="tab-sources">
  <div class="card"><h2>Files in the bundle</h2>
    <details class="help"><summary>How to read this</summary><ul>
      <li>"read" files were parsed; "found" files are in the bundle but not used by this version; "skipped" files were refused (size limit, unsafe name, read error).</li>
      <li>First and last are the timestamps of the first and last parsed line.</li></ul></details>
    <div class="scroll"><table id="sources"></table></div></div>
</section>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
"use strict";
var D=JSON.parse(document.getElementById('data').textContent);
var PH=D.phases, PHN={}, SHORT={'portal-prelogin':'PP','portal-login':'PL','portal-config':'PC','gw-prelogin':'GP','gw-login':'GL','tunnel':'TU'};
PH.forEach(function(p){PHN[p[0]]=p[1];});
PHN.session='Session';PHN.system='System';PHN.aux='Housekeeping';
var OUT=D.outcomes;
function h(tag,attrs,kids){var e=document.createElement(tag);if(attrs){for(var k in attrs){if(k==='text')e.textContent=attrs[k];else if(k==='cls')e.className=attrs[k];else if(k.slice(0,2)==='on')e.addEventListener(k.slice(2),attrs[k]);else e.setAttribute(k,attrs[k]);}}
 if(kids!=null){(Array.isArray(kids)?kids:[kids]).forEach(function(c){if(c==null)return;e.appendChild(typeof c==='string'?document.createTextNode(c):c);});}return e;}
function clear(e){while(e.firstChild)e.removeChild(e.firstChild);return e;}
function p2(n){return (n<10?'0':'')+n;}
function fdate(ms){if(ms==null)return '';var d=new Date(ms);return d.getUTCFullYear()+'-'+p2(d.getUTCMonth()+1)+'-'+p2(d.getUTCDate());}
function ftime(ms,msec){if(ms==null)return '';var d=new Date(ms);var s=p2(d.getUTCHours())+':'+p2(d.getUTCMinutes())+':'+p2(d.getUTCSeconds());if(msec){var m=d.getUTCMilliseconds();s+='.'+(m<10?'00':m<100?'0':'')+m;}return s;}
function fdt(ms){return ms==null?'':fdate(ms)+' '+ftime(ms);}
function fdur(ms){if(ms==null||ms<0)return '';var s=Math.round(ms/1000);if(s<60)return s+' s';var m=Math.floor(s/60);if(m<60)return m+' min '+(s%60)+' s';var hh=Math.floor(m/60);if(hh<48)return hh+' h '+(m%60)+' min';return Math.floor(hh/24)+' d '+(hh%24)+' h';}
function fdelta(ms){if(ms<1000)return '+'+ms+' ms';if(ms<60000)return '+'+(ms/1000).toFixed(1)+' s';return '+'+fdur(ms);}
function fsize(n){if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(0)+' KB';return (n/1048576).toFixed(1)+' MB';}

var rows=D.rows;rows.forEach(function(r,i){r.i=i;});
var S={period:'all',portal:'',out:{connected:1,failed:1,cancelled:1,incomplete:1,system:0},q:'',aux:false,detail:false,limit:200,open:{}};
var portals={};rows.forEach(function(r){if(r.k!=='system')portals[r.p||'']=(portals[r.p||'']||0)+1;});
var portalNames=Object.keys(portals).sort(function(a,b){return portals[b]-portals[a];});
var PERIODS=[['all','All'],['1','Last 24 hours'],['7','Last 7 days'],['30','Last 30 days'],['90','Last 90 days']];

function inPeriod(r){if(S.period==='all')return true;return r.e>=D.meta.last-(+S.period)*86400000;}
function base(){return rows.filter(function(r){return inPeriod(r)&&(!S.portal||r.k==='system'||(r.p||'(not logged)')===S.portal);});}
function matchQ(r,q){if(!q)return true;var hay=[r.p,r.g,r.u,r.r,r.er,(r.n||[]).join(' '),OUT[r.o]].join(' ').toLowerCase();if(hay.indexOf(q)>=0)return true;for(var i=0;i<r.ev.length;i++){if(r.ev[i][3].toLowerCase().indexOf(q)>=0)return true;}return false;}

/* ---------- header, tabs, warnings */
document.getElementById('sub').textContent=D.meta.bundle+'  |  generated '+D.meta.generated+' by panos-toolbox '+D.meta.tool+'  |  times are the client\'s local time';
var TABS=[['summary','Summary'],['config','Client configuration'],['timeline','Login timeline'],['sources','Sources']];
function show(id){TABS.forEach(function(t){document.getElementById('tab-'+t[0]).classList.toggle('on',t[0]===id);document.getElementById('nb-'+t[0]).classList.toggle('on',t[0]===id);});}
TABS.forEach(function(t){document.getElementById('nav').appendChild(h('button',{id:'nb-'+t[0],text:t[1],onclick:function(){show(t[0]);}}));});
if(D.warnings.length){document.getElementById('warn').appendChild(h('div',{cls:'warnbox'},[h('b',{text:'Analysis notes'}),h('ul',null,D.warnings.map(function(w){return h('li',{text:w});}))]));}

/* ---------- shared filter controls */
function sel(opts,val,fn){var s=h('select',{onchange:function(){fn(s.value);}});opts.forEach(function(o){var op=h('option',{value:o[0],text:o[1]});if(o[0]===val)op.selected=true;s.appendChild(op);});return s;}
function filterControls(){var po=[['','All portals']].concat(portalNames.map(function(p){var n=p||'(not logged)';return [n,n+' ('+portals[p]+')'];}));
 return [h('label',null,['Period ',sel(PERIODS,S.period,function(v){S.period=v;S.limit=200;renderAll();})]),h('label',null,['Portal ',sel(po,S.portal,function(v){S.portal=v;S.limit=200;renderAll();})])];}

/* ---------- summary */
function badge(o){return h('span',{cls:'badge b-'+o,text:OUT[o]||o});}
function steps(r){var d=h('span',{cls:'steps'});PH.forEach(function(p){var st=(r.ph||{})[p[0]]||'';d.appendChild(h('span',{cls:'step '+st,title:p[1]+': '+(st==='ok'?'completed':st==='fail'?'failed here':st==='warn'?'completed with warnings':st==='pending'?'started, no result logged':'not reached'),text:SHORT[p[0]]}));});return d;}
function gotoTimeline(q,outs){S.q=q||'';if(outs){for(var k in S.out)S.out[k]=outs.indexOf(k)>=0?1:0;}S.limit=200;renderTimelineBar();renderTimeline();show('timeline');}
function renderSummary(){
 var bar=clear(document.getElementById('bar-summary'));filterControls().forEach(function(c){bar.appendChild(c);});
 var att=base().filter(function(r){return r.k!=='system';});
 var c={connected:0,failed:0,cancelled:0,incomplete:0};att.forEach(function(r){c[r.o]=(c[r.o]||0)+1;});
 var tiles=clear(document.getElementById('tiles'));
 [['total','Connection attempts',att.length],['connected','Connected',c.connected],['failed','Failed',c.failed],['cancelled','Cancelled by user',c.cancelled],['incomplete','No outcome logged',c.incomplete]].forEach(function(t){tiles.appendChild(h('div',{cls:'tile '+t[0]},[h('b',{text:String(t[2])}),h('span',{text:t[1]})]));});
 var last=clear(document.getElementById('last'));var la=att[att.length-1];
 if(!la){last.appendChild(h('span',{cls:'mute',text:'No connection attempt in the selected period.'}));}
 else{last.appendChild(h('div',{cls:'facts'},[fact('Started',fdt(la.s)),fact('Portal',(la.p||'(not logged)')+(la.pi?' * (inferred)':'')),fact('Gateway',la.g||'-'),fact('User',la.u||'-'),h('div',null,[h('span',{text:'Outcome: '}),badge(la.o)]),h('div',null,[h('span',{text:'Steps: '}),steps(la)]),fact('Detail',la.r||la.er||(la.o==='connected'?(la.dn?'session ended':'no tunnel-down event logged after the connection'):'-'))]));
  last.appendChild(h('button',{cls:'link',text:'Open in the timeline',onclick:function(){S.open={};S.open[la.i]=1;S.period='all';S.portal='';gotoTimeline('',['connected','failed','cancelled','incomplete']);}}));}
 var groups={};att.forEach(function(r){if(r.o==='connected')return;var key=r.o+'|'+r.st+'|'+r.r;var g=groups[key]||(groups[key]={o:r.o,st:r.st,r:r.r,n:0,last:0,p:{}});g.n++;g.last=Math.max(g.last,r.s);g.p[r.p||'(not logged)']=1;});
 var list=Object.keys(groups).map(function(k){return groups[k];}).sort(function(a,b){return b.n-a.n;});
 var box=clear(document.getElementById('reasons'));
 if(!list.length){box.appendChild(h('span',{cls:'mute',text:'Every attempt in the selected period connected.'}));}
 else{var t=h('table',null,h('tr',null,[h('th',{text:'Outcome'}),h('th',{text:'Stage'}),h('th',{text:'Message'}),h('th',{cls:'num',text:'Attempts'}),h('th',{text:'Portals'}),h('th',{text:'Last seen'})]));
  list.slice(0,40).forEach(function(g){t.appendChild(h('tr',null,[h('td',null,badge(g.o)),h('td',{text:PHN[g.st]||'-'}),h('td',null,h('button',{cls:'link',text:g.r||'(no message)',onclick:function(){gotoTimeline(g.r,[g.o]);}})),h('td',{cls:'num',text:String(g.n)}),h('td',{text:Object.keys(g.p).join(', ')}),h('td',{text:fdt(g.last)})]));});
  box.appendChild(t);if(list.length>40)box.appendChild(h('div',{cls:'mute small',text:(list.length-40)+' more distinct messages not shown.'}));}
 var pp={};att.forEach(function(r){var k=r.p||'(not logged)';var g=pp[k]||(pp[k]={n:0,connected:0,failed:0,cancelled:0,incomplete:0,last:null});g.n++;g[r.o]++;if(!g.last||r.s>g.last.s)g.last=r;});
 var pt=h('table',null,h('tr',null,[h('th',{text:'Portal'}),h('th',{cls:'num',text:'Attempts'}),h('th',{cls:'num',text:'Connected'}),h('th',{cls:'num',text:'Failed'}),h('th',{cls:'num',text:'Cancelled'}),h('th',{cls:'num',text:'No outcome'}),h('th',{text:'Last attempt'}),h('th',{text:'Last outcome'})]));
 Object.keys(pp).sort(function(a,b){return pp[b].n-pp[a].n;}).forEach(function(k){var g=pp[k];pt.appendChild(h('tr',null,[h('td',{text:k}),h('td',{cls:'num',text:String(g.n)}),h('td',{cls:'num',text:String(g.connected)}),h('td',{cls:'num',text:String(g.failed)}),h('td',{cls:'num',text:String(g.cancelled)}),h('td',{cls:'num',text:String(g.incomplete)}),h('td',{text:fdt(g.last.s)}),h('td',null,badge(g.last.o))]));});
 clear(document.getElementById('portals')).appendChild(pt);
}
function fact(k,v){return h('div',null,[h('span',{text:k+': '}),v]);}
(function(){var t=document.getElementById('overview');D.overview.forEach(function(r){t.appendChild(h('tr',null,[h('td',{text:r[0]}),h('td',{text:r[1]})]));});})();

/* ---------- configuration */
function renderConfig(){var q=document.getElementById('cfgq').value.trim().toLowerCase();var box=clear(document.getElementById('config'));var shown=0,total=0;
 D.sections.forEach(function(sec,idx){var body=h('div');var n=0;
  sec.groups.forEach(function(g){var rws=g.rows.filter(function(r){total++;return !q||r[0].toLowerCase().indexOf(q)>=0||r[1].toLowerCase().indexOf(q)>=0||g.name.toLowerCase().indexOf(q)>=0;});if(!rws.length)return;n+=rws.length;
   if(g.name)body.appendChild(h('h3',{text:g.name}));
   var t=h('table',{cls:'kv'});rws.forEach(function(r){var v=r[1];t.appendChild(h('tr',null,[h('td',{text:r[0]}),h('td',null,h('span',{cls:v.length>300?'long':'',text:v===''?'(empty)':v}))]));});body.appendChild(t);});
  if(!n)return;shown+=n;
  var d=h('details',{cls:'sec'},[h('summary',null,[sec.title+' ',h('span',{cls:'mute small',text:'  '+sec.source+(sec.ts?', logged '+sec.ts:'')+', '+n+' item'+(n===1?'':'s')})]),sec.note?h('div',{cls:'mute small',text:sec.note}):null,body]);
  if(q||idx<2)d.open=true;box.appendChild(d);});
 if(!D.sections.length)box.appendChild(h('span',{cls:'mute',text:'No configuration source found in the bundle.'}));
 document.getElementById('cfgcount').textContent=q?shown+' matching item'+(shown===1?'':'s'):'';}
document.getElementById('cfgq').addEventListener('input',renderConfig);
document.getElementById('cfgopen').addEventListener('click',function(){[].forEach.call(document.querySelectorAll('#config details'),function(d){d.open=true;});});
document.getElementById('cfgclose').addEventListener('click',function(){[].forEach.call(document.querySelectorAll('#config details'),function(d){d.open=false;});});

/* ---------- timeline */
function renderTimelineBar(){var bar=clear(document.getElementById('bar-timeline'));filterControls().forEach(function(c){bar.appendChild(c);});
 Object.keys(OUT).forEach(function(o){bar.appendChild(h('button',{cls:'chip'+(S.out[o]?' on':''),text:OUT[o],'aria-pressed':S.out[o]?'true':'false',onclick:function(){S.out[o]=S.out[o]?0:1;S.limit=200;renderTimelineBar();renderTimeline();}}));});
 var q=h('input',{type:'search',placeholder:'Search portal, gateway, user, message',value:S.q});q.addEventListener('input',function(){S.q=q.value;S.limit=200;renderTimeline();});
 bar.appendChild(h('label',null,['Search ',q]));
 var c1=h('input',{type:'checkbox'});c1.checked=S.detail;c1.addEventListener('change',function(){S.detail=c1.checked;S.limit=200;renderTimeline();});
 bar.appendChild(h('label',null,[c1,' only rows with PanGPS detail']));
 var c2=h('input',{type:'checkbox'});c2.checked=S.aux;c2.addEventListener('change',function(){S.aux=c2.checked;renderTimeline();});
 bar.appendChild(h('label',null,[c2,' show housekeeping events (cookies, files)']));}
(function(){var l=document.getElementById('legend');[['ok','completed'],['warn','completed with warnings'],['fail','failed here'],['pending','started, no result logged'],['','not reached']].forEach(function(x){l.appendChild(h('span',null,[h('span',{cls:'step '+x[0],text:''}),x[1]]));});})();
function detailRow(r){var facts=[fact('Started',fdt(r.s)),fact('Last event',fdt(r.e))];
 if(r.k!=='system'){facts.push(fact('Portal',(r.p||'(not logged)')+(r.pi?' * (inferred from the nearest attempts)':'')),fact('Gateway',r.g||'-'),fact('User',r.u||'-'));
  if(r.up!=null){facts.push(fact('Tunnel up',fdt(r.up)+' ('+fdur(r.up-r.s)+' after start)'));facts.push(fact('Tunnel down',r.dn!=null?fdt(r.dn)+' (session '+fdur(r.dn-r.up)+')':'not logged'));if(r.er)facts.push(fact('End of session',r.er));}
  if(r.r)facts.push(fact('Result detail',r.r));if(r.n&&r.n.length)facts.push(fact('Notes',r.n.join('; ')));}
 var t=h('table',{cls:'ev'},h('tr',{cls:'head'},[h('td',{text:'Time'}),h('td',{text:'Since start'}),h('td',{text:'Step'}),h('td',{text:'Source'}),h('td',{text:'Event'})]));
 var hidden=0,day='';
 r.ev.forEach(function(e){if(e[2]==='aux'&&!S.aux){hidden+=e[5];return;}
  var d=fdate(e[0]);if(d!==day){day=d;t.appendChild(h('tr',{cls:'head'},[h('td',{colspan:'5',text:d})]));}
  var txt=e[3];if(e[5]>1)txt+='   (x'+e[5]+', last at '+(fdate(e[6])!==d?fdt(e[6]):ftime(e[6]))+')';
  var src=D.srcs[e[4]]||'';var det=/^PanGPS/i.test(src)&&!D.meta.fallback;
  t.appendChild(h('tr',{cls:'l-'+e[1]+(det?' detail':'')},[h('td',{cls:'t',text:ftime(e[0],true)}),h('td',{cls:'t',text:fdelta(e[0]-r.s)}),h('td',{cls:'t',text:PHN[e[2]]||''}),h('td',{cls:'t s',text:src}),h('td',{cls:'m',text:txt})]));});
 var kids=[h('div',{cls:'facts'},facts),t];
 if(hidden)kids.push(h('div',{cls:'mute small',text:hidden+' housekeeping event'+(hidden===1?'':'s')+' hidden (tick "show housekeeping events").'}));
 if(!r.d&&r.k!=='system'&&D.meta.detail_from!=null)kids.push(h('div',{cls:'mute small',text:'No PanGPS.log detail: that log covers '+fdt(D.meta.detail_from)+' to '+fdt(D.meta.detail_to)+'.'}));
 return h('tr',{cls:'det'},h('td',{colspan:'9'},kids));}
function renderTimeline(){var q=S.q.trim().toLowerCase();
 var list=base().filter(function(r){return S.out[r.o]&&(!S.detail||r.d)&&matchQ(r,q);});list.reverse();
 var t=clear(document.getElementById('tl'));
 t.appendChild(h('tr',null,[h('th',{text:'Start'}),h('th',{text:'Portal'}),h('th',{text:'Gateway'}),h('th',{text:'User'}),h('th',{text:'Steps'}),h('th',{text:'Outcome'}),h('th',{text:'Session'}),h('th',{text:'Detail'}),h('th',{text:''})]));
 list.slice(0,S.limit).forEach(function(r){var sys=r.k==='system';
  var msg=r.r||'';if(r.o==='connected'){msg=r.er||(r.dn==null?'no tunnel-down event logged':'');}if(r.n&&r.n.length)msg+=(msg?' | ':'')+r.n.join('; ');
  var tr=h('tr',{cls:'row'+(sys?' sys':'')+(S.open[r.i]?' open':''),tabindex:'0','aria-expanded':S.open[r.i]?'true':'false'},[h('td',{text:fdt(r.s)}),h('td',r.pi?{text:r.p+' *',title:'Portal not logged for this attempt: inferred from the nearest attempts, which both used it'}:{text:sys?'':(r.p||'(not logged)')}),h('td',{text:r.g||''}),h('td',{text:r.u||''}),h('td',null,sys?null:steps(r)),h('td',null,badge(r.o)),h('td',{text:r.up!=null&&r.dn!=null?fdur(r.dn-r.up):''}),h('td',{cls:'wrap',text:msg}),h('td',{cls:'mute small',text:r.d?'detail':''})]);
  function toggle(){if(S.open[r.i]){delete S.open[r.i];}else{S.open[r.i]=1;}renderTimeline();}
  tr.addEventListener('click',toggle);tr.addEventListener('keydown',function(ev){if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();toggle();}});
  t.appendChild(tr);if(S.open[r.i])t.appendChild(detailRow(r));});
 document.getElementById('count').textContent=list.length+' row'+(list.length===1?'':'s')+' match'+(list.length===1?'es':'')+(list.length>S.limit?', showing the newest '+S.limit:'')+'.';
 var more=clear(document.getElementById('more'));if(list.length>S.limit)more.appendChild(h('button',{cls:'chip',text:'Show 200 more',onclick:function(){S.limit+=200;renderTimeline();}}));}

/* ---------- sources */
(function(){var t=document.getElementById('sources');t.appendChild(h('tr',null,[h('th',{text:'File'}),h('th',{cls:'num',text:'Size'}),h('th',{text:'Status'}),h('th',{text:'Used for / note'}),h('th',{cls:'num',text:'Records'}),h('th',{text:'First'}),h('th',{text:'Last'})]));
 D.sources.forEach(function(s){t.appendChild(h('tr',null,[h('td',{text:s.name}),h('td',{cls:'num',text:fsize(s.size)}),h('td',{text:s.status}),h('td',{text:s.note}),h('td',{cls:'num',text:String(s.lines)}),h('td',{text:s.first}),h('td',{text:s.last})]));});})();

function renderAll(){renderSummary();renderTimelineBar();renderTimeline();}
renderAll();renderConfig();show('summary');
})();
</script>
</body>
</html>
'''


def render_page(title: str, payload: str) -> str:
    """Return the page with the JSON ``payload`` embedded."""
    page = TEMPLATE.replace("__TITLE__", html.escape(title))
    return page.replace("__DATA__", payload)

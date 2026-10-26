#!/usr/bin/env python3
"""
tsf.analyzer - Extracts Throughput (kbps) and related metrics from the
dp-monitor.* files of a Palo Alto Networks Tech Support File (TSF) and builds a
standalone HTML report (filterable/exportable table + interactive charts,
including CPU load by group).

Standard library only.

Usage:
    panos-toolbox tsf analyze tsf1.tgz [tsf2.tgz ...] [-o OUTDIR]
    panos-toolbox tsf analyze /path/to/extracted_TSF_dir
    panos-toolbox tsf analyze dp-monitor.log    # single file
    python -m panos_toolbox.tsf.analyzer ...    # equivalent

Each TSF produces <name>_throughput.html; with multiple inputs a summary
index.html is also created.
"""
import argparse
import html
import json
import os
import re
import sys
import tarfile
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
DP_FILE_RE = re.compile(r'(?:^|/)var/log/pan/(dp-monitor\.[^/]+)$')
HDR_RE = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))? '
    r'([+-])(\d{2})(\d{2})\s+---\s+(\S+)')
HDR_LOOSE_RE = re.compile(r'^\d{4}-\d{2}-\d{2} \S+ .*\s---\s')
TARGET_RE = re.compile(r'^:?\s*target-dp:\s*(\S+)')
METRIC_RES = {
    'kbps': re.compile(r'^:?\s*Throughput:\s*(\d+)\s*kbps'),
    'pps': re.compile(r'^:?\s*Packet rate:\s*(\d+)\s*/s'),
    'cps': re.compile(r'^:?\s*New connection establish rate:\s*(\d+)\s*cps'),
    'sess': re.compile(r'^:?\s*Number of allocated sessions:\s*(\d+)'),
    'util': re.compile(r'^:?\s*Session table utilization:\s*(\d+)\s*%'),
}
THROUGHPUT_LOOSE = re.compile(r'^:?\s*Throughput:')
GRP_TITLE_RE = re.compile(r'^:?\s*CPU load sampling by group:')
GRP_LINE_RE = re.compile(r'^:?\s*([A-Za-z]\w*)\s*:\s*(\d+)\s*%\s*$')


def dp_label(raw):
    """'*.dp0' -> 'dp0'; 's1.dp1' stays 's1.dp1'."""
    return raw[2:] if raw.startswith('*.') else raw


def parse_header(line):
    """Returns (epoch_ms_utc, offset_str, section) or None."""
    m = HDR_RE.match(line)
    if not m:
        return None
    y, mo, d, h, mi, s, frac, sign, oh, om, section = m.groups()
    ms = int((frac or '0').ljust(3, '0')[:3])
    off = timedelta(hours=int(oh), minutes=int(om))
    if sign == '-':
        off = -off
    try:
        local = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s),
                         ms * 1000, tzinfo=timezone(off))
    except ValueError:
        return None
    return int(local.timestamp() * 1000), f'{sign}{oh}{om}', section


def parse_lines(lines, src, samples, seen, warnings, offsets):
    """Walks the lines of a dp-monitor.* file and collects the samples.

    Each '--- <name>' section is processed on its own: the session metrics
    (after 'target-dp:') yield one sample per DP; the 'CPU load sampling by
    group' block is bound to the DP of that same section.
    Returns the number of Throughput samples found (duplicates included).
    """
    ts = None            # timestamp (ms UTC) of the last valid header
    dp = None            # current DP (last target-dp seen in the section)
    rec = None
    sec_recs, sec_dps, sec_groups = [], [], []
    cur_group = None
    n_found = 0

    def close_rec():
        nonlocal rec
        if rec is not None and rec.get('kbps') is not None:
            sec_recs.append(rec)
        rec = None

    def end_section():
        nonlocal n_found, cur_group
        close_rec()
        pend = [g for g in sec_groups if g['dp'] is None]
        for g in sec_groups:
            if g['dp'] is not None:
                for r in sec_recs:
                    if r['dp'] == g['dp']:
                        r['grp'] = g['vals']
        if pend:
            if len(pend) == len(sec_dps):
                if len(sec_dps) > 1:
                    warnings.append(f'{src}: "CPU load by group" blocks bound '
                                    f'to DPs by order of appearance (unverified)')
                for g, d in zip(pend, sec_dps):
                    for r in sec_recs:
                        if r['dp'] == d:
                            r['grp'] = g['vals']
            elif sec_recs:
                warnings.append(f'{src}: {len(pend)} "CPU load by group" blocks '
                                f'and {len(sec_dps)} DPs in the same section, '
                                f'cannot bind them: CPU groups skipped')
        for r in sec_recs:
            n_found += 1
            key = (r['dp'], r['t'])
            if key not in seen:        # duplicate = overlapping rotated files
                seen.add(key)
                samples.append(r)
        sec_recs.clear(); sec_dps.clear(); sec_groups.clear()
        cur_group = None

    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip('\r\n')

        if line[:2].isdigit():
            h = parse_header(line)
            if h:
                end_section()
                ts, off, _section = h
                offsets.add(off)
                dp = None
                continue
            if HDR_LOOSE_RE.match(line):
                end_section()
                ts = None
                dp = None
                warnings.append(f'{src}:{lineno}: header with unparseable '
                                f'timestamp, following data ignored '
                                f'until the next valid header')
                continue

        if cur_group is not None:
            m = GRP_LINE_RE.match(line)
            if m:
                cur_group['vals'][m.group(1)] = int(m.group(2))
                continue
            cur_group = None
        if GRP_TITLE_RE.match(line):
            if ts is not None:
                cur_group = {'dp': dp, 'vals': {}}
                sec_groups.append(cur_group)
            continue

        m = TARGET_RE.match(line)
        if m:
            close_rec()
            dp = dp_label(m.group(1))
            if dp not in sec_dps:
                sec_dps.append(dp)
            continue

        for key, rx in METRIC_RES.items():
            m = rx.match(line)
            if not m:
                continue
            if ts is None:
                if key == 'kbps':
                    warnings.append(f'{src}:{lineno}: Throughput without '
                                    f'a valid timestamp, skipped')
                break
            if rec is not None and rec.get(key) is not None:
                close_rec()            # nuovo blocco senza target-dp
            if rec is None:
                rec = {'t': ts, 'dp': dp or 'n/a', 'src': src,
                       'kbps': None, 'pps': None, 'cps': None,
                       'sess': None, 'util': None}
            rec[key] = int(m.group(1))
            break
        else:
            if THROUGHPUT_LOOSE.match(line):
                warnings.append(f'{src}:{lineno}: Throughput line in unexpected '
                                f'format: {line.strip()[:60]!r}')
    end_section()
    return n_found


def iter_text_lines(fobj):
    for b in fobj:
        yield b.decode('utf-8', errors='replace')


def collect(path, warnings):
    """Returns (samples, offsets, n_files) for a TSF / directory / file."""
    samples, seen, offsets = [], set(), set()
    n_files = 0

    def handle(name, fobj):
        nonlocal n_files
        base = os.path.basename(name)
        if base.endswith('.gz'):
            warnings.append(f'{base}: compressed file (.gz) not supported, '
                            f'skipped')
            return
        n_files += 1
        try:
            found = parse_lines(iter_text_lines(fobj), base, samples, seen,
                                warnings, offsets)
        except Exception as exc:  # corrupted/truncated file
            warnings.append(f'{base}: read error ({exc}), '
                            f'partial data kept')
            return
        if found == 0:
            warnings.append(f'{base}: no Throughput samples found')

    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for f in sorted(files):
                full = os.path.join(root, f)
                rel = os.path.relpath(full, path).replace(os.sep, '/')
                if DP_FILE_RE.search('/' + rel):
                    with open(full, 'rb') as fh:
                        handle(rel, fh)
    elif tarfile.is_tarfile(path):
        with tarfile.open(path, 'r:*') as tf:
            for m in tf:                      # single-pass read
                if m.isfile() and DP_FILE_RE.search(m.name.lstrip('./')):
                    handle(m.name, tf.extractfile(m))
    else:                                     # single log file
        with open(path, 'rb') as fh:
            handle(path, fh)

    if n_files == 0:
        warnings.append('no dp-monitor.* file found in /var/log/pan')
    samples.sort(key=lambda r: (r['t'], r['dp']))
    return samples, offsets, n_files


def add_aggregate(samples):
    """Adds the 'ALL' series (sum across DPs) when there is more than one DP."""
    dps = sorted({s['dp'] for s in samples})
    if len(dps) < 2:
        return dps
    by_t = {}
    for s in samples:
        by_t.setdefault(s['t'], []).append(s)
    agg = []
    for t, group in sorted(by_t.items()):
        row = {'t': t, 'dp': 'ALL', 'src': ','.join(sorted({g['src'] for g in group}))}
        for k in ('kbps', 'pps', 'cps', 'sess'):
            vals = [g[k] for g in group if g[k] is not None]
            row[k] = sum(vals) if vals else None
        utils = [g['util'] for g in group if g['util'] is not None]
        row['util'] = max(utils) if utils else None   # aggregate = maximum
        agg.append(row)
    samples.extend(agg)
    samples.sort(key=lambda r: (r['t'], r['dp'] != 'ALL', r['dp']))
    return ['ALL'] + dps


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------
TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Throughput - __TITLE__</title>
<style>
:root{--ink:#1c2530;--mute:#5d6b7a;--line:#d8dde3;--bg:#f4f6f8;--card:#fff;--acc:#1f6f8b;--warn-bg:#fff4d6;--warn-bd:#c98a00}
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
</style>
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

</main>

<script>
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
$('#title').textContent = 'Throughput - ' + D.name;
$('#sub').textContent = D.samples.length ? ('Period ' + iso(TMIN) + ' - ' + iso(TMAX) + ' UTC | dp-monitor files read: ' + D.files + ' | generated ' + D.generated + ' UTC') : '';
$('#utc').textContent = 'Reminder: all times in this report are in UTC. The original firewall timestamps' + (D.offsets.length ? ' (detected offsets: ' + D.offsets.join(', ') + ')' : '') + ' have been converted.' + (D.series[0]==='ALL' ? ' The ALL series is the sum across DPs (for session table utilization it is the maximum value).' : '');
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
function renderActive(){ if(activeTab==='chart'){ drawMain(); renderTable(); } else drawGroups(); }
function showTab(n){
  activeTab=n;
  ['chart','cpu'].forEach(k=>{ const tab=$('#tab-'+k), pan=$('#p-'+k); tab.setAttribute('aria-selected',String(k===n)); tab.tabIndex=k===n?0:-1; pan.hidden=k!==n; });
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

const TABS=['chart'].concat(hasG?['cpu']:[]);
if(!hasG) $('#tabs').style.display='none';
TABS.forEach(k=>{ $('#tab-'+k).onclick=()=>showTab(k); });
$('#tabs').onkeydown=e=>{
  const i=TABS.indexOf(activeTab); let j=-1;
  if(e.key==='ArrowRight') j=(i+1)%TABS.length; else if(e.key==='ArrowLeft') j=(i+TABS.length-1)%TABS.length; else if(e.key==='Home') j=0; else if(e.key==='End') j=TABS.length-1;
  if(j<0) return; e.preventDefault(); showTab(TABS[j]); $('#tab-'+TABS[j]).focus();
};
window.addEventListener('resize',renderActive);
showTab('chart');
</script>
</body>
</html>
'''


def fmt_kbps(v):
    if v >= 1e6:
        return f'{v / 1e6:.2f} Gbps'
    if v >= 1e3:
        return f'{v / 1e3:.1f} Mbps'
    return f'{v} kbps'


def utc_str(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def render_report(name, samples, series, offsets, warnings, n_files, tpl):
    data = {
        'name': name,
        'generated': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'offsets': sorted(offsets),
        'files': n_files,
        'warnings': warnings,
        'series': series,
        'samples': samples,
    }
    groups = []
    for smp in samples:
        for k in (smp.get('grp') or {}):
            if k not in groups:
                groups.append(k)
    rows = []
    for smp in samples:
        r = {k: v for k, v in smp.items() if k != 'grp'}
        g = smp.get('grp')
        r['g'] = [g.get(k) for k in groups] if g else None
        rows.append(r)
    data['groups'] = groups
    data['samples'] = rows
    blob = json.dumps(data, separators=(',', ':')).replace('</', '<\\/')
    return (tpl.replace('__DATA__', blob)
               .replace('__TITLE__', html.escape(name)))


def render_index(rows):
    body = ''.join(
        '<tr><td><a href="{f}">{n}</a></td><td>{s}</td><td>{a}</td><td>{b}</td>'
        '<td>{p}</td><td>{w}</td></tr>'.format(
            f=html.escape(r['file']), n=html.escape(r['name']), s=r['samples'],
            a=r['start'], b=r['end'], p=r['peak'], w=r['warnings'])
        for r in rows)
    return ('<!doctype html><meta charset="utf-8"><title>Throughput summary</title>'
            '<style>body{font:15px system-ui,sans-serif;margin:2rem;color:#1c2530}'
            'table{border-collapse:collapse}td,th{padding:.4rem .8rem;border-bottom:'
            '1px solid #d8dde3;text-align:left}</style>'
            '<h1>Throughput summary</h1><p>Times in UTC.</p>'
            '<table><tr><th>TSF</th><th>Samples</th><th>Start</th><th>End</th>'
            f'<th>Peak</th><th>Warnings</th></tr>{body}</table>')


def main(argv=None):
    ap = argparse.ArgumentParser(prog='panos-toolbox tsf analyze', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('inputs', nargs='+', help='TSF (.tgz/.tar.gz), directory or dp-monitor.* file')
    ap.add_argument('-o', '--outdir', default='output', help='output directory (default: output)')
    ap.add_argument('--open', action='store_true', help='open the report in the default browser')
    args = ap.parse_args(argv)

    tpl = TEMPLATE
    os.makedirs(args.outdir, exist_ok=True)

    index_rows = []
    for path in args.inputs:
        warnings = []
        name = re.sub(r'(\.tar\.gz|\.tgz|\.tar)$', '', os.path.basename(path.rstrip('/')))
        try:
            samples, offsets, n_files = collect(path, warnings)
        except Exception as exc:
            print(f'[ERROR] {path}: {exc}', file=sys.stderr)
            continue
        if not samples:
            print(f'[WARNING] {path}: no samples extracted', file=sys.stderr)
            for w in warnings:
                print('  -', w, file=sys.stderr)
            continue
        series = add_aggregate(samples)
        out = os.path.join(args.outdir, f'{name}_throughput.html')
        with open(out, 'w', encoding='utf-8') as fh:
            fh.write(render_report(name, samples, series, offsets, warnings, n_files, tpl))
        base = [s for s in samples if s['dp'] == series[0]]
        peak = max(base, key=lambda s: s['kbps'])
        print(f'[OK] {path}: {len(base)} samples, {len(series) - (series[0] == "ALL")} DP, '
              f'{len(warnings)} warnings -> {out}')
        for w in warnings:
            print('  -', w, file=sys.stderr)
        index_rows.append({
            'file': os.path.basename(out), 'name': name, 'samples': len(base),
            'start': utc_str(base[0]['t']), 'end': utc_str(base[-1]['t']),
            'peak': f"{fmt_kbps(peak['kbps'])} ({utc_str(peak['t'])})",
            'warnings': len(warnings)})

    if len(index_rows) > 1:
        with open(os.path.join(args.outdir, 'index.html'), 'w', encoding='utf-8') as fh:
            fh.write(render_index(index_rows))
        print(f'[OK] summary -> {os.path.join(args.outdir, "index.html")}')

    if index_rows and args.open:
        target = 'index.html' if len(index_rows) > 1 else index_rows[0]['file']
        webbrowser.open(Path(args.outdir, target).resolve().as_uri())


if __name__ == '__main__':
    sys.exit(main())

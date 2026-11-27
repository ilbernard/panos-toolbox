"""Dataplane Analysis tab of the runtime report (CSS and JavaScript).

Part of the page assembled by ``report_template.py``; the same safety rules apply (text nodes
only, no ``innerHTML``). The tab has a correlation chart, where any metric of the capture can be
overlaid, and a set of panels that can be reordered, resized and hidden. All its time charts
share the time window, the cursor, the drag-to-zoom and the finding markers (``syncGroup``).
"""
from __future__ import annotations

DP_CSS = r"""
.dpgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 14px;align-items:start}
.dppanel{grid-column:span 1;min-width:0}
.dppanel.full{grid-column:1 / -1}
.dppanel[hidden]{display:none}
.dppanel.dragging{opacity:.45}
.dppanel.over-before{box-shadow:0 -4px 0 var(--acc)}
.dppanel.over-after{box-shadow:0 4px 0 var(--acc)}
.dppanel>.subpanel{overflow-x:auto}
.dptools{margin-left:auto;display:inline-flex;gap:3px;align-items:center}
.dptools button{font-size:12px;padding:1px 8px}
.dptools .grip{cursor:grab;user-select:none;border:1px dashed var(--line);border-radius:3px;padding:0 8px;color:var(--mute);font-size:12px}
.dpbar{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line);padding:6px 0;margin:0 0 12px}
@media print{ .dptools,.dpbar,.picker,.picked{display:none!important} .dpbar{position:static} }
"""

JS_DATAPLANE = r'''
// ================= Dataplane Analysis
const LAYOUT_KEY = 'panosToolbox.runtime.dataplane.v1';
function loadLayout(){ try{ const v = JSON.parse(localStorage.getItem(LAYOUT_KEY) || '{}'); return v && typeof v === 'object' ? v : {}; }catch(e){ return {}; } }
function saveLayout(v){ try{ localStorage.setItem(LAYOUT_KEY, JSON.stringify(v)); }catch(e){} }
const strList = v => Array.isArray(v) ? v.filter(x => typeof x === 'string') : null;

// Every time series of the capture, for the correlation chart. Each keeps its own timestamps.
function metricCatalog(){
  const out = [];
  const add = (group, id, name, unit, t, v) => { if(t.length && v.some(isNum)) out.push({id, group, name, unit, t, v}); };
  const uniq = (list, f) => Array.from(new Set(list.flatMap(f)));
  const rs = RM.series || [], rt = tsOf(rs);
  add('CPU', 'cpu.coremax', 'CPU busiest core (60 s max)', '%', rt, rs.map(x => x.core_max));
  add('CPU', 'cpu.coreavg', 'CPU highest core average (60 s)', '%', rt, rs.map(x => x.core_avg));
  add('CPU', 'cpu.groupmax', 'CPU busiest group', '%', rt, rs.map(x => x.group_max_pct));
  const H = RM.heat;
  if(H && (H.cores || []).length){
    const ids = H.cores.map(String), n = H.cells[ids[0]].length, t = Array.from({length:n}, (_, i) => H.t0_ms + i * (H.step_s || 1) * 1000);
    const at = i => ids.map(id => H.cells[id][i]).filter(isNum);
    add('CPU', 'cpu.sec.max', 'CPU per second, busiest core', '%', t, t.map((_, i) => at(i).length ? Math.max(...at(i)) : null));
    add('CPU', 'cpu.sec.avg', 'CPU per second, average of the cores', '%', t, t.map((_, i) => { const v = at(i); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null; }));
    ids.forEach(id => add('CPU per core', 'cpu.core.' + id, 'CPU core ' + id + ' (per second)', '%', t, H.cells[id]));
  }
  uniq(rs, x => Object.keys(x.groups || {})).forEach(k => add('CPU per group', 'cpu.group.' + k, 'CPU group ' + k, '%', rt, rs.map(x => (x.groups || {})[k])));
  uniq(rs, x => Object.keys(x.util_max || {})).forEach(k => add('Resources', 'res.' + k, 'Resource ' + k + ' (60 s max)', '%', rt, rs.map(x => (x.util_max || {})[k])));
  const st = tsOf(SS);
  [['allocated', 'Sessions allocated', ''], ['util_pct', 'Session table utilization', '%'], ['tcp', 'Active TCP sessions', ''], ['udp', 'Active UDP sessions', ''],
   ['icmp', 'Active ICMP sessions', ''], ['cps', 'Connection rate', 'cps'], ['pps', 'Packet rate', 'pps'], ['kbps', 'Throughput (show session info)', 'kbps']]
    .forEach(([k, name, u]) => add('Sessions', 'ss.' + k, name, u, st, SS.map(x => x[k])));
  const tt = (TP.t || []).map(ms), rx = ((TP.total || {}).rx_bps || []).map(bpsM), tx = ((TP.total || {}).tx_bps || []).map(bpsM);
  add('Throughput', 'tp.sum', 'Throughput total received + transmitted', 'Mbit/s', tt, rx.map((v, i) => isNum(v) && isNum(tx[i]) ? v + tx[i] : null));
  add('Throughput', 'tp.rx', 'Throughput total received', 'Mbit/s', tt, rx);
  add('Throughput', 'tp.tx', 'Throughput total transmitted', 'Mbit/s', tt, tx);
  Object.keys(TP.interfaces || {}).sort((a, b) => a.localeCompare(b, undefined, {numeric:true})).forEach(n => { const f = TP.interfaces[n];
    add('Interfaces', 'if.rx.' + n, n + ' received', 'Mbit/s', tt, f.rx_bps.map(bpsM));
    add('Interfaces', 'if.tx.' + n, n + ' transmitted', 'Mbit/s', tt, f.tx_bps.map(bpsM)); });
  const bl = backlogByDp();
  bl.keys.forEach(k => { const l = bl.by[k], t = tsOf(l);
    add('Ingress backlog', 'bl.total.' + k, 'Backlog total ' + k, '%', t, l.map(x => x.total));
    add('Ingress backlog', 'bl.atomic.' + k, 'Backlog atomic ' + k, '%', t, l.map(x => x.atomic)); });
  const ps = PBP.series || [], lat = PBP.latency || [];
  add('Packet buffer', 'pbp.cong', 'Packet buffer congestion', '%', tsOf(ps), ps.map(x => x.congestion_pct));
  add('Packet buffer', 'pbp.lat', 'Packet buffer latency latest', 'ms', tsOf(lat), lat.map(x => x.latest_ms));
  add('Packet buffer', 'pbp.latmax', 'Packet buffer latency max', 'ms', tsOf(lat), lat.map(x => x.max_ms));
  const dt = ((DL.top || {}).t || []).map(ms), used = (DL.top || {}).used || [], rates = DL.rates || {};
  (DL.counters || []).forEach(c => add('Counters (' + c.severity + ')', 'ct.' + c.name, c.name, '/s', dt, dt.map((_, i) => used[i] === false ? null : (rates[c.name] || {})[i] || 0)));
  const pt = (POW.intervals || []).map(ms);
  Object.keys(POW.groups || {}).forEach(n => add('POW groups', 'pow.' + n, 'POW ' + n + ' average', 'us', pt, POW.groups[n].avg_us));
  add('Management plane', 'mp.load1', 'Management load (1 min)', '', tsOf(LOAD), LOAD.map(x => x.load1));
  add('Management plane', 'mp.load5', 'Management load (5 min)', '', tsOf(LOAD), LOAD.map(x => x.load5));
  return out;
}
const bpsM = v => isNum(v) ? v / 1e6 : null;
function backlogByDp(){
  const keys = [], by = {};
  (BL.series || []).forEach(x => { const k = x.slot + ' / ' + x.dp; if(!by[k]){ by[k] = []; keys.push(k); } by[k].push(x); });
  const peak = k => Math.max(0, ...by[k].map(x => x.total || 0));
  keys.sort((a, b) => peak(b) - peak(a));
  return {keys, by};
}

// ---- CPU heatmap: one row per core, one cell per second (see analysis._cpu_heat)
const heatColor = v => isNum(v) ? 'rgba(180,35,24,' + (0.06 + 0.94 * v / 100).toFixed(2) + ')' : '';
function cpuHeat(host, H, G){
  const ids = (H.cores || []).map(String), n = ids.length, stepMs = (H.step_s || 1) * 1000;
  const ncell = n ? H.cells[ids[0]].length : 0;
  if(!n || !ncell){ host.appendChild(noData('No per-second CPU data in this capture.')); return; }
  const thr = +(TH.cpu_core_warn || 80);
  const wrap = E('div', {class:'chart'}), box = E('div'); wrap.appendChild(box); host.appendChild(wrap);
  function draw(){
    clear(box);
    const [d0, d1] = G.domain(), span = d1 - d0;
    const W = Math.max(480, Math.floor(wrap.clientWidth || host.clientWidth || 1000));
    const L = 62, PK = 46, Rr = 62, T = 22, B = 28, LEG = 26, pw = W - L - Rr;
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
        const from = H.t0_ms + j * stepMs - d0, a = Math.floor(from / bt), b = Math.max(a, Math.ceil((from + stepMs) / bt) - 1);
        if(b < 0 || a >= nb) continue;
        if(pk === null || v > pk) pk = v;
        for(let c = Math.max(0, a); c <= Math.min(b, nb - 1); c++) if(vals[c] === null || v > vals[c]) vals[c] = v;
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
        svg.appendChild(S('rect', {x:W - Rr + 8, y, width:PK - 8, height:rp + 0.3, fill:heatColor(pk)}));
        if(rp >= 8) svg.appendChild(S('text', {x:W - Rr + 8 + (PK - 8) / 2, y:yc, 'text-anchor':'middle', 'font-size':fs, fill:pk >= 55 ? '#fff' : '#1c2530', text:String(pk)}));
      }
    });
    svg.appendChild(S('text', {x:W - Rr + 8 + (PK - 8) / 2, y:T - 7, 'text-anchor':'middle', class:'ax', text:'peak'}));
    const nt = Math.max(2, Math.min(8, Math.floor(pw / 110)));
    for(let i = 0; i <= nt; i++){
      const t = d0 + span * i / nt, x = L + pw * i / nt;
      svg.appendChild(S('line', {x1:x, x2:x, y1:T + ph, y2:T + ph + 4, class:'axl'}));
      svg.appendChild(S('text', {x, y:T + ph + 17, 'text-anchor':i === 0 ? 'start' : i === nt ? 'end' : 'middle', class:'ax', text:timeLabel(t, span)}));
    }
    svg.appendChild(S('text', {x:W - 16, y:T + ph + 26, 'text-anchor':'end', class:'ax', text:'UTC'}));
    svg.appendChild(S('line', {x1:L, x2:L + pw, y1:T + ph, y2:T + ph, class:'axl'}));
    drawMarkers(svg, G, t => L + (t - d0) / span * pw, d0, d1, T, ph);
    const ly = T + ph + B + 4, gid = 'hmg' + (++clipN);
    svg.appendChild(S('defs', null, S('linearGradient', {id:gid, x1:0, x2:1, y1:0, y2:0}, S('stop', {offset:0, 'stop-color':heatColor(0)}), S('stop', {offset:1, 'stop-color':heatColor(100)}))));
    svg.appendChild(S('text', {x:L, y:ly + 9, class:'ax', text:'0%'}));
    svg.appendChild(S('rect', {x:L + 26, y:ly, width:140, height:11, fill:'url(#' + gid + ')', stroke:'#d8dde3'}));
    svg.appendChild(S('text', {x:L + 172, y:ly + 9, class:'ax', text:'100%'}));
    svg.appendChild(S('rect', {x:L + 226, y:ly, width:14, height:11, fill:'#eef1f4', stroke:'#d8dde3'}));
    svg.appendChild(S('text', {x:L + 246, y:ly + 9, class:'ax', text:'no data'}));
    svg.appendChild(S('rect', {x:L + 316, y:ly + 0.5, width:14, height:10, fill:heatColor(thr), stroke:'#1c2530', 'stroke-width':1}));
    svg.appendChild(S('text', {x:L + 336, y:ly + 9, class:'ax', text:'at or above ' + thr + '% (cpu_core_warn)'}));
    const guide = S('line', {y1:T, y2:T + ph, stroke:'#1c2530', 'stroke-width':1, 'stroke-dasharray':'3 3', visibility:'hidden'});
    svg.appendChild(guide);
    G.add(svg, t => { if(t == null || t < d0 || t > d1){ guide.setAttribute('visibility', 'hidden'); return; }
      const x = L + (t - d0) / span * pw; guide.setAttribute('x1', x); guide.setAttribute('x2', x); guide.setAttribute('visibility', 'visible'); });
    const ov = S('rect', {x:L, y:T, width:pw, height:ph, fill:'transparent', style:'cursor:crosshair'});
    syncPointer(ov, svg, G, W, x => d0 + (x - L) / pw * span, L, L + pw, T, ph, (ev, t) => {
      const r = svg.getBoundingClientRect(), py = (ev.clientY - r.top) * (W / r.width);
      const k = Math.max(0, Math.min(n - 1, Math.floor((py - T) / rp))), c = Math.max(0, Math.min(nb - 1, Math.floor((t - d0) / bt)));
      const a = d0 + c * bt, v = cols[k][c];
      return ['core ' + ids[k], isoOf(a) + ' - ' + isoOf(a + bt) + ' UTC', isNum(v) ? 'max ' + v + ' %' : 'no data'].concat(markerLines(G, t, span * 5 / pw));
    });
    svg.appendChild(ov); box.appendChild(svg);
  }
  CHARTS.push({draw, wrap}); draw();
  const um = H.unmeasured || [];
  if(um.length) host.appendChild(E('p', {class:'hint', text:'Not measured by the firewall (printed as *): core ' + um.join(', core ') + '. Not drawn.'}));
  if((H.step_s || 1) > 1) host.appendChild(E('p', {class:'hint', text:'Long capture: every cell is the maximum of ' + H.step_s + ' seconds.'}));
}

// ---- panels: each one builds its content into a box
function panelDefs(G){
  const rs = RM.series || [], rt = tsOf(rs), bl = backlogByDp(), ps = PBP.series || [], lat = PBP.latency || [];
  const need = (ok, what, build) => box => { if(!ok) box.appendChild(naMsg(what)); else build(box); };
  const res = build => need(RM.available, 'the resource-monitor command', build);
  const blg = build => need(BL.available, 'the ingress-backlogs command', build);
  const pbp = build => need(PBP.available, 'the packet buffer protection commands', build);
  const tp = build => need(TP.available, 'the interface counters (show counter interface all)', build);
  const defs = [];
  const def = (id, title, build, o) => defs.push(Object.assign({id, title, build}, o || {}));

  def('res_cpu', 'Data plane CPU per cycle', res(box => lineChart(box, {sync:G, t:rt, unit:'%', yMax:100, title:'Core CPU',
    series:[{name:'busiest core (max 60 s)', values:rs.map(x => x.core_max)}, {name:'highest core average (60 s)', values:rs.map(x => x.core_avg)}], legend:true})));
  def('res_heat', 'CPU per core (heatmap)', res(box => { if(RM.heat) cpuHeat(box, RM.heat, G); else box.appendChild(noData('No per-second CPU table could be parsed.')); }));
  def('tp_total', 'Total throughput', tp(box => {
    const T = (TP.t || []).map(ms), rx = (TP.total.rx_bps || []).map(bpsM), tx = (TP.total.tx_bps || []).map(bpsM);
    const sum = rx.map((v, i) => isNum(v) && isNum(tx[i]) ? v + tx[i] : null);
    // the figure the firewall reports in "show session info" (kbps), once per cycle, at its own time
    lineChart(box, {sync:G, unit:'Mbit/s', title:'Total throughput of the physical ports', legend:true, t:T, series:[
      {name:'received (all physical ports)', values:rx}, {name:'transmitted (all physical ports)', values:tx},
      {name:'received + transmitted', values:sum, dash:'5 4', color:PALETTE[5]},
      {name:'firewall figure (show session info, per cycle)', t:tsOf(SS), values:SS.map(x => isNum(x.kbps) ? x.kbps / 1000 : null), color:PALETTE[4]}]});
    const peak = Math.max(0, ...sum.filter(isNum)), ok = sum.filter(isNum);
    box.appendChild(E('p', {class:'hint', text:'Whole capture: peak received + transmitted ' + fmtX(peak) + ' Mbit/s, mean ' + fmtX(ok.length ? ok.reduce((p, q) => p + q, 0) / ok.length : 0) +
      ' Mbit/s over ' + ok.length + ' interval(s); average interval ' + fmtX((TP.dt || []).reduce((p, q) => p + q, 0) / Math.max(1, (TP.dt || []).length)) + ' s.' +
      ((TP.total.rx_bps || []).some(v => v == null) ? ' Some intervals have no total (a port counter went backwards).' : '')}));
  }));
  def('bl_chart', 'Ingress backlog usage', blg(box => {
    if(!bl.keys.length){ box.appendChild(noData()); return; }
    const holder = E('div');
    const show = k => { clear(holder); const l = bl.by[k];
      lineChart(holder, {sync:G, t:tsOf(l), unit:'%', yMax:100, title:'Ingress backlog usage', series:[{name:'atomic %', values:l.map(x => x.atomic)}, {name:'total %', values:l.map(x => x.total)}], legend:true,
        extra:i => ['sessions in list: ' + l[i].real + ', special tags: ' + l[i].special]}); };
    box.appendChild(E('div', {class:'bar'}, selectBox('Slot / data plane', bl.keys.map(k => [k, k]), show)));
    box.appendChild(holder); show(bl.keys[0]);
  }));
  def('pbp_congestion', 'Packet buffer congestion', pbp(box => {
    const act = []; ps.forEach((x, i) => { if(x.active) act.push(i); });
    lineChart(box, {sync:G, t:tsOf(ps), unit:'%', yMax:100, title:'Packet buffer congestion', series:[{name:'congestion %', values:ps.map(x => x.congestion_pct)}], marks:act.length <= 40 ? act : [],
      extra:i => ['used / total: ' + fmtN(ps[i].used) + ' / ' + fmtN(ps[i].total), 'protection active: ' + (ps[i].active ? 'yes' : 'no')]});
    if(act.length) box.appendChild(E('p', {class:'hint', text:(act.length <= 40 ? 'Red rings mark the ' : 'Protection was active in ') + act.length + ' sample(s)' + (act.length <= 40 ? ' where protection was active.' : ' (too many to mark).')}));
    if(PBP.basis) box.appendChild(E('p', {class:'hint', text:'Basis: ' + PBP.basis}));
  }));
  def('pbp_latency', 'Packet buffer latency', pbp(box => lineChart(box, {sync:G, t:tsOf(lat), unit:'ms', title:'Packet buffer latency', legend:true,
    series:[{name:'latest ms', values:lat.map(x => x.latest_ms)}, {name:'max ms', values:lat.map(x => x.max_ms)}]})));
  def('res_groups', 'CPU per group', res(box => {
    const cols = E('div', {class:'cols'});
    const l = E('div', null, E('h4', {text:'Busiest group per cycle', style:'margin:6px 0'})), r = E('div', null, E('h4', {text:'Last sample, every group', style:'margin:6px 0'}), bars(RM.last_groups, +(TH.cpu_group_warn || 80), 50));
    cols.appendChild(l); cols.appendChild(r); box.appendChild(cols);
    lineChart(l, {sync:G, t:rt, unit:'%', yMax:100, title:'Busiest group', height:220, series:[{name:'busiest group %', values:rs.map(x => x.group_max_pct)}], extra:i => ['group: ' + (rs[i].group_max_name || 'n/a')]});
  }));
  def('res_util', 'Resource utilization, maximum over the capture (60 s figures)', res(box => {
    const um = {}; rs.forEach(x => Object.keys(x.util_max || {}).forEach(k => { um[k] = Math.max(um[k] || 0, x.util_max[k]); }));
    box.appendChild(bars(um, 90, 70));
  }));
  def('bl_offenders', 'Offending sessions', blg(box => {
    const off = BL.offenders || [];
    if(!off.length){ box.appendChild(E('p', {text:'No session held a large share of the backlog.'})); return; }
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
    box.appendChild(E('div', {class:'scroll'}, t));
  }));
  def('bl_tags', 'Special tags (not sessions)', blg(box => { const tags = BL.special_tags || [];
    box.appendChild(tags.length ? dataTable([
      {k:'name', label:'Tag', cls:'mono'}, {k:'pct_max', label:'Max %', cls:'r', num:true}, {k:'count_max', label:'Max count', cls:'r', num:true},
      {k:'samples', label:'Samples', cls:'r', num:true}], tags, {sort:'pct_max', dir:-1, cls:'auto'}).el : E('p', {text:'No special tags were seen.'}));
  }));
  def('pbp_entries', 'Last packet buffer protection table' + (PBP.entries_t ? ' (' + sec(PBP.entries_t) + ' UTC)' : ''), pbp(box => {
    const en = PBP.entries || [], keys = [], numeric = /^(pcs|percentage|packets_total|dropped|time_till_discard)$/;
    en.forEach(e => Object.keys(e).forEach(k => { if(!keys.includes(k)) keys.push(k); }));
    box.appendChild(en.length ? dataTable(keys.map(k => ({k, label:k.replace(/_/g, ' '), cls:'mono' + (numeric.test(k) ? ' r' : ''), num:numeric.test(k),
      get:r => numeric.test(k) ? Number(r[k]) : String(r[k] == null ? '' : r[k]), cell:r => String(r[k] == null ? '' : r[k])})), en, {cls:'auto'}).el : E('p', {text:'The table was empty in every sample.'}));
  }));
  def('tp_ifaces', 'Throughput per interface', tp(box => {
    const T = (TP.t || []).map(ms);
    const rows = Object.keys(TP.interfaces || {}).map(n => { const f = TP.interfaces[n], r = f.rx_bps.map(bpsM), t = f.tx_bps.map(bpsM);
      const s2 = r.map((v, i) => (isNum(v) ? v : 0) + (isNum(t[i]) ? t[i] : 0));
      return {name:n, r, t, peak:Math.max(0, ...s2), mean:s2.length ? s2.reduce((p, q) => p + q, 0) / s2.length : 0}; });
    if(!rows.length){ box.appendChild(noData('No interface counters were parsed.')); return; }
    let q = '', busy = true, order = 'peak';
    const grid = E('div', {class:'cols two'}), note = E('p', {class:'hint'});
    const LIMIT = 60;
    const paint = () => {
      clear(grid);
      const list0 = rows.filter(r => (!busy || r.peak > 0) && (!q || r.name.toLowerCase().includes(q)));
      list0.sort((x, y) => order === 'name' ? x.name.localeCompare(y.name, undefined, {numeric:true}) : y.peak - x.peak);
      const total = list0.length;
      list0.slice(0, LIMIT).forEach(r => { const h = E('div', null, E('h4', {text:r.name + '   peak ' + fmtX(r.peak) + ' Mbit/s, mean ' + fmtX(r.mean) + ' Mbit/s', style:'margin:8px 0 0'}));
        grid.appendChild(h);
        lineChart(h, {sync:G, t:T, unit:'Mbit/s', title:'Throughput of ' + r.name, height:170, series:[{name:'received', values:r.r, color:PALETTE[0]}, {name:'transmitted', values:r.t, color:PALETTE[1]}], legend:true}); });
      note.textContent = (total > LIMIT ? 'Showing the first ' + LIMIT + ' of ' + total + ' interfaces. ' : total + ' interface(s). ') +
        (TP.skipped_idle ? TP.skipped_idle + ' physical port(s) without configuration and without traffic are not listed. ' : '') + (TP.resets ? TP.resets + ' counter reset(s) left a gap.' : '');
      if(!total) grid.appendChild(noData('No interface matches.'));
      redrawCharts();
    };
    const inp = E('input', {type:'search', size:'24', placeholder:'Filter by name', 'aria-label':'Filter interfaces'});
    inp.addEventListener('input', () => { q = inp.value.trim().toLowerCase(); paint(); });
    const cb = E('input', {type:'checkbox', checked:true, 'aria-label':'Only interfaces with traffic'});
    cb.addEventListener('change', () => { busy = cb.checked; paint(); });
    box.appendChild(E('div', {class:'bar'}, inp, E('label', null, cb, ' only interfaces with traffic'),
      selectBox('Sort by', [['peak', 'peak throughput'], ['name', 'name']], v => { order = v; paint(); })));
    box.appendChild(note); box.appendChild(grid); paint();
  }));
  def('res_mgmt', 'Management plane load average', box => lineChart(box, {sync:G, t:tsOf(LOAD), title:'Load average', legend:true,
    series:[{name:'1 min', values:LOAD.map(x => x.load1)}, {name:'5 min', values:LOAD.map(x => x.load5)}, {name:'15 min', values:LOAD.map(x => x.load15)}]}), {off:true});
  return defs;
}

function renderDataplane(){
  const root = clear($('#b-dataplane'));
  const catalog = metricCatalog(), byId = new Map(catalog.map(m => [m.id, m]));
  let t0 = Infinity, t1 = -Infinity;
  catalog.forEach(m => m.t.forEach(t => { if(t < t0) t0 = t; if(t > t1) t1 = t; }));
  if(!isFinite(t0)){ t0 = 0; t1 = 60e3; }
  if(t1 === t0){ t0 -= 30e3; t1 += 30e3; }
  const zoomNote = E('span', {class:'hint'}), resetZoom = E('button', {type:'button', text:'Reset zoom'});
  const G = syncGroup(t0, t1, () => { zoomState(); redrawCharts(); });
  function zoomState(){
    const [a, b] = G.domain(); resetZoom.disabled = !G.zoom;
    zoomNote.textContent = (G.zoom ? 'Zoomed: ' : 'Whole capture: ') + sec(isoOf(a)) + ' - ' + sec(isoOf(b)) + ' UTC. Drag on a chart to zoom, double click to reset.';
  }
  resetZoom.addEventListener('click', () => G.setZoom(null));
  G.markers = FND.map(f => ({t:ms(f.t), level:f.level, code:f.code, title:f.title})).filter(m => isFinite(m.t) && m.t >= t0 && m.t <= t1);

  const saved = loadLayout();
  G.showMarkers = saved.markers !== false;
  const defaults = ['cpu.sec.max', 'ss.allocated', 'tp.sum', 'bl.total.' + (backlogByDp().keys[0] || ''), 'pbp.cong'];
  if(!byId.has(defaults[0])) defaults[0] = 'cpu.coremax';
  const topDrop = (DL.counters || []).find(c => c.severity === 'drop' && byId.has('ct.' + c.name));
  if(topDrop) defaults.push('ct.' + topDrop.name);
  const wanted = strList(saved.metrics);
  const sel = new Set((wanted || defaults).filter(id => byId.has(id)));
  // a saved selection that matches nothing in this capture falls back to the defaults
  if(wanted && wanted.length && !sel.size) defaults.filter(id => byId.has(id)).forEach(id => sel.add(id));
  let metricsTouched = !!wanted, relative = saved.scale !== 'absolute';

  const defs = panelDefs(G), ids = defs.map(d => d.id);
  const order = (strList(saved.order) || []).filter(id => ids.includes(id));
  ids.forEach(id => { if(!order.includes(id)) order.push(id); });
  const hidden = new Set(strList(saved.hidden) || defs.filter(d => d.off).map(d => d.id));
  const half = new Set(strList(saved.half) || []);
  const persist = () => saveLayout({order, hidden:Array.from(hidden), half:Array.from(half), markers:G.showMarkers,
    metrics:metricsTouched ? Array.from(sel) : undefined, scale:relative ? 'relative' : 'absolute'});

  // toolbar
  const mk = E('input', {type:'checkbox', checked:G.showMarkers});
  mk.addEventListener('change', () => { G.showMarkers = mk.checked; persist(); redrawCharts(); });
  const hiddenBar = E('span', {class:'picked', style:'margin:0'});
  const reset = E('button', {type:'button', text:'Reset layout'});
  reset.addEventListener('click', () => { try{ localStorage.removeItem(LAYOUT_KEY); }catch(e){} renderDataplane(); redrawCharts(); });
  root.appendChild(E('div', {class:'dpbar'}, E('div', {class:'bar', style:'margin:0'}, resetZoom, E('label', null, mk, ' finding markers (' + G.markers.length + ')'), reset, zoomNote),
    E('div', {class:'bar', style:'margin:4px 0 0'}, hiddenBar)));
  zoomState();

  // correlation chart
  const holder = E('div');
  const drawCorr = () => {
    clear(holder);
    const chosen = Array.from(sel).map(id => byId.get(id));
    const allPct = chosen.every(m => m.unit === '%');
    const series = chosen.map((m, k) => {
      const peak = m.v.reduce((a, v) => isNum(v) && v > a ? v : a, 0);
      const asIs = !relative && m.unit === '%';
      return Object.assign({name:m.name + ' [max ' + fmtN(peak) + (m.unit ? ' ' + m.unit : '') + ']', t:m.t, raw:m.v, unit:m.unit,
        values:m.v.map(v => !isNum(v) ? null : asIs ? v : peak > 0 ? v * 100 / peak : 0)}, lineStyle(k));
    });
    lineChart(holder, {sync:G, series, legend:true, height:380, yMax:100, title:'Correlation of the selected metrics',
      unit:relative ? '% of max' : allPct ? '%' : '% / % of max', empty:sel.size ? 'The selected metrics have no data.' : 'No metric selected: add one above.'});
  };
  const picker = seriesPicker(catalog, sel, () => { metricsTouched = true; persist(); drawCorr(); },
    {what:'metrics', buttons:[['Defaults', () => defaults.filter(id => byId.has(id))]]});
  const scaleBox = selectBox('Scale', [['relative', 'Each series as % of its max'], ['absolute', 'Percent metrics on 0-100, others as % of max']], v => { relative = v === 'relative'; persist(); drawCorr(); });
  scaleBox.querySelector('select').value = relative ? 'relative' : 'absolute';
  const corr = sub('Correlation', 'dp_corr', E('div', {class:'bar'}, scaleBox), picker.el, holder);
  root.appendChild(corr); drawCorr();

  // movable panels
  const grid = E('div', {class:'dpgrid'}), panels = new Map();
  root.appendChild(grid);
  let dragId = null;
  const place = () => { order.forEach(id => grid.appendChild(panels.get(id))); };
  function apply(){
    clear(hiddenBar);
    if(hidden.size) hiddenBar.appendChild(E('span', {class:'hint', text:'Hidden panels (click to show):'}));
    order.forEach(id => {
      const p = panels.get(id), d = defs.find(x => x.id === id), off = hidden.has(id);
      p.hidden = off; p.classList.toggle('full', !half.has(id));
      p.querySelector('.wd').textContent = half.has(id) ? 'Full width' : 'Half width';
      if(off){ const b = E('button', {type:'button', class:'pk', text:'+ ' + d.title}); b.addEventListener('click', () => { hidden.delete(id); apply(); persist(); p.scrollIntoView({block:'nearest'}); }); hiddenBar.appendChild(b); }
    });
    redrawCharts();
  }
  const move = (id, step) => {
    const shown = order.filter(x => !hidden.has(x)), other = shown[shown.indexOf(id) + step];
    if(!other) return;
    order.splice(order.indexOf(id), 1); order.splice(order.indexOf(other) + (step > 0 ? 1 : 0), 0, id);
    place(); apply(); persist();
  };
  defs.forEach(d => {
    const box = sub(d.title, d.id), head = box.querySelector('.sechead');
    const p = E('div', {class:'dppanel', 'data-panel':d.id}, box);
    const grip = E('span', {class:'grip', title:'Drag to move the panel', text:'☰ move'});
    const btn = (text, label, fn, cls) => { const b = E('button', {type:'button', class:cls, title:label, 'aria-label':label + ': ' + d.title, text}); b.addEventListener('click', fn); return b; };
    head.appendChild(E('span', {class:'dptools'}, grip, btn('↑', 'Move up', () => move(d.id, -1)), btn('↓', 'Move down', () => move(d.id, 1)),
      btn('Half width', 'Change width', () => { if(half.has(d.id)) half.delete(d.id); else half.add(d.id); apply(); persist(); }, 'wd'),
      btn('Hide', 'Hide panel', () => { hidden.add(d.id); apply(); persist(); })));
    // draggable only while the grip is held, so that dragging on a chart zooms instead
    grip.addEventListener('mousedown', () => { p.draggable = true; });
    grip.addEventListener('mouseup', () => { p.draggable = false; });
    p.addEventListener('dragstart', ev => { dragId = d.id; p.classList.add('dragging'); ev.dataTransfer.effectAllowed = 'move'; ev.dataTransfer.setData('text/plain', d.id); });
    p.addEventListener('dragend', () => { dragId = null; p.draggable = false; panels.forEach(x => x.classList.remove('dragging', 'over-before', 'over-after')); });
    const after = ev => { const r = p.getBoundingClientRect(); return half.has(d.id) && half.has(dragId) ? ev.clientX > r.left + r.width / 2 : ev.clientY > r.top + r.height / 2; };
    p.addEventListener('dragover', ev => { if(!dragId || dragId === d.id) return; ev.preventDefault(); const a = after(ev); p.classList.toggle('over-after', a); p.classList.toggle('over-before', !a); });
    p.addEventListener('dragleave', () => p.classList.remove('over-before', 'over-after'));
    p.addEventListener('drop', ev => {
      if(!dragId || dragId === d.id) return; ev.preventDefault();
      const a = after(ev); order.splice(order.indexOf(dragId), 1); order.splice(order.indexOf(d.id) + (a ? 1 : 0), 0, dragId);
      p.classList.remove('over-before', 'over-after'); place(); apply(); persist();
    });
    panels.set(d.id, p);
  });
  place();
  defs.forEach(d => { const p = panels.get(d.id); p.hidden = hidden.has(d.id); p.classList.toggle('full', !half.has(d.id)); });
  defs.forEach(d => d.build(panels.get(d.id).firstChild));
  apply();
}
'''

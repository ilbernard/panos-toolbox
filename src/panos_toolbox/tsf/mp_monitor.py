"""Management plane memory and processes of the TSF report (standard library only).

Reads the ``memory`` and ``processes`` sections of ``var/log/pan/mp-monitor.log`` and its
rotations (``.1`` to ``.4``, same naming as dp-monitor) and turns them into a memory series,
a per-process history, a summary and flags. The other sections of the file (``cpu``,
``top_summary``, ``pidstat``, ``filesystem``, ...) are ignored.

Source. Every section starts with a header line exactly like dp-monitor's
(``2026-11-10 22:49:25.399 +0100  --- memory``, parsed with ``analyzer.parse_header``, so
the offset of the header itself is used: the offset of mp-monitor can differ from the
dp-monitor one) and ends with a line of dashes.

* ``memory``: a table with the columns ``Type``, ``Free (kB)``, ``min (kB)``, ``Total (kB)``
  and ``MemAvailable (kB)``, rows ``Mem`` and ``Swap``. Columns are located by their header
  names, not by position. The Swap row may lack MemAvailable and its Total can be
  ``UNKNOWN`` (stored as None). Memory used % = (Total - MemAvailable) / Total * 100 of
  the ``Mem`` row, rounded to 2 decimals; a Mem row without both values is discarded.
* ``processes``: ``Total num processes: N`` and a table ``Name PID CPU% FDs Open Virt Mem
  Res+Swap State [Res+Swap-Lazy]``, mapped by the header names. A name can be truncated by
  the tool with a trailing ``+`` (kept as is). The last column can be empty. A row with
  fewer fields than the mandatory columns (7 on the devices seen) or a non-numeric value
  is discarded and counted. The value ``Unknown`` (seen in CPU%, Virt Mem and Res+Swap of
  processes that ended while the sample was taken, with state ``Unk``) is kept as None: the
  row stays, the value is ignored and counted (``unknown_values``). The ``Totals`` row that
  closes the table (sums of the columns) is not a process and is skipped without being counted.

Per process name. Several rows with the same name in one sample (different PIDs) are
combined: CPU = the highest, Res+Swap = the sum. A process is followed by name across
samples; Res+Swap is in kB.

Flags (same dict structure as dp_health / pow_perf, so findings.from_flags works):

* ``MP_MEMORY``: level from the LAST sample, warn when memory used % is STRICTLY greater than
  ``mem_warn``, crit when STRICTLY greater than ``mem_crit``.
* ``MP_MEMORY_PAST_PEAK`` (warn): the peak of the period was above ``mem_warn`` but the last
  value is back at or below it (so ``MP_MEMORY`` does not apply).
* ``PROC_CPU`` (warn, one per process name): the process was at or above ``proc_cpu_warn`` CPU
  in at least ``proc_cpu_min_samples`` CONSECUTIVE samples of the processes section. One-sample
  spikes (a ``grep`` at 100%, a short ``python`` job) are normal on these devices and are not
  flagged. A run is broken when the process is missing from a sample, or when the gap to the
  previous processes sample is larger than ``proc_cpu_gap_factor`` times the median interval
  between processes samples. The workers (names starting with ``pan_task`` or ``all_task``,
  MP_WORKER_PREFIXES) and the short-lived commands in MP_IGNORE_PROCS are never flagged (they
  are still listed in the tables).
* ``PROC_ZOMBIE`` (info): processes seen in state ``Z``. Info never raises the module status.
  Other states (S, R, D, I, Unk) are not anomalies.

No correlation between processes and memory is computed.

Samples seen in several rotated files are kept once: the first one wins (feed the files
oldest first), keyed by (section, time).

Tune MP_THRESHOLDS in code with ``evaluate_mp_monitor(store, thresholds={...})`` or on the
command line with the ``--mp-<name>`` options. Unknown keys raise ValueError.
"""
from __future__ import annotations

import math
import re
import statistics
from datetime import datetime, timezone
from typing import Any

# Every number used by evaluate_mp_monitor().
MP_THRESHOLDS = {
    'mem_warn': 75,               # memory used %, STRICTLY greater (warn)
    'mem_crit': 90,               # memory used %, STRICTLY greater (crit)
    'proc_cpu_warn': 80,          # process CPU %, at or above
    'proc_cpu_min_samples': 2,    # consecutive samples at or above proc_cpu_warn to flag
    'proc_cpu_gap_factor': 2,     # a run breaks when the gap > factor x median interval
}

# Never flagged by PROC_CPU (still shown in the tables).
MP_WORKER_PREFIXES = ('pan_task', 'all_task')
MP_IGNORE_PROCS = ('grep', 'ps', 'top', 'sh', 'bash', 'awk', 'sed', 'cat')

FLAG_CODES = ('MP_MEMORY', 'MP_MEMORY_PAST_PEAK', 'PROC_CPU', 'PROC_ZOMBIE')
TOP_N = 10

SECTIONS = ('memory', 'processes')
DASH_RE = re.compile(r'^\s*-{5,}\s*$')
MEM_COL_RE = re.compile(r'MemAvailable \(kB\)|Free \(kB\)|min \(kB\)|Total \(kB\)|Type')
MEM_KEYS = {'Type': 'type', 'Free (kB)': 'free', 'min (kB)': 'min', 'Total (kB)': 'total',
            'MemAvailable (kB)': 'avail'}
PROC_COL_RE = re.compile(r'Name|PID|CPU%|FDs Open|Virt Mem|Res\+Swap-Lazy|Res\+Swap|State')
PROC_KEYS = {'Name': 'name', 'PID': 'pid', 'CPU%': 'cpu', 'FDs Open': 'fds',
             'Virt Mem': 'virt', 'Res+Swap': 'rss', 'State': 'state',
             'Res+Swap-Lazy': 'lazy'}
PROC_REQUIRED = ('name', 'pid', 'cpu', 'rss', 'state')
TOTAL_RE = re.compile(r'^Total num processes:\s*(\d+)')

COUNTERS = ('mem_samples', 'proc_samples', 'duplicates', 'bad_rows', 'bad_values',
            'unknown_values')


def new_store() -> dict[str, Any]:
    """Accumulator for parse_mp_monitor(): samples keyed by (section, t) plus counters."""
    return {'samples': {}, 'counters': dict.fromkeys(COUNTERS, 0), 'offsets': set()}


def has_data(store) -> bool:
    return bool(store and store.get('samples'))


def source_ranges(store) -> dict[str, dict[str, int]]:
    """Per source file (base name): sample count, first and last timestamp (ms UTC)."""
    out: dict[str, dict[str, int]] = {}
    for rec in (store or {}).get('samples', {}).values():
        r = out.setdefault(rec['src'], {'n': 0, 'first': rec['t'], 'last': rec['t']})
        r['n'] += 1
        r['first'] = min(r['first'], rec['t'])
        r['last'] = max(r['last'], rec['t'])
    return out


def _int(tok: str):
    """Non-negative integer or None."""
    try:
        v = int(tok)
    except ValueError:
        return None
    return v if v >= 0 else None


def _num(tok: str):
    """Non-negative number (int when whole) or None."""
    try:
        v = float(tok)
    except ValueError:
        return None
    if v < 0 or not math.isfinite(v):
        return None
    return int(v) if v == int(v) else v


_BAD = object()


def _unknown_or(tok: str, conv, cnt):
    """conv(tok); 'Unknown' -> None (counted); anything else not numeric -> _BAD."""
    if tok == 'Unknown':
        cnt['unknown_values'] += 1
        return None
    v = conv(tok)
    return _BAD if v is None else v


def parse_mp_monitor(lines, src, store, warnings) -> int:
    """Walks the lines of an mp-monitor.* file and adds the samples to `store`.

    `store` comes from new_store() and accumulates over the files, which must be passed in
    rotation order, oldest first: a duplicate (same section and time) keeps the FIRST one.
    Returns the number of samples found (duplicates included). Header parsing is the
    analyzer's own (parse_header), so both agree on timestamps and offsets.
    """
    from .analyzer import HDR_LOOSE_RE, parse_header

    samples, cnt = store['samples'], store['counters']
    n_found = 0
    warned = set()
    ts = None
    name = None          # 'memory' / 'processes' while inside one of those sections
    mem = None           # {'cols': [...], 'rows': {type: {key: value}}}
    proc = None          # {'cols': [...] or None, 'rows': [...], 'declared': n}

    def warn_once(key, msg):
        if key not in warned:
            warned.add(key)
            warnings.append(f'{src}: {msg}')

    def add(section, rec):
        nonlocal n_found
        n_found += 1
        cnt['mem_samples' if section == 'memory' else 'proc_samples'] += 1
        key = (section, rec['t'])
        if key in samples:
            cnt['duplicates'] += 1
        else:
            samples[key] = rec

    def end_section():
        nonlocal ts, name, mem, proc
        if ts is not None and name == 'memory' and mem is not None:
            row = mem['rows'].get('Mem')
            if row is not None:
                total, avail = row.get('total'), row.get('avail')
                if total and avail is not None and avail <= total:
                    sw = mem['rows'].get('Swap') or {}
                    add('memory', {
                        't': ts, 'src': src, 'total': total, 'free': row.get('free'),
                        'min': row.get('min'), 'avail': avail,
                        'used_pct': round((total - avail) / total * 100, 2),
                        'swap_total': sw.get('total'), 'swap_free': sw.get('free')})
                else:
                    cnt['bad_rows'] += 1
        elif ts is not None and name == 'processes' and proc is not None and proc['rows']:
            add('processes', {'t': ts, 'src': src, 'rows': proc['rows'],
                              'declared': proc['declared']})
        ts, name, mem, proc = None, None, None, None

    for raw in lines:
        line = raw.rstrip('\r\n')
        if line[:2].isdigit():
            h = parse_header(line)
            if h:
                end_section()
                t, off, sec = h
                store['offsets'].add(off)
                if sec in SECTIONS:
                    ts, name = t, sec
                    if sec == 'memory':
                        mem = {'cols': None, 'rows': {}}
                    else:
                        proc = {'cols': None, 'rows': [], 'declared': None}
                continue
            if HDR_LOOSE_RE.match(line):
                end_section()           # header with an unparseable timestamp
                warn_once('hdr', 'header with unparseable timestamp, following data ignored '
                                 'until the next valid header')
                continue
        if name is None:
            continue
        if DASH_RE.match(line):
            end_section()
            continue
        text = line.strip()
        if not text:
            continue

        if name == 'memory':
            if text.startswith('Type'):
                mem['cols'] = [MEM_KEYS[c] for c in MEM_COL_RE.findall(text)]
                continue
            toks = text.split()
            if mem['cols'] is None or toks[0] not in ('Mem', 'Swap'):
                continue                # e.g. "Last 180 seconds"
            row = {}
            for key, tok in zip(mem['cols'][1:], toks[1:]):
                if tok == 'UNKNOWN':
                    row[key] = None
                    continue
                v = _int(tok)
                if v is None:
                    cnt['bad_values'] += 1
                row[key] = v
            mem['rows'].setdefault(toks[0], row)
            continue

        # name == 'processes'
        m = TOTAL_RE.match(text)
        if m:
            proc['declared'] = int(m.group(1))
            continue
        if text.startswith('Name') and 'PID' in text:
            cols = [PROC_KEYS[c] for c in PROC_COL_RE.findall(text)]
            if all(k in cols for k in PROC_REQUIRED):
                proc['cols'] = cols
            else:
                warn_once('proc_hdr', 'processes table header without the expected columns, '
                                      'section skipped')
            continue
        cols = proc['cols']
        if cols is None:
            continue
        toks = text.split()
        if toks[0] == 'Totals':         # summary row at the end of the table, not a process
            continue
        need = len(cols) - (1 if cols[-1] == 'lazy' else 0)
        if len(toks) < need:
            cnt['bad_rows'] += 1
            continue
        d = dict(zip(cols, toks))
        pid = _int(d['pid'])
        cpu, rss = _unknown_or(d['cpu'], _num, cnt), _unknown_or(d['rss'], _int, cnt)
        if pid is None or cpu is _BAD or rss is _BAD:
            cnt['bad_rows'] += 1
            continue
        proc['rows'].append((d['name'], pid, cpu, rss, d['state']))
    end_section()
    return n_found


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def _utc(ms) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def _flag(subject, code, level, text):
    return {'code': code, 'level': level, 'text': text, 'subject': subject}


def _mb(kb) -> str:
    return f'{kb / 1024:,.0f} MB'


def ignored_kind(name: str) -> str:
    """'worker', 'command' or '' (the process can be flagged)."""
    if name.startswith(MP_WORKER_PREFIXES):
        return 'worker'
    if name in MP_IGNORE_PROCS:
        return 'command'
    return ''


def _runs(vals, times, warn, max_gap):
    """[[first, last], ...] index runs of consecutive samples with value >= warn."""
    runs: list[list[int]] = []
    cur = None
    for i, v in enumerate(vals):
        if v is not None and v >= warn:
            if cur is not None and cur[1] == i - 1 and times[i] - times[i - 1] <= max_gap:
                cur[1] = i
            else:
                cur = [i, i]
                runs.append(cur)
        else:
            cur = None
    return runs


def _memory_view(recs, th):
    recs = sorted(recs, key=lambda r: r['t'])
    ts = [r['t'] for r in recs]
    used = [r['used_pct'] for r in recs]
    swap = []
    for r in recs:
        st, sf = r['swap_total'], r['swap_free']
        swap.append(round((st - sf) / st * 100, 2) if st and sf is not None and sf <= st
                    else None)
    out: dict[str, Any] = {'t': ts, 'used_pct': used, 'swap_used_pct': swap,
                           'avail_kb': [r['avail'] for r in recs],
                           'total_kb': [r['total'] for r in recs], 'summary': None}
    if recs:
        peak = max(used)
        i_peak = used.index(peak)
        out['summary'] = {
            'n': len(recs), 'last': used[-1], 'last_t': ts[-1], 'peak': peak,
            'peak_t': ts[i_peak], 'total_kb': recs[-1]['total'],
            'avail_kb': recs[-1]['avail'], 'min_avail_kb': min(r['avail'] for r in recs),
            'over_warn': sum(1 for v in used if v > th['mem_warn']),
            'over_crit': sum(1 for v in used if v > th['mem_crit'])}
    return out


def _memory_flags(mem, th):
    s = mem['summary']
    if s is None:
        return []
    last, peak = s['last'], s['peak']
    if last > th['mem_warn']:
        level = 'crit' if last > th['mem_crit'] else 'warn'
        limit = th['mem_crit'] if level == 'crit' else th['mem_warn']
        text = (f'Management plane memory used is {last:g}% in the last sample '
                f'({_utc(s["last_t"])}): {_mb(s["total_kb"] - s["avail_kb"])} of '
                f'{_mb(s["total_kb"])} not available (MemAvailable {_mb(s["avail_kb"])}), above '
                f'{limit:g}% (warn {th["mem_warn"]:g}%, crit {th["mem_crit"]:g}%); peak '
                f'{peak:g}% on {_utc(s["peak_t"])}; {s["over_warn"]} of {s["n"]} samples '
                f'above {th["mem_warn"]:g}%.')
        return [_flag('memory', 'MP_MEMORY', level, text)]
    if peak > th['mem_warn']:
        crossed = f', crossing {th["mem_crit"]:g}%' if peak > th['mem_crit'] else ''
        text = (f'Management plane memory used peaked at {peak:g}% on {_utc(s["peak_t"])}'
                f'{crossed} but is back at {last:g}% in the last sample ({_utc(s["last_t"])}); '
                f'{s["over_warn"]} of {s["n"]} samples above {th["mem_warn"]:g}%.')
        return [_flag('memory', 'MP_MEMORY_PAST_PEAK', 'warn', text)]
    return []


def evaluate_mp_monitor(store, thresholds=None) -> dict[str, Any]:
    """Builds the JSON-serialisable view of a parse_mp_monitor() store.

    Keys: 'thresholds'; 'n_mem' / 'n_proc' (samples per section); 'period' ({'first',
    'last'} in ms UTC, or None); 'memory' (columnar lists aligned with 't': 'used_pct',
    'swap_used_pct', 'avail_kb', 'total_kb', and 'summary': n, last/last_t, peak/peak_t,
    total_kb, avail_kb, min_avail_kb, over_warn, over_crit); 'interval_s' (median interval
    between processes samples, or None); 'procs' (one dict per process name: name, ignored
    ('worker', 'command' or ''), n, peak_cpu/peak_cpu_t, n_high (samples at or above
    proc_cpu_warn), longest_run (samples) with run_start/run_end, n_runs (runs of at least
    proc_cpu_min_samples), peak_rss/peak_rss_t, first_rss, last_rss, growth (last - first,
    kB), n_rss (samples with a known Res+Swap), zombie (samples in state Z)); 'top_cpu', 'top_rss', 'top_growth' (name lists, at most
    TOP_N, by peak CPU, peak Res+Swap and positive growth); 'flagged' (names with a PROC_CPU
    flag); 'zombies' ({name: samples}); 'findings' (flag dicts {code, level, text, subject});
    'discarded' (counters); 'warnings'. The store is not modified.
    """
    th = dict(MP_THRESHOLDS)
    unknown = set(thresholds or {}) - set(MP_THRESHOLDS)
    if unknown:
        raise ValueError('unknown management plane threshold(s): '
                         + ', '.join(sorted(unknown)))
    th.update(thresholds or {})
    samples = (store or {}).get('samples', {})
    mem_recs = [r for (sec, _t), r in samples.items() if sec == 'memory']
    proc_recs = sorted((r for (sec, _t), r in samples.items() if sec == 'processes'),
                       key=lambda r: r['t'])
    all_t = [r['t'] for r in samples.values()]
    out: dict[str, Any] = {
        'thresholds': th, 'n_mem': len(mem_recs), 'n_proc': len(proc_recs),
        'period': {'first': min(all_t), 'last': max(all_t)} if all_t else None,
        'memory': _memory_view(mem_recs, th), 'interval_s': None, 'procs': [],
        'top_cpu': [], 'top_rss': [], 'top_growth': [], 'flagged': [], 'zombies': {},
        'findings': [], 'warnings': [],
        'discarded': dict((store or {}).get('counters', dict.fromkeys(COUNTERS, 0))),
    }
    out['findings'].extend(_memory_flags(out['memory'], th))

    times = [r['t'] for r in proc_recs]
    gaps = [b - a for a, b in zip(times, times[1:])]
    median = statistics.median(gaps) if gaps else 0
    max_gap = th['proc_cpu_gap_factor'] * median
    if gaps:
        out['interval_s'] = round(median / 1000, 1)
    # name -> per sample (cpu, rss, zombie) or None when the process is not in the sample.
    series: dict[str, list] = {}
    for i, rec in enumerate(proc_recs):
        agg: dict[str, list] = {}
        for pname, _pid, cpu, rss, state in rec['rows']:
            a = agg.setdefault(pname, [None, None, False])
            if cpu is not None:
                a[0] = cpu if a[0] is None else max(a[0], cpu)
            if rss is not None:
                a[1] = rss if a[1] is None else a[1] + rss
            a[2] = a[2] or state == 'Z'
        for pname, a in agg.items():
            series.setdefault(pname, [None] * len(proc_recs))[i] = tuple(a)
    min_run = th['proc_cpu_min_samples']
    flags = []
    for pname in sorted(series):
        pts = series[pname]
        cpus = [p[0] if p else None for p in pts]
        have = [(i, p) for i, p in enumerate(pts) if p]
        cpu_pts = [(i, p[0]) for i, p in have if p[0] is not None]
        rss_pts = [(i, p[1]) for i, p in have if p[1] is not None]
        peak_cpu = max((v for _i, v in cpu_pts), default=None)
        i_cpu = next((i for i, v in cpu_pts if v == peak_cpu), None)
        peak_rss = max((v for _i, v in rss_pts), default=None)
        i_rss = next((i for i, v in rss_pts if v == peak_rss), None)
        runs = _runs(cpus, times, th['proc_cpu_warn'], max_gap)
        best = max(runs, key=lambda r: (r[1] - r[0], -r[0])) if runs else None
        long_n = best[1] - best[0] + 1 if best else 0
        n_runs = sum(1 for r in runs if r[1] - r[0] + 1 >= min_run)
        kind = ignored_kind(pname)
        rec = {
            'name': pname, 'ignored': kind, 'n': len(have), 'peak_cpu': peak_cpu,
            'peak_cpu_t': times[i_cpu] if i_cpu is not None else None,
            'n_high': sum(1 for c in cpus if c is not None and c >= th['proc_cpu_warn']),
            'longest_run': long_n,
            'run_start': times[best[0]] if best else None,
            'run_end': times[best[1]] if best else None, 'n_runs': n_runs,
            'peak_rss': peak_rss, 'peak_rss_t': times[i_rss] if i_rss is not None else None,
            'first_rss': rss_pts[0][1] if rss_pts else None,
            'last_rss': rss_pts[-1][1] if rss_pts else None,
            'growth': rss_pts[-1][1] - rss_pts[0][1] if len(rss_pts) > 1 else 0,
            'n_rss': len(rss_pts),
            'zombie': sum(1 for _i, p in have if p[2])}
        out['procs'].append(rec)
        if rec['zombie']:
            out['zombies'][pname] = rec['zombie']
        if long_n >= min_run and not kind:
            out['flagged'].append(pname)
            flags.append((long_n, peak_cpu, pname, _flag(pname, 'PROC_CPU', 'warn', (
                f'Process {pname}: CPU at or above {th["proc_cpu_warn"]:g}% for {long_n} '
                f'consecutive samples (longest run {_utc(rec["run_start"])} to '
                f'{_utc(rec["run_end"])}); peak {peak_cpu:g}% on {_utc(rec["peak_cpu_t"])}; '
                f'{n_runs} run(s) of at least {min_run:g} samples.'))))
    flags.sort(key=lambda x: (-x[0], -x[1], x[2]))
    out['findings'].extend(f[3] for f in flags)
    if out['zombies']:
        last_z = sorted({r[0] for r in proc_recs[-1]['rows'] if r[4] == 'Z'}) if proc_recs else []
        listing = ', '.join(f'{n} ({c} sample(s))' for n, c in sorted(out['zombies'].items()))
        tail = (f' In the last sample: {", ".join(last_z)}.' if last_z
                else ' None in the last sample.')
        out['findings'].append(_flag('zombie', 'PROC_ZOMBIE', 'info',
                                     f'Zombie processes (state Z) seen: {listing}.{tail}'))

    procs = out['procs']
    out['top_cpu'] = [p['name'] for p in sorted(
        procs, key=lambda p: (-(p['peak_cpu'] or 0), p['name']))[:TOP_N]]
    out['top_rss'] = [p['name'] for p in sorted(
        procs, key=lambda p: (-(p['peak_rss'] or 0), p['name']))[:TOP_N]]
    out['top_growth'] = [p['name'] for p in sorted(
        (p for p in procs if p['growth'] > 0 and p['n_rss'] > 1),
        key=lambda p: (-p['growth'], p['name']))[:TOP_N]]

    d = out['discarded']
    if d.get('bad_rows') or d.get('bad_values'):
        out['warnings'].append(
            f'{d.get("bad_rows", 0)} row(s) were discarded (too few fields, a non-numeric '
            f'value, or a Mem row without Total/MemAvailable) and {d.get("bad_values", 0)} '
            f'non-numeric memory value(s) ignored.')
    if d.get('unknown_values'):
        out['warnings'].append(
            f'{d["unknown_values"]} CPU%/Res+Swap value(s) read as "Unknown" were ignored '
            f'(processes that ended while the sample was taken).')
    if out['n_proc'] and not out['n_mem']:
        out['warnings'].append('No usable memory section was found.')
    if out['n_mem'] and not out['n_proc']:
        out['warnings'].append('No usable processes section was found.')
    return out

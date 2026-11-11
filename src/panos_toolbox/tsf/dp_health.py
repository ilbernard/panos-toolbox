"""Dataplane health of the TSF report (standard library only).

Reads the resource monitor that sits in the ``panio`` sections of the dp-monitor.* files
(packet-buffer, packet-descriptor and session utilization, and the per-core CPU load)
and turns it into a time series per DP, a summary and flags.

Source (all lines of a ``panio`` section start with ':' on the devices seen so far):

* ``Resource monitoring sampling data (per second)``: a table ``CPU load (%) during last 15
  seconds`` (header ``core 0 1 2 ...``, 15 rows, one value per core; devices with many cores
  split it into several blocks, each with its own ``core`` header) and the blocks
  ``Resource utilization (%) during last 15 seconds`` (``session:``, ``packet buffer:``,
  ``packet descriptor:``, ... each followed by 15 values).
* ``Resource monitoring statistics (per minute)``: the same for the last 15 minutes. The CPU
  table has two columns (avg, max) per core.
* ``target-dp:`` blocks of the same section: ``Session table utilization`` is the fallback
  for the session utilization when the resource block is absent.

A ``*`` in a CPU table cell means "measurement missing" and is stored as None. Values outside
0-100 are discarded (None). A row whose column count does not match the header is discarded.
Both are counted (see ``discarded`` in the view).

DP binding: a resource block is bound to the ``target-dp`` of the SAME section by order of
appearance, as ``analyzer.parse_lines`` does for "CPU load sampling by group". If the number
of blocks and DPs differs nothing is bound and a warning is added (once per file). An optional
explicit line ``DP <name>:`` before a resource block binds it to that DP (best effort,
UNVERIFIED: not seen on a real device, since only single-DP devices were available). Values are
never summed or averaged across DPs; every DP is evaluated on its own.

Evaluation (PEAK versus LAST). PANW.labs evaluates only the last sample. A TSF is a
history, so the level of a flag is based on the PEAK over the whole period; the text gives the
peak (value and UTC time), the last value and how many samples were at or above the
threshold. The value of a sample is the maximum of its 15 per-second values (so a spike inside
the 15-second window is not averaged away). "Last" is the value of the last sample in time.
Samples seen in several rotated files are kept once (the first wins, as in parse_lines).

Tune DP_THRESHOLDS in code with ``evaluate_dp_health(store, thresholds={...})`` or on the
command line with the ``--dp-<name>`` options. Unknown keys raise ValueError.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Every number used by evaluate_dp_health(). Percentages are 0-100.
DP_THRESHOLDS = {
    'session_util_warn': 70,      # session utilization peak (warn)
    'session_util_crit': 90,      # session utilization peak (crit)
    'pkt_buffer_warn': 50,        # packet buffer utilization peak (warn)
    'pkt_buffer_crit': 80,        # packet buffer utilization peak (crit)
    'core_peak_warn': 90,         # per-second CPU load of any core (warn, no crit)
}

FLAG_CODES = ('SESSION_UTIL', 'PKT_BUFFER', 'CORE_PEAK')
MAX_CORES_LISTED = 10

SECTION = 'panio'
RES_TITLE_S = re.compile(r'^Resource monitoring sampling data \(per second\)')
RES_TITLE_M = re.compile(r'^Resource monitoring statistics \(per minute\)')
CPU_TITLE_RE = re.compile(r'^CPU load \(%\) during last \d+ (seconds|minutes)')
UTIL_TITLE_RE = re.compile(r'^Resource utilization \(%\) during last \d+ (seconds|minutes)')
CORE_HDR_RE = re.compile(r'^core((?:\s+\d+)+)\s*$')
AVGMAX_RE = re.compile(r'^(?:avg\s+max\s*)+$')
ROW_RE = re.compile(r'^[\d*]+(?:\s+[\d*]+)*$')
LABEL_RE = re.compile(r'^([A-Za-z][\w ()-]*?)(?: \((average|maximum)\))?:$')
DP_HDR_RE = re.compile(r'^DP\s+([\w.*-]+?)\s*:$')

COUNTERS = ('asterisks', 'out_of_range', 'bad_rows', 'samples_parsed', 'blocks')


def new_store() -> dict[str, Any]:
    """Accumulator for parse_dp_health(): samples keyed by (dp, t) plus counters."""
    return {'samples': {}, 'counters': dict.fromkeys(COUNTERS, 0)}


def has_data(store) -> bool:
    return bool(store and store.get('samples'))


def _cell(tok: str, cnt: dict[str, int]):
    """One table cell: '*' -> None, outside 0-100 -> None (both counted)."""
    if tok == '*':
        cnt['asterisks'] += 1
        return None
    v = int(tok)
    if v > 100:
        cnt['out_of_range'] += 1
        return None
    return v


def _structural(text: str) -> bool:
    """True for a line that ends a table: a title, a core header, a label or a DP header."""
    return bool(CORE_HDR_RE.match(text) or RES_TITLE_S.match(text) or RES_TITLE_M.match(text)
                or CPU_TITLE_RE.match(text) or UTIL_TITLE_RE.match(text)
                or LABEL_RE.match(text) or DP_HDR_RE.match(text))


def _new_block(dp):
    return {'dp': dp, 'cpu_s': {}, 'cpu_m': {}, 'res_s': {}, 'res_m': {}}


def _block_has_data(b) -> bool:
    return bool(b['cpu_s'] or b['cpu_m'] or b['res_s'] or b['res_m'])


def _vals(seq):
    return [v for v in seq if v is not None]


def _mx(seq):
    v = _vals(seq)
    return max(v) if v else None


def _avg(seq):
    v = _vals(seq)
    return round(sum(v) / len(v), 1) if v else None


def _sample_from_block(b, t, dp, src):
    rec = {'t': t, 'dp': dp, 'src': src, 'util_tdp': None, 'sess': None, 'sess_avg': None,
           'pb_avg': None, 'pb_max': None, 'pd_avg': None, 'pd_max': None,
           'pdc_avg': None, 'pdc_max': None, 'sess_m': None, 'pb_m': None,
           'core_s': {}, 'core_m': {}}
    rs, rm = b['res_s'], b['res_m']
    if 'session' in rs:
        rec['sess'], rec['sess_avg'] = _mx(rs['session']), _avg(rs['session'])
    for key, name in (('pb', 'packet buffer'), ('pd', 'packet descriptor'),
                      ('pdc', 'packet descriptor (on-chip)')):
        if name in rs:
            rec[key + '_avg'], rec[key + '_max'] = _avg(rs[name]), _mx(rs[name])
    rec['sess_m'] = _mx(rm.get(('session', 'maximum'), []))
    rec['pb_m'] = _mx(rm.get(('packet buffer', 'maximum'), []))
    for core, vals in b['cpu_s'].items():
        m = _mx(vals)
        if m is not None:
            rec['core_s'][core] = m
    for core, pairs in b['cpu_m'].items():
        m = _mx([p[1] for p in pairs])
        if m is not None:
            rec['core_m'][core] = m
    return rec


def parse_dp_health(lines, src, store, warnings) -> int:
    """Walks the lines of a dp-monitor.* file and adds the resource samples to `store`.

    `store` comes from new_store() and accumulates over the files, which must be passed in
    rotation order, oldest first: a duplicate (same DP and time) keeps the FIRST sample.
    Returns the number of samples found (duplicates included). Header and target-dp parsing
    are the analyzer's own (HDR_RE, TARGET_RE), so both agree on timestamps and DP names.
    """
    from .analyzer import METRIC_RES, TARGET_RE, dp_label, parse_header

    samples = store['samples']
    cnt = store['counters']
    state = {'n_found': 0, 'warned_bind': False, 'warned_order': False}
    ts = None                 # timestamp of the last valid header of a panio section
    in_panio = False
    sec = None

    def new_section():
        return {'blocks': [], 'dps': [], 'tdp': {}, 'cur': None, 'dp': None,
                'pending_dp': None, 'ctx': None, 'cpu_kind': None, 'table': None,
                'label': None}

    def start_block():
        b = _new_block(sec['pending_dp'])
        sec['pending_dp'] = None
        sec['blocks'].append(b)
        sec['cur'] = b
        return b

    def end_section():
        nonlocal sec, ts, in_panio
        if sec is not None and ts is not None:
            _finish_section(sec, ts)
        sec, ts, in_panio = None, None, False

    def _finish_section(s, t):
        blocks = [b for b in s['blocks'] if _block_has_data(b)]
        cnt['blocks'] += len(blocks)
        bound = [(b['dp'], b) for b in blocks if b['dp'] is not None]
        pend = [b for b in blocks if b['dp'] is None]
        free = [d for d in s['dps'] if d not in {d2 for d2, _b in bound}]
        if pend:
            if len(pend) == len(free):
                if len(s['dps']) > 1 and not state['warned_order']:
                    state['warned_order'] = True
                    warnings.append(f'{src}: dataplane resource blocks bound to DPs by '
                                    f'order of appearance (unverified)')
                bound.extend(zip(free, pend))
            elif not state['warned_bind']:
                state['warned_bind'] = True
                warnings.append(f'{src}: {len(pend)} dataplane resource blocks and '
                                f'{len(free)} DPs in the same section, cannot bind '
                                f'them: dataplane health skipped for those blocks')
        recs = {}
        for dp, b in bound:
            recs[dp] = _sample_from_block(b, t, dp, src)
        for dp, util in s['tdp'].items():
            rec = recs.get(dp)
            if rec is None:
                rec = recs[dp] = _sample_from_block(_new_block(dp), t, dp, src)
            rec['util_tdp'] = util
        for dp, rec in recs.items():
            if all(rec[k] is None for k in ('util_tdp', 'sess', 'pb_max', 'pd_max', 'pdc_max')) \
                    and not rec['core_s'] and not rec['core_m']:
                continue
            state['n_found'] += 1
            cnt['samples_parsed'] += 1
            samples.setdefault((dp, t), rec)       # duplicate = overlapping rotated files

    def table_row(tok_line):
        tb = sec['table']
        toks = tok_line.split()
        if tb['dead'] or len(toks) != tb['width']:
            cnt['bad_rows'] += 1
            return
        blk = sec['cur']
        cols = tb['cols']
        if tb['kind'] == 's':
            for core, tok in zip(cols, toks):
                blk['cpu_s'].setdefault(core, []).append(_cell(tok, cnt))
        else:
            for i, core in enumerate(cols):
                avg, mx = _cell(toks[2 * i], cnt), _cell(toks[2 * i + 1], cnt)
                blk['cpu_m'].setdefault(core, []).append((avg, mx))

    for raw in lines:
        line = raw.rstrip('\r\n')

        if line[:2].isdigit():
            h = parse_header(line)
            if h:
                end_section()
                ts, _off, name = h
                if name == SECTION:
                    in_panio = True
                    sec = new_section()
                else:
                    ts = None
                continue
            if re.match(r'^\d{4}-\d{2}-\d{2} \S+ .*\s---\s', line):
                end_section()          # header with unparseable timestamp (parse_lines warns)
                continue
        if not in_panio or sec is None:
            continue

        # Target-dp blocks (session table utilization fallback).
        m = TARGET_RE.match(line)
        if m:
            sec['dp'] = dp_label(m.group(1))
            if sec['dp'] not in sec['dps']:
                sec['dps'].append(sec['dp'])
            sec['ctx'] = sec['table'] = sec['label'] = None
            continue
        m = METRIC_RES['util'].match(line)
        if m:
            sec['tdp'][sec['dp'] or 'n/a'] = int(m.group(1))
            continue
        m = DP_HDR_RE.match(line[1:].strip() if line.startswith(':') else line.strip())
        if m:                                       # explicit "DP <name>:" line (unverified)
            sec['pending_dp'] = dp_label(m.group(1))
            sec['table'] = sec['label'] = None
            continue
        if not line.startswith(':'):
            sec['table'] = sec['label'] = None      # e.g. the pan_comm table, not ours
            continue

        text = line[1:].strip()
        tb = sec['table']
        if tb is not None:
            if tb['await_am']:                       # the "avg max" line of a per-minute table
                tb['await_am'] = False
                if AVGMAX_RE.match(text):
                    if len(text.split()) != tb['width']:
                        tb['dead'] = True
                    continue
                tb['dead'] = True                # per-minute table without its "avg max" line
            if ROW_RE.match(text):
                table_row(text)
                continue
            if text and not _structural(text):
                cnt['bad_rows'] += 1             # e.g. a garbled row: count it, keep the table
                continue
            sec['table'] = None
        if sec['label'] is not None:
            lab, sec['label'] = sec['label'], None
            if ROW_RE.match(text) and sec['cur'] is not None:
                vals = [_cell(tok, cnt) for tok in text.split()]
                key = lab[0] if lab[1] is None else (lab[0], lab[1])
                (sec['cur']['res_m'] if sec['ctx'] == 'm' else sec['cur']['res_s'])[key] = vals
                continue

        if not (CORE_HDR_RE.match(text) or CPU_TITLE_RE.match(text)):
            sec['cpu_kind'] = None       # a "core" header counts only inside the CPU tables
        if not text:
            continue
        if RES_TITLE_S.match(text):
            start_block()
            sec['ctx'] = 's'
            continue
        if RES_TITLE_M.match(text):
            if sec['cur'] is None:
                start_block()
            sec['ctx'] = 'm'
            continue
        m = CPU_TITLE_RE.match(text)
        if m:
            sec['cpu_kind'] = 's' if m.group(1) == 'seconds' else 'm'
            continue
        m = UTIL_TITLE_RE.match(text)
        if m:
            sec['ctx'] = 's' if m.group(1) == 'seconds' else 'm'
            continue
        m = CORE_HDR_RE.match(text)
        if m and sec['cur'] is not None and sec['cpu_kind'] is not None:
            cols = [int(x) for x in m.group(1).split()]
            kind = sec['cpu_kind']
            sec['table'] = {'cols': cols, 'kind': kind, 'dead': False, 'await_am': kind == 'm',
                            'width': (2 if kind == 'm' else 1) * len(cols)}
            continue
        m = LABEL_RE.match(text)
        if m and sec['ctx'] is not None:
            name = m.group(1).strip().lower()
            sec['label'] = (name, m.group(2))
    end_section()
    return state['n_found']


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def _utc(ms) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def _flag(dp, code, level, text):
    return {'code': code, 'level': level, 'text': text, 'dp': dp}


def _summary(ts, vals):
    """Last and peak of a series; None entries are skipped. Peak = first occurrence."""
    pts = [(t, v) for t, v in zip(ts, vals) if v is not None]
    if not pts:
        return {'n': 0, 'last': None, 'last_t': None, 'peak': None, 'peak_t': None}
    peak = max(v for _t, v in pts)
    peak_t = next(t for t, v in pts if v == peak)
    return {'n': len(pts), 'last': pts[-1][1], 'last_t': pts[-1][0],
            'peak': peak, 'peak_t': peak_t}


def _level_flag(dp, code, label, summ, warn, crit):
    peak = summ['peak']
    if peak is None or peak < warn:
        return None
    level, limit = ('crit', crit) if peak >= crit else ('warn', warn)
    over = summ['over'][level]
    text = (f'{label} peaked at {peak}% on {_utc(summ["peak_t"])}; last sample '
            f'{summ["last"]}% ({_utc(summ["last_t"])}); {over} of {summ["n"]} samples '
            f'at or above {limit}% (warn {warn}%, crit {crit}%).')
    return _flag(dp, code, level, f'DP {dp}: {text}')


def _core_value(rec):
    """(value, core) of the busiest core of a sample: per-second table, else per-minute max."""
    tab = rec['core_s'] or rec['core_m']
    if not tab:
        return None, None
    core = min(tab, key=lambda c: (-tab[c], c))
    return tab[core], core


def evaluate_dp_health(store, thresholds=None) -> dict[str, Any]:
    """Builds the JSON-serialisable view of a parse_dp_health() store.

    Keys: 'thresholds', 'dps' (names), 'series' (per DP, columnar lists aligned with 't'),
    'summary' (per DP: last/peak per metric), 'cores' (per DP: per-core peak table),
    'findings' (flag dicts {code, level, text, dp}, same structure as pow_perf and
    interface_errors flags, so findings.from_flags works), 'discarded' (counters),
    'warnings' and 'n_samples'. The store is not modified.
    """
    th = dict(DP_THRESHOLDS)
    unknown = set(thresholds or {}) - set(DP_THRESHOLDS)
    if unknown:
        raise ValueError('unknown dataplane health threshold(s): ' + ', '.join(sorted(unknown)))
    th.update(thresholds or {})
    by_dp: dict[str, list] = {}
    for (dp, _t), rec in (store or {}).get('samples', {}).items():
        by_dp.setdefault(dp, []).append(rec)
    out: dict[str, Any] = {
        'thresholds': th, 'dps': sorted(by_dp), 'series': {}, 'summary': {}, 'cores': {},
        'findings': [], 'warnings': [], 'n_samples': 0,
        'discarded': dict((store or {}).get('counters', dict.fromkeys(COUNTERS, 0))),
    }
    for dp in out['dps']:
        recs = sorted(by_dp[dp], key=lambda r: r['t'])
        out['n_samples'] += len(recs)
        ts = [r['t'] for r in recs]
        sess = [r['sess'] if r['sess'] is not None else r['util_tdp'] for r in recs]
        n_fallback = sum(1 for r in recs if r['sess'] is None and r['util_tdp'] is not None)
        core_best = [_core_value(r) for r in recs]
        ser = {
            't': ts, 'sess': sess,
            'sess_src': ['res' if r['sess'] is not None else 'tdp' for r in recs],
            'sess_avg': [r['sess_avg'] for r in recs], 'sess_m': [r['sess_m'] for r in recs],
            'pb_avg': [r['pb_avg'] for r in recs], 'pb_max': [r['pb_max'] for r in recs],
            'pb_m': [r['pb_m'] for r in recs],
            'pd_avg': [r['pd_avg'] for r in recs], 'pd_max': [r['pd_max'] for r in recs],
            'pdc_avg': [r['pdc_avg'] for r in recs], 'pdc_max': [r['pdc_max'] for r in recs],
            'core_max': [c[0] for c in core_best], 'core_id': [c[1] for c in core_best],
            'core_m_max': [max(r['core_m'].values()) if r['core_m'] else None for r in recs],
        }
        out['series'][dp] = ser
        summ = {
            'session': _summary(ts, sess), 'pkt_buffer': _summary(ts, ser['pb_max']),
            'pkt_desc': _summary(ts, ser['pd_max']), 'pkt_desc_onchip': _summary(ts, ser['pdc_max']),
            'core': _summary(ts, ser['core_max']),
        }
        for key, (w, c) in {'session': ('session_util_warn', 'session_util_crit'),
                            'pkt_buffer': ('pkt_buffer_warn', 'pkt_buffer_crit')}.items():
            vals = {'session': sess, 'pkt_buffer': ser['pb_max']}[key]
            summ[key]['over'] = {'warn': sum(1 for v in vals if v is not None and v >= th[w]),
                                 'crit': sum(1 for v in vals if v is not None and v >= th[c])}
        # Core table: per core peak (and when), last value and per-minute max peak.
        ids = sorted({c for r in recs for c in list(r['core_s']) + list(r['core_m'])})
        peak, peak_t, last, peak_m = [], [], [], []
        for c in ids:
            pts = [(r['t'], (r['core_s'] or r['core_m']).get(c)) for r in recs]
            pts = [(t, v) for t, v in pts if v is not None]
            pm = [v for r in recs for v in [r['core_m'].get(c)] if v is not None]
            if pts:
                pk = max(v for _t, v in pts)
                peak.append(pk)
                peak_t.append(next(t for t, v in pts if v == pk))
                last.append(pts[-1][1])
            else:
                peak.append(None); peak_t.append(None); last.append(None)
            peak_m.append(max(pm) if pm else None)
        out['cores'][dp] = {'ids': ids, 'peak': peak, 'peak_t': peak_t, 'last': last,
                            'peak_m': peak_m}
        cs = summ['core']
        cs['over'] = sum(1 for v in ser['core_max'] if v is not None and v >= th['core_peak_warn'])
        cs['peak_core'] = next((c for c, v in zip(ids, peak) if v == cs['peak']), None) \
            if cs['peak'] is not None else None
        cs['last_core'] = next((c[1] for c in reversed(core_best) if c[0] is not None), None)
        out['summary'][dp] = summ
        # Flags
        flags = out['findings']
        for fl in (
            _level_flag(dp, 'SESSION_UTIL', 'session utilization', summ['session'],
                        th['session_util_warn'], th['session_util_crit']),
            _level_flag(dp, 'PKT_BUFFER', 'packet buffer utilization', summ['pkt_buffer'],
                        th['pkt_buffer_warn'], th['pkt_buffer_crit']),
        ):
            if fl:
                flags.append(fl)
        hot = [(c, v) for c, v in zip(ids, peak) if v is not None and v >= th['core_peak_warn']]
        if hot:
            hot.sort(key=lambda cv: (-cv[1], cv[0]))
            names = ', '.join(f'{c} ({v}%)' for c, v in hot[:MAX_CORES_LISTED])
            if len(hot) > MAX_CORES_LISTED:
                names += f' (+{len(hot) - MAX_CORES_LISTED} more)'
            flags.append(_flag(
                dp, 'CORE_PEAK', 'warn',
                f'DP {dp}: core {hot[0][0]} peaked at {cs["peak"]}% on {_utc(cs["peak_t"])}; '
                f'busiest core in the last sample: {cs["last_core"]} at {cs["last"]}% '
                f'({_utc(cs["last_t"])}); {cs["over"]} of {cs["n"]} samples had a core at or '
                f'above {th["core_peak_warn"]}%. Cores at or above the limit: {names}.'))
        if n_fallback:
            out['warnings'].append(
                f'DP {dp}: {n_fallback} of {len(recs)} samples have no per-second resource '
                f'block; their session utilization is the "Session table utilization" line '
                f'(a single integer reading).')
        if len(recs) and not any(v is not None for v in ser['core_max']):
            out['warnings'].append(f'DP {dp}: no CPU load per core was found.')
    d = out['discarded']
    if d.get('bad_rows') or d.get('out_of_range'):
        out['warnings'].append(
            f'{d.get("bad_rows", 0)} CPU row(s) with a wrong column count and '
            f'{d.get("out_of_range", 0)} value(s) outside 0-100 were discarded.')
    return out

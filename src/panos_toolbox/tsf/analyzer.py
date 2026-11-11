#!/usr/bin/env python3
"""
tsf.analyzer - Extracts Throughput (kbps) and related metrics from the
dp-monitor.* files of a Palo Alto Networks Tech Support File (TSF) and builds a
standalone HTML report (filterable/exportable table + interactive charts,
including CPU load by group). The output of `debug dataplane pow performance`
(tmp/cli/*.txt) is analyzed into a "POW performance" tab (see pow_perf.py), and the interface
counters (`show counter interface all`, `show interface ...`) into an "Interface Errors" tab
(see interface_errors.py). The resource monitor of the same dp-monitor files (session, packet
buffer and descriptor utilization, CPU load per core) goes into a "Dataplane health" tab (see
dp_health.py).

Standard library only.

Usage:
    panos-toolbox tsf analyze tsf1.tgz [tsf2.tgz ...] [-o OUTDIR]
    panos-toolbox tsf analyze /path/to/extracted_TSF_dir
    panos-toolbox tsf analyze dp-monitor.log    # single file
    panos-toolbox tsf analyze cli_output.txt    # single file with POW / interface output
    python -m panos_toolbox.tsf.analyzer ...    # equivalent

Each TSF produces <name>_throughput.html (<name>_pow.html when it has only POW
data, <name>_interfaces.html when it has only interface data, <name>_tsf.html when it has
both); with multiple inputs a summary index.html is also created. The POW and interface
anomaly thresholds can be tuned with the --pow-<name> and --if-<name> options, the dataplane
health ones with --dp-<name> (see --help).
"""
import argparse
import html
import io
import json
import os
import re
import sys
import tarfile
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta, timezone

from . import archive, dp_health, if_glossary, pow_glossary
from .coverage import build_coverage
from .dp_health import DP_THRESHOLDS, evaluate_dp_health
from .findings import analysis_status
from .model import Collected, Inventory
from .interface_errors import (
    IF_THRESHOLDS,
    evaluate_interfaces,
    glossary_keys,
    merge_parsed,
    parse_interfaces,
)
from .interface_errors import has_data as ifc_has_data
from .pow_perf import POW_THRESHOLDS, evaluate, has_data, parse_pow
from .report_help import render_section_help
from .report_template import TEMPLATE

# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
DP_FILE_RE = re.compile(r'(?:^|/)var/log/pan/(dp-monitor\.[^/]+)$')
CLI_FILE_RE = re.compile(r'(?:^|/)tmp/cli/[^/]+\.txt$')
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


CMP_KEYS = ('kbps', 'pps', 'cps', 'sess', 'util', 'grp')


def _cmp_val(sample, key):
    """Value used to compare duplicates: a missing or empty 'grp' is the same thing,
    while for the numeric fields 0 and a missing value are different."""
    v = sample.get(key)
    return (v or None) if key == 'grp' else v


def iso_utc(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


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


def parse_lines(lines, src, samples, seen, warnings, offsets, conflicts=None):
    """Walks the lines of a dp-monitor.* file and collects the samples.

    Each '--- <name>' section is processed on its own: the session metrics
    (after 'target-dp:') yield one sample per DP; the 'CPU load sampling by
    group' block is bound to the DP of that same section.
    Returns the number of Throughput samples found (duplicates included).

    Duplicates (same DP and timestamp, e.g. overlapping rotated files) keep the
    FIRST sample. `seen` is either a set of (dp, t) keys (old behaviour: duplicates
    dropped silently) or a dict (dp, t) -> kept sample, which also detects conflicts:
    a duplicate whose kbps/pps/cps/sess/util/grp differ from the kept one is dropped
    too, but reported. Each conflict is appended to `conflicts` (if given) as a tuple
    (dp, t, kept_src, dropped_src), and, to avoid flooding, one aggregated warning is
    added to `warnings` per (kept_src, dropped_src) pair at the end of the call: for a
    single sample '<dropped>: sample <dp> @ <UTC time> conflicts with <kept> (kept the
    first)', for N > 1 '<dropped>: N samples conflict with <kept> (kept the first);
    first: <dp> @ <UTC time>'. A conflict inside one file reads 'conflicts with another
    sample of the same file'. Identical duplicates are never reported.
    """
    pairs = {}           # (kept_src, dropped_src) -> [count, first dp, first t]
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
                if isinstance(seen, dict):
                    seen[key] = r
                else:
                    seen.add(key)
                samples.append(r)
            elif isinstance(seen, dict):
                kept = seen[key]
                if any(_cmp_val(kept, k) != _cmp_val(r, k) for k in CMP_KEYS):
                    if conflicts is not None:
                        conflicts.append((r['dp'], r['t'], kept['src'], src))
                    pair = pairs.setdefault((kept['src'], src), [0, r['dp'], r['t']])
                    pair[0] += 1
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
    for (kept_src, dropped_src), (count, pdp, pt) in pairs.items():
        other = ('another sample of the same file' if kept_src == dropped_src
                 else kept_src)
        if count == 1:
            warnings.append(f'{dropped_src}: sample {pdp} @ {iso_utc(pt)} conflicts '
                            f'with {other} (kept the first)')
        else:
            warnings.append(f'{dropped_src}: {count} samples conflict with {other} '
                            f'(kept the first); first: {pdp} @ {iso_utc(pt)}')
    return n_found


def iter_text_lines(fobj):
    for b in fobj:
        yield b.decode('utf-8', errors='replace')


def _select_family(logical):
    """Family of an archive member (logical path, '.gz' dropped), or None."""
    if DP_FILE_RE.search('/' + logical):
        return 'dp-monitor'
    if CLI_FILE_RE.search('/' + logical):
        return 'cli'
    return None


def collect(path, warnings):
    """Returns a Collected (samples, offsets, n_files, pow_data, ifc_data, inventory,
    conflicts, status).

    pow_data is the parse_pow() result of the first 'debug dataplane pow
    performance' output found (tmp/cli/*.txt, or a single input file), or None.
    ifc_data is the merged parse_interfaces() result of the interface counter outputs
    found in the same files, or None. Archives and directories are read with
    archive.py (in memory, unsafe members skipped); dp-monitor files are parsed in
    rotation order, oldest to current.
    """
    samples, seen, offsets = [], {}, set()
    conflicts = []
    dp_store = dp_health.new_store()
    n_files = 0
    pow_found = []
    ifc_found = []
    inventory = Inventory()

    def handle(name, fobj):
        nonlocal n_files
        base = os.path.basename(name)
        n_files += 1
        decoded = []                      # decoded once, reused by dp_health

        def tee():
            for ln in iter_text_lines(fobj):
                decoded.append(ln)
                yield ln

        try:
            found = parse_lines(tee(), base, samples, seen, warnings, offsets, conflicts)
        except Exception as exc:  # corrupted/truncated file
            warnings.append(f'{base}: read error ({exc}), '
                            f'partial data kept')
            found = None
        try:
            dp_health.parse_dp_health(decoded, base, dp_store, warnings)
        except (ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
            warnings.append(f'{base}: dataplane health not parsed ({exc})')
        if found is None:
            return
        if found == 0:
            warnings.append(f'{base}: no Throughput samples found')

    def handle_cli(name, fobj):
        base = os.path.basename(name)
        try:
            text_lines = list(iter_text_lines(fobj))
        except (OSError, EOFError, tarfile.TarError) as exc:  # truncated archive
            warnings.append(f'{base}: CLI output read error ({exc}), skipped')
            return
        parsed = parse_pow(text_lines, src=base)
        if has_data(parsed):
            pow_found.append((base, parsed))
        ifc = parse_interfaces(text_lines, src=base)
        # Files with only context (system info, clock, global counters) are kept too: the
        # interface counters may sit in another file of the same TSF.
        if ifc_has_data(ifc) or ifc['system'] or ifc['global'] or ifc['collected_at']:
            ifc_found.append(ifc)

    def have_ifc():
        return any(ifc_has_data(p) for p in ifc_found)

    if os.path.isdir(path) or tarfile.is_tarfile(path):
        dp_members = []
        for mem in archive.iter_members(path, _select_family, inventory):
            base = os.path.basename(mem.name)
            if mem.error:
                warnings.append(f'{base}: read error ({mem.error}), partial data kept')
            if mem.truncated and not mem.error:
                warnings.append(f'{base}: larger than the read limit, only its last '
                                f'part was analysed')
            if mem.family == 'dp-monitor':
                dp_members.append(mem)
            else:
                handle_cli(mem.name, io.BytesIO(mem.data))
        order = {n: i for i, n in enumerate(
            archive.sort_rotations([m.name for m in dp_members]))}
        for mem in sorted(dp_members, key=lambda m: order[m.name]):
            handle(mem.name, io.BytesIO(mem.data))
        for name, reason in inventory.skipped:
            if reason == archive.REASON_UNSAFE:
                warnings.append(f'{name}: unsafe member path, skipped')
        warnings.extend(inventory.notes)
    else:                                     # single file: POW output or log
        with open(path, 'rb') as fh:
            handle_cli(path, fh)
        if not pow_found and not have_ifc():
            with open(path, 'rb') as fh:
                handle(path, fh)

    if n_files == 0 and not pow_found and not have_ifc():
        warnings.append('no dp-monitor.* file found in /var/log/pan')
    if len(pow_found) > 1:
        warnings.append(f'POW output found in {len(pow_found)} files, '
                        f'using {pow_found[0][0]}')
    samples.sort(key=lambda r: (r['t'], r['dp']))
    pow_data = pow_found[0][1] if pow_found else None
    ifc_data = merge_parsed(ifc_found) if have_ifc() else None
    return Collected(samples, offsets, n_files, pow_data, ifc_data, inventory, conflicts,
                     analysis_status(inventory, len(conflicts)),
                     dp_store if dp_health.has_data(dp_store) else None)


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


def fmt_kbps(v):
    if v >= 1e6:
        return f'{v / 1e6:.2f} Gbps'
    if v >= 1e3:
        return f'{v / 1e3:.1f} Mbps'
    return f'{v} kbps'


def utc_str(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def render_report(name, samples, series, offsets, warnings, n_files, tpl, pow_view=None,
                  thresholds=None, ifc_view=None, if_thresholds=None, coverage=None,
                  dph_view=None, dp_thresholds=None):
    data = {
        'name': name,
        'kind': 'TSF analysis' if pow_view or ifc_view or dph_view else 'Throughput',
        'generated': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'offsets': sorted(offsets),
        'files': n_files,
        'warnings': warnings,
        'series': series,
        'samples': samples,
        'pow': pow_view,
        'ifc': ifc_view,
        'coverage': coverage,
        'dph': dph_view,
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
    # Glossary entries (tooltips): every counter of the POW view, plus the CPU groups the
    # glossary knows. The glossary is partly inferred; each entry carries a confidence code.
    names = set()
    if pow_view:
        views = [pow_view['global']] + list(pow_view['cores'].values())
        for v in views:
            names.update(r['name'] for r in v['groups'] + v['funcs'])
            names.update(h['name'] for h in v['hist'])
    names.update(g for g in groups if g in pow_glossary.GLOSSARY)
    gl_names = pow_glossary.glossary_subset(names)
    gl_fields = pow_glossary.field_entries()
    if ifc_view:
        gl_names.update(if_glossary.glossary_subset(glossary_keys(ifc_view)))
        gl_fields.update(if_glossary.field_entries())
    data['gl'] = {'names': gl_names, 'fields': gl_fields, 'conf': pow_glossary.CONF_TEXT}
    blob = json.dumps(data, separators=(',', ':')).replace('</', '<\\/')
    out = tpl
    for key, val in render_section_help(thresholds, if_thresholds, dp_thresholds).items():
        out = out.replace(key, val)
    return (out.replace('__DATA__', blob)
               .replace('__KIND__', data['kind'])
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
    ap.add_argument('inputs', nargs='+',
                    help='TSF (.tgz/.tar.gz), directory, dp-monitor.* file or a text file '
                         'with `debug dataplane pow performance` or interface counter output')
    ap.add_argument('-o', '--outdir', default='output', help='output directory (default: output)')
    ap.add_argument('--open', action='store_true', help='open the report in the default browser')
    grp = ap.add_argument_group(
        'POW performance thresholds',
        'Tunables of the POW anomaly flags (defaults in brackets; see pow_perf.POW_THRESHOLDS '
        'and the flag reference in the report help). Percent values are 0-100.')
    for key, default in POW_THRESHOLDS.items():
        grp.add_argument('--pow-' + key.replace('_', '-'), dest='pow_' + key, metavar='N',
                         type=float, default=None, help=f'{key} [{default:g}]')
    igrp = ap.add_argument_group(
        'Interface Errors thresholds',
        'Tunables of the interface error flags (defaults in brackets; see '
        'interface_errors.IF_THRESHOLDS and the flag reference in the report help).')
    for key, default in IF_THRESHOLDS.items():
        igrp.add_argument('--if-' + key.replace('_', '-'), dest='if_' + key, metavar='N',
                          type=float, default=None, help=f'{key} [{default:g}]')
    dgrp = ap.add_argument_group(
        'Dataplane health thresholds',
        'Tunables of the dataplane health flags (defaults in brackets; see '
        'dp_health.DP_THRESHOLDS and the flag reference in the report help). Percent values '
        'are 0-100.')
    for key, default in DP_THRESHOLDS.items():
        dgrp.add_argument('--dp-' + key.replace('_', '-'), dest='dp_' + key, metavar='N',
                          type=float, default=None, help=f'{key} [{default:g}]')
    args = ap.parse_args(argv)
    overrides = {k: getattr(args, 'pow_' + k) for k in POW_THRESHOLDS
                 if getattr(args, 'pow_' + k) is not None}
    if any(v < 0 for v in overrides.values()):
        ap.error('POW thresholds must be >= 0')
    if_overrides = {k: getattr(args, 'if_' + k) for k in IF_THRESHOLDS
                    if getattr(args, 'if_' + k) is not None}
    if any(v < 0 for v in if_overrides.values()):
        ap.error('interface thresholds must be >= 0')
    dp_overrides = {k: getattr(args, 'dp_' + k) for k in DP_THRESHOLDS
                    if getattr(args, 'dp_' + k) is not None}
    if any(v < 0 for v in dp_overrides.values()):
        ap.error('dataplane health thresholds must be >= 0')

    tpl = TEMPLATE
    os.makedirs(args.outdir, exist_ok=True)

    index_rows = []
    for path in args.inputs:
        warnings = []
        name = re.sub(r'(\.tar\.gz|\.tgz|\.tar)$', '', os.path.basename(path.rstrip('/')))
        try:
            col = collect(path, warnings)
            samples, offsets, n_files = col.samples, col.offsets, col.n_files
            pow_data, ifc_data = col.pow_data, col.ifc_data
        except Exception as exc:
            print(f'[ERROR] {path}: {exc}', file=sys.stderr)
            continue
        if not samples and pow_data is None and ifc_data is None and col.dp_health is None:
            print(f'[WARNING] {path}: no samples extracted', file=sys.stderr)
            for w in warnings:
                print('  -', w, file=sys.stderr)
            continue
        series = add_aggregate(samples) if samples else []
        pow_view = evaluate(pow_data, overrides) if pow_data else None
        ifc_view = evaluate_interfaces(ifc_data, if_overrides) if ifc_data else None
        dph_view = evaluate_dp_health(col.dp_health, dp_overrides) if col.dp_health else None
        pow_warnings = pow_data['warnings'] if pow_data else []
        ifc_warnings = ifc_view['warnings'] if ifc_view else []
        if samples:
            suffix = '_throughput.html'
        elif pow_data is None and ifc_view is None:
            suffix = '_dphealth.html'
        elif pow_data is None:
            suffix = '_interfaces.html'
        else:
            suffix = '_tsf.html' if ifc_view else '_pow.html'
        out = os.path.join(args.outdir, f'{name}{suffix}')
        with open(out, 'w', encoding='utf-8') as fh:
            fh.write(render_report(name, samples, series, offsets, warnings, n_files, tpl,
                                   pow_view, overrides, ifc_view, if_overrides,
                                   build_coverage(col), dph_view, dp_overrides))
        partial = ''
        if col.status == 'partial':
            n_trunc = sum(len(f.truncated) for f in col.inventory.families.values())
            partial = (f' [analysis partial: {len(col.conflicts)} conflicts, '
                       f'{n_trunc} truncated members]')
        dph_warnings = dph_view['warnings'] if dph_view else []
        n_warn = len(warnings) + len(pow_warnings) + len(ifc_warnings) + len(dph_warnings)
        row = {'file': os.path.basename(out), 'name': name, 'samples': 0,
               'start': '-', 'end': '-', 'peak': '-', 'warnings': n_warn}
        if samples:
            base = [s for s in samples if s['dp'] == series[0]]
            peak = max(base, key=lambda s: s['kbps'])
            print(f'[OK] {path}: {len(base)} samples, {len(series) - (series[0] == "ALL")} DP, '
                  f'{n_warn} warnings{partial} -> {out}')
            row.update(samples=len(base), start=utc_str(base[0]['t']),
                       end=utc_str(base[-1]['t']),
                       peak=f"{fmt_kbps(peak['kbps'])} ({utc_str(peak['t'])})")
        elif pow_data is not None:
            g = pow_data['global']
            print(f'[OK] {path}: POW performance{" and interface errors" if ifc_view else " only"} '
                  f'({len(g["funcs"])} functions, '
                  f'{len(g["groups"])} workgroups, {len(pow_data["cores"])} cores), '
                  f'{n_warn} warnings{partial} -> {out}')
        elif pow_data is None and ifc_view is None:
            print(f'[OK] {path}: dataplane health only ({dph_view["n_samples"]} samples), '
                  f'{n_warn} warnings{partial} -> {out}')
        else:
            print(f'[OK] {path}: interface errors only ({len(ifc_view["rows"])} interfaces, '
                  f'{n_warn} warnings{partial} -> {out}')
        for w in warnings + pow_warnings + ifc_warnings + dph_warnings:
            print('  -', w, file=sys.stderr)
        index_rows.append(row)

    if len(index_rows) > 1:
        with open(os.path.join(args.outdir, 'index.html'), 'w', encoding='utf-8') as fh:
            fh.write(render_index(index_rows))
        print(f'[OK] summary -> {os.path.join(args.outdir, "index.html")}')

    if index_rows and args.open:
        target = 'index.html' if len(index_rows) > 1 else index_rows[0]['file']
        webbrowser.open(Path(args.outdir, target).resolve().as_uri())


if __name__ == '__main__':
    sys.exit(main())

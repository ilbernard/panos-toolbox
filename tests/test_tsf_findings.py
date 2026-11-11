"""Tests for tsf/findings.py and the sample conflict reporting of tsf/analyzer.py."""
from __future__ import annotations

from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer, findings, interface_errors, pow_perf
from panos_toolbox.tsf.findings import Finding, SourceRef
from panos_toolbox.tsf.model import Inventory

DATA = Path(__file__).parent / 'data'


def block(ts, kbps, dp='dp0'):
    return (f'{ts} +0000 --- dp-monitor\ntarget-dp: *.{dp}\n'
            f'Throughput: {kbps} kbps\n')


def make_dir(tmp_path, files):
    d = tmp_path / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    for name, text in files.items():
        (d / name).write_text(text)
    return tmp_path


def test_conflict_across_rotations_cites_both_files(tmp_path):
    root = make_dir(tmp_path, {
        'dp-monitor.log': block('2026-10-27 08:00:00', 222),
        'dp-monitor.log.1': block('2026-10-27 08:00:00', 111),
    })
    warnings = []
    col = analyzer.collect(str(root), warnings)
    # Rotation order: .log.1 is parsed first, so its value is kept.
    assert [(s['src'], s['kbps']) for s in col.samples] == [('dp-monitor.log.1', 111)]
    assert len(col.conflicts) == 1
    dp, _t, kept, dropped = col.conflicts[0]
    assert (dp, kept, dropped) == ('dp0', 'dp-monitor.log.1', 'dp-monitor.log')
    assert warnings == [
        ('dp-monitor.log: sample dp0 @ 2026-10-27T08:00:00Z conflicts with '
        'dp-monitor.log.1 (kept the first)')]
    assert col.status == 'partial'


def test_identical_duplicate_is_silent(tmp_path):
    text = block('2026-10-27 08:00:00', 111)
    root = make_dir(tmp_path, {'dp-monitor.log': text, 'dp-monitor.log.1': text})
    warnings = []
    col = analyzer.collect(str(root), warnings)
    assert len(col.samples) == 1
    assert col.conflicts == []
    assert warnings == []
    assert col.status == 'complete'


def test_many_conflicts_aggregated_per_file_pair():
    n = 5
    first = ''.join(block(f'2026-10-27 08:0{i}:00', 10 + i) for i in range(n))
    second = ''.join(block(f'2026-10-27 08:0{i}:00', 500 + i) for i in range(n))
    third = ''.join(block(f'2026-10-27 08:0{i}:00', 900 + i) for i in range(2))
    samples, seen, warnings, offsets, conflicts = [], {}, [], set(), []
    for src, text in (('a', first), ('b', second), ('c', third)):
        analyzer.parse_lines(text.splitlines(True), src, samples, seen, warnings,
                             offsets, conflicts)
    assert len(samples) == n and len(conflicts) == n + 2
    assert warnings == [
        'b: 5 samples conflict with a (kept the first); first: dp0 @ 2026-10-27T08:00:00Z',
        'c: 2 samples conflict with a (kept the first); first: dp0 @ 2026-10-27T08:00:00Z',
    ]


def test_conflict_inside_one_file():
    text = block('2026-10-27 08:00:00', 1) + block('2026-10-27 08:00:00', 2)
    samples, seen, warnings, conflicts = [], {}, [], []
    analyzer.parse_lines(text.splitlines(True), 'f', samples, seen, warnings, set(),
                         conflicts)
    assert [s['kbps'] for s in samples] == [1]
    assert warnings == [
        ('f: sample dp0 @ 2026-10-27T08:00:00Z conflicts with another sample of the '
        'same file (kept the first)')]


def test_module_status():
    info = Finding('A', findings.INFO, 't')
    warn = Finding('B', findings.WARNING, 't')
    crit = Finding('C', findings.CRITICAL, 't')
    assert findings.module_status([crit], has_data=False) == 'no_data'
    assert findings.module_status([], has_data=True) == 'ok'
    assert findings.module_status([info, info], has_data=True) == 'ok'
    assert findings.module_status([info, warn], has_data=True) == 'warning'
    assert findings.module_status([warn, crit, info], has_data=True) == 'critical'


def test_analysis_status():
    inv = Inventory()
    assert findings.analysis_status(inv, 0) == 'complete'
    inv.family('cli').found.append('x.txt')
    assert findings.analysis_status(inv, 0) == 'complete'
    assert findings.analysis_status(inv, 1) == 'partial'
    inv.family('dp-monitor').truncated.append('dp-monitor.log')
    assert findings.analysis_status(inv, 0) == 'partial'
    inv2 = Inventory(notes=['archive limit reached'])
    assert findings.analysis_status(inv2, 0) == 'partial'


def test_finding_defaults_are_independent():
    a, b = Finding('A', 'info', 't'), Finding('B', 'info', 't')
    a.refs.append(SourceRef('f', 3))
    assert b.refs == [] and a.scope == '' and SourceRef('f').line is None


def test_from_flags_unknown_level():
    with pytest.raises(ValueError):
        findings.from_flags([{'code': 'X', 'level': 'bad', 'text': 't'}])


def _all_flags(rows):
    return [(r, f) for r in rows for f in r['flags']]


def test_from_flags_pow_sample():
    parsed = pow_perf.parse_pow((DATA / 'pow_performance_sample.txt').read_text().splitlines(True))
    view = pow_perf.evaluate(parsed)
    rows = view['global']['groups'] + view['global']['funcs']
    pairs = _all_flags(rows)
    assert pairs
    row, flag = pairs[0]
    before = [dict(f) for f in row['flags']]
    out = findings.from_flags(row['flags'], scope=row['name'],
                              refs=[SourceRef('pow_performance_sample.txt')])
    assert row['flags'] == before            # read-only
    assert len(out) == len(row['flags'])
    assert out[0].code == flag['code'] and out[0].text == flag['text']
    assert out[0].scope == row['name']
    assert out[0].refs == [SourceRef('pow_performance_sample.txt')]
    assert {f.level for f in out} <= set(findings.LEVELS)


def test_from_flags_interface_sample():
    parsed = interface_errors.parse_interfaces(
        (DATA / 'interface_errors_sample.txt').read_text().splitlines(True),
        src='interface_errors_sample.txt')
    view = interface_errors.evaluate_interfaces(parsed)
    levels = {'info': 'info', 'warn': 'warning', 'crit': 'critical'}
    n = 0
    for row in view['rows']:
        out = findings.from_flags(row['flags'], scope=row['name'])
        assert [(f.code, f.level) for f in out] == [
            (fl['code'], levels[fl['level']]) for fl in row['flags']]
        n += len(out)
    assert n > 0


def test_zero_versus_missing_value_is_a_conflict():
    from panos_toolbox.tsf import analyzer
    hdr = '2026-10-27 09:00:00 +0100 --- dp-monitor'
    a = [hdr, 'target-dp: *.dp0', 'Throughput: 100 kbps',
         'New connection establish rate: 0 cps']
    b = [hdr, 'target-dp: *.dp0', 'Throughput: 100 kbps']
    samples, seen, warnings, offsets, conflicts = [], {}, [], set(), []
    analyzer.parse_lines(a, 'a.log', samples, seen, warnings, offsets, conflicts)
    analyzer.parse_lines(b, 'b.log', samples, seen, warnings, offsets, conflicts)
    assert len(samples) == 1
    assert [(c[2], c[3]) for c in conflicts] == [('a.log', 'b.log')]

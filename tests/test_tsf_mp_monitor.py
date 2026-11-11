"""Tests for tsf/mp_monitor.py and the Management plane tab of the report.

Synthetic data only (no real TSF content); no device is contacted.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer, findings, mp_monitor
from panos_toolbox.tsf.mp_monitor import (
    FLAG_CODES,
    MP_THRESHOLDS,
    evaluate_mp_monitor,
    parse_mp_monitor,
)

SAMPLE = Path(__file__).parent / 'data' / 'mp_monitor_sample.log'
DASH = '-----------------------------'
BASE = datetime(2026, 10, 27, 8, 0, 0, tzinfo=timezone.utc)      # UTC base time


def ms(minutes=0, seconds=0):
    return int((BASE + timedelta(minutes=minutes, seconds=seconds)).timestamp() * 1000)


def stamp(minutes=0, seconds=0, off='+0000'):
    d = BASE + timedelta(minutes=minutes, seconds=seconds)
    return d.strftime('%Y-%m-%d %H:%M:%S.000 ') + off


def mem_sec(minutes, total=1000, avail=500, swap='6104084', off='+0000', seconds=0):
    return [f'{stamp(minutes, seconds, off)}  --- memory', 'Last 180 seconds',
            'Type       Free (kB)     min (kB)      Total (kB)    MemAvailable (kB)',
            f'Mem        344656        323512        {total}       {avail}          ',
            f'Swap       4858572       4858572       {swap}', DASH]


def prow(name, cpu, rss=1000, state='S', pid=100):
    return f'{name:<22} {pid:<8} {cpu:<5} {9:<10} {358116:<12} {rss:<12} {state:<10}'


def proc_sec(minutes, rows, seconds=0, off='+0000'):
    header = ('Name                   PID      CPU%  FDs Open   Virt Mem     Res+Swap     '
              'State      Res+Swap-Lazy   ')
    return [f'{stamp(minutes, seconds, off)}  --- processes',
            f'Total num processes: {len(rows)}', header, *rows, DASH]


def parse(lines, store=None, src='mp-monitor.log'):
    store = store or mp_monitor.new_store()
    warnings = []
    n = parse_mp_monitor(lines, src, store, warnings)
    return n, store, warnings


def view_of(lines, **th):
    _n, store, _w = parse(lines)
    return evaluate_mp_monitor(store, th or None)


def codes(view):
    return [f['code'] for f in view['findings']]


def proc_series(name, cpus, rss=None, step=1, **kw):
    """Processes sections one `step` minutes apart with `name` at the given CPU values."""
    lines = []
    for i, c in enumerate(cpus):
        rows = [prow('idle', 0)]
        if c is not None:
            rows.append(prow(name, c, rss[i] if rss else 1000, **kw))
        lines += proc_sec(i * step, rows)
    return lines


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def test_memory_used_percent_formula():
    _n, store, _w = parse(mem_sec(0, total=7216044, avail=3157004))
    rec = store['samples'][('memory', ms())]
    assert rec['used_pct'] == round((7216044 - 3157004) / 7216044 * 100, 2) == 56.25
    assert rec['total'] == 7216044 and rec['avail'] == 3157004 and rec['src'] == 'mp-monitor.log'


def test_memory_columns_are_found_by_header_name():
    lines = [f'{stamp()}  --- memory', 'Type  MemAvailable (kB)  Total (kB)  Free (kB)',
             'Mem   100                1000        5', DASH]
    _n, store, _w = parse(lines)
    rec = store['samples'][('memory', ms())]
    assert rec['avail'] == 100 and rec['total'] == 1000 and rec['free'] == 5
    assert rec['used_pct'] == 90.0


def test_swap_unknown_and_swap_without_memavailable():
    _n, store, _w = parse(mem_sec(0, swap='UNKNOWN'))
    rec = store['samples'][('memory', ms())]
    assert rec['swap_total'] is None and rec['used_pct'] == 50.0
    lines = mem_sec(1)[:-2] + ['Swap       4858572       4858572       6104084', DASH]
    _n, store, _w = parse(lines)
    assert store['samples'][('memory', ms(1))]['swap_total'] == 6104084
    view = evaluate_mp_monitor(store)
    assert view['memory']['swap_used_pct'] == [round((6104084 - 4858572) / 6104084 * 100, 2)]
    view = view_of(mem_sec(0, swap='UNKNOWN'))
    assert view['memory']['swap_used_pct'] == [None]


def test_mem_row_without_total_or_available_is_discarded():
    lines = [f'{stamp()}  --- memory', 'Type  Free (kB)  Total (kB)  MemAvailable (kB)',
             'Mem   5  1000', DASH]
    n, store, _w = parse(lines)
    assert n == 0 and not store['samples'] and store['counters']['bad_rows'] == 1
    view = evaluate_mp_monitor(store)
    assert view['memory']['summary'] is None and view['warnings']


def test_processes_mapped_by_header_with_empty_lazy_column():
    lines = proc_sec(0, [prow('brdagent', 0, 6324),
                         prow('configd', 6, 1759116) + ' 858624',
                         prow('worker_x', 3, 5, state='Unk')])
    n, store, _w = parse(lines)
    rows = store['samples'][('processes', ms())]['rows']
    assert n == 1 and len(rows) == 3
    assert rows[1] == ('configd', 100, 6, 1759116, 'S')
    assert rows[2][4] == 'Unk'


def test_short_rows_are_discarded_and_counted():
    lines = proc_sec(0, [prow('a', 1), 'bad 12 3', prow('b', 2), 'x y z 1 2 3',
                         'c 5 notnum 1 2 3 S'])
    _n, store, _w = parse(lines)
    assert [r[0] for r in store['samples'][('processes', ms())]['rows']] == ['a', 'b']
    assert store['counters']['bad_rows'] == 3
    view = evaluate_mp_monitor(store)
    assert view['discarded']['bad_rows'] == 3 and view['warnings']


def test_unknown_values_are_kept_as_none_not_discarded():
    row = 'grep                   41010    Unknown 0          Unknown      Unknown      Unk'
    lines = (proc_sec(0, [row, prow('configd', 10, 500)]) + proc_sec(1, [prow('configd', 10, 700)]))
    _n, store, _w = parse(lines)
    assert store['samples'][('processes', ms())]['rows'][0] == ('grep', 41010, None, None, 'Unk')
    assert store['counters']['bad_rows'] == 0 and store['counters']['unknown_values'] == 2
    view = evaluate_mp_monitor(store)
    g = next(p for p in view['procs'] if p['name'] == 'grep')
    assert g['peak_cpu'] is None and g['peak_rss'] is None and g['growth'] == 0
    assert g['n'] == 1 and 'grep' not in view['top_growth']
    assert next(p for p in view['procs'] if p['name'] == 'configd')['growth'] == 200
    assert any('Unknown' in w for w in view['warnings'])
    json.dumps(view)


def test_totals_row_is_skipped_without_counting():
    totals = 'Totals                         1279  5350       5034055516   431514448               428966760'
    _n, store, _w = parse(proc_sec(0, [prow('a', 1), totals]))
    assert [r[0] for r in store['samples'][('processes', ms())]['rows']] == ['a']
    assert store['counters']['bad_rows'] == 0


def test_truncated_names_keep_the_plus():
    view = view_of(proc_sec(0, [prow('pan_logdb+', 3), prow('devicetel+', 1)]))
    assert {p['name'] for p in view['procs']} == {'pan_logdb+', 'devicetel+'}


def test_other_sections_are_ignored_and_dashes_end_a_section():
    lines = ([f'{stamp()}  --- cpu', 'Cpu(s): 3%us', DASH] + mem_sec(0)
             + ['Mem        1  2  3  4', f'{stamp(1)}  --- top_summary', 'x', DASH])
    n, store, _w = parse(lines)
    assert n == 1 and list(store['samples']) == [('memory', ms())]


def test_unparseable_header_ignores_following_data():
    bad = ['2026-13-45 99:99:99.000 +0000  --- memory'] + mem_sec(0)[1:]
    n, store, w = parse(bad)
    assert n == 0 and not store['samples'] and w


def test_offset_conversion_uses_the_header_offset():
    # 01:00:00 -0700 is 08:00:00 UTC; 10:00:00 +0200 is 08:00:00 UTC as well.
    a = mem_sec(0, off='-0700')
    a[0] = '2026-10-27 01:00:00.000 -0700  --- memory'
    b = mem_sec(1, off='+0200')
    b[0] = '2026-10-27 10:01:00.000 +0200  --- memory'
    _n, store, _w = parse(a + b)
    assert sorted(t for _s, t in store['samples']) == [ms(0), ms(1)]
    assert store['offsets'] == {'-0700', '+0200'}


def test_rotation_dedup_first_wins_and_order(tmp_path):
    d = tmp_path / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    old = mem_sec(0, avail=500) + mem_sec(1, avail=500)
    cur = mem_sec(1, avail=100) + mem_sec(2, avail=100)     # overlaps at minute 1
    (d / 'mp-monitor.log.1').write_text('\n'.join(old) + '\n', encoding='utf-8')
    (d / 'mp-monitor.log').write_text('\n'.join(cur) + '\n', encoding='utf-8')
    col = analyzer.collect(str(tmp_path), [])
    samples = col.mp_data['samples']
    assert sorted(t for _s, t in samples) == [ms(0), ms(1), ms(2)]
    assert samples[('memory', ms(1))]['src'] == 'mp-monitor.log.1'
    assert samples[('memory', ms(1))]['avail'] == 500
    assert col.mp_data['counters']['duplicates'] == 1
    assert 'mp-monitor' in col.inventory.families


def test_rotation_order_is_oldest_first_with_four_rotations(tmp_path):
    d = tmp_path / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    # Same time in every file with a different value: the oldest (.4) must win.
    for suffix, avail in (('', 1), ('.1', 2), ('.2', 3), ('.3', 4), ('.4', 5)):
        (d / f'mp-monitor.log{suffix}').write_text('\n'.join(mem_sec(0, avail=avail)) + '\n',
                                                   encoding='utf-8')
    col = analyzer.collect(str(tmp_path), [])
    assert col.mp_data['samples'][('memory', ms())]['src'] == 'mp-monitor.log.4'


def test_collect_without_mp_monitor_has_no_mp_data():
    col = analyzer.collect(str(Path(__file__).parent / 'data' / 'dp_monitor_sample.log'), [])
    assert col.mp_data is None


def test_sample_file():
    n, store, w = parse(SAMPLE.read_text(encoding='utf-8').splitlines(), src='s.log')
    assert n == 6 and not w
    view = evaluate_mp_monitor(store)
    assert view['n_mem'] == 3 and view['n_proc'] == 3
    assert view['memory']['used_pct'] == [75.0, 76.25, 77.5]
    # 01:00:00.250 -0700 = 08:00:00.250 UTC.
    assert view['memory']['t'][0] == ms() + 250
    assert view['discarded']['bad_rows'] == 1
    assert 'pan_logdb+' in {p['name'] for p in view['procs']}
    assert codes(view) == ['MP_MEMORY', 'PROC_CPU', 'PROC_ZOMBIE']
    assert view['flagged'] == ['configd']


# --------------------------------------------------------------------------
# Memory flags
# --------------------------------------------------------------------------
@pytest.mark.parametrize('avail, expected', [
    (250, []),                       # 75.0 exactly: not flagged
    (249, ['MP_MEMORY']),            # 75.1
    (100, ['MP_MEMORY']),            # 90.0 exactly: warn, not crit
    (99, ['MP_MEMORY']),             # 90.1: crit
])
def test_mp_memory_boundaries(avail, expected):
    view = view_of(mem_sec(0, total=1000, avail=avail))
    assert codes(view) == expected
    if avail == 100:
        assert view['findings'][0]['level'] == 'warn'
    if avail == 99:
        assert view['findings'][0]['level'] == 'crit'


def test_mp_memory_uses_the_last_sample():
    view = view_of(mem_sec(0, avail=50) + mem_sec(1, avail=400))
    assert 'MP_MEMORY' not in codes(view)
    view = view_of(mem_sec(0, avail=400) + mem_sec(1, avail=200))
    f = view['findings'][0]
    assert f['code'] == 'MP_MEMORY' and f['level'] == 'warn' and '80%' in f['text']


def test_mp_memory_past_peak():
    view = view_of(mem_sec(0, avail=400) + mem_sec(1, avail=50) + mem_sec(2, avail=300))
    assert codes(view) == ['MP_MEMORY_PAST_PEAK']
    f = view['findings'][0]
    assert f['level'] == 'warn' and '95' in f['text'] and 'crossing 90%' in f['text']
    assert '2026-10-27 08:01:00 UTC' in f['text']
    # Last value exactly at the limit is "back at or below".
    view = view_of(mem_sec(0, avail=100) + mem_sec(1, avail=250))
    assert codes(view) == ['MP_MEMORY_PAST_PEAK']
    # Never together with MP_MEMORY.
    view = view_of(mem_sec(0, avail=50) + mem_sec(1, avail=60))
    assert codes(view) == ['MP_MEMORY']


def test_memory_threshold_override():
    view = view_of(mem_sec(0, avail=400), mem_warn=50, mem_crit=55)
    assert view['findings'][0]['level'] == 'crit'
    with pytest.raises(ValueError):
        evaluate_mp_monitor(mp_monitor.new_store(), {'nope': 1})


# --------------------------------------------------------------------------
# PROC_CPU
# --------------------------------------------------------------------------
def test_single_spike_is_not_flagged():
    view = view_of(proc_series('daemon', [5, 100, 5, 4]))
    assert codes(view) == []
    p = next(p for p in view['procs'] if p['name'] == 'daemon')
    assert p['peak_cpu'] == 100 and p['n_high'] == 1 and p['longest_run'] == 1


def test_two_consecutive_samples_flag_at_the_boundary():
    view = view_of(proc_series('daemon', [5, 80, 80, 5]))      # >= 80 counts
    assert codes(view) == ['PROC_CPU']
    f = view['findings'][0]
    assert f['subject'] == 'daemon' and f['level'] == 'warn'
    assert '2 consecutive samples' in f['text'] and 'peak 80%' in f['text']
    assert '2026-10-27 08:01:00 UTC to 2026-10-27 08:02:00 UTC' in f['text']
    assert '1 run(s)' in f['text']
    assert codes(view_of(proc_series('daemon', [79, 79, 79]))) == []


def test_run_needs_consecutive_samples_not_just_two_spikes():
    assert codes(view_of(proc_series('daemon', [90, 5, 90, 5, 90]))) == []


def test_process_missing_from_a_sample_breaks_the_run():
    assert codes(view_of(proc_series('daemon', [90, None, 90]))) == []


def test_longest_run_and_number_of_runs():
    cpus = [90, 90, 5, 90, 90, 90, 5, 90]
    view = view_of(proc_series('daemon', cpus))
    p = next(p for p in view['procs'] if p['name'] == 'daemon')
    assert p['longest_run'] == 3 and p['n_runs'] == 2 and p['n_high'] == 6
    assert p['run_start'] == ms(3) and p['run_end'] == ms(5)
    assert '3 consecutive samples' in view['findings'][0]['text']
    assert '2 run(s)' in view['findings'][0]['text']


def test_large_gap_breaks_a_run():
    lines = []
    for minute in (0, 1, 2, 3, 10, 11):          # median interval 1 min; gap 7 min > 2 x
        lines += proc_sec(minute, [prow('daemon', 95 if minute in (3, 10) else 0)])
    view = view_of(lines)
    assert codes(view) == []                      # 3 and 10 are adjacent samples but 7 min apart
    # A gap of exactly 2 x the median does not break the run.
    lines = []
    for minute in (0, 1, 2, 4, 5):
        lines += proc_sec(minute, [prow('daemon', 95 if minute in (2, 4) else 0)])
    assert codes(view_of(lines)) == ['PROC_CPU']
    # The factor is tunable.
    assert codes(view_of(lines, proc_cpu_gap_factor=1.5)) == []


def test_min_samples_and_warn_overrides():
    cpus = [90, 90, 90]
    assert codes(view_of(proc_series('d', cpus), proc_cpu_min_samples=4)) == []
    assert codes(view_of(proc_series('d', cpus), proc_cpu_min_samples=1)) == ['PROC_CPU']
    assert codes(view_of(proc_series('d', cpus), proc_cpu_warn=95)) == []


@pytest.mark.parametrize('name', ['pan_task_3', 'all_task_1', 'pan_task_9+', 'grep', 'ps', 'top',
                                  'sh', 'bash', 'awk', 'sed', 'cat'])
def test_workers_and_short_lived_commands_are_never_flagged(name):
    view = view_of(proc_series(name, [99, 99, 99, 99]))
    assert codes(view) == [] and view['flagged'] == []
    p = next(p for p in view['procs'] if p['name'] == name)         # still in the tables
    assert p['peak_cpu'] == 99 and p['ignored'] in ('worker', 'command')


def test_similar_names_are_not_ignored():
    view = view_of(proc_series('grepper', [99, 99]))
    assert codes(view) == ['PROC_CPU']


def test_one_flag_per_process_ordered_by_longest_run():
    lines = []
    for i in range(4):
        lines += proc_sec(i, [prow('aa', 90), prow('bb', 90 if i < 2 else 0, pid=2),
                              prow('cc', 99 if i > 1 else 0, pid=3)])
    view = view_of(lines)
    assert [f['subject'] for f in view['findings']] == ['aa', 'cc', 'bb']     # longest run, then peak


# --------------------------------------------------------------------------
# Zombies, memory per process
# --------------------------------------------------------------------------
def test_zombie_info_does_not_raise_the_status():
    lines = proc_sec(0, [prow('dead', 0, 0, 'Z'), prow('ok', 1)]) \
        + proc_sec(1, [prow('dead', 0, 0, 'Z'), prow('ok2', 1, state='Unk')])
    view = view_of(lines)
    assert codes(view) == ['PROC_ZOMBIE']
    f = view['findings'][0]
    assert f['level'] == 'info' and 'dead (2 sample(s))' in f['text']
    assert 'In the last sample: dead' in f['text']
    assert view['zombies'] == {'dead': 2}
    fl = findings.from_flags(view['findings'])
    assert findings.module_status(fl, True) == findings.OK
    # Other states are not anomalies.
    rows = [prow(f'p{i}', 1, state=s) for i, s in enumerate('SRDI')] + [prow('u', 1, state='Unk')]
    assert codes(view_of(proc_sec(0, rows))) == []


def test_top_processes_by_peak_and_growth():
    lines = []
    for i in range(3):
        lines += proc_sec(i, [prow('big', 1, 5000 + 10 * i, pid=1),
                              prow('grows', 1, 100 + 400 * i, pid=2),
                              prow('shrinks', 1, 900 - 100 * i, pid=3),
                              prow('flat', 1, 50, pid=4)])
    view = view_of(lines)
    assert view['top_rss'][:2] == ['big', 'grows'] and view['top_rss'][-1] == 'flat'
    assert view['top_growth'] == ['grows', 'big']          # only positive growth
    p = next(p for p in view['procs'] if p['name'] == 'grows')
    assert p['first_rss'] == 100 and p['last_rss'] == 900 and p['growth'] == 800
    assert p['peak_rss'] == 900 and p['peak_rss_t'] == ms(2)


def test_top_lists_are_limited_to_ten():
    rows = [prow(f'proc{i:02d}', i, 1000 + i, pid=i + 1) for i in range(15)]
    view = view_of(proc_sec(0, rows) + proc_sec(1, [prow(f'proc{i:02d}', i, 2000 + i, pid=i + 1)
                                                    for i in range(15)]))
    assert len(view['top_rss']) == len(view['top_cpu']) == len(view['top_growth']) == 10
    assert view['top_cpu'][0] == 'proc14'


def test_same_name_with_several_pids_is_combined():
    view = view_of(proc_sec(0, [prow('python', 10, 100, pid=1), prow('python', 40, 300, pid=2)]))
    p = view['procs'][0]
    assert p['peak_cpu'] == 40 and p['peak_rss'] == 400


# --------------------------------------------------------------------------
# View, findings, coverage
# --------------------------------------------------------------------------
def test_view_is_json_serializable_and_works_with_findings():
    _n, store, _w = parse(SAMPLE.read_text(encoding='utf-8').splitlines())
    view = evaluate_mp_monitor(store)
    assert json.loads(json.dumps(view)) == view
    fl = findings.from_flags(view['findings'])
    assert [f.level for f in fl] == ['warning', 'warning', 'info']
    assert findings.module_status(fl, True) == findings.WARNING
    assert view['period'] == {'first': ms(0) + 87, 'last': ms(2) + 250}
    assert view['interval_s'] == 60.0
    assert set(view['thresholds']) == set(MP_THRESHOLDS)


def test_evaluation_does_not_modify_the_store():
    _n, store, _w = parse(SAMPLE.read_text(encoding='utf-8').splitlines())
    before = repr(sorted(store['samples'].items()))
    evaluate_mp_monitor(store)
    assert repr(sorted(store['samples'].items())) == before


def test_coverage_lists_mp_monitor_with_time_range(tmp_path):
    from panos_toolbox.tsf.coverage import build_coverage
    d = tmp_path / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    (d / 'mp-monitor.log').write_text('\n'.join(mem_sec(0) + mem_sec(5)) + '\n', encoding='utf-8')
    col = analyzer.collect(str(tmp_path), [])
    fams = {f['family']: f for f in build_coverage(col)['families']}
    assert fams['dp-monitor']['states'] == ['absent']
    mp = fams['mp-monitor']
    assert mp['states'] == ['ok'] and mp['samples'] == 2
    assert (mp['first'], mp['last']) == (ms(0), ms(5))
    assert mp['members'][0]['samples'] == 2


def test_coverage_marks_mp_monitor_absent():
    from panos_toolbox.tsf.coverage import build_coverage
    col = analyzer.collect(str(Path(__file__).parent / 'data'), [])
    # a directory without var/log/pan: archive-like input, family absent
    fams = {f['family']: f for f in build_coverage(col)['families']}
    assert fams['mp-monitor']['states'] == ['absent']


# --------------------------------------------------------------------------
# Integration: main(), report
# --------------------------------------------------------------------------
def run_main(tmp_path, *argv):
    out = tmp_path / 'out'
    analyzer.main([str(SAMPLE), '-o', str(out), *argv])
    files = list(out.glob('*.html'))
    assert len(files) == 1
    return files[0], files[0].read_text(encoding='utf-8')


def report_data(html_text):
    m = re.search(r'const D = (\{.*?\});\nconst \$', html_text, re.DOTALL)
    return json.loads(m.group(1).replace('<\\/', '</'))


def test_single_mp_file_gives_mp_report_with_suffix(tmp_path):
    path, out = run_main(tmp_path)
    assert path.name.endswith('_mp.html')
    assert 'id="tab-mp"' in out and 'id="p-mp"' in out and '>Management plane<' in out
    for sid in ('mp', 'mpflags', 'mpchart', 'mpprocs'):
        assert f'id="help-{sid}" hidden' in out
    assert '__HB_' not in out and '__HP_' not in out
    data = report_data(out)
    assert data['mp']['n_mem'] == 3 and data['kind'] == 'TSF analysis'
    assert [f['code'] for f in data['mp']['findings']] == ['MP_MEMORY', 'PROC_CPU', 'PROC_ZOMBIE']
    for code in FLAG_CODES:
        assert f'<code>{code}</code>' in out
    assert 'mem_warn = 75%' in out and 'proc_cpu_min_samples = 2' in out
    assert '-0700' in data['offsets']


def test_archive_report_has_the_tab(tmp_path):
    d = tmp_path / 'tsf' / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    (d / 'mp-monitor.log').write_text(SAMPLE.read_text(encoding='utf-8'), encoding='utf-8')
    analyzer.main([str(tmp_path / 'tsf'), '-o', str(tmp_path / 'out')])
    out = (tmp_path / 'out' / 'tsf_mp.html').read_text(encoding='utf-8')
    assert report_data(out)['mp']['n_proc'] == 3
    assert report_data(out)['coverage']['families'][1]['family'] == 'mp-monitor'


def test_report_without_mp_data_has_no_mp_view():
    out = analyzer.render_report('t', [], [], set(), [], 0, analyzer.TEMPLATE)
    assert '"mp":null' in out


def test_cli_thresholds_reach_the_view_and_the_help(tmp_path):
    _p, out = run_main(tmp_path, '--mp-mem-warn', '80', '--mp-mem-crit', '95',
                       '--mp-proc-cpu-warn', '91', '--mp-proc-cpu-min-samples', '3',
                       '--mp-proc-cpu-gap-factor', '2.5')
    data = report_data(out)
    th = data['mp']['thresholds']
    assert th['mem_warn'] == 80 and th['mem_crit'] == 95 and th['proc_cpu_warn'] == 91
    assert th['proc_cpu_min_samples'] == 3 and th['proc_cpu_gap_factor'] == 2.5
    assert [f['code'] for f in data['mp']['findings']] == ['PROC_ZOMBIE']
    assert 'mem_warn = 80%' in out and 'mem_warn = 75%' not in out
    assert 'proc_cpu_gap_factor = 2.5' in out


def test_cli_rejects_negative_mp_threshold(tmp_path):
    with pytest.raises(SystemExit):
        analyzer.main([str(SAMPLE), '-o', str(tmp_path), '--mp-mem-warn', '-1'])


def test_every_mp_option_exists():
    ap_help = subprocess.run(
        [sys.executable, '-m', 'panos_toolbox.tsf.analyzer', '--help'], check=False,
        capture_output=True, text=True).stdout
    for key in MP_THRESHOLDS:
        assert '--mp-' + key.replace('_', '-') in ap_help


def test_defaults():
    assert MP_THRESHOLDS == {'mem_warn': 75, 'mem_crit': 90, 'proc_cpu_warn': 80,
                             'proc_cpu_min_samples': 2, 'proc_cpu_gap_factor': 2}


@pytest.mark.skipif(shutil.which('node') is None, reason='node not available')
def test_generated_javascript_is_valid(tmp_path):
    _p, out = run_main(tmp_path)
    scripts = re.findall(r'<script>(.*?)</script>', out, re.DOTALL)
    js = tmp_path / 'report.js'
    js.write_text(scripts[-1], encoding='utf-8')
    res = subprocess.run(['node', '--check', str(js)], check=False, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr

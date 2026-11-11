"""Tests for tsf/dp_health.py and the Dataplane health tab of the report.

Synthetic data only (no real TSF content); no device is contacted.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer, dp_health, findings
from panos_toolbox.tsf.dp_health import DP_THRESHOLDS, evaluate_dp_health, parse_dp_health

SAMPLE = Path(__file__).parent / 'data' / 'dp_monitor_health_sample.log'
OLD_SAMPLE = Path(__file__).parent / 'data' / 'dp_monitor_sample.log'

# Local times are +0100: 08:20:20 local = 07:20:20 UTC.
T_A = 1793085620000 + 485     # 2026-10-27 08:20:20.485 +0100
T_B = T_A + 600000
T_B_SAMPLE = 1793086220512     # 08:30:20.512 +0100, the second section of the sample file


def hdr(ts='2026-10-27 08:20:20.485', section='panio'):
    return f'{ts} +0100  --- {section}'


def cpu_s(cols, rows, prefix=':'):
    """Per-second CPU table: header with the core numbers plus the given value rows."""
    out = [prefix + 'core' + ''.join(f'{c:4d}' for c in cols)]
    for r in rows:
        out.append(prefix + '    ' + ''.join(f'{v:>4}' for v in r))
    return out


def cpu_m(cols, rows):
    """Per-minute CPU table: rows are lists of (avg, max) per core."""
    out = [':core    ' + ''.join(f'{c:<8d}' for c in cols), ':     ' + 'avg max ' * len(cols)]
    for r in rows:
        out.append(':    ' + ''.join(f'{a:>4}{m:>4}' for a, m in r))
    return out


def util(name, vals):
    return [f':{name}:', ':' + ''.join(f'{v:4d}' for v in vals) + ' ', ':']


def res_block(*, sess=1, pb=4, pd=0, cores=4, cpu=1, spike=None, extra_s=None, extra_m=None,
              dp_line=None):
    """One resource monitor block. sess/pb/pd are ints (15 equal values) or lists."""
    def v15(x):
        return list(x) if isinstance(x, (list, tuple)) else [x] * 15
    cols = list(range(cores))
    rows = []
    for i in range(15):
        row = [cpu] * cores
        if spike and i == 5:
            row[spike[0]] = spike[1]
        rows.append(row)
    out = []
    if dp_line:
        out.append(dp_line)
    out += [':Resource monitoring sampling data (per second):', ':', ':CPU load (%) during last 15 seconds: ']
    out += extra_s if extra_s is not None else cpu_s(cols, rows)
    out += [':', ':Resource utilization (%) during last 15 seconds: ']
    out += util('session', v15(sess)) + util('packet buffer', v15(pb))
    out += util('packet descriptor', v15(pd))
    out += [':Resource monitoring statistics (per minute):', ':CPU load (%) during last 15 minutes: ']
    mrows = [[(cpu, cpu)] * cores for _ in range(15)]
    out += extra_m if extra_m is not None else cpu_m(cols, mrows)
    out += [':Resource utilization (%) during last 15 minutes: ']
    out += util('session (average)', v15(sess)) + util('session (maximum)', v15(sess))
    return out


def target(dp='*.dp0', util_pct=7):
    return [f':target-dp:                                       {dp}',
            ':----------------------------------------------------------------',
            ':Number of allocated sessions:                    100',
            f':Session table utilization:                       {util_pct}%',
            ':Packet rate:                                     10/s',
            ':Throughput:                                      100 kbps']


def section(ts, blocks, targets, name='panio'):
    out = [hdr(ts, name), 'pan_comm message statistics', '  URL_REPLY   1 2 3', '', ':']
    for b in blocks:
        out += b + [':']
    for t in targets:
        out += t
    return out


def parse(lines, src='f.log', store=None):
    store = store if store is not None else dp_health.new_store()
    warnings = []
    n = parse_dp_health([ln + '\n' for ln in lines], src, store, warnings)
    return n, store, warnings


def sample_of(store, dp='dp0', t=T_A):
    return store['samples'][(dp, t)]


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def test_sample_file_per_second_and_per_minute():
    store, warnings = dp_health.new_store(), []
    n = parse_dp_health(SAMPLE.open(encoding='utf-8'), 's.log', store, warnings)
    assert n == 2 and not warnings
    a, b = sample_of(store, t=T_A), sample_of(store, t=T_B_SAMPLE)
    assert a['sess'] == 1 and a['util_tdp'] == 1 and a['pb_max'] == 5 and a['pb_avg'] == 4.5
    assert a['pd_max'] == 0 and a['pdc_max'] == 5
    assert sorted(a['core_s']) == list(range(8)) and sorted(a['core_m']) == list(range(8))
    assert b['sess'] == 75 and b['pb_max'] == 55
    assert b['core_s'][5] == 95 and b['core_m'][5] == 95
    assert b['sess_m'] == 75 and b['pb_m'] is not None
    c = store['counters']
    assert c['asterisks'] == 1 and c['bad_rows'] == 1 and c['out_of_range'] == 0
    assert c['samples_parsed'] == 2


def test_only_panio_sections_are_read():
    lines = section('2026-10-27 08:20:20.485', [res_block()], [target()], name='panio_infreq')
    n, store, _w = parse(lines)
    assert n == 0 and not store['samples']
    n, store, _w = parse(section('2026-10-27 08:20:20.485', [res_block()], [target()]))
    assert n == 1 and (('dp0', T_A) in store['samples'])


def test_split_core_blocks_are_merged_32_cores():
    def rows(base):
        return [[base + c for c in range(16)] for _ in range(15)]
    s_lines = cpu_s(range(16), rows(0)) + cpu_s(range(16, 32), rows(16))
    m_lines = []
    for first in range(0, 32, 8):
        cols = list(range(first, first + 8))
        m_lines += cpu_m(cols, [[(c, c + 2) for c in cols]] * 15)
    block = res_block(extra_s=s_lines, extra_m=m_lines)
    n, store, w = parse(section('2026-10-27 08:20:20.485', [block], [target()]))
    rec = sample_of(store)
    assert n == 1 and not w
    assert sorted(rec['core_s']) == list(range(32))
    assert rec['core_s'][0] == 0 and rec['core_s'][16] == 16 and rec['core_s'][31] == 31
    assert sorted(rec['core_m']) == list(range(32))
    assert rec['core_m'][9] == 11 and rec['core_m'][31] == 33
    view = evaluate_dp_health(store)
    assert view['cores']['dp0']['ids'] == list(range(32))
    assert view['summary']['dp0']['core']['peak_core'] == 31


def test_asterisk_is_none_not_zero():
    # Core 1 is '*' in every row: it must be absent, not 0. Core 2 is '*' in some rows.
    rows = [[5, '*', '*', 3] if i % 2 else [5, '*', 9, 3] for i in range(15)]
    block = res_block(extra_s=cpu_s(range(4), rows))
    _n, store, w = parse(section('2026-10-27 08:20:20.485', [block], [target()]))
    rec = sample_of(store)
    assert 1 not in rec['core_s'] and rec['core_s'][2] == 9 and rec['core_s'][0] == 5
    assert store['counters']['asterisks'] == 15 + 7 and not w


def test_asterisk_in_a_column_that_is_all_missing_still_gives_other_cores():
    rows = [['*', '*', '*', '*']] * 15
    block = res_block(extra_s=cpu_s(range(4), rows))
    _n, store, _w = parse(section('2026-10-27 08:20:20.485', [block], [target()]))
    rec = sample_of(store)
    assert rec['core_s'] == {} and rec['core_m'] != {}
    view = evaluate_dp_health(store)
    # falls back to the per-minute maximum for the busiest core
    assert view['series']['dp0']['core_max'] == [1]


def test_out_of_range_values_are_discarded_and_counted():
    rows = [[5, 101, 100, 3]] + [[5, 2, 100, 3]] * 14
    block = res_block(extra_s=cpu_s(range(4), rows))
    _n, store, _w = parse(section('2026-10-27 08:20:20.485', [block], [target()]))
    rec = sample_of(store)
    assert rec['core_s'][1] == 2 and rec['core_s'][2] == 100
    assert store['counters']['out_of_range'] == 1


def test_resource_values_out_of_range_are_discarded():
    block = res_block(sess=[250] + [3] * 14)
    _n, store, _w = parse(section('2026-10-27 08:20:20.485', [block], [target()]))
    assert sample_of(store)['sess'] == 3
    assert store['counters']['out_of_range'] >= 1      # also seen in the per-minute copy


def test_wrong_column_rows_are_discarded_and_counted():
    rows = [[5, 4, 3, 2]] * 14 + [[99, 99, 99]]            # short row
    rows[3] = [1, 2, 3, 4, 5]                             # long row
    block = res_block(extra_s=cpu_s(range(4), rows))
    _n, store, _w = parse(section('2026-10-27 08:20:20.485', [block], [target()]))
    rec = sample_of(store)
    assert store['counters']['bad_rows'] == 2
    assert rec['core_s'] == {0: 5, 1: 4, 2: 3, 3: 2}      # the 99s of the bad row are not used


def test_garbled_row_is_counted_and_does_not_stop_the_table():
    s_lines = cpu_s(range(4), [[1, 1, 1, 1]] * 3) + [':    1   x   1   1'] + \
        cpu_s(range(4), [])[1:] + [':    7   7   7   7']
    block = res_block(extra_s=s_lines)
    _n, store, _w = parse(section('2026-10-27 08:20:20.485', [block], [target()]))
    assert store['counters']['bad_rows'] == 1 and sample_of(store)['core_s'][0] == 7


def test_per_minute_table_without_avg_max_line_is_discarded():
    m_lines = [':core    0       1       2       3', ':       1   2   1   2   1   2   1   2']
    block = res_block(extra_m=m_lines)
    _n, store, _w = parse(section('2026-10-27 08:20:20.485', [block], [target()]))
    assert sample_of(store)['core_m'] == {} and store['counters']['bad_rows'] == 1


def test_binding_to_target_dp_single():
    n, store, w = parse(section('2026-10-27 08:20:20.485', [res_block(sess=11)],
                                [target('s1.dp1', 9)]))
    assert n == 1 and not w
    rec = sample_of(store, dp='s1.dp1')
    assert rec['sess'] == 11 and rec['util_tdp'] == 9


def test_multi_dp_binding_by_order_warns_once():
    lines = section('2026-10-27 08:20:20.485', [res_block(sess=11), res_block(sess=22)],
                    [target('*.dp0', 5), target('*.dp1', 6)])
    lines += section('2026-10-27 08:30:20.485', [res_block(sess=33), res_block(sess=44)],
                     [target('*.dp0', 5), target('*.dp1', 6)])
    n, store, w = parse(lines)
    assert n == 4
    assert sample_of(store, 'dp0')['sess'] == 11 and sample_of(store, 'dp1')['sess'] == 22
    assert store['samples'][('dp1', T_A + 600000)]['sess'] == 44
    assert len([x for x in w if 'by order of appearance' in x]) == 1
    view = evaluate_dp_health(store)
    assert view['dps'] == ['dp0', 'dp1']
    assert view['series']['dp0']['sess'] == [11, 33] and view['series']['dp1']['sess'] == [22, 44]


def test_block_dp_count_mismatch_binds_nothing_and_warns_once():
    lines = []
    for ts in ('2026-10-27 08:20:20.485', '2026-10-27 08:30:20.485'):
        lines += section(ts, [res_block(sess=11), res_block(sess=22)], [target('*.dp0', 5)])
    n, store, w = parse(lines)
    mism = [x for x in w if 'cannot bind' in x]
    assert len(mism) == 1 and '2 dataplane resource blocks and 1 DPs' in mism[0]
    # No resource data is attributed, but the Session table utilization is still known.
    rec = sample_of(store)
    assert rec['sess'] is None and rec['core_s'] == {} and rec['util_tdp'] == 5
    assert n == 2


def test_explicit_dp_header_binds_block():
    lines = section('2026-10-27 08:20:20.485',
                    [res_block(sess=11, dp_line=':DP dp1:'), res_block(sess=22, dp_line='DP dp0:')],
                    [target('*.dp0', 5), target('*.dp1', 6)])
    _n, store, w = parse(lines)
    assert sample_of(store, 'dp1')['sess'] == 11 and sample_of(store, 'dp0')['sess'] == 22
    assert not w


def test_fallback_to_session_table_utilization():
    lines = section('2026-10-27 08:20:20.485', [], [target('*.dp0', 42)])
    n, store, w = parse(lines)
    assert n == 1 and not w
    view = evaluate_dp_health(store)
    ser = view['series']['dp0']
    assert ser['sess'] == [42] and ser['sess_src'] == ['tdp']
    assert any('Session table utilization' in x for x in view['warnings'])
    assert any('no CPU load per core' in x for x in view['warnings'])
    # Per-second block wins when it exists.
    lines = section('2026-10-27 08:20:20.485', [res_block(sess=[3] * 14 + [8])], [target('*.dp0', 42)])
    _n, store, _w = parse(lines)
    ser = evaluate_dp_health(store)['series']['dp0']
    assert ser['sess'] == [8] and ser['sess_src'] == ['res']


def test_dedup_first_wins_across_rotations():
    a = section('2026-10-27 08:20:20.485', [res_block(sess=11)], [target('*.dp0', 5)])
    b = section('2026-10-27 08:20:20.485', [res_block(sess=99)], [target('*.dp0', 5)])
    b += section('2026-10-27 08:30:20.485', [res_block(sess=22)], [target('*.dp0', 5)])
    store = dp_health.new_store()
    parse(a, 'old.log', store)
    n, _s, _w = parse(b, 'new.log', store)
    assert n == 2 and len(store['samples']) == 2
    assert sample_of(store)['sess'] == 11 and sample_of(store)['src'] == 'old.log'
    assert sample_of(store, t=T_B)['src'] == 'new.log'


def test_bad_header_ignores_following_data():
    lines = ['2026-13-45 99:99:99.000 +0100  --- panio'] + res_block() + target()
    n, store, _w = parse(lines)
    assert n == 0 and not store['samples']


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def view_for(*samples, thresholds=None):
    """samples: (ts, kwargs for res_block); one DP."""
    lines = []
    for ts, kw in samples:
        lines += section(ts, [res_block(**kw)], [target('*.dp0', 1)])
    _n, store, _w = parse(lines)
    return evaluate_dp_health(store, thresholds)


def codes(view):
    return {f['code']: f for f in view['findings']}


@pytest.mark.parametrize('sess,expected', [(69, None), (70, 'warn'), (89, 'warn'),
                                           (90, 'crit'), (100, 'crit')])
def test_session_util_levels(sess, expected):
    v = view_for(('2026-10-27 08:20:20.485', {'sess': sess}))
    fl = codes(v).get('SESSION_UTIL')
    assert (fl['level'] if fl else None) == expected


@pytest.mark.parametrize('pb,expected', [(49, None), (50, 'warn'), (79, 'warn'),
                                         (80, 'crit'), (95, 'crit')])
def test_packet_buffer_levels(pb, expected):
    v = view_for(('2026-10-27 08:20:20.485', {'pb': pb}))
    fl = codes(v).get('PKT_BUFFER')
    assert (fl['level'] if fl else None) == expected


@pytest.mark.parametrize('peak,expected', [(89, None), (90, 'warn'), (100, 'warn')])
def test_core_peak_levels(peak, expected):
    v = view_for(('2026-10-27 08:20:20.485', {'cores': 6, 'spike': (4, peak)}))
    fl = codes(v).get('CORE_PEAK')
    assert (fl['level'] if fl else None) == expected
    if fl:
        assert 'DP dp0' in fl['text'] and 'core 4' in fl['text'] and fl['dp'] == 'dp0'


def test_core_peak_names_every_hot_core():
    rows = [[95, 10, 92, 10]] + [[10, 10, 10, 10]] * 14
    block = res_block(extra_s=cpu_s(range(4), rows))
    _n, store, _w = parse(section('2026-10-27 08:20:20.485', [block], [target()]))
    fl = codes(evaluate_dp_health(store))['CORE_PEAK']
    assert '0 (95%)' in fl['text'] and '2 (92%)' in fl['text'] and '1 (' not in fl['text']


def test_no_flags_on_a_healthy_device():
    v = view_for(('2026-10-27 08:20:20.485', {}))
    assert v['findings'] == [] and v['n_samples'] == 1


def test_peak_versus_last_in_the_flag_text():
    v = view_for(('2026-10-27 08:20:20.485', {'sess': 80}),
                 ('2026-10-27 08:30:20.485', {'sess': 20}),
                 ('2026-10-27 08:40:20.485', {'sess': 75}),
                 ('2026-10-27 08:50:20.485', {'sess': 10}))
    fl = codes(v)['SESSION_UTIL']
    assert fl['level'] == 'warn'                       # level comes from the peak
    assert 'peaked at 80% on 2026-10-27 07:20:20 UTC' in fl['text']
    assert 'last sample 10% (2026-10-27 07:50:20 UTC)' in fl['text']
    assert '2 of 4 samples at or above 70%' in fl['text']
    s = v['summary']['dp0']['session']
    assert (s['peak'], s['last'], s['over']['warn'], s['over']['crit']) == (80, 10, 2, 0)


def test_crit_counts_samples_at_the_crit_limit():
    v = view_for(('2026-10-27 08:20:20.485', {'pb': 90}), ('2026-10-27 08:30:20.485', {'pb': 85}),
                 ('2026-10-27 08:40:20.485', {'pb': 60}))
    fl = codes(v)['PKT_BUFFER']
    assert fl['level'] == 'crit' and '2 of 3 samples at or above 80%' in fl['text']


def test_packet_buffer_uses_max_of_the_window_and_series_has_avg_and_max():
    pb = [10] * 14 + [60]
    v = view_for(('2026-10-27 08:20:20.485', {'pb': pb}))
    ser = v['series']['dp0']
    assert ser['pb_max'] == [60] and ser['pb_avg'] == [13.3]
    assert 'PKT_BUFFER' in codes(v)


def test_thresholds_override_and_unknown_key():
    v = view_for(('2026-10-27 08:20:20.485', {'sess': 30}), thresholds={'session_util_warn': 25})
    assert codes(v)['SESSION_UTIL']['level'] == 'warn' and v['thresholds']['session_util_warn'] == 25
    v = view_for(('2026-10-27 08:20:20.485', {'sess': 30}),
                 thresholds={'session_util_warn': 10, 'session_util_crit': 30})
    assert codes(v)['SESSION_UTIL']['level'] == 'crit'
    with pytest.raises(ValueError):
        evaluate_dp_health(dp_health.new_store(), {'no_such_key': 1})


def test_defaults():
    assert DP_THRESHOLDS == {'session_util_warn': 70, 'session_util_crit': 90,
                             'pkt_buffer_warn': 50, 'pkt_buffer_crit': 80,
                             'core_peak_warn': 90}


def test_view_is_json_serializable_and_works_with_findings():
    store, warnings = dp_health.new_store(), []
    parse_dp_health(SAMPLE.open(encoding='utf-8'), 's.log', store, warnings)
    view = evaluate_dp_health(store)
    json.dumps(view)
    fs = findings.from_flags(view['findings'], scope='dp0')
    assert {f.code for f in fs} == {'SESSION_UTIL', 'PKT_BUFFER', 'CORE_PEAK'}
    assert {f.level for f in fs} == {findings.WARNING}
    assert set(view) >= {'thresholds', 'dps', 'series', 'summary', 'cores', 'findings',
                         'discarded', 'warnings', 'n_samples'}
    assert view['discarded']['asterisks'] == 1 and view['discarded']['bad_rows'] == 1
    assert any('wrong column count' in x for x in view['warnings'])
    ser = view['series']['dp0']
    assert len(ser['t']) == 2 and ser['t'] == sorted(ser['t'])
    assert ser['core_id'] == [ser['core_id'][0], 5]


def test_dps_are_evaluated_separately_never_summed():
    lines = section('2026-10-27 08:20:20.485', [res_block(sess=80), res_block(sess=10)],
                    [target('*.dp0', 5), target('*.dp1', 6)])
    _n, store, _w = parse(lines)
    v = evaluate_dp_health(store)
    assert [f['dp'] for f in v['findings'] if f['code'] == 'SESSION_UTIL'] == ['dp0']
    assert v['summary']['dp1']['session']['peak'] == 10 and 'ALL' not in v['dps']


# --------------------------------------------------------------------------
# Integration: collect(), main(), report
# --------------------------------------------------------------------------
def test_collect_feeds_dp_health_and_leaves_parse_lines_alone(tmp_path):
    d = tmp_path / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    (d / 'dp-monitor.log').write_text(SAMPLE.read_text(encoding='utf-8'), encoding='utf-8')
    warnings = []
    col = analyzer.collect(str(tmp_path), warnings)
    assert col.dp_health is not None and len(col.dp_health['samples']) == 2
    assert len(col.samples) == 2 and col.samples[0]['kbps'] == 6178
    assert set(col.samples[0]) == {'t', 'dp', 'src', 'kbps', 'pps', 'cps', 'sess', 'util', 'grp'}


def test_collect_without_resource_monitor_has_no_dp_health():
    col = analyzer.collect(str(OLD_SAMPLE), [])
    assert col.dp_health is None and col.samples


def test_collect_dedups_rotated_files_first_wins(tmp_path):
    d = tmp_path / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    old = SAMPLE.read_text(encoding='utf-8')
    (d / 'dp-monitor.log.1').write_text(old, encoding='utf-8')
    (d / 'dp-monitor.log').write_text(old.replace('Throughput:                                      6178', 'Throughput:                                      1'),
                                      encoding='utf-8')
    col = analyzer.collect(str(tmp_path), [])
    assert len(col.dp_health['samples']) == 2
    assert {r['src'] for r in col.dp_health['samples'].values()} == {'dp-monitor.log.1'}


def run_main(tmp_path, *argv):
    out = tmp_path / 'out'
    analyzer.main([str(SAMPLE), '-o', str(out), *argv])
    return next(out.glob('*.html')).read_text(encoding='utf-8')


def report_data(html_text):
    m = re.search(r'const D = (\{.*?\});\nconst \$', html_text, re.DOTALL)
    return json.loads(m.group(1).replace('<\\/', '</'))


def test_render_report_contains_the_tab_and_help(tmp_path):
    out = run_main(tmp_path)
    assert 'id="tab-dph"' in out and 'id="p-dph"' in out and '>Dataplane health<' in out
    for sid in ('dph', 'dphflags', 'dphchart', 'dphcores'):
        assert f'id="help-{sid}" hidden' in out
    assert '__HB_' not in out and '__HP_' not in out
    data = report_data(out)
    assert data['dph']['dps'] == ['dp0'] and data['dph']['n_samples'] == 2
    assert {f['code'] for f in data['dph']['findings']} == {'SESSION_UTIL', 'PKT_BUFFER', 'CORE_PEAK'}
    for code in dp_health.FLAG_CODES:
        assert f'<code>{code}</code>' in out
    assert 'session_util_warn = 70%' in out


def test_report_without_resource_monitor_has_no_dph_data():
    out = analyzer.render_report('t', [], [], set(), [], 0, analyzer.TEMPLATE)
    assert '"dph":null' in out


def test_cli_thresholds_reach_the_view_and_the_help(tmp_path):
    out = run_main(tmp_path, '--dp-session-util-warn', '95', '--dp-session-util-crit', '99',
                   '--dp-core-peak-warn', '50.5')
    data = report_data(out)
    th = data['dph']['thresholds']
    assert th['session_util_warn'] == 95 and th['core_peak_warn'] == 50.5
    assert 'SESSION_UTIL' not in {f['code'] for f in data['dph']['findings']}
    assert 'session_util_warn = 95%' in out and 'core_peak_warn = 50.5%' in out
    assert 'session_util_warn = 70%' not in out


def test_cli_rejects_negative_dp_threshold(tmp_path):
    with pytest.raises(SystemExit):
        analyzer.main([str(SAMPLE), '-o', str(tmp_path), '--dp-pkt-buffer-warn', '-1'])


def test_every_dp_option_exists():
    ap_help = subprocess.run(
        [sys.executable, '-m', 'panos_toolbox.tsf.analyzer', '--help'], check=False,
        capture_output=True, text=True).stdout
    for key in DP_THRESHOLDS:
        assert '--dp-' + key.replace('_', '-') in ap_help


@pytest.mark.skipif(shutil.which('node') is None, reason='node not available')
def test_generated_javascript_is_valid(tmp_path):
    out = run_main(tmp_path)
    scripts = re.findall(r'<script>(.*?)</script>', out, re.DOTALL)
    js = tmp_path / 'report.js'
    js.write_text(scripts[-1], encoding='utf-8')
    res = subprocess.run(['node', '--check', str(js)], check=False, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr

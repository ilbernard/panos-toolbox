"""Characterization tests for tsf/analyzer.py (Step 0 baseline).

These tests pin down the CURRENT behaviour of the data collection layer
(parse_header, parse_lines, collect, add_aggregate). They do not state what the
behaviour should be: where something looks odd, a comment says so.
"""
from __future__ import annotations

import io
import tarfile
from pathlib import Path

from panos_toolbox.tsf import analyzer

SAMPLE = Path(__file__).parent / 'data' / 'dp_monitor_sample.log'

T0 = 1793085620000          # 2026-10-27 07:20:20 UTC
T1 = T0 + 60000

W_ORDER = ('x: "CPU load by group" blocks bound to DPs by order of appearance '
           '(unverified)')
W_MISMATCH = ('x: 2 "CPU load by group" blocks and 1 DPs in the same section, '
              'cannot bind them: CPU groups skipped')
W_BADHDR = ('x:1: header with unparseable timestamp, following data ignored until '
            'the next valid header')
W_GZ = 'dp-monitor.log.1.gz: compressed file (.gz) not supported, skipped'


def hdr(ts='2026-10-27 08:20:20', off='+0100'):
    return f'{ts} {off} --- dp-monitor\n'


def run_parse(lines, src='f.log'):
    samples, seen, warnings, offsets = [], set(), [], set()
    n = analyzer.parse_lines(lines, src, samples, seen, warnings, offsets)
    return n, samples, seen, warnings, offsets


def make_tgz(path, members):
    with tarfile.open(path, 'w:gz') as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


# --------------------------------------------------------------------------
# parse_header
# --------------------------------------------------------------------------
def test_parse_header_valid_returns_utc_ms_offset_section():
    assert analyzer.parse_header('2026-10-27 08:20:20 +0100 --- dp-monitor') == (
        T0, '+0100', 'dp-monitor')


def test_parse_header_fraction_negative_offset():
    ms, off, sec = analyzer.parse_header('2026-10-27 08:20:20.5 -0530 --- dp-monitor')
    assert off == '-0530'
    assert sec == 'dp-monitor'
    # 08:20:20.5 at -05:30 is 13:50:20.5 UTC = T0 (07:20:20 UTC) + 6h30 + 500 ms
    assert ms == T0 + (6 * 60 + 30) * 60000 + 500


def test_parse_header_not_a_header_returns_none():
    assert analyzer.parse_header('Throughput: 10 kbps') is None
    assert analyzer.parse_header('2026-10-27 08:20:20 --- dp-monitor') is None


def test_parse_header_unreadable_timestamp_returns_none():
    # Month 13 matches the regex but datetime() raises ValueError -> None.
    assert analyzer.parse_header('2026-13-27 08:20:20 +0100 --- dp-monitor') is None


# --------------------------------------------------------------------------
# parse_lines
# --------------------------------------------------------------------------
def test_parse_lines_sample_file():
    with open(SAMPLE, encoding='utf-8') as fh:
        n, samples, seen, warnings, offsets = run_parse(fh, src='dp-monitor.log')
    assert n == 4
    assert warnings == []
    assert offsets == {'+0100'}
    assert seen == {('dp0', T0), ('dp1', T0), ('dp0', T1), ('dp1', T1)}
    assert [(s['dp'], s['t']) for s in samples] == [
        ('dp0', T0), ('dp1', T0), ('dp0', T1), ('dp1', T1)]
    first = samples[0]
    assert first == {
        't': T0, 'dp': 'dp0', 'src': 'dp-monitor.log', 'kbps': 1000, 'pps': 100,
        'cps': 10, 'sess': 500, 'util': 1,
        'grp': {'flow_lookup': 5, 'flow_fastpath': 10},
    }
    assert samples[1]['grp'] == {'flow_lookup': 7, 'flow_fastpath': 20}
    assert samples[1]['kbps'] == 3000
    # Second section has no CPU group block: no 'grp' key at all.
    assert 'grp' not in samples[2]
    assert samples[3]['kbps'] == 4000 and samples[3]['util'] == 4


def test_parse_lines_group_bound_by_order_adds_no_warning_for_single_dp():
    lines = [
        hdr(), 'target-dp: *.dp0\n', 'Throughput: 10 kbps\n',
        'CPU load sampling by group:\n', '  a : 1%\n',
    ]
    n, samples, _seen, warnings, _off = run_parse(lines)
    assert n == 1
    assert samples[0]['grp'] == {'a': 1}
    assert warnings == []


def test_parse_lines_group_before_target_dp_bound_by_order_warns():
    # Group blocks appear before the target-dp lines: dp is None at that time,
    # so they are bound by order of appearance, with a warning (2 DPs).
    lines = [
        hdr(),
        'CPU load sampling by group:\n', '  a : 1%\n',
        'CPU load sampling by group:\n', '  a : 2%\n',
        'target-dp: *.dp0\n', 'Throughput: 10 kbps\n',
        'target-dp: *.dp1\n', 'Throughput: 20 kbps\n',
    ]
    n, samples, _seen, warnings, _off = run_parse(lines, src='x')
    assert n == 2
    assert [s['grp'] for s in samples] == [{'a': 1}, {'a': 2}]
    assert warnings == [W_ORDER]


def test_parse_lines_group_count_mismatch_skips_groups_with_warning():
    lines = [
        hdr(),
        'CPU load sampling by group:\n', '  a : 1%\n',
        'CPU load sampling by group:\n', '  a : 2%\n',
        'target-dp: *.dp0\n', 'Throughput: 10 kbps\n',
    ]
    n, samples, _seen, warnings, _off = run_parse(lines, src='x')
    assert n == 1
    assert 'grp' not in samples[0]
    assert warnings == [W_MISMATCH]


def test_parse_lines_without_target_dp_uses_na():
    n, samples, _seen, _w, _o = run_parse([hdr(), 'Throughput: 10 kbps\n'])
    assert n == 1
    assert samples[0]['dp'] == 'n/a'


def test_parse_lines_duplicate_same_values_dropped_but_counted():
    body = [hdr(), 'target-dp: *.dp0\n', 'Throughput: 10 kbps\n']
    samples, seen, warnings, offsets = [], set(), [], set()
    n1 = analyzer.parse_lines(body, 'a', samples, seen, warnings, offsets)
    n2 = analyzer.parse_lines(body, 'b', samples, seen, warnings, offsets)
    # n_found counts duplicates, the sample list does not.
    assert (n1, n2) == (1, 1)
    assert len(samples) == 1
    assert samples[0]['src'] == 'a'
    assert warnings == []


def test_parse_lines_duplicate_different_values_first_wins_silently():
    first = [hdr(), 'target-dp: *.dp0\n', 'Throughput: 10 kbps\n']
    second = [hdr(), 'target-dp: *.dp0\n', 'Throughput: 99999 kbps\n']
    samples, seen, warnings, offsets = [], set(), [], set()
    analyzer.parse_lines(first, 'a', samples, seen, warnings, offsets)
    n2 = analyzer.parse_lines(second, 'b', samples, seen, warnings, offsets)
    assert n2 == 1
    assert [(s['src'], s['kbps']) for s in samples] == [('a', 10)]
    # Odd: the conflicting value is lost and no warning is emitted.
    assert warnings == []


def test_parse_lines_duplicate_within_same_file_also_dropped():
    lines = [hdr(), 'target-dp: *.dp0\n', 'Throughput: 10 kbps\n',
             hdr(), 'target-dp: *.dp0\n', 'Throughput: 20 kbps\n']
    n, samples, _seen, _w, _o = run_parse(lines)
    assert n == 2
    assert [s['kbps'] for s in samples] == [10]


def test_parse_lines_unparseable_timestamp_header_ignores_following_data():
    lines = [
        '2026-13-27 08:20:20 +0100 --- dp-monitor\n',
        'target-dp: *.dp0\n', 'Throughput: 10 kbps\n',
        hdr(), 'target-dp: *.dp0\n', 'Throughput: 20 kbps\n',
    ]
    n, samples, _seen, warnings, offsets = run_parse(lines, src='x')
    assert n == 1
    assert [s['kbps'] for s in samples] == [20]
    assert offsets == {'+0100'}
    # The loose header matches ('2026-13-27 08:20:20 +0100 --- ...'); the
    # Throughput after it has no valid timestamp.
    assert warnings == [W_BADHDR, 'x:3: Throughput without a valid timestamp, skipped']


def test_parse_lines_throughput_before_any_header_warns():
    n, samples, _seen, warnings, _o = run_parse(['Throughput: 10 kbps\n'], src='x')
    assert n == 0 and samples == []
    assert warnings == ['x:1: Throughput without a valid timestamp, skipped']


def test_parse_lines_unexpected_throughput_format_warns():
    lines = [hdr(), 'Throughput: fast\n']
    n, samples, _seen, warnings, _o = run_parse(lines, src='x')
    assert n == 0 and samples == []
    assert warnings == ["x:2: Throughput line in unexpected format: 'Throughput: fast'"]


def test_parse_lines_record_without_kbps_is_not_a_sample():
    lines = [hdr(), 'target-dp: *.dp0\n', 'Packet rate: 5 /s\n']
    n, samples, _seen, _w, _o = run_parse(lines)
    assert n == 0 and samples == []


def test_parse_lines_dp_label_keeps_non_wildcard_names():
    lines = [hdr(), 'target-dp: s1.dp1\n', 'Throughput: 10 kbps\n']
    _n, samples, _seen, _w, _o = run_parse(lines)
    assert samples[0]['dp'] == 's1.dp1'


def test_parse_lines_colon_prefixed_lines_and_crlf_accepted():
    lines = [hdr().replace('\n', '\r\n'), ': target-dp: *.dp0\r\n',
             ': Throughput: 10 kbps\r\n']
    n, samples, _seen, _w, _o = run_parse(lines)
    assert n == 1 and samples[0]['dp'] == 'dp0'


# --------------------------------------------------------------------------
# collect
# --------------------------------------------------------------------------
def sample_text():
    return SAMPLE.read_bytes()


def check_sample_result(result, n_files=1):
    samples, offsets, nf, pow_data, ifc_data = result
    assert nf == n_files
    assert offsets == {'+0100'}
    assert pow_data is None and ifc_data is None
    assert [(s['dp'], s['t']) for s in samples] == [
        ('dp0', T0), ('dp1', T0), ('dp0', T1), ('dp1', T1)]


def test_collect_directory(tmp_path):
    d = tmp_path / 'tsf' / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    (d / 'dp-monitor.log').write_bytes(sample_text())
    (d / 'other.log').write_bytes(b'ignored')
    warnings = []
    result = analyzer.collect(str(tmp_path / 'tsf'), warnings)
    check_sample_result(result)
    assert warnings == []
    assert result[0][0]['src'] == 'dp-monitor.log'


def test_collect_directory_without_dp_monitor_warns(tmp_path):
    warnings = []
    samples, offsets, n_files, pow_data, ifc_data = analyzer.collect(
        str(tmp_path), warnings)
    assert (samples, offsets, n_files, pow_data, ifc_data) == ([], set(), 0, None, None)
    assert warnings == ['no dp-monitor.* file found in /var/log/pan']


def test_collect_directory_requires_var_log_pan_path(tmp_path):
    # A dp-monitor.* file outside var/log/pan is not picked up.
    (tmp_path / 'dp-monitor.log').write_bytes(sample_text())
    warnings = []
    result = analyzer.collect(str(tmp_path), warnings)
    assert result[0] == [] and result[2] == 0
    assert warnings == ['no dp-monitor.* file found in /var/log/pan']


def test_collect_directory_rotations_merged_and_deduplicated(tmp_path):
    d = tmp_path / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    (d / 'dp-monitor.log').write_bytes(sample_text())
    (d / 'dp-monitor.log.1').write_bytes(sample_text())
    warnings = []
    result = analyzer.collect(str(tmp_path), warnings)
    # Files are visited in sorted order: 'dp-monitor.log' before '.log.1'.
    check_sample_result(result, n_files=2)
    assert {s['src'] for s in result[0]} == {'dp-monitor.log'}
    assert warnings == []


def test_collect_tgz(tmp_path):
    tgz = tmp_path / 'tsf.tgz'
    make_tgz(tgz, {
        'tsf/var/log/pan/dp-monitor.log': sample_text(),
        'tsf/var/log/pan/other.log': b'x',
    })
    warnings = []
    check_sample_result(analyzer.collect(str(tgz), warnings))
    assert warnings == []


def test_collect_tgz_dot_slash_prefix_and_rotation_order(tmp_path):
    # Members are processed in archive order (no sorting): the first member
    # wins on duplicate (dp, t) keys.
    a = hdr() + 'target-dp: *.dp0\nThroughput: 111 kbps\n'
    b = hdr() + 'target-dp: *.dp0\nThroughput: 222 kbps\n'
    tgz = tmp_path / 'tsf.tgz'
    make_tgz(tgz, {
        './var/log/pan/dp-monitor.log.1': a.encode(),
        './var/log/pan/dp-monitor.log': b.encode(),
    })
    warnings = []
    samples, _off, n_files, _p, _i = analyzer.collect(str(tgz), warnings)
    assert n_files == 2
    assert [(s['src'], s['kbps']) for s in samples] == [('dp-monitor.log.1', 111)]
    assert warnings == []


def test_collect_tgz_without_dp_monitor_warns(tmp_path):
    tgz = tmp_path / 'tsf.tgz'
    make_tgz(tgz, {'tsf/var/log/pan/other.log': b'x'})
    warnings = []
    result = analyzer.collect(str(tgz), warnings)
    assert result[0] == [] and result[2] == 0
    assert warnings == ['no dp-monitor.* file found in /var/log/pan']


def test_collect_single_file():
    warnings = []
    check_sample_result(analyzer.collect(str(SAMPLE), warnings))
    # The single file is passed through handle(): src is its basename.
    assert warnings == []


def test_collect_single_file_without_samples_warns(tmp_path):
    f = tmp_path / 'notes.txt'
    f.write_text('nothing useful here\n', encoding='utf-8')
    warnings = []
    samples, _off, n_files, pow_data, ifc_data = analyzer.collect(str(f), warnings)
    assert samples == [] and pow_data is None and ifc_data is None
    assert n_files == 1
    assert warnings == ['notes.txt: no Throughput samples found']


# Step 0 baseline: .gz behaviour changes in step 1
def test_collect_tgz_gz_member_skipped_with_warning(tmp_path):
    tgz = tmp_path / 'tsf.tgz'
    make_tgz(tgz, {
        'tsf/var/log/pan/dp-monitor.log': sample_text(),
        'tsf/var/log/pan/dp-monitor.log.1.gz': b'\x1f\x8b not really gzip',
    })
    warnings = []
    result = analyzer.collect(str(tgz), warnings)
    check_sample_result(result, n_files=1)     # the .gz member is not counted
    assert warnings == [W_GZ]


# Step 0 baseline: .gz behaviour changes in step 1
def test_collect_tgz_only_gz_member_adds_no_data_warning(tmp_path):
    tgz = tmp_path / 'tsf.tgz'
    make_tgz(tgz, {'var/log/pan/dp-monitor.log.1.gz': b'\x1f\x8b'})
    warnings = []
    result = analyzer.collect(str(tgz), warnings)
    assert result[0] == [] and result[2] == 0
    assert warnings == [W_GZ, 'no dp-monitor.* file found in /var/log/pan']


# --------------------------------------------------------------------------
# add_aggregate
# --------------------------------------------------------------------------
def rec(t, dp, kbps=None, pps=None, cps=None, sess=None, util=None, src='s'):
    return {'t': t, 'dp': dp, 'src': src, 'kbps': kbps, 'pps': pps, 'cps': cps,
            'sess': sess, 'util': util}


def test_add_aggregate_single_dp_unchanged():
    samples = [rec(1, 'dp0', 10), rec(2, 'dp0', 20)]
    before = list(samples)
    assert analyzer.add_aggregate(samples) == ['dp0']
    assert samples == before


def test_add_aggregate_empty():
    assert analyzer.add_aggregate([]) == []


def test_add_aggregate_two_dps_sums_and_max_util():
    samples = [
        rec(1, 'dp0', 10, 1, 2, 3, 40, src='a'),
        rec(1, 'dp1', 20, 4, 5, 6, 60, src='b'),
        rec(2, 'dp0', 30, 7, 8, 9, 10, src='a'),
        rec(2, 'dp1', 40, 1, 1, 1, 5, src='a'),
    ]
    assert analyzer.add_aggregate(samples) == ['ALL', 'dp0', 'dp1']
    assert [(s['t'], s['dp']) for s in samples] == [
        (1, 'ALL'), (1, 'dp0'), (1, 'dp1'), (2, 'ALL'), (2, 'dp0'), (2, 'dp1')]
    all1, all2 = samples[0], samples[3]
    assert all1 == {'t': 1, 'dp': 'ALL', 'src': 'a,b', 'kbps': 30, 'pps': 5,
                    'cps': 7, 'sess': 9, 'util': 60}
    assert all2 == {'t': 2, 'dp': 'ALL', 'src': 'a', 'kbps': 70, 'pps': 8,
                    'cps': 9, 'sess': 10, 'util': 10}


def test_add_aggregate_none_values_ignored_or_stay_none():
    samples = [rec(1, 'dp0', 10), rec(1, 'dp1', 20, pps=5)]
    analyzer.add_aggregate(samples)
    agg = samples[0]
    assert agg['dp'] == 'ALL'
    assert agg['kbps'] == 30
    assert agg['pps'] == 5
    assert agg['cps'] is None and agg['sess'] is None and agg['util'] is None


def test_add_aggregate_does_not_carry_grp_and_ignores_missing_dp_at_time():
    # A time with only one DP present still gets an ALL row equal to that DP.
    # The aggregate row has no 'grp' key.
    s = rec(1, 'dp0', 10)
    s['grp'] = {'a': 1}
    samples = [s, rec(1, 'dp1', 20), rec(2, 'dp0', 5)]
    analyzer.add_aggregate(samples)
    alls = [x for x in samples if x['dp'] == 'ALL']
    assert [(x['t'], x['kbps']) for x in alls] == [(1, 30), (2, 5)]
    assert all('grp' not in x for x in alls)

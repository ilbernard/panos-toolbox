"""Tests for the POW performance parser, heuristics and the TSF analyzer integration.

Standard library only; no device is contacted.
"""
import io
import json
import tarfile
from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer
from panos_toolbox.tsf.pow_perf import (
    POW_THRESHOLDS,
    classify_function,
    evaluate,
    has_data,
    parse_pow,
)

FIXTURE = Path(__file__).parent / 'data' / 'pow_sample.txt'

# Legacy (pre-9.1) group table, from the KB article quoted in pow_perf.py.
LEGACY_TEXT = """\
> debug dataplane pow performance
group              max-us             avg-us      count
:flow_lookup          0                0            0
:flow_fastpath        59441            15       8391514
:flow_slowpath        57527            75        262375
"""

MODERN_HDR = ('group max-us avg-us count total-us ac-max-us ac-avg-us ac-count '
              'ac-total-us')
FUNC_HDR = 'func ' + MODERN_HDR[len('group '):]


def _modern_text(rows, kind='group'):
    """Builds a one-section POW text with the given rows (dicts) of the given kind."""
    hdr = MODERN_HDR if kind == 'group' else FUNC_HDR
    lines = ['> debug dataplane pow performance all', '', hdr]
    defaults = {'max': 0, 'avg': 0.0, 'count': 0, 'total': 0,
                'acmax': 0, 'acavg': 0.0, 'account': 0, 'actotal': 0}
    for r in rows:
        v = dict(defaults, **r)
        lines.append('{name} {max} {avg} {count} {total} {acmax} {acavg} {account} {actotal}'
                     .format(**v))
    return lines


def _parse_text(text):
    return parse_pow(text.splitlines(), src='test')


def _row(evaluated, table, name, view='global'):
    v = evaluated['global'] if view == 'global' else evaluated['cores'][view]
    return next(r for r in v[table] if r['name'] == name)


def _codes(row):
    return {f['code']: f['level'] for f in row['flags']}


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def test_fixture_parses_global_and_cores():
    with open(FIXTURE, encoding='utf-8') as fh:
        parsed = parse_pow(fh, src='pow_sample.txt')
    assert parsed['format'] == 'modern'
    assert parsed['collected_at'] == 'Tue Oct 27 08:20:20 CET 2026'
    assert has_data(parsed)
    g = parsed['global']
    assert len(g['groups']) == 7
    assert len(g['funcs']) == 10
    assert [h['name'] for h in g['hist']] == ['dfa_match']
    assert len(g['hist'][0]['bins']) == 13
    assert sorted(parsed['cores']) == [0, 1]
    assert len(parsed['cores'][1]['funcs']) == 10
    assert parsed['cores'][1]['hist'] == []
    assert any('core 16-31' in w and 'Server error' in w for w in parsed['warnings'])


def test_fixture_row_values():
    with open(FIXTURE, encoding='utf-8') as fh:
        parsed = parse_pow(fh)
    row = next(r for r in parsed['global']['funcs'] if r['name'] == 'sml_vm')
    assert row == {'name': 'sml_vm', 'max_us': 14552, 'avg_us': 4.0, 'count': 355485,
                   'total_us': 1445402, 'ac_max_us': 14552, 'ac_avg_us': 3.9,
                   'ac_count': 553627, 'ac_total_us': 2190455}


def test_legacy_format_computes_total_and_leaves_ac_empty():
    parsed = _parse_text(LEGACY_TEXT)
    assert parsed['format'] == 'legacy'
    rows = {r['name']: r for r in parsed['global']['groups']}
    assert set(rows) == {'flow_lookup', 'flow_fastpath', 'flow_slowpath'}
    fast = rows['flow_fastpath']
    assert fast['max_us'] == 59441
    assert fast['avg_us'] == 15.0
    assert fast['count'] == 8391514
    assert fast['total_us'] == 8391514 * 15
    assert fast['ac_count'] is None and fast['ac_total_us'] is None


def test_legacy_header_variants_are_mapped_by_label():
    text = ('> debug dataplane pow performance all\n\n'
            'group max. proc us ave. proc us count\n'
            ':flow_np 89 2.0 8794649\n')
    parsed = _parse_text(text)
    assert parsed['format'] == 'legacy'
    row = parsed['global']['groups'][0]
    assert (row['name'], row['max_us'], row['avg_us'], row['count']) == \
        ('flow_np', 89, 2.0, 8794649)


def test_server_error_section_is_a_warning_not_a_crash():
    text = ('> debug dataplane pow performance all core 16-31\n\n'
            'Server error : high-availability not enabled\n\n'
            '> debug dataplane pow status\n')
    parsed = _parse_text(text)
    assert not has_data(parsed)
    expected = ('test: pow performance all core 16-31: Server error '
                '(high-availability not enabled), skipped')
    assert parsed['warnings'] == [expected]


def test_non_pow_text_has_no_data():
    parsed = _parse_text('> show clock\n\nTue Oct 27 08:20:20 CET 2026\n')
    assert not has_data(parsed)
    assert parsed['collected_at'] == 'Tue Oct 27 08:20:20 CET 2026'


# --------------------------------------------------------------------------
# Classification and flags
# --------------------------------------------------------------------------
@pytest.mark.parametrize('name, expected', [
    ('sml_vm', 'L7'),
    ('ssl_proxy_proc', 'DECRYPT'),
    ('ecdhe_generate_xchg_key', 'DECRYPT'),
    ('rsa_something_new', 'DECRYPT'),
    ('dhe_gen_key', 'DECRYPT'),
    ('tunnel_esp', 'TUNNEL'),
    ('urlcache_lookup', 'URL'),
    ('session_age', 'other'),
])
def test_classify_function(name, expected):
    assert classify_function(name) == expected


def test_top_cpu_crit_and_no_flag_for_small_rows():
    with open(FIXTURE, encoding='utf-8') as fh:
        ev = evaluate(parse_pow(fh))
    fast = _row(ev, 'groups', 'flow_fastpath')
    assert fast['share'] > POW_THRESHOLDS['share_crit']
    assert _codes(fast)['TOP_CPU'] == 'crit'
    assert 'TOP_CPU' not in _codes(_row(ev, 'groups', 'flow_host'))
    assert fast['description'].startswith('fastpath processing')


def test_max_spike_warn_and_crit():
    rows = [{'name': 'sml_vm', 'max': 14552, 'avg': 4.0, 'count': 1000, 'total': 4000},
            {'name': 'ctd_token', 'max': 200000, 'avg': 4.0, 'count': 1000, 'total': 4000},
            {'name': 'dfa_match', 'max': 5000, 'avg': 4.0, 'count': 1000, 'total': 4000}]
    ev = evaluate(_parse_text('\n'.join(_modern_text(rows, 'func'))))
    assert _codes(_row(ev, 'funcs', 'sml_vm'))['MAX_SPIKE'] == 'warn'
    assert _codes(_row(ev, 'funcs', 'ctd_token'))['MAX_SPIKE'] == 'crit'
    assert 'MAX_SPIKE' not in _codes(_row(ev, 'funcs', 'dfa_match'))


def test_max_spike_needs_min_count():
    rows = [{'name': 'sml_vm', 'max': 50000, 'avg': 4.0, 'count': 3, 'total': 12}]
    ev = evaluate(_parse_text('\n'.join(_modern_text(rows, 'func'))))
    assert 'MAX_SPIKE' not in _codes(_row(ev, 'funcs', 'sml_vm'))


def test_avg_drift_warn_crit_and_no_flag():
    rows = [
        {'name': 'policy_lookup', 'max': 1, 'avg': 100.0, 'count': 50, 'total': 5000,
         'acmax': 1, 'acavg': 20.0, 'account': 500, 'actotal': 10000},   # 5x: crit
        {'name': 'appid_match', 'max': 1, 'avg': 60.0, 'count': 50, 'total': 3000,
         'acmax': 1, 'acavg': 40.0, 'account': 500, 'actotal': 20000},   # 1.5x: no flag
        {'name': 'sml_vm', 'max': 1, 'avg': 40.0, 'count': 50, 'total': 2000,
         'acmax': 1, 'acavg': 15.0, 'account': 500, 'actotal': 7500},    # 2.67x: warn
    ]
    ev = evaluate(_parse_text('\n'.join(_modern_text(rows, 'func'))))
    assert _codes(_row(ev, 'funcs', 'policy_lookup'))['AVG_DRIFT'] == 'crit'
    assert _codes(_row(ev, 'funcs', 'sml_vm'))['AVG_DRIFT'] == 'warn'
    assert 'AVG_DRIFT' not in _codes(_row(ev, 'funcs', 'appid_match'))


def test_high_avg_uses_decrypt_limit():
    rows = [{'name': 'dfa_match', 'max': 1, 'avg': 1500.0, 'count': 20, 'total': 30000},
            {'name': 'rsa_sign_sw', 'max': 1, 'avg': 1882.0, 'count': 14, 'total': 26353},
            {'name': 'rsa_big', 'max': 1, 'avg': 12000.0, 'count': 14, 'total': 168000}]
    ev = evaluate(_parse_text('\n'.join(_modern_text(rows, 'func'))))
    assert _codes(_row(ev, 'funcs', 'dfa_match'))['HIGH_AVG'] == 'warn'
    assert 'HIGH_AVG' not in _codes(_row(ev, 'funcs', 'rsa_sign_sw'))
    assert _codes(_row(ev, 'funcs', 'rsa_big'))['HIGH_AVG'] == 'warn'


def test_historical_only_is_info():
    rows = [{'name': 'mi_proxy_host_open', 'max': 0, 'avg': 0.0, 'count': 0, 'total': 0,
             'acmax': 11311, 'acavg': 11311.0, 'account': 1, 'actotal': 11311}]
    ev = evaluate(_parse_text('\n'.join(_modern_text(rows, 'func'))))
    assert _codes(_row(ev, 'funcs', 'mi_proxy_host_open')) == {
        'HISTORICAL_ONLY': 'info', 'TOP_CPU_ACC': 'info'}


def test_ratio_and_legacy_has_no_accumulated_flags():
    rows = [{'name': 'dfa_match', 'max': 1, 'avg': 100.0, 'count': 50, 'total': 5000,
             'acmax': 1, 'acavg': 20.0, 'account': 100, 'actotal': 2000}]
    ev = evaluate(_parse_text('\n'.join(_modern_text(rows, 'func'))))
    assert _row(ev, 'funcs', 'dfa_match')['ratio'] == 0.5
    legacy = evaluate(_parse_text(LEGACY_TEXT))
    assert legacy['format'] == 'legacy'
    assert all(f['code'] not in ('AVG_DRIFT', 'MAX_SPIKE_ACC')
               for r in legacy['global']['groups'] for f in r['flags'])
    assert legacy['banner'][0]['level'] == 'info'


def test_category_summary_and_dominance():
    rows = [{'name': 'rsa_sign_sw', 'max': 1, 'avg': 900.0, 'count': 1, 'total': 900},
            {'name': 'dfa_match', 'max': 1, 'avg': 100.0, 'count': 1, 'total': 100}]
    ev = evaluate(_parse_text('\n'.join(_modern_text(rows, 'func'))))
    summary = ev['global']['func_summary']
    assert summary['basis'] == 'current'
    assert summary['total_us'] == 1000
    assert summary['dominant'] == ['DECRYPT']
    assert summary['by_category'][0] == {'category': 'DECRYPT', 'total_us': 900, 'share': 90.0}
    assert any('DECRYPT is 90%' in b['text'] for b in ev['banner'])


def test_fixture_category_shares_add_up():
    with open(FIXTURE, encoding='utf-8') as fh:
        summary = evaluate(parse_pow(fh))['global']['func_summary']
    assert summary['basis'] == 'current'
    assert round(sum(b['share'] for b in summary['by_category'])) == 100
    assert {b['category'] for b in summary['by_category']} >= {'L7', 'DECRYPT', 'other'}


def test_histogram_stats_and_tail():
    text = ['> debug dataplane pow performance all', '', 'func max-us avg-us count total-us',
            'f1 1 1.0 999 999', '',
            'slow_func (func)', 'col    avg-ticks   avg-us        count     total-us',
            '  1          10        1          990          990',
            ' 2          20000        20000          1          20000',
            '  3          30000        30000          9          270000', '']
    ev = evaluate(_parse_text('\n'.join(text)))
    hist = ev['global']['hist'][0]
    assert hist['count'] == 1000
    assert hist['p50_us'] == 1
    assert hist['p99_us'] == 1
    assert hist['max_bin_us'] == 30000
    assert hist['flags'][0]['code'] == 'TAIL'
    assert hist['flags'][0]['level'] == 'warn'   # 1 call at 20000 us = 0.1% < 1%


def test_histogram_tail_crit():
    text = ['> debug dataplane pow performance all', '', 'func max-us avg-us count total-us',
            'f1 1 1.0 999 999', '',
            'slow_func (func)', 'col    avg-ticks   avg-us        count     total-us',
            '  1          10        1          990          990',
            '  2          200000        150000          1          150000', '']
    ev = evaluate(_parse_text('\n'.join(text)))
    assert ev['global']['hist'][0]['flags'][0]['level'] == 'crit'


def test_core_imbalance_warn_and_crit():
    def cores(totals):
        lines = []
        for i, total in enumerate(totals):
            lines += ['> debug dataplane pow performance all core 0-15', '', f'Core {i}:']
            lines += _modern_text([{'name': 'flow_fastpath', 'max': 1, 'avg': 1.0,
                                    'count': total, 'total': total}])[2:]
            lines.append('')
        return _parse_text('\n'.join(lines))

    warn = evaluate(cores([100, 100, 300]))['core_summary']
    assert warn['median_group_total_us'] == 100
    assert warn['flags'][2][0]['level'] == 'warn'
    crit = evaluate(cores([100, 100, 500]))['core_summary']
    assert crit['flags'][2][0]['level'] == 'crit'
    assert 0 not in crit['flags']


def test_core_imbalance_needs_three_active_cores():
    lines = []
    for i, total in enumerate([100, 900]):
        lines += ['> debug dataplane pow performance all core 0-15', '', f'Core {i}:']
        lines += _modern_text([{'name': 'flow_fastpath', 'max': 1, 'avg': 1.0,
                                'count': total, 'total': total}])[2:]
        lines.append('')
    summary = evaluate(_parse_text('\n'.join(lines)))['core_summary']
    assert summary['median_group_total_us'] is None
    assert summary['flags'] == {}


def test_fixture_idle_core_reported():
    with open(FIXTURE, encoding='utf-8') as fh:
        ev = evaluate(parse_pow(fh))
    assert ev['core_summary']['idle'] == [0]
    assert ev['core_summary']['active'] == [1]


def test_thresholds_override_and_unknown_key():
    rows = [{'name': 'sml_vm', 'max': 50000, 'avg': 4.0, 'count': 100, 'total': 400}]
    text = '\n'.join(_modern_text(rows, 'func'))
    assert 'MAX_SPIKE' in _codes(_row(evaluate(_parse_text(text)), 'funcs', 'sml_vm'))
    relaxed = evaluate(_parse_text(text), thresholds={'max_spike_abs_us': 60000})
    assert 'MAX_SPIKE' not in _codes(_row(relaxed, 'funcs', 'sml_vm'))
    with pytest.raises(ValueError):
        evaluate(_parse_text(text), thresholds={'no_such_key': 1})


def test_evaluate_does_not_modify_input_and_is_json_serialisable():
    with open(FIXTURE, encoding='utf-8') as fh:
        parsed = parse_pow(fh)
    before = json.dumps(parsed, sort_keys=True)
    ev = evaluate(parsed)
    assert json.dumps(parsed, sort_keys=True) == before
    assert 'flags' not in parsed['global']['groups'][0]
    assert json.loads(json.dumps(ev))['global']['groups'][0]['flags'] is not None


# --------------------------------------------------------------------------
# Analyzer integration
# --------------------------------------------------------------------------
DP_TEXT = (
    '2026-10-27 08:20:20 +0100 --- dp-monitor\n'
    'target-dp: *.dp0\n'
    'Throughput: 1234 kbps\n'
    'Packet rate: 100 /s\n'
    '2026-10-27 08:21:20 +0100 --- dp-monitor\n'
    'target-dp: *.dp0\n'
    'Throughput: 2345 kbps\n'
    'Packet rate: 200 /s\n'
)


def test_main_single_pow_file_writes_pow_only_report(tmp_path):
    outdir = tmp_path / 'out'
    assert analyzer.main([str(FIXTURE), '-o', str(outdir)]) is None
    report = outdir / 'pow_sample.txt_pow.html'
    content = report.read_text(encoding='utf-8')
    assert 'POW performance' in content
    assert '"kind":"TSF analysis"' in content
    assert '"pow":{' in content


def test_main_tgz_with_pow_and_dp_monitor(tmp_path):
    tsf = tmp_path / 'tsf.tgz'
    with tarfile.open(tsf, 'w:gz') as tf:
        for name, data in (('tsf/tmp/cli/show-pow.txt', FIXTURE.read_bytes()),
                           ('tsf/var/log/pan/dp-monitor.log', DP_TEXT.encode())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    outdir = tmp_path / 'out'
    analyzer.main([str(tsf), '-o', str(outdir)])
    content = (outdir / 'tsf_throughput.html').read_text(encoding='utf-8')
    assert 'POW performance' in content
    assert '>Dataplane<' in content
    assert '"pow":{' in content and '"samples":[{' in content


def test_main_tgz_dp_monitor_only_has_no_pow(tmp_path):
    tsf = tmp_path / 'dp-only.tgz'
    data = DP_TEXT.encode()
    with tarfile.open(tsf, 'w:gz') as tf:
        info = tarfile.TarInfo('var/log/pan/dp-monitor.log')
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    outdir = tmp_path / 'out'
    analyzer.main([str(tsf), '-o', str(outdir)])
    content = (outdir / 'dp-only_throughput.html').read_text(encoding='utf-8')
    assert '"pow":null' in content
    assert '>Dataplane<' in content


def test_main_tgz_with_cli_file_without_pow_writes_nothing(tmp_path):
    tsf = tmp_path / 'noise.tgz'
    data = b'> show clock\n\nTue Oct 27 08:20:20 CET 2026\n'
    with tarfile.open(tsf, 'w:gz') as tf:
        info = tarfile.TarInfo('tmp/cli/clock.txt')
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    outdir = tmp_path / 'out'
    analyzer.main([str(tsf), '-o', str(outdir)])
    assert not outdir.exists() or not any(outdir.iterdir())


def test_latency_counters_excluded_from_cpu_share():
    from panos_toolbox.tsf import pow_perf
    text = (
        "> debug dataplane pow performance all\n\n"
        "group max-us avg-us count total-us ac-max-us ac-avg-us ac-count ac-total-us\n\n"
        "func max-us avg-us count total-us ac-max-us ac-avg-us ac-count ac-total-us\n"
        "pbp_buf_latency 100 3.0 1000000 3000000 100 3.0 1000000 3000000\n"
        "sml_vm 50 4.0 1000 4000 50 4.0 1000 4000\n"
    )
    ev = pow_perf.evaluate(pow_perf.parse_pow(text.splitlines()))
    rows = {r['name']: r for r in ev['global']['funcs']}
    assert rows['pbp_buf_latency']['category'] == 'latency'
    assert rows['pbp_buf_latency']['share'] == 0.0
    assert rows['sml_vm']['share'] == 100.0

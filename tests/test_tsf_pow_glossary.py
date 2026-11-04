"""Tests for the counter glossary, tooltips data, per-section help and the extra POW rules.

Standard library only; no device is contacted.
"""
import json
import re
from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer, pow_glossary
from panos_toolbox.tsf.pow_perf import POW_THRESHOLDS, classify_function, evaluate, parse_pow

SAMPLE = Path(__file__).parent / 'data' / 'pow_performance_sample.txt'
HDR = 'max-us avg-us count total-us ac-max-us ac-avg-us ac-count ac-total-us'


def _text(funcs, groups=(), prefix=''):
    return (prefix + 'group ' + HDR + '\n' + '\n'.join(groups) + '\n\nfunc ' + HDR + '\n'
            + '\n'.join(funcs) + '\n')


def _row(name, mx=1, avg=1.0, cnt=1000, tot=None, amx=2, aavg=1.0, acnt=100000, atot=None):
    tot = int(avg * cnt) if tot is None else tot
    atot = int(aavg * acnt) if atot is None else atot
    return f'{name} {mx} {avg} {cnt} {tot} {amx} {aavg} {acnt} {atot}'


def _ev(text, th=None):
    return evaluate(parse_pow(text.splitlines()), th)


def _codes(view, table, name):
    row = next(r for r in view[table] if r['name'] == name)
    return {f['code']: f['level'] for f in row['flags']}


@pytest.fixture(scope='module')
def sample_ev():
    return _ev(SAMPLE.read_text())


# ---------------------------------------------------------------- parsing
def test_plain_output_without_command_line_is_parsed():
    parsed = parse_pow(SAMPLE.read_text().splitlines())
    g = parsed['global']
    assert (len(g['groups']), len(g['funcs']), len(g['hist'])) == (16, 228, 74)
    assert {h['kind'] for h in g['hist']} == {'func', 'group'}
    assert parsed['format'] == 'modern' and not parsed['warnings']


def test_prompt_noise_and_blank_lines():
    text = ('admin@PA-560(active)> debug dataplane pow performance all\n\n'
            + _text([_row('sml_vm'), '', _row('ctd_token')]) + '\nadmin@PA-560(active)> \n')
    g = parse_pow(text.splitlines())['global']
    assert [r['name'] for r in g['funcs']] == ['sml_vm', 'ctd_token']


def test_pre_91_plain_snippet_computes_total():
    text = ('group max. proc us ave. proc us count\nflow_fastpath 500 20.5 1000\n\n'
            'func max. proc us ave. proc us count\nsml_vm 90 2.0 5000\n')
    parsed = parse_pow(text.splitlines())
    assert parsed['format'] == 'legacy'
    ev = evaluate(parsed)
    assert ev['global']['funcs'][0]['total_us'] == 10000
    assert ev['global']['funcs'][0]['ac_total_us'] is None
    assert ev['global']['gloss_summary']


def test_malformed_lines_are_skipped_with_warnings():
    parsed = parse_pow(_text([_row('good'), 'bad_row 1 2.0 abc', 'short 1 2.0 3',
                              _row('also_good')]).splitlines())
    assert [r['name'] for r in parsed['global']['funcs']] == ['good', 'also_good']
    assert len(parsed['warnings']) == 2


def test_truncated_histogram_row_is_a_warning():
    text = _text([_row('sml_vm')]) + '\nsml_vm (func)\ncol avg-ticks avg-us count total-us\n 8 100 0 5 3\n 9 200\n'
    parsed = parse_pow(text.splitlines())
    assert len(parsed['global']['hist'][0]['bins']) == 1 and parsed['warnings']


def test_several_dataplanes_only_first_is_analysed_with_warning():
    text = 'DP dp0:\n' + _text([_row('sml_vm')]) + '\nDP dp1:\n' + _text([_row('ctd_token')])
    parsed = parse_pow(text.splitlines())
    assert [r['name'] for r in parsed['global']['funcs']] == ['sml_vm']
    assert any('dp1' in w for w in parsed['warnings'])


def test_dp_header_does_not_swallow_rows_named_dp_something():
    parsed = parse_pow(_text([_row('dpdk'), _row('sml_vm')]).splitlines())
    assert [r['name'] for r in parsed['global']['funcs']] == ['dpdk', 'sml_vm']


# ---------------------------------------------------------------- glossary
def test_glossary_covers_the_fixture():
    parsed = parse_pow(SAMPLE.read_text().splitlines())
    g = parsed['global']
    names = {r['name'] for r in g['groups'] + g['funcs']} | {h['name'] for h in g['hist']}
    assert names <= set(pow_glossary.GLOSSARY)
    assert all(pow_glossary.lookup(n)['conf'] in 'DGIU' for n in names)


def test_lookup_never_raises_and_falls_back():
    assert pow_glossary.lookup('brand_new')['category'] == 'Unclassified'
    assert pow_glossary.lookup('brand_new')['conf'] == 'U'
    assert pow_glossary.lookup('mi_something_new')['category'].startswith('Module internal')


def test_field_entries_have_confidence_and_cover_columns():
    f = pow_glossary.field_entries()
    for col in ('max-us', 'avg-us', 'count', 'total-us', 'ac-max-us', 'ac-avg-us', 'ac-count',
                'ac-total-us', 'share', 'ratio', 'flags', 'name', 'category'):
        assert f[col]['f'] in 'DGIU' and f[col]['m']
    assert not f['avg-us']['m'].endswith('(D)')


# ---------------------------------------------------------------- latency
@pytest.mark.parametrize('name', ['pbp_buf_latency', 'pkt_rx_tx_latency', 'rsa_sign_hw_latency',
                                  'qat_packet_latency', 'brand_new_latency'])
def test_latency_names_are_classified_and_excluded(name):
    assert classify_function(name) == 'latency'
    ev = _ev(_text([_row(name, cnt=5000, tot=5_000_000_000), _row('sml_vm', tot=100)]))
    rows = {r['name']: r for r in ev['global']['funcs']}
    assert rows[name]['share'] == 0.0 and rows['sml_vm']['share'] == 100.0
    assert all(c['category'] != 'latency' for c in ev['global']['func_summary']['by_category'])
    assert sum(c['total_us'] for c in ev['global']['gloss_summary']) == 100


def test_fixture_cpu_totals_exclude_latency(sample_ev):
    fam = sample_ev['global']['gloss_summary']
    assert abs(sum(c['share'] for c in fam) - 100) < 0.1
    assert sum(c['total_us'] for c in fam) < 200_000_000      # pkt_rx_tx_latency alone is 9.2e9
    assert 'Latency measures (not CPU time)' not in {c['category'] for c in fam}


# ------------------------------------------------------ roll-up and rules
def test_gloss_summary_keeps_unclassified_and_marks_zero_families(sample_ev):
    ev = _ev(_text([_row('sml_vm', tot=100), _row('mystery_counter', tot=50)]))
    fam = {c['category']: c for c in ev['global']['gloss_summary']}
    assert fam['Unclassified']['total_us'] == 50 and fam['Unclassified']['unknown'] == 1
    assert sum(c['total_us'] for c in fam.values()) == 150
    sf = {c['category']: c for c in sample_ev['global']['gloss_summary']}
    assert sf['SD-WAN / FEC']['zero'] is True
    assert sf['Layer-7 / Content-ID and ML']['zero'] is False


def test_unknown_counter_flag_and_banner():
    ev = _ev(_text([_row('mystery_counter', cnt=10, tot=10),
                    _row('stack_trace', cnt=0, tot=0, acnt=5, atot=5),
                    _row('idle_unknown', mx=0, avg=0.0, cnt=0, tot=0, amx=0, aavg=0.0, acnt=0, atot=0),
                    _row('sml_vm')]))
    g = ev['global']
    assert _codes(g, 'funcs', 'mystery_counter')['UNKNOWN'] == 'warn'
    assert _codes(g, 'funcs', 'stack_trace')['UNKNOWN'] == 'info'
    assert 'UNKNOWN' not in _codes(g, 'funcs', 'idle_unknown')
    assert 'UNKNOWN' not in _codes(g, 'funcs', 'sml_vm')
    item = next(b for b in ev['banner'] if 'no known meaning' in b['text'])
    assert set(item['names']) == {'mystery_counter', 'stack_trace'}


def test_latency_high_flag():
    ev = _ev(_text([_row('pbp_buf_latency', avg=5000.0, cnt=5000), _row('qat_batch_latency', avg=3.0)]))
    assert _codes(ev['global'], 'funcs', 'pbp_buf_latency')['LATENCY_HIGH'] == 'info'
    assert 'HIGH_AVG' not in _codes(ev['global'], 'funcs', 'pbp_buf_latency')
    assert 'LATENCY_HIGH' not in _codes(ev['global'], 'funcs', 'qat_batch_latency')


def test_hist_slow_flag_and_threshold_override():
    text = (_text([_row('sml_vm')]) + '\nsml_vm (func)\ncol avg-ticks avg-us count total-us\n'
            ' 10 1 1 1000 1000\n 20 1 2000 500 1000000\n')
    flags = [f['code'] for f in _ev(text)['global']['hist'][0]['flags']]
    assert 'HIST_SLOW' in flags
    quiet = [f['code'] for f in _ev(text, {'hist_slow_share': 100})['global']['hist'][0]['flags']]
    assert 'HIST_SLOW' not in quiet


def test_decrypt_share_hint_below_dominance():
    ev = _ev(_text([_row('rsa_sign_sw', tot=2_000_000), _row('sml_vm', tot=8_000_000)]))
    assert any(b['text'].startswith('DECRYPT is 20%') for b in ev['banner'])
    off = _ev(_text([_row('rsa_sign_sw', tot=2_000_000), _row('sml_vm', tot=8_000_000)]),
              {'decrypt_share_warn': 50})
    assert not any(b['text'].startswith('DECRYPT is') for b in off['banner'])


def test_new_thresholds_are_part_of_pow_thresholds():
    for k in ('latency_high_us', 'decrypt_share_warn', 'hist_slow_us', 'hist_slow_share',
              'hist_slow_min_count'):
        assert k in POW_THRESHOLDS


# ---------------------------------------------------------------- report
def _report_data(page):
    m = re.search(r'const D = (\{.*?\});\nconst \$', page, re.S)
    return json.loads(m.group(1))


def test_report_embeds_tooltip_data_and_has_no_help_tab(tmp_path):
    analyzer.main([str(SAMPLE), '-o', str(tmp_path)])
    page = next(tmp_path.glob('*.html')).read_text(encoding='utf-8')
    d = _report_data(page)
    gl = d['gl']
    assert gl['names']['sml_vm']['f'] == 'D' and gl['names']['flow_fastpath']['k'] == 'group'
    assert len(gl['names']) <= len(pow_glossary.GLOSSARY)
    assert {'max-us', 'avg-us', 'total-us', 'ac-total-us', 'share'} <= set(gl['fields'])
    assert set(gl['conf']) == {'D', 'G', 'I', 'U'}
    assert 'role="tooltip"' in page and 'aria-describedby' in page
    assert 'id="tab-help"' not in page and 'id="p-help"' not in page
    assert 'src="http' not in page and 'href="http' not in page


def test_unknown_counter_marked_in_tooltip_data(tmp_path):
    f = tmp_path / 'x.txt'
    f.write_text(_text([_row('mystery_counter', cnt=10, tot=10)]))
    out = tmp_path / 'out'
    analyzer.main([str(f), '-o', str(out)])
    d = _report_data(next(out.glob('*.html')).read_text(encoding='utf-8'))
    e = d['gl']['names']['mystery_counter']
    assert e['f'] == 'U' and e['c'] == 'Unclassified' and e['u'] == 0


def test_cli_threshold_flags(tmp_path, capsys):
    analyzer.main([str(SAMPLE), '-o', str(tmp_path / 'o'), '--pow-share-warn', '90',
                   '--pow-hist-slow-share', '99'])
    d = _report_data(next((tmp_path / 'o').glob('*.html')).read_text(encoding='utf-8'))
    th = d['pow']['thresholds']
    assert th['share_warn'] == 90 and th['hist_slow_share'] == 99
    assert not any(f['code'] == 'TOP_CPU' for r in d['pow']['global']['funcs'] for f in r['flags'])
    with pytest.raises(SystemExit):
        analyzer.main([str(SAMPLE), '--pow-share-warn', '-1', '-o', str(tmp_path / 'x')])
    with pytest.raises(SystemExit) as exc:
        analyzer.main(['-h'])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert '--pow-share-warn' in out and '--pow-latency-high-us' in out

"""Tests for the report template split and the Help tab.

Standard library only; no device is contacted.
"""
import re
from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer, pow_perf, report_template
from panos_toolbox.tsf.report_help import render_help

FIXTURE = Path(__file__).parent / 'data' / 'pow_sample.txt'
PERF_SRC = Path(pow_perf.__file__).read_text(encoding='utf-8')


def test_template_import_and_pieces():
    tpl = analyzer.TEMPLATE
    assert '__DATA__' in tpl and '__TITLE__' in tpl and '__HELP__' in tpl
    for name in ('TEMPLATE_HEAD', 'TEMPLATE_CSS', 'TEMPLATE_BODY', 'JS_CORE', 'JS_POW',
                 'JS_TABS'):
        piece = getattr(report_template, name)
        assert piece and piece in tpl, name
    assert 'id="tab-help"' in tpl and 'id="p-help"' in tpl


def test_render_help_includes_live_thresholds_and_escapes():
    out = render_help()
    assert str(pow_perf.POW_THRESHOLDS['high_avg_us_decrypt']) in out
    assert str(pow_perf.POW_THRESHOLDS['share_warn']) in out
    changed = render_help({'share_warn': 12.5})
    assert 'share_warn = 12.5%' in changed
    assert 'share_warn = 10.0%' not in changed
    hostile = render_help({'top_n': '<script>x</script>'})
    assert '<script>x</script>' not in hostile
    assert '&lt;script&gt;x&lt;/script&gt;' in hostile


def test_render_help_rejects_unknown_threshold():
    with pytest.raises(ValueError):
        render_help({'no_such_key': 1})


def test_render_help_leaves_no_placeholders():
    out = render_help()
    assert not re.search(r'\{[a-z_]+\}', out)


def test_every_flag_code_in_pow_perf_is_documented():
    codes = set(re.findall(r"_flag\(\s*r?\w*,\s*'([A-Z_]+)'", PERF_SRC))
    # TAIL and CORE_IMBALANCE are built as dict literals, not through _flag().
    codes |= set(re.findall(r"'code':\s*'([A-Z_]+)'", PERF_SRC))
    assert {'TOP_CPU', 'MAX_SPIKE', 'AVG_DRIFT', 'HIGH_AVG', 'TAIL', 'CORE_IMBALANCE'} <= codes
    out = render_help()
    missing = sorted(c for c in codes if f'<code>{c}</code>' not in out)
    assert not missing, missing


def test_main_pow_report_has_help_tab(tmp_path):
    outdir = tmp_path / 'out'
    analyzer.main([str(FIXTURE), '-o', str(outdir)])
    reports = list(outdir.glob('*.html'))
    assert len(reports) == 1
    content = reports[0].read_text(encoding='utf-8')
    assert 'id="tab-help"' in content
    assert 'id="p-help"' in content
    assert '__HELP__' not in content
    assert '__DATA__' not in content
    assert '__TITLE__' not in content

"""Tests for the report template split and the per-section help.

Standard library only; no device is contacted.
"""
import re
from pathlib import Path

import pytest

from panos_toolbox.tsf import (
    analyzer,
    dp_health,
    log_events,
    mp_monitor,
    pow_perf,
    report_template,
    system_health,
)
from panos_toolbox.tsf.report_help import SECTION_HELP, SECTION_TITLES, render_section_help


def render_help(thresholds=None):
    """All section help texts joined, as one string."""
    return ''.join(render_section_help(thresholds).values())

FIXTURE = Path(__file__).parent / 'data' / 'pow_sample.txt'
PERF_SRC = Path(pow_perf.__file__).read_text(encoding='utf-8')
DPH_SRC = Path(dp_health.__file__).read_text(encoding='utf-8')
MP_SRC = Path(mp_monitor.__file__).read_text(encoding='utf-8')
SYS_SRC = Path(system_health.__file__).read_text(encoding='utf-8')
LOG_SRC = Path(log_events.__file__).read_text(encoding='utf-8')


def test_template_import_and_pieces():
    tpl = analyzer.TEMPLATE
    assert '__DATA__' in tpl and '__TITLE__' in tpl
    for name in ('TEMPLATE_HEAD', 'TEMPLATE_CSS', 'TEMPLATE_BODY', 'JS_CORE', 'JS_POW',
                 'JS_TABS'):
        piece = getattr(report_template, name)
        assert piece and piece in tpl, name
    # No global Help tab: every section has its own placeholders instead.
    assert 'id="tab-help"' not in tpl and 'id="p-help"' not in tpl
    for sid in SECTION_HELP:
        assert f'__HB_{sid}__' in tpl and f'__HP_{sid}__' in tpl, sid


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


def test_template_is_fluid_with_1900_minimum_width():
    tpl = report_template.TEMPLATE
    assert 'min-width:1900px' in tpl
    assert 'max-width:1280px' not in tpl


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


def test_every_flag_code_in_dp_health_is_documented():
    codes = set(re.findall(r"_flag\(\s*r?\w*,\s*'([A-Z_]+)'", DPH_SRC))
    codes |= set(re.findall(r"'code':\s*'([A-Z_]+)'", DPH_SRC))
    assert {'SESSION_UTIL', 'PKT_BUFFER', 'CORE_PEAK', 'CORE_PEAK_MINUTE'} <= codes
    assert codes <= set(dp_health.FLAG_CODES)
    out = render_help()
    missing = sorted(c for c in codes if f'<code>{c}</code>' not in out)
    assert not missing, missing


def test_every_flag_code_in_mp_monitor_is_documented():
    codes = set(re.findall(r"_flag\(\s*(?:\w+|'\w+'),\s*'([A-Z_]+)'", MP_SRC))
    codes |= set(re.findall(r"'code':\s*'([A-Z_]+)'", MP_SRC))
    assert {'MP_MEMORY', 'MP_MEMORY_PAST_PEAK', 'PROC_CPU', 'PROC_ZOMBIE'} <= codes
    assert codes <= set(mp_monitor.FLAG_CODES)
    out = render_help()
    missing = sorted(c for c in codes if f'<code>{c}</code>' not in out)
    assert not missing, missing


def test_every_flag_code_in_system_health_is_documented():
    codes = set(re.findall(r"_flag\(\s*(?:\w+|'\w+'|f?'[^']*'),\s*'([A-Z_]+)'", SYS_SRC))
    codes |= set(re.findall(r"'code':\s*'([A-Z_]+)'", SYS_SRC))
    assert {'PROC_NOT_RUNNING', 'CFG_MEMORY', 'NAT_POOL', 'CORE_FILES'} <= codes
    assert codes <= set(system_health.FLAG_CODES)
    assert set(system_health.CODE_CHECK) == set(system_health.FLAG_CODES)
    out = render_help()
    missing = sorted(c for c in codes if f'<code>{c}</code>' not in out)
    assert not missing, missing


def test_every_flag_code_in_log_events_is_documented():
    codes = set(re.findall(r"_flag\(.*?,\s*'([A-Z][A-Z_]+)',\s*'(?:crit|warn|info)'", LOG_SRC,
                           re.DOTALL))
    assert {'KERNEL_CRASH', 'KERNEL_CRASH_SEEN', 'LOG_ERROR_REPEAT', 'NEAR_COMMIT'} <= codes
    assert codes <= set(log_events.FLAG_CODES) and set(log_events.CODE_CHECK) == codes
    out = render_help()
    missing = sorted(c for c in codes if f'<code>{c}</code>' not in out)
    assert not missing, missing


def test_render_help_shows_live_log_thresholds():
    out = ''.join(render_section_help(None, None, None, None, {'crash_min': 7}).values())
    assert 'crash_min = 7 events' in out and 'crash_min = 5 events' not in out
    out = ''.join(render_section_help(None, None, None, None,
                                      {'log_repeat_min': 33, 'corr_window_s': 45}).values())
    assert 'log_repeat_min = 33 occurrences' in out and 'corr_window_s = 45 s' in out


def test_render_help_shows_live_sys_thresholds():
    out = ''.join(render_section_help(None, None, None, None, {'cfg_mem_warn': 42.5}).values())
    assert 'cfg_mem_warn = 42.5%' in out and 'cfg_mem_warn = 50%' not in out
    with pytest.raises(ValueError):
        render_section_help(None, None, None, None, {'no_such_key': 1})


def test_render_help_shows_live_mp_thresholds():
    out = ''.join(render_section_help(None, None, None, {'mem_warn': 60.5}).values())
    assert 'mem_warn = 60.5%' in out and 'mem_warn = 75%' not in out
    with pytest.raises(ValueError):
        render_section_help(None, None, None, {'no_such_key': 1})


def test_render_help_shows_live_dp_thresholds():
    out = ''.join(render_section_help(None, None, {'pkt_buffer_warn': 33.5}).values())
    assert 'pkt_buffer_warn = 33.5%' in out and 'pkt_buffer_warn = 50%' not in out
    out = ''.join(render_section_help(None, None, {'core_peak_minute_warn': 77}).values())
    assert 'core_peak_minute_warn = 77%' in out
    with pytest.raises(ValueError):
        render_section_help(None, None, {'no_such_key': 1})


def test_main_pow_report_has_section_help_and_no_help_tab(tmp_path):
    outdir = tmp_path / 'out'
    analyzer.main([str(FIXTURE), '-o', str(outdir)])
    reports = list(outdir.glob('*.html'))
    assert len(reports) == 1
    content = reports[0].read_text(encoding='utf-8')
    assert 'id="tab-help"' not in content
    assert 'id="p-help"' not in content
    assert '__HB_' not in content and '__HP_' not in content
    assert '__DATA__' not in content
    assert '__TITLE__' not in content


def test_every_section_has_its_own_collapsed_help(tmp_path):
    outdir = tmp_path / 'out'
    analyzer.main([str(FIXTURE), '-o', str(outdir)])
    content = next(outdir.glob('*.html')).read_text(encoding='utf-8')
    assert set(SECTION_TITLES) == set(SECTION_HELP)
    for sid in SECTION_HELP:
        assert f'aria-controls="help-{sid}"' in content
        assert f'id="help-{sid}" hidden' in content
    assert 'aria-expanded="false"' in content and 'aria-expanded="true"' not in content

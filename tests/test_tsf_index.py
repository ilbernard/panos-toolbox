"""Tests for the TSF summary index (analyzer.render_index / summarize_views / main)."""
from __future__ import annotations

import io
import re
import tarfile
from pathlib import Path

from panos_toolbox.tsf import analyzer

DATA = Path(__file__).parent / 'data'


def row(name, modules=(), counts=None, **kw):
    r = {'file': f'{name}_tsf.html', 'name': name, 'samples': 0, 'start': '-', 'end': '-',
         'peak': '-', 'warnings': 0, 'analysis': 'complete', 'analysis_reason': '',
         'modules': list(modules), 'counts': counts or {'crit': 0, 'warn': 0, 'info': 0}}
    r.update(kw)
    return r


def names_in_order(page):
    return re.findall(r'<a href="[^"]*">([^<]*)</a>', page)


def test_title_heading_and_new_columns():
    page = analyzer.render_index([row('a'), row('b')])
    assert '<title>TSF summary</title>' in page and '<h1>TSF summary</h1>' in page
    assert 'Throughput summary' not in page
    for col in ('TSF', 'Analysis', 'Modules', 'Findings', 'Samples', 'Start', 'End', 'Peak',
                'Warnings'):
        assert f'<th>{col}</th>' in page
    assert '<link' not in page and 'src=' not in page


def test_mixed_rows_status_badges_counts_and_missing_throughput():
    rows = [
        row('full', [('DP health', 'ok'), ('MP', 'warning'), ('System', 'critical'),
                     ('POW', 'no_data'), ('Interfaces', 'ok')],
            {'crit': 2, 'warn': 3, 'info': 4}, samples=5, start='2026-01-01 00:00:00',
            end='2026-01-01 01:00:00', peak='1 Mbps (x)', warnings=2, analysis='partial',
            analysis_reason='2 member(s) read only in part; 1 conflicting duplicate sample(s)'),
        row('mponly', [('MP', 'ok')]),
        row('bare'),                      # no modules, no counts, no throughput
    ]
    for r in rows:
        r.pop('counts') if r['name'] == 'bare' else None
    page = analyzer.render_index(rows)
    assert 'class="b b-partial" title="2 member(s) read only in part; 1 conflicting' in page
    assert 'b-complete' in page
    assert 'DP health: ok' in page and 'System: critical' in page and 'POW: no data' in page
    # modules not present are omitted
    mponly = re.search(r'<tr><td><a href="mponly_tsf.html">.*?</tr>', page).group(0)
    assert 'MP: ok' in mponly and 'DP health' not in mponly and 'System' not in mponly
    full = re.search(r'<tr><td><a href="full_tsf.html">.*?</tr>', page).group(0)
    assert re.search(r'n-crit"[^>]*>2<.*n-warn"[^>]*>3<.*n-info"[^>]*>4<', full)
    assert '<td>5</td>' in full and '1 Mbps (x)' in full
    assert 'bare_tsf.html' in page        # no KeyError, empty cells shown as '-'


def test_sort_worst_status_first_then_name():
    rows = [row('zz', [('MP', 'ok')]), row('aa', [('MP', 'ok')]),
            row('nodata'), row('warn', [('MP', 'ok'), ('POW', 'warning')]),
            row('crit', [('System', 'critical'), ('MP', 'warning')]),
            row('crit0', [('System', 'critical')])]
    assert names_in_order(analyzer.render_index(rows)) == [
        'crit', 'crit0', 'warn', 'aa', 'zz', 'nodata']


def test_escaping():
    evil = '<script>alert(1)</script>"&'
    page = analyzer.render_index([row(evil, analysis='partial', analysis_reason='"><img src=x>',
                                      peak='<b>', file='a"b.html')])
    assert '<script>' not in page and '<img' not in page and '<b>' not in page
    assert '&lt;script&gt;' in page and 'href="a&quot;b.html"' in page


def _tgz(path, members):
    with tarfile.open(path, 'w:gz') as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def test_main_writes_index_for_two_tgz(tmp_path):
    a = tmp_path / 'fw-a.tgz'
    b = tmp_path / 'fw-b.tgz'
    _tgz(a, {'t/var/log/pan/dp-monitor.log': (DATA / 'dp_monitor_sample.log').read_bytes(),
             't/var/log/pan/mp-monitor.log': (DATA / 'mp_monitor_sample.log').read_bytes()})
    _tgz(b, {'t/tmp/cli/sys.txt': (DATA / 'cli_system_health_sample.txt').read_bytes()})
    out = tmp_path / 'out'
    analyzer.main([str(a), str(b), '-o', str(out)])
    page = (out / 'index.html').read_text(encoding='utf-8')
    assert '<title>TSF summary</title>' in page
    assert 'fw-a_throughput.html' in page and 'fw-b_sys.html' in page
    assert 'MP: ' in page and 'System: ' in page
    assert (out / 'fw-a_throughput.html').exists() and (out / 'fw-b_sys.html').exists()
    assert len(names_in_order(page)) == 2


def test_main_single_input_writes_no_index(tmp_path):
    out = tmp_path / 'out'
    analyzer.main([str(DATA / 'dp_monitor_sample.log'), '-o', str(out)])
    assert not (out / 'index.html').exists()


def test_summarize_views_counts_levels_without_reparsing():
    fl = [{'code': 'X', 'level': 'crit', 'text': 't'}, {'code': 'Y', 'level': 'warn', 'text': 't'},
          {'code': 'Z', 'level': 'info', 'text': 't'}]
    mp = {'findings': fl}
    dph = {'findings': [fl[2]]}
    mods, counts = analyzer.summarize_views(None, None, dph, mp, None)
    assert mods == [('DP health', 'ok'), ('MP', 'critical')]
    assert counts == {'crit': 1, 'warn': 1, 'info': 2}

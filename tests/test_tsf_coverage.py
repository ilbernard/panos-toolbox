"""Tests for tsf/coverage.py and the Source coverage tab of the report."""
from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer, archive
from panos_toolbox.tsf.coverage import MAX_CONFLICTS, build_coverage

SAMPLE = (Path(__file__).parent / 'data' / 'dp_monitor_sample.log').read_bytes()
DP = 'var/log/pan/dp-monitor.log'


def build_tgz(path, entries):
    with tarfile.open(path, 'w:gz') as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            if isinstance(data, tuple):
                info.type, info.linkname = tarfile.SYMTYPE, data[1]
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))


def conflicting(data):
    """Same timestamps as `data`, different throughput."""
    return data.replace(b'Throughput: 1000 kbps', b'Throughput: 2000 kbps')


def collect(path):
    warnings = []
    return analyzer.collect(str(path), warnings), warnings


def fam(view, name):
    return next(f for f in view['families'] if f['family'] == name)


def test_complete_archive(tmp_path):
    p = tmp_path / 't.tgz'
    build_tgz(p, [(DP, SAMPLE)])
    col, _ = collect(p)
    v = build_coverage(col)
    json.dumps(v)
    assert v['status'] == 'complete' and v['archive'] and v['summary'] == []
    dp = fam(v, 'dp-monitor')
    assert dp['states'] == ['ok'] and dp['found'] == dp['read'] == 1
    assert dp['samples'] > 0 and dp['first'] <= dp['last'] and dp['conflicts'] == 0
    assert dp['members'][0]['state'] == 'read' and dp['members'][0]['first'] == dp['first']
    cli = fam(v, 'cli')                       # known family, nothing found
    assert cli['states'] == ['absent'] and cli['found'] == 0 and cli['members'] == []
    assert v['conflicts'] == {'total': 0, 'shown': 0, 'items': []}


def test_truncated_member(tmp_path, monkeypatch):
    p = tmp_path / 't.tgz'
    build_tgz(p, [(DP, SAMPLE * 3)])
    monkeypatch.setattr(archive, 'MAX_MEMBER_BYTES', len(SAMPLE) + 10)
    col, _ = collect(p)
    v = build_coverage(col)
    dp = fam(v, 'dp-monitor')
    assert v['status'] == 'partial' and 'truncated' in dp['states']
    assert dp['truncated'] == 1 and dp['members'][0]['state'] == 'truncated'
    assert any('read only in part' in s for s in v['summary'])


def test_zero_sample_family(tmp_path):
    p = tmp_path / 't.tgz'
    build_tgz(p, [(DP, b'nothing useful here\n')])
    col, _ = collect(p)
    dp = fam(build_coverage(col), 'dp-monitor')
    assert dp['states'] == ['zero_samples'] and dp['found'] == dp['read'] == 1
    assert dp['samples'] == 0 and dp['first'] is None
    assert dp['members'][0]['samples'] == 0


def test_conflicts_listed_and_capped(tmp_path):
    p = tmp_path / 't.tgz'
    build_tgz(p, [(DP, SAMPLE), (DP + '.1', conflicting(SAMPLE))])
    col, warnings = collect(p)
    v = build_coverage(col)
    assert v['status'] == 'partial'
    dp = fam(v, 'dp-monitor')
    assert 'conflict' in dp['states'] and dp['conflicts'] == v['conflicts']['total'] > 0
    c = v['conflicts']['items'][0]
    assert set(c) == {'dp', 't', 'kept', 'dropped'} and c['kept'] != c['dropped']
    assert any('conflict' in w for w in warnings)
    # cap
    col.conflicts = [('dp0', i, 'a', 'b') for i in range(MAX_CONFLICTS + 50)]
    v = build_coverage(col)
    assert v['conflicts']['total'] == MAX_CONFLICTS + 50
    assert v['conflicts']['shown'] == len(v['conflicts']['items']) == MAX_CONFLICTS


def test_unsafe_member_listed(tmp_path):
    p = tmp_path / 't.tgz'
    build_tgz(p, [(DP, SAMPLE), ('../evil/var/log/pan/dp-monitor.log', SAMPLE),
                  ('var/log/pan/link', ('sym', '/etc/passwd'))])
    col, _ = collect(p)
    v = build_coverage(col)
    reasons = {s['name']: s['reason'] for s in v['skipped']}
    assert reasons['../evil/var/log/pan/dp-monitor.log'] == 'unsafe path'
    assert 'link' in reasons.values()
    assert v['status'] == 'complete'          # skipped members alone do not make it partial


def test_single_file_minimal_view(tmp_path):
    p = tmp_path / 'dp-monitor.log'
    p.write_bytes(SAMPLE)
    col, _ = collect(p)
    v = build_coverage(col)
    json.dumps(v)
    assert v['archive'] is False and v['families'] == []
    assert any('Single-file' in n for n in v['notes'])


def report(tmp_path, entries):
    p = tmp_path / 't.tgz'
    build_tgz(p, entries)
    col, warnings = collect(p)
    series = analyzer.add_aggregate(col.samples)
    return analyzer.render_report('t', col.samples, series, col.offsets, warnings,
                                  col.n_files, analyzer.TEMPLATE,
                                  coverage=build_coverage(col))


def script_of(html_text):
    return re.findall(r'<script>(.*?)</script>', html_text, re.DOTALL)[-1]


def test_render_report_has_tab_badge_and_help(tmp_path):
    out = report(tmp_path, [(DP, SAMPLE), (DP + '.1', conflicting(SAMPLE))])
    assert 'id="tab-cov"' in out and 'id="p-cov"' in out and 'id="astatus"' in out
    assert 'id="help-coverage"' in out and '__HB_' not in out and '__HP_' not in out
    m = re.search(r'const D = (\{.*?\});\nconst \$', out, re.DOTALL)
    data = json.loads(m.group(1).replace('<\\/', '</'))
    assert data['coverage']['status'] == 'partial'


def test_render_report_without_coverage_still_works(tmp_path):
    out = analyzer.render_report('t', [], [], set(), [], 0, analyzer.TEMPLATE)
    assert '"coverage":null' in out


@pytest.mark.skipif(shutil.which('node') is None, reason='node not available')
def test_generated_javascript_is_valid(tmp_path):
    out = report(tmp_path, [(DP, SAMPLE), (DP + '.1', conflicting(SAMPLE))])
    js = tmp_path / 'report.js'
    js.write_text(script_of(out), encoding='utf-8')
    res = subprocess.run(['node', '--check', str(js)], check=False, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr

"""Tests of the chart helpers of the TSF report (point reduction and gap breaking).

The helpers are standalone JavaScript functions in the report template, so they are
evaluated with node (skipped when node is not installed). No network, no device.
"""
import json
import shutil
import subprocess

import pytest

from panos_toolbox.tsf import report_template
from panos_toolbox.tsf.report_help import SECTION_HELP

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not available')

SRC = report_template.JS_CORE
BEGIN, END = '// CHART-HELPERS-BEGIN', '// CHART-HELPERS-END'


def helpers():
    assert BEGIN in SRC and END in SRC
    return SRC[SRC.index(BEGIN):SRC.index(END)]


def js(expr):
    """Evaluate a JavaScript expression with the chart helpers loaded and return it as JSON."""
    prog = helpers() + '\nconsole.log(JSON.stringify(' + expr + '));'
    res = subprocess.run(['node', '-e', prog], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


def test_reduction_keeps_peaks_first_and_last():
    n = 20000
    vs = [10.0] * n
    vs[7777] = 99.0
    vs[12345] = -5.0
    out = js(f'(()=>{{const ts=Array.from({{length:{n}}},(_,i)=>i*1000), vs={json.dumps(vs)};'
             f'const k=reduceMinMax(ts,vs,0,{(n - 1) * 1000},200); return {{k:k, n:{n}}};}})()')
    kept = out['k']
    assert len(kept) <= 2 * 200 + 2 < n
    assert kept == sorted(set(kept))
    assert 0 in kept and n - 1 in kept
    assert 7777 in kept and 12345 in kept


def test_no_reduction_when_few_points():
    out = js('reduceMinMax([0,1000,2000,3000,4000,5000], [1,2,3,2,1,5], 0, 5000, 100)')
    assert out == [0, 1, 2, 3, 4, 5]


def test_chart_runs_reduces_only_long_series():
    short = js('chartRuns(Array.from({length:50},(_,i)=>({t:i*1000,v:i})),0,49000,800)')
    assert len(short) == 1 and len(short[0]) == 50
    long_ = js('chartRuns(Array.from({length:5000},(_,i)=>({t:i*1000,v:i%7})),0,4999000,500)')
    assert len(long_) == 1 and len(long_[0]) < 5000
    assert long_[0][0]['t'] == 0 and long_[0][-1]['t'] == 4999000


def test_gap_break_over_three_times_median():
    # 600 s cadence, one 2400 s hole (4x median): broken
    out = js('splitGaps([0,600000,1200000,3600000,4200000],[1,1,1,1,1],60000,21600000,3)')
    assert out == [[0, 1, 2], [3, 4]]
    # 1500 s hole (2.5x median): not broken
    out = js('splitGaps([0,600000,1200000,2700000,3300000],[1,1,1,1,1],60000,21600000,3)')
    assert out == [[0, 1, 2, 3, 4]]


def test_no_break_under_sixty_seconds():
    # 1 s cadence, one 30 s hole (30x median) is still under 60 s: not broken
    ts = [0, 1000, 2000, 32000, 33000]
    assert js(f'splitGaps({ts},[1,1,1,1,1],60000,21600000,3)') == [[0, 1, 2, 3, 4]]
    # a 90 s hole is broken
    ts = [0, 1000, 2000, 92000, 93000]
    assert js(f'splitGaps({ts},[1,1,1,1,1],60000,21600000,3)') == [[0, 1, 2], [3, 4]]


def test_always_break_over_six_hours():
    # 4 h cadence: 3x median is 12 h, clamped to 6 h; a 7 h hole breaks, 4 h does not
    h = 3600000
    assert js(f'splitGaps([0,{4 * h},{11 * h}],[1,1,1],60000,21600000,3)') == [[0, 1], [2]]
    assert js(f'splitGaps([0,{4 * h},{8 * h}],[1,1,1],60000,21600000,3)') == [[0, 1, 2]]


def test_missing_value_breaks_the_line_and_is_not_zero():
    out = js('splitGaps([0,1000,2000,3000,4000],[5,null,7,undefined,9],60000,21600000,3)')
    assert out == [[0], [2], [4]]
    out = js('chartRuns([{t:0,v:5},{t:1000,v:null},{t:2000,v:7}],0,2000,800)')
    assert out == [[{'t': 0, 'v': 5}], [{'t': 2000, 'v': 7}]]
    assert all(p['v'] != 0 for run in out for p in run)
    assert js('realPts([{t:0,v:0},{t:1,v:null},{t:2,v:3}])') == [{'t': 0, 'v': 0}, {'t': 2, 'v': 3}]


def test_chart_help_entries_mention_the_behaviour():
    for key in ('chart', 'cpu', 'dphchart', 'mpchart'):
        txt = SECTION_HELP[key]
        assert '3 times the median' in txt and '6 hours' in txt, key

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
DBEGIN, DEND = '// DPH-HELPERS-BEGIN', '// DPH-HELPERS-END'


def helpers():
    """The chart helpers and the dataplane health helpers (both are pure functions)."""
    assert BEGIN in SRC and END in SRC and DBEGIN in SRC and DEND in SRC
    return SRC[SRC.index(BEGIN):SRC.index(END)] + SRC[SRC.index(DBEGIN):SRC.index(DEND)]


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
    for key in ('chart', 'cpu', 'mpchart'):
        txt = SECTION_HELP[key]
        assert '3 times the median' in txt and '6 hours' in txt, key


# --------------------------------------------------------------------------
# Dataplane health helpers (reconstructed timestamps, per-core grids, dedup)
# --------------------------------------------------------------------------
MIN = 60000


def test_row_time_rules():
    # per-second: row i is T - i s; per-minute: the whole minute ending i minutes before the last boundary at or before T
    assert js('[recSec(1000000,0), recSec(1000000,4), recSec(1000000,14)]') == [1000000, 996000, 986000]
    t = 7 * MIN + 20485                      # 00:07:20.485
    assert js(f'[recMin({t},0), recMin({t},1), recMin({t},14)]') == [7 * MIN, 6 * MIN, -7 * MIN]


def test_second_grid_row_i_is_t_minus_i_seconds_oldest_first_in_the_grid():
    # one capture at T, 3 rows x 2 cores, row-major, newest row first
    out = js('secondGrid([100000],[[1,10, 2,20, 3,30]],2)')
    assert out['t'] == [98000, 99000, 100000]
    assert out['cols'] == [[3, 2, 1], [30, 20, 10]]


def test_second_grid_missing_is_null_and_windows_do_not_overlap():
    out = js('secondGrid([100000, 700000],[[1,null, 2,5],[7,8, 9,null]],2)')
    assert out['t'] == [99000, 100000, 699000, 700000]
    assert out['cols'][1] == [5, None, None, 8]
    assert out['t'] == sorted(set(out['t']))
    # a capture without a table is skipped, not zero-filled
    out = js('secondGrid([100000, 700000],[null,[4,5]],1)')
    assert out['t'] == [699000, 700000] and out['cols'] == [[5, 4]]


def test_second_grid_equal_timestamps_newest_capture_wins():
    out = js('secondGrid([100000, 101000],[[1,2],[8,9]],1)')   # windows overlap: 99,100 and 100,101
    assert out['t'] == [99000, 100000, 101000]
    assert out['cols'][0] == [2, 9, 8]                        # second 100: A row 0 = 2, B row 1 = 9: B is newer


def test_minute_grid_dedups_overlapping_windows_newest_capture_wins():
    # capture A at minute 100: rows (newest first) 1..15 for minutes 100,99,...,86
    a = list(range(1, 16))
    # capture B 10 minutes later (minute 110): rows 10..14 are the same minutes as A rows 0..4 but with other values
    b = [50 + r for r in range(10)] + [900, 901, 902, 903, 904]
    out = js(f'minuteGrid([100,110],[{a},{b}],1)')
    keys = [t // MIN for t in out['t']]
    assert keys == list(range(86, 111))                       # 25 distinct minutes, ascending
    assert len(out['t']) == len(set(out['t']))                # no duplicate timestamps
    col = dict(zip(keys, out['cols'][0]))
    # B row r is minute 110 - r: rows 10..14 are minutes 100..96 and carry the newer capture's values
    assert [col[100], col[99], col[98], col[97], col[96]] == [900, 901, 902, 903, 904]
    assert col[95] == 6 and col[86] == 15                     # minutes only the older capture has
    assert col[110] == 50 and col[101] == 59                  # minutes only the newer capture has
    assert out['t'][0] == 86 * MIN                            # whole-minute end times


def test_minute_grid_missing_never_replaces_a_real_value():
    out = js('minuteGrid([100,101],[[5,6],[null,7]],1)')
    col = dict(zip([t // MIN for t in out['t']], out['cols'][0]))
    # row 0 of B (minute 101) is null and nothing else knows it: stays null; B row 1 (minute 100) = 7 wins over A row 0 = 5
    assert col[100] == 7 and col[101] is None and col[99] == 6


def test_minute_grid_jitter_free_keys_for_real_cadence():
    # 20 captures every 10 minutes with 15 rows each: every minute once, no duplicate time
    out = js('(()=>{const k0=Array.from({length:20},(_,i)=>1000+10*i); const f=k0.map((k,c)=>Array.from({length:15},(_,r)=>k-r));'
             'return minuteGrid(k0,f,1);})()')
    assert len(out['t']) == len(set(out['t'])) == 19 * 10 + 15
    assert out['cols'][0] == [t // MIN for t in out['t']]    # each minute carries the value of its own key


def test_grid_max_merge_max_and_session_series():
    assert js('gridMax({t:[1,2,3],cols:[[1,null,null],[5,2,null]]})') == [
        {'t': 1, 'v': 5}, {'t': 2, 'v': 2}, {'t': 3, 'v': None}]
    assert js('mergeMax([[{t:1,v:3},{t:2,v:null}],[{t:1,v:9},{t:2,v:4},{t:3,v:1}]])') == [
        {'t': 1, 'v': 9}, {'t': 2, 'v': 4}, {'t': 3, 'v': 1}]
    # session: per-second values where the capture has them, the target-dp reading (fb) where it has not
    out = js('sessionSeries([100000,700000,1300000],[[1,2],null,[null,null]],[null,40,50])')
    assert out == [{'t': 99000, 'v': 2}, {'t': 100000, 'v': 1}, {'t': 700000, 'v': 40}, {'t': 1300000, 'v': 50}]


def test_metric_list_contains_only_present_metrics():
    full = ('{by_dp:{dp0:{us:{sess:[[1]],pb:[[1]],pd:[[1]],pdc:[[1]]},um:{pb_avg:[[1]]},cs:[[1]],cma:[[1]],cmm:[[1]]}}}')
    assert js(f'dphAvail({full},["dp0"])') == [
        'util', 'hpkt', 'hcore_s', 'pc_s', 'hcore_mm', 'pc_mm', 'pc_ma']
    # no on-chip descriptors, no per-minute average, no per-second CPU table
    part = '{by_dp:{dp0:{us:{sess:[[1]],pb:[[1]],pd:[[1]]},um:{},cs:[null],cma:[null],cmm:[[1]]}}}'
    assert js(f'dphAvail({part},["dp0"])') == ['util', 'hpkt', 'hcore_mm', 'pc_mm']
    # any single kind is enough, and the combined metric is listed once
    assert js('dphAvail({by_dp:{dp0:{us:{},um:{pb_avg:[[3]]},cs:[],cma:[],cmm:[]},dp1:{us:{pdc:[[2]]},um:{},cs:[],cma:[],cmm:[]}}},["dp0","dp1"])') == ['hpkt']
    # all-missing values do not count as present
    assert js('dphAvail({by_dp:{dp0:{us:{pb:[[null,null]]},um:{},cs:[[null]],cma:[],cmm:[]}}},["dp0"])') == []
    assert js('dphAvail({by_dp:{}},["dp0"])') == []


def test_packet_metric_lists_only_the_kinds_with_data():
    got = js('pktKinds(m=>({hpb_avg:[{t:1,v:null}], hpb_max:[{t:1,v:5},{t:2,v:null}], hpd_max:[], hpdc_max:[{t:1,v:0}]})[m]).map(k=>[k[0],k[1]])')
    assert got == [['hpb_max', 'Packet buffer (max)'], ['hpdc_max', 'Packet descriptor on-chip (max)']]
    assert js('pktKinds(m=>[])') == []
    assert len(js('PKT_KINDS')) == 4 and len({k[2] for k in js('PKT_KINDS')}) == 4     # distinct colours


def test_chart_help_mentions_the_reconstruction_and_the_new_metrics():
    txt = SECTION_HELP['chart']
    for needle in ('Reconstructed timestamps', 'newest first', 'inferred', 'most recent capture',
                   'per-minute avg', 'Busiest core (per-second)'):
        assert needle in txt, needle

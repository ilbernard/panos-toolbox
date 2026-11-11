"""Tests for tsf/log_events.py (kernel crashes, daemon errors, commit/job context) and the
Logs group of the System health tab.

Synthetic data only (hostnames, paths and messages are invented); no device is contacted.
"""
from __future__ import annotations

import gzip
import io
import json
import re
import shutil
import subprocess
import tarfile
from datetime import date
from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer, archive, log_events
from panos_toolbox.tsf.log_events import (
    FLAG_CODES,
    LOG_THRESHOLDS,
    evaluate_log_events,
    infer_offset,
    new_store,
    parse_daemon_log,
    parse_jobs,
    parse_messages,
)

TS = '2026-03-10 02:06:51.823 +0100'


def kernel(lines, store=None, src='messages'):
    store = store or new_store()
    parse_messages(lines, src, store, [])
    return store


def klines(body, n=1, host='fw1'):
    return [f'Mar 10 09:02:{i % 60:02d} {host} kernel: {body}' for i in range(n)]


def kview(lines, **th):
    return evaluate_log_events(kernel(lines), th or None)


def codes(view):
    return [f['code'] for f in view['findings']]


def daemon(text, name='devsrv', store=None, src='devsrv.log'):
    store = store or new_store()
    n = parse_daemon_log(text, name, src, store, [])
    return n, store


def dview(text, name='devsrv', **th):
    return evaluate_log_events(daemon(text, name)[1], th or None)


def err_lines(msg, n, start_min=0, level='Error:', off='+0100'):
    return '\n'.join(f'2026-03-10 02:{(start_min + i) % 60:02d}:00.000 {off} {level}  {msg}'
                     for i in range(n)) + '\n'


# --------------------------------------------------------------------------
# A) Kernel log
# --------------------------------------------------------------------------
def test_defaults():
    assert LOG_THRESHOLDS == {'crash_min': 5, 'log_repeat_min': 20, 'corr_window_s': 90,
                              'commit_gap_s': 120, 'log_recent_h': 24, 'commit_min_lines': 2}
    assert set(FLAG_CODES) == set(log_events.CODE_CHECK)


@pytest.mark.parametrize('body, proc, kind', [
    ('[123.4] myproc[1234]: segfault at 0 ip 00007f sp 00007ffd error 4 in libx.so', 'myproc',
     'segfault'),
    ('myproc[77]: segfault at 10 ip 0 sp 0 error 6', 'myproc', 'segfault'),
    ('traps: myproc[1234] general protection fault ip:7f sp:7e error:0 in libx.so',
     'myproc', 'general protection'),
    ('[9.1] traps: other-d[5] general protection ip:7f sp:7e error:0', 'other-d',
     'general protection'),
    ('general protection fault: 0000 [#1] SMP', '(unknown)', 'general protection'),
    ('Out of memory: Killed process 321 (big) total-vm:1kB, anon-rss:2kB', 'big', 'oom-kill'),
    ('Out of memory: Kill process 322 (big2) score 900 or sacrifice child', 'big2', 'oom-kill'),
    ('oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),task=big3,pid=323,uid=0', 'big3',
     'oom-kill'),
    ('Killed process 324 (big4) total-vm:1kB', 'big4', 'oom-kill'),
])
def test_kernel_event_variants(body, proc, kind):
    st = kernel(klines(body, 2))
    ev = evaluate_log_events(st)['logs']['kernel']['events']
    assert [(e['process'], e['type'], e['count']) for e in ev] == [(proc, kind, 2)] \
        or (kind == 'oom-kill' and [(e['process'], e['type']) for e in ev] == [(proc, kind)])


def test_oom_lines_of_one_kill_count_once():
    lines = ['Mar 10 09:00:00 fw kernel: Out of memory: Kill process 900 (big) score 9',
             'Mar 10 09:00:00 fw kernel: oom-kill:constraint=X,task=big,pid=900,uid=0',
             'Mar 10 09:00:01 fw kernel: Killed process 900 (big) total-vm:1kB',
             'Mar 10 09:05:00 fw kernel: Killed process 901 (big) total-vm:1kB']
    ev = evaluate_log_events(kernel(lines))['logs']['kernel']['events']
    assert [(e['process'], e['type'], e['count'], e['pids']) for e in ev] == [
        ('big', 'oom-kill', 2, ['900', '901'])]


def test_five_events_are_critical_four_are_info():
    v = kview(klines('myproc[1]: segfault at 0 ip 0 sp 0', 5))
    assert codes(v) == ['KERNEL_CRASH']
    f = v['findings'][0]
    assert f['level'] == 'crit' and 'myproc' in f['text'] and '5 segfault' in f['text']
    assert 'no year' in f['text']
    assert v['checks'][0]['status'] == 'critical' and v['checks'][0]['id'] == 'kernel'
    v = kview(klines('myproc[1]: segfault at 0 ip 0 sp 0', 4))
    assert codes(v) == ['KERNEL_CRASH_SEEN'] and v['findings'][0]['level'] == 'info'
    assert 'myproc segfault x4' in v['findings'][0]['text']
    assert v['checks'][0]['status'] == 'ok'          # info never raises the status
    v = kview(klines('myproc[1]: segfault at 0 ip 0 sp 0', 4), crash_min=4)
    assert codes(v) == ['KERNEL_CRASH']


def test_same_process_different_types_are_separate_and_mixed_levels():
    lines = (klines('a[1]: segfault at 0 ip 0 sp 0', 5) + klines('a[1]: segfault at 0', 0)
             + klines('traps: a[1] general protection fault ip:1', 2))
    v = kview(lines)
    assert sorted(codes(v)) == ['KERNEL_CRASH', 'KERNEL_CRASH_SEEN']


def test_non_kernel_and_unrelated_kernel_lines_are_ignored():
    lines = ['Mar 10 09:00:00 fw sshd[1]: segfault at 0 ip 0',
             ('Mar 10 09:00:00 fw kernel: udevd (1170): /proc/1170/oom_adj is deprecated, '
              'please use /proc/1170/oom_score_adj instead.'),
             'Mar 10 09:00:00 fw kernel: SMP: Booting CPU02 (CoreId  2)...',
             'Mar 10 09:00:00 fw logger: Killed process 5 (x)']
    st = kernel(lines)
    v = evaluate_log_events(st)
    assert not v['findings'] and st['kernel']['lines'] == 2
    assert v['checks'][0]['status'] == 'ok' and '0 crash event' in v['checks'][0]['value']


def test_kernel_times_are_as_written_and_not_utc():
    v = kview(klines('myproc[1]: segfault at 0 ip 0 sp 0', 5))
    ev = v['logs']['kernel']['events'][0]
    assert ev['first'] == 'Mar 10 09:02:00' and ev['last'] == 'Mar 10 09:02:04'
    assert 'no year' in v['logs']['kernel']['time_note']


def test_no_messages_file_is_no_data():
    v = evaluate_log_events(new_store())
    assert [(c['id'], c['status']) for c in v['checks']] == [
        ('kernel', 'no_data'), ('log_errors', 'no_data'), ('commits', 'no_data')]
    assert {c['group'] for c in v['checks']} == {'Logs'}


# --------------------------------------------------------------------------
# B) Daemon logs
# --------------------------------------------------------------------------
def test_normalisation_of_pids_hex_and_paths():
    text = (f'{TS} Error:  failed pid 12345 at 0xDEADBEEF (client_id=987654) '
            f'file[/opt/x/1234/y.xml] port 22\n'
            f'{TS} Error:  failed pid 99999 at 0x1f (client_id=111111) '
            f'file[/opt/x/1234/y.xml] port 22\n')
    st = daemon(text)[1]
    keys = list(st['daemons']['devsrv']['msgs'])
    assert keys == ['Error: failed pid N at 0xH (client_id=N) file[/opt/x/1234/y.xml] port 22']
    assert st['daemons']['devsrv']['msgs'][keys[0]][0] == 2
    assert log_events.normalize_message("see '/a/b/1234' and [/c/5678] 4567") == \
        "see '/a/b/1234' and [/c/5678] N"


def test_repeat_threshold_flags_at_20_not_19():
    v = dview(err_lines('Failed to open file[/opt/x/v]', 20))
    assert codes(v) == ['LOG_ERROR_REPEAT']
    f = v['findings'][0]
    assert f['level'] == 'warn' and '20 times' in f['text'] and 'devsrv.log' in f['text']
    assert 'first 2026-03-10 01:00:00 UTC' in f['text'] and 'last 2026-03-10 01:19:00 UTC' in f['text']
    assert v['checks'][1]['status'] == 'warning'
    v = dview(err_lines('Failed to open file[/opt/x/v]', 19))
    assert codes(v) == [] and v['checks'][1]['status'] == 'ok'
    v = dview(err_lines('Failed to open file[/opt/x/v]', 19), log_repeat_min=19)
    assert codes(v) == ['LOG_ERROR_REPEAT']


def test_ids_collapse_into_one_message_for_the_repeat_count():
    text = ''.join(f'{TS} Error:  conn {1000 + i} lost, pid {50000 + i}\n' for i in range(25))
    v = dview(text)
    assert codes(v) == ['LOG_ERROR_REPEAT'] and '25 times' in v['findings'][0]['text']


@pytest.mark.parametrize('line, is_err', [
    (f'{TS} Error:  boom', True),
    (f'{TS} error: boom', True),
    (f'{TS} ERROR boom', True),
    (f'{TS} ERROR: boom', True),
    (f'{TS} CRIT: boom', True),
    (f'{TS} Critical: boom', True),
    (f'{TS} fatal: boom', True),
    ('error: cannot stat /etc/logrotate.d/frr: No such file or directory', True),
    (f'{TS} {TS} Error:  doubled timestamp', True),
    (f'{TS} Warning:  boom', False),
    (f'{TS} INFO: operation completed with no error', False),
    (f'{TS} Result: 0 errors found', False),
    (f'{TS} Error code 5 reported', False),       # no colon, not capitals: not a level token
    (f'{TS} something failed: Error: later in the text', False),
    ('plain text without timestamp', False),
])
def test_error_line_heuristic(line, is_err):
    n, _st = daemon(line + '\n')
    assert n == (1 if is_err else 0)


def test_doubled_timestamp_and_no_timestamp_messages_are_the_same_key():
    text = f'{TS} {TS} Error:  boom 12345\n{TS} Error:  boom 99999\nError:  boom 54321\n'
    st = daemon(text)[1]
    msgs = st['daemons']['devsrv']['msgs']
    assert list(msgs) == ['Error: boom N'] and msgs['Error: boom N'][0] == 3
    # 2 of the 3 occurrences carry a timestamp: recent count 2 < 3, so chronic, not a warning
    v = evaluate_log_events(st, {'log_repeat_min': 3})
    assert codes(v) == ['LOG_ERROR_CHRONIC']
    v = evaluate_log_events(st, {'log_repeat_min': 2})
    assert codes(v) == ['LOG_ERROR_REPEAT']


def test_message_without_timestamp_is_chronic_and_has_no_utc_time():
    text = '2026-03-10 02:00:00.000 +0100 INFO: reference line\n' + 'error: cannot stat /etc/x\n' * 21
    v = dview(text)
    assert codes(v) == ['LOG_ERROR_CHRONIC'] and v['findings'][0]['level'] == 'info'
    assert v['logs']['daemons']['rows'][0]['messages'][0]['first'] is None
    assert v['checks'][1]['status'] == 'ok'


def test_first_last_across_files_and_files_listed():
    st = new_store()
    daemon(err_lines('same', 10, 30), store=st, src='devsrv.log.old')
    daemon(err_lines('same', 12, 0), store=st, src='devsrv.log')
    v = evaluate_log_events(st)
    assert codes(v) == ['LOG_ERROR_REPEAT'] and '22 times' in v['findings'][0]['text']
    m = v['logs']['daemons']['rows'][0]['messages'][0]
    assert m['files'] == ['devsrv.log', 'devsrv.log.old'] and m['count'] == 22


def test_flag_cap_and_aggregate_declared():
    text = ''.join(err_lines(f'distinct problem {chr(97 + i)}', 20 + i) for i in range(25))
    v = dview(text)
    flags = [f for f in v['findings'] if f['code'] == 'LOG_ERROR_REPEAT']
    assert len(flags) == log_events.MAX_REPEAT_FLAGS + 1
    assert 'distinct problem y' in flags[0]['text']             # most frequent first
    assert flags[-1]['subject'] == 'other repeated messages' and '5 more' in flags[-1]['text']
    assert any('summarised in one flag' in b for b in v['logs']['budgets'])
    assert v['warnings'] and 'budgets' in v['warnings'][0]
    assert v['logs']['daemons']['n_flagged'] == 25


def test_view_lists_at_most_50_messages_per_daemon(monkeypatch):
    text = ''.join(f'{TS} Error:  unique problem {chr(65 + i // 26)}{chr(97 + i % 26)}\n'
                   for i in range(60))
    v = dview(text)
    row = v['logs']['daemons']['rows'][0]
    assert len(row['messages']) == log_events.MAX_MSGS_PER_DAEMON_VIEW and row['omitted'] == 10
    assert any('10 less frequent' in b for b in v['logs']['budgets'])
    monkeypatch.setattr(log_events, 'MAX_DISTINCT_PER_DAEMON', 5)
    st = daemon(text)[1]
    d = st['daemons']['devsrv']
    assert len(d['msgs']) == 5 and d['dropped'] == 55 and d['errors'] == 60
    v = evaluate_log_events(st)
    assert any('were not counted' in b for b in v['logs']['budgets'])


def test_candidate_prefilter_equals_a_full_scan():
    lines = []
    for i in range(300):
        lines.append(f'2026-03-10 02:{i % 60:02d}:00.000 +0100 ' + [
            'Error:  a 12345', 'Warning:  b', 'CRIT x', 'info ok', 'COMMIT commit: t',
            'fatal: z', 'err: q 9999', 'the text mentions Error: late', 'Crit: c',
            'Critical: y'][i % 10])
        if i % 7 == 0:
            lines.append('error: no timestamp')
    text = '\n'.join(lines) + '\n'
    brute = [m for m in log_events.LINE_RE.finditer(text)]
    fast = [log_events.LINE_RE.match(text, ls) for ls in log_events._candidate_lines(text)]
    fast = [m for m in fast if m]
    assert [m.start() for m in fast] == [m.start() for m in brute]
    assert len(brute) > 100


def test_chunked_decoding_gives_the_same_counts(monkeypatch):
    data = (err_lines('chunk test', 30) + 'noise line\n' * 50).encode()
    n1, st1 = daemon(data)
    monkeypatch.setattr(log_events, 'CHUNK_BYTES', 200)
    n2, st2 = daemon(data)
    assert n1 == n2 == 30
    assert st1['daemons']['devsrv']['lines'] == st2['daemons']['devsrv']['lines'] == 80


def test_path_regexes():
    m = log_events.DAEMON_PATH_RE
    for ok in ('var/log/pan/devsrv.log', 'var/log/pan/devsrv.log.1', 'var/log/pan/ms.log.old',
               'x/var/log/pan/ikemgr-ng.log.0', 'var/log/pan/ikemgr.log'):
        assert m.search('/' + ok), ok
    for bad in ('var/log/pan/sysd_x.log', 'var/log/pan/mp-monitor.log', 'var/log/pan/pan_task_4.log',
                'var/log/pan/ikemgr-ng.log-2026', 'var/log/pan/devsrv.log.bak'):
        assert not m.search('/' + bad), bad
    assert m.search('/var/log/pan/ikemgr-ng.log').group(1) == 'ikemgr-ng'
    for ok in ('var/log/messages', 'var/log/messages.3', 'var/log/messages.old'):
        assert log_events.MESSAGES_PATH_RE.search('/' + ok)
    assert not log_events.MESSAGES_PATH_RE.search('/var/log/messages-20260101')


# --------------------------------------------------------------------------
# C) Commit windows, jobs, offsets
# --------------------------------------------------------------------------
def configd(lines):
    return '\n'.join(f'2026-03-10 {t} +0100 {rest}' for t, rest in lines) + '\n'


def test_commit_windows_group_by_gap():
    text = configd([('02:06:51.823', 'COMMIT pan_cfg_mgr_a: Time'),
                    ('02:07:50.000', 'COMMIT pan_cfg_mgr_b: Time'),
                    ('02:09:49.000', 'COMMIT commit: Time'),       # 119 s later: same window
                    ('02:20:00.000', 'COMMIT commit: Time'),       # new window
                    ('02:25:00.000', 'Error:  not a commit line'),
                    ('02:26:00.000', 'INFO: commit in the middle')])
    st = daemon(text, 'configd', src='configd.log')[1]
    wins = log_events.commit_windows(st, 120)
    assert [(w['n'], w['daemons']) for w in wins] == [(3, ['configd']), (1, ['configd'])]
    assert (wins[0]['end'] - wins[0]['start']) == 177_177
    assert len(log_events.commit_windows(st, 60)) == 3


def test_commit_lines_need_an_offset_and_ms_is_best_effort():
    st = new_store()
    daemon('COMMIT without timestamp\n', 'configd', st, 'configd.log')
    daemon('2026-03-10 02:06:51.000 +0100 Commit job 5 started\n'
           '2026-03-10 02:06:52.000 +0100 mgmt internal: client certificate profile commit\n',
           'ms', st, 'ms.log')
    daemon('2026-03-10 02:06:51.000 +0100 COMMIT x\n', 'devsrv', st, 'devsrv.log')
    wins = log_events.commit_windows(st, 120)
    assert len(wins) == 1 and wins[0]['n'] == 1 and wins[0]['daemons'] == ['ms']


JOBS = """\
> show jobs processed

Enqueued              Dequeued           ID  PositionInQ                              Type                         Status Result Completed
------------------------------------------------------------------------------------------------------------------------------------------
2026/03/11 10:26:45   10:26:45        26750                                           Exec                            ACT   PEND        10%
2026/03/09 23:58:00   23:58:30        26693                                        Content                            FIN     OK 00:07:11
2026/03/09 02:00:08   02:00:08        26691                                         Downld                            FIN     OK 02:02:07
2026/03/08 16:06:48   16:06:48        26583                                            IoT                            FIN     OK 16:08:48
2026/03/08 16:00:00                   26580            3                         AutoCommit                         PEND   PEND
2026/03/08 15:00:00   15:00:01        26570                                     Commit All                            FIN   FAIL 15:01:00

> show clock
"""


def jobs_store(text=JOBS, days=None):
    st = new_store()
    n = parse_jobs(text.splitlines(), 'cli.txt', st, [])
    assert n == len(st['jobs']['rows'])
    st['offset_days'] = days if days is not None else {
        f'2026-03-{d:02d}': {'+0100': 10} for d in range(7, 13)}
    return st


def test_jobs_parsing_columns_and_types():
    st = jobs_store()
    rows = {r['id']: r for r in st['jobs']['rows']}
    assert len(rows) == 6
    assert rows['26750']['pct'] == '10%'
    assert rows['26750']['done'] is None and rows['26750']['status'] == 'ACT'
    assert rows['26693']['type'] == 'Content' and rows['26693']['done'] == '00:07:11'
    assert rows['26580']['deq'] is None and rows['26580']['position'] == '3'
    assert rows['26580']['type'] == 'AutoCommit' and rows['26580']['result'] == 'PEND'
    assert rows['26570']['type'] == 'Commit All' and rows['26570']['result'] == 'FAIL'


def test_job_midnight_rollover_and_running_job_without_end():
    st = jobs_store()
    tl = evaluate_log_events(st)['logs']['context']['timeline']
    jobs = {r['label'].split()[-1]: r for r in tl if r['kind'] == 'job'}
    c = jobs['26693']
    assert c['offset'] == '+0100' and c['offset_state'] == 'inferred'
    # dequeued 2026-03-09 23:58:30 local = 22:58:30 UTC; completed 00:07:11 next day local.
    assert log_events.utc_str(c['start']) == '2026-03-09 22:58:30 UTC'
    assert log_events.utc_str(c['end']) == '2026-03-09 23:07:11 UTC'
    run = jobs['26750']
    assert run['running'] and run['end'] is None and log_events.utc_str(run['start']) == \
        '2026-03-11 09:26:45 UTC'
    pend = jobs['26580']                      # never dequeued: enqueue time, no end
    assert pend['running'] and log_events.utc_str(pend['start']) == '2026-03-08 15:00:00 UTC'


def test_jobs_first_section_wins_and_warns_for_another_file():
    st = jobs_store()
    w = []
    assert parse_jobs(JOBS.splitlines(), 'other.txt', st, w) == 0
    assert st['jobs']['duplicates'] == 1 and any('already read' in x for x in w)


@pytest.mark.parametrize('days, day, expected', [
    ({}, date(2026, 3, 10), (None, 'unknown')),
    ({'2026-03-09': {'+0100': 4}}, date(2026, 3, 10), ('+0100', 'inferred')),
    ({'2026-03-07': {'+0100': 4}}, date(2026, 3, 10), ('+0100', 'inferred')),      # 3 days: nearest
    ({'2026-03-06': {'+0100': 4}}, date(2026, 3, 10), (None, 'unknown')),          # too far
    # DST change on the 29th: the most frequent offset differs between the dates around it.
    ({'2026-03-28': {'+0100': 9}, '2026-03-29': {'+0200': 6, '+0100': 3},
      '2026-03-30': {'+0200': 9}}, date(2026, 3, 29), (None, 'ambiguous')),
    ({'2026-03-28': {'+0100': 9}, '2026-03-29': {'+0200': 6, '+0100': 3},
      '2026-03-30': {'+0200': 9}}, date(2026, 3, 28), (None, 'ambiguous')),
    ({'2026-03-28': {'+0100': 9}, '2026-03-29': {'+0100': 9}, '2026-03-30': {'+0200': 9}},
     date(2026, 3, 30), (None, 'ambiguous')),
    ({'2026-03-27': {'+0100': 9}, '2026-03-28': {'+0100': 9}, '2026-03-29': {'+0100': 9}},
     date(2026, 3, 27), ('+0100', 'inferred')),
    # another representation of the same instant (e.g. a subprocess time zone): vote
    ({'2026-03-09': {'+0100': 80, '-0700': 20}, '2026-03-10': {'+0100': 80, '-0700': 20}},
     date(2026, 3, 10), ('+0100', 'inferred')),
    ({'2026-03-09': {'+0100': 50, '-0700': 50}}, date(2026, 3, 10), (None, 'ambiguous')),
])
def test_infer_offset(days, day, expected):
    assert infer_offset({'offset_days': days}, day) == expected


def test_offsets_are_collected_from_daemon_logs_and_taps():
    st = new_store()
    daemon(err_lines('x', 3, off='+0100'), store=st)
    list(log_events.tap_offsets(
        ['2026-03-11 10:00:00.000 -0700  --- memory', 'noise',
         '2026-03-11 10:30:00.000 -0700  --- memory'], st))
    assert set(st['offset_days']['2026-03-10']) == {'+0100'}
    assert st['offset_days']['2026-03-11'] == {'-0700': 1}       # one sample per date and hour


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------
def utc_ms(day, hms):
    from datetime import datetime, timezone
    return int(datetime.strptime(f'{day} {hms}', '%Y-%m-%d %H:%M:%S')
               .replace(tzinfo=timezone.utc).timestamp() * 1000)


def ctx_store(commit_lines=True):
    st = jobs_store()
    if commit_lines:
        daemon(configd([('02:06:51.000', 'COMMIT a'), ('02:08:00.000', 'COMMIT b')]),
               'configd', st, 'configd.log')
    return st


def mp_stub(start, end, name='configd', level='warn'):
    flag = {'code': 'PROC_CPU', 'level': level, 'text': f'Process {name}: CPU high.',
            'subject': name}
    return {'procs': [{'name': name, 'run_start': start, 'run_end': end}],
            'findings': [flag], 'memory': {'summary': None}}, flag


def test_proc_cpu_run_near_commit_window_is_correlated_and_flag_kept():
    st = ctx_store()
    # commit window 01:06:51 - 01:08:00 UTC; run starts 90 s after its end
    mp, flag = mp_stub(utc_ms('2026-03-10', '01:09:30'), utc_ms('2026-03-10', '01:12:00'))
    v = evaluate_log_events(st, None, mp, None)
    near = [f for f in v['findings'] if f['code'] == 'NEAR_COMMIT']
    assert len(near) == 1 and near[0]['level'] == 'info'
    assert 'PROC_CPU configd' in near[0]['text'] and 'commit window' in near[0]['text']
    assert flag['level'] == 'warn' and flag['code'] == 'PROC_CPU'          # never changed
    assert flag['text'].startswith('Process configd: CPU high.') and ' Near commit window' in flag['text']
    ctx = v['logs']['context']
    assert ctx['n_correlations'] == 1 and v['checks'][2]['status'] == 'ok'
    assert '1 item(s) near' in v['checks'][2]['value']


def test_run_outside_the_margin_is_not_correlated():
    st = ctx_store()
    mp, flag = mp_stub(utc_ms('2026-03-10', '01:09:31'), utc_ms('2026-03-10', '01:12:00'))
    v = evaluate_log_events(st, None, mp, None)
    assert 'NEAR_COMMIT' not in codes(v) and flag['text'] == 'Process configd: CPU high.'
    assert v['logs']['context']['n_correlations'] == 0
    v = evaluate_log_events(ctx_store(), {'corr_window_s': 100}, mp_stub(
        utc_ms('2026-03-10', '01:09:31'), utc_ms('2026-03-10', '01:12:00'))[0], None)
    assert 'NEAR_COMMIT' in codes(v)


def test_job_correlation_says_offset_inferred():
    st = ctx_store(commit_lines=False)
    # job 26691 dequeued 02:00:08 local = 01:00:08 UTC, completed 01:02:07 UTC
    mp, flag = mp_stub(utc_ms('2026-03-09', '01:01:00'), utc_ms('2026-03-09', '01:01:30'))
    v = evaluate_log_events(st, None, mp, None)
    near = [f for f in v['findings'] if f['code'] == 'NEAR_COMMIT']
    assert len(near) == 1 and 'Downld job 26691' in near[0]['text']
    assert 'offset inferred (+0100)' in near[0]['text']
    assert 'offset inferred +0100' in flag['text']
    item = v['logs']['context']['correlations'][0]
    assert item['jobs'][0]['id'] == '26691' and item['windows'] == []
    row = next(r for r in v['logs']['context']['timeline'] if r['label'].endswith('26691'))
    assert row['near'] == ['PROC_CPU configd']


def test_running_job_is_not_correlated():
    st = ctx_store(commit_lines=False)
    mp, _flag = mp_stub(utc_ms('2026-03-11', '09:27:00'), utc_ms('2026-03-11', '09:28:00'))
    assert 'NEAR_COMMIT' not in codes(evaluate_log_events(st, None, mp, None))


def test_dst_ambiguous_job_is_not_correlated_but_commit_window_is():
    days = {'2026-03-28': {'+0100': 9}, '2026-03-29': {'+0200': 6, '+0100': 3},
            '2026-03-30': {'+0200': 9}}
    jobs = ('> show jobs processed\n\nEnqueued Dequeued ID PositionInQ Type Status Result '
            'Completed\n-----\n'
            '2026/03/29 05:00:00   05:00:00        1000     Content   FIN     OK 05:10:00\n')
    st = jobs_store(jobs, days)
    daemon('2026-03-29 05:04:00.000 +0200 COMMIT a\n2026-03-29 05:04:20.000 +0200 COMMIT b\n',
           'configd', st, 'configd.log')
    mp, flag = mp_stub(utc_ms('2026-03-29', '03:04:00'), utc_ms('2026-03-29', '03:04:30'))
    v = evaluate_log_events(st, None, mp, None)
    near = [f for f in v['findings'] if f['code'] == 'NEAR_COMMIT']
    assert len(near) == 1 and 'commit window' in near[0]['text'] and 'job 1000' not in near[0]['text']
    job = next(r for r in v['logs']['context']['timeline'] if r['kind'] == 'job')
    assert job['offset_state'] == 'ambiguous' and job['start'] is None
    assert v['logs']['context']['job_offsets'] == {'ambiguous': 1}
    assert 'without a usable offset' in v['checks'][2]['note']
    assert flag['level'] == 'warn'
    # with the commit window removed nothing is near any more
    st2 = jobs_store(jobs, days)
    mp2, _f2 = mp_stub(utc_ms('2026-03-29', '03:04:00'), utc_ms('2026-03-29', '03:04:30'))
    assert 'NEAR_COMMIT' not in codes(evaluate_log_events(st2, None, mp2, None))


def test_memory_peak_and_core_peaks_are_correlated():
    st = ctx_store()
    t_commit = utc_ms('2026-03-10', '01:07:00')
    mflag = {'code': 'MP_MEMORY_PAST_PEAK', 'level': 'warn', 'text': 'peak', 'subject': 'memory'}
    mp = {'procs': [], 'findings': [mflag], 'memory': {'summary': {'peak_t': t_commit}}}
    d1 = {'code': 'CORE_PEAK', 'level': 'warn', 'text': 'cp', 'dp': 'dp0'}
    d2 = {'code': 'CORE_PEAK_MINUTE', 'level': 'warn', 'text': 'cm', 'dp': 'dp0'}
    d3 = {'code': 'CORE_PEAK', 'level': 'warn', 'text': 'far', 'dp': 'dp1'}
    dph = {'findings': [d1, d2, d3], 'summary': {
        'dp0': {'core': {'peak_t': t_commit + 60_000},
                'core_minute': {'peak_t': utc_ms('2026-03-10', '01:20:00')}},   # covers 01:05-01:20
        'dp1': {'core': {'peak_t': utc_ms('2026-03-10', '05:00:00')},
                'core_minute': {'peak_t': None}}}}
    v = evaluate_log_events(st, None, mp, dph)
    labels = sorted(f['subject'] for f in v['findings'] if f['code'] == 'NEAR_COMMIT')
    assert labels == ['CORE_PEAK DP dp0', 'CORE_PEAK_MINUTE DP dp0', 'MP_MEMORY_PAST_PEAK (memory peak)']
    assert 'Near' in mflag['text'] and 'Near' in d1['text'] and d3['text'] == 'far'
    assert [d1['level'], d2['level'], mflag['level']] == ['warn'] * 3


def test_near_findings_are_capped(monkeypatch):
    monkeypatch.setattr(log_events, 'MAX_NEAR_FINDINGS', 2)
    st = ctx_store()
    flags = [{'code': 'PROC_CPU', 'level': 'warn', 'text': 't', 'subject': f'p{i}'} for i in range(4)]
    mp = {'procs': [{'name': f'p{i}', 'run_start': utc_ms('2026-03-10', '01:07:00'),
                     'run_end': utc_ms('2026-03-10', '01:07:10')} for i in range(4)],
          'findings': flags, 'memory': {'summary': None}}
    v = evaluate_log_events(st, None, mp, None)
    near = [f for f in v['findings'] if f['code'] == 'NEAR_COMMIT']
    assert len(near) == 3 and near[-1]['subject'] == 'other items'
    assert all(f['level'] == 'warn' for f in flags) and all('Near' in f['text'] for f in flags)
    assert any('summarised in one finding' in b for b in v['logs']['budgets'])


def test_unknown_threshold_raises():
    with pytest.raises(ValueError):
        evaluate_log_events(new_store(), {'nope': 1})


def test_view_is_json_serialisable():
    st = ctx_store()
    daemon(err_lines('x 12345', 30), store=st)
    kernel(klines('p[1]: segfault at 0', 6), st)
    mp, _f = mp_stub(utc_ms('2026-03-10', '01:07:00'), utc_ms('2026-03-10', '01:07:10'))
    json.dumps(evaluate_log_events(st, None, mp, None))


# --------------------------------------------------------------------------
# Archive, analyzer, coverage, report
# --------------------------------------------------------------------------
def build_tgz(path, entries):
    with tarfile.open(path, 'w:gz') as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def mp_monitor_text(off='+0100'):
    header = ('Name                   PID      CPU%  FDs Open   Virt Mem     Res+Swap     '
              'State      Res+Swap-Lazy   ')
    out = []
    for minute in (8, 9, 10):
        out += [f'2026-03-10 02:{minute:02d}:00.000 {off}  --- processes', 'Total num processes: 2',
                header,
                f'{"idle":<22} {1:<8} {0:<5} {9:<10} {358116:<12} {1000:<12} {"S":<10}',
                f'{"fakedaemon":<22} {2:<8} {100:<5} {9:<10} {358116:<12} {1000:<12} {"S":<10}',
                '-----------------------------']
    return '\n'.join(out) + '\n'


def sample_archive(path):
    cfg = configd([('02:06:51.823', 'COMMIT pan_cfg_mgr_a: Time'),
                   ('02:08:30.000', 'COMMIT commit: Time')])
    dev = ''.join(err_lines('Failed to open file[/opt/x/v]', 25, 0, off='+0100')
                  .replace('2026-03-10', f'2026-03-{d:02d}') for d in (9, 10, 11))
    kern = ('\n'.join(klines('myproc[1]: segfault at 0 ip 0 sp 0', 5, 'fwtest')) + '\n').encode()
    cli = (JOBS.replace('2026/03/09 23:58:00   23:58:30', '2026/03/10 02:04:46   02:04:46')
           .replace('00:07:11', '02:14:11')).encode()
    build_tgz(path, [
        ('var/log/messages', kern),
        ('var/log/messages.1.gz', gzip.compress(b'Mar  1 01:00:00 fwtest kernel: boot\n')),
        ('var/log/pan/devsrv.log', dev.encode()),
        ('var/log/pan/configd.log', cfg.encode()),
        ('var/log/pan/sysd_x.log', b'2026-03-10 02:00:00.000 +0100 Error:  ignored daemon\n'),
        ('var/log/pan/mp-monitor.log', mp_monitor_text().encode()),
        ('tmp/cli/techsupport_fwtest_20260311_1000.txt', cli)])


def collect(path):
    w = []
    return analyzer.collect(str(path), w), w


def test_select_family():
    sel = analyzer._select_family
    assert sel('var/log/messages') == 'messages' and sel('var/log/messages.2') == 'messages'
    assert sel('var/log/pan/configd.log.old') == 'daemon-log'
    assert sel('var/log/pan/sysd_x.log') is None and sel('var/log/messages-2026') is None


def test_archive_collects_logs_and_coverage_lists_the_families(tmp_path):
    p = tmp_path / 'a.tgz'
    sample_archive(p)
    col, _w = collect(p)
    st = col.log_data
    assert st['kernel']['files'] == ['messages.1.gz', 'messages']      # rotation order
    assert sorted(st['daemons']) == ['configd', 'devsrv']
    assert len(st['jobs']['rows']) == 6 and st['commit_ts']
    assert '2026-03-10' in st['offset_days'] and '+0100' in st['offset_days']['2026-03-10']
    cov = analyzer.build_coverage(col)
    fams = {f['family']: f for f in cov['families']}
    assert fams['messages']['found'] == 2 and fams['messages']['read'] == 2
    assert fams['daemon-log']['found'] == 2 and 'ok' in fams['daemon-log']['states']
    assert [m['name'] for m in fams['daemon-log']['members']] == [
        'var/log/pan/devsrv.log', 'var/log/pan/configd.log']
    # absent families are listed too
    p2 = tmp_path / 'b.tgz'
    build_tgz(p2, [('tmp/cli/techsupport_x.txt', b'> show clock\nx\n')])
    fams2 = {f['family']: f for f in analyzer.build_coverage(collect(p2)[0])['families']}
    assert fams2['messages']['states'] == ['absent'] and fams2['daemon-log']['states'] == ['absent']


def test_log_limits_apply_to_the_new_families(tmp_path, monkeypatch):
    p = tmp_path / 'a.tgz'
    sample_archive(p)
    monkeypatch.setattr(archive, 'MAX_MEMBER_BYTES', 300)
    col, w = collect(p)
    cov = analyzer.build_coverage(col)
    fams = {f['family']: f for f in cov['families']}
    assert 'truncated' in fams['daemon-log']['states'] and col.status == 'partial'
    assert any('larger than the read limit' in x for x in w)


def report_data(out):
    m = re.search(r'const D = (\{.*?\});\nconst \$', out, re.DOTALL)
    return json.loads(m.group(1).replace('<\\/', '</'))


def run_report(tmp_path, *extra):
    p = tmp_path / 'fwtest.tgz'
    sample_archive(p)
    outdir = tmp_path / 'out'
    analyzer.main([str(p), '-o', str(outdir), *extra])
    path = next(outdir.glob('fwtest_*.html'))
    return path, path.read_text(encoding='utf-8')


def test_report_has_logs_group_correlation_and_help(tmp_path):
    _path, out = run_report(tmp_path)
    data = report_data(out)
    sysv = data['sys']
    logs = [c for c in sysv['checks'] if c['group'] == 'Logs']
    assert [(c['id'], c['status']) for c in logs] == [
        ('kernel', 'critical'), ('log_errors', 'warning'), ('commits', 'ok')]
    got = sorted(f['code'] for f in sysv['findings'])
    assert got.count('KERNEL_CRASH') == 1 and got.count('LOG_ERROR_REPEAT') == 1
    assert got.count('NEAR_COMMIT') == 1                                    # fakedaemon run
    near = next(f for f in sysv['findings'] if f['code'] == 'NEAR_COMMIT')
    assert 'PROC_CPU fakedaemon' in near['text'] and 'offset inferred (+0100)' in near['text']
    # the PROC_CPU flag of the Management plane tab is kept, with the note
    pc = next(f for f in data['mp']['findings'] if f['code'] == 'PROC_CPU')
    assert pc['level'] == 'warn' and 'Near' in pc['text'] and pc['subject'] == 'fakedaemon'
    assert sysv['status'] == 'critical'
    assert sysv['thresholds']['crash_min'] == 5 and sysv['thresholds']['cfg_mem_warn'] == 50
    ctx = sysv['logs']['context']
    assert ctx['n_windows'] == 1 and ctx['n_jobs'] == 6
    kinds = [r['kind'] for r in ctx['timeline']]
    assert kinds.count('commit') == 1 and kinds.count('job') == 6
    # coverage and help
    assert {f['family'] for f in data['coverage']['families']} >= {'messages', 'daemon-log'}
    for code in FLAG_CODES:
        assert f'<code>{code}</code>' in out
    assert 'crash_min = 5 events' in out and 'log_repeat_min = 20 occurrences' in out
    assert '__HB_' not in out and '__HP_' not in out
    for fn in ('sysDetailKernel', 'sysDetailLogErrors', 'sysDetailCommits'):
        assert fn in out
    assert 'kernel:sysDetailKernel' in out and 'commits:sysDetailCommits' in out


def test_cli_options_reach_the_view_and_the_help(tmp_path):
    _p, out = run_report(tmp_path, '--sys-crash-min', '6', '--sys-log-repeat-min', '100',
                         '--sys-corr-window-s', '45', '--sys-commit-gap-s', '10',
                         '--sys-cfg-mem-warn', '60')
    data = report_data(out)
    th = data['sys']['thresholds']
    assert (th['crash_min'], th['log_repeat_min'], th['corr_window_s'], th['commit_gap_s'],
            th['cfg_mem_warn']) == (6, 100, 45, 10, 60)
    codes_ = [f['code'] for f in data['sys']['findings']]
    assert 'KERNEL_CRASH' not in codes_ and 'KERNEL_CRASH_SEEN' in codes_
    assert 'LOG_ERROR_REPEAT' not in codes_
    assert 'crash_min = 6 events' in out and 'log_repeat_min = 100' in out


def test_every_log_option_exists_and_negative_is_rejected(tmp_path):
    import sys
    helptext = subprocess.run([sys.executable, '-m', 'panos_toolbox.tsf.analyzer', '--help'],
                              check=False, capture_output=True, text=True).stdout
    for key in LOG_THRESHOLDS:
        assert '--sys-' + key.replace('_', '-') in helptext
    with pytest.raises(SystemExit):
        analyzer.main([str(tmp_path / 'x'), '-o', str(tmp_path), '--sys-crash-min', '-1'])


def test_report_without_logs_has_no_logs_view(tmp_path):
    sample = Path(__file__).parent / 'data' / 'cli_system_health_sample.txt'
    outdir = tmp_path / 'out'
    analyzer.main([str(sample), '-o', str(outdir)])
    out = next(outdir.glob('*.html')).read_text(encoding='utf-8')
    data = report_data(out)
    assert 'logs' not in data['sys'] and {c['group'] for c in data['sys']['checks']} == {
        'CLI snapshot', 'Archive members'}


def test_jobs_only_cli_file_gives_a_sys_report(tmp_path):
    f = tmp_path / 'jobs.txt'
    f.write_text(JOBS, encoding='utf-8')
    outdir = tmp_path / 'out'
    analyzer.main([str(f), '-o', str(outdir)])
    out = next(outdir.glob('*_sys.html')).read_text(encoding='utf-8')
    sysv = report_data(out)['sys']
    commits = next(c for c in sysv['checks'] if c['id'] == 'commits')
    assert commits['status'] == 'ok' and sysv['logs']['context']['n_jobs'] == 6
    assert sysv['logs']['context']['job_offsets'] == {'unknown': 6}   # no explicit-offset header


def test_help_documents_the_caps_normalisation_and_offset_rule():
    from panos_toolbox.tsf.report_help import render_section_help
    out = ''.join(render_section_help().values())
    for text in ('no year and no UTC offset', 'normalised', 'offset is inferred', 'ambiguous',
                 'not de-duplicated', 'At most 20 messages', 'at most 50 messages per daemon',
                 'never changes any level', 'daemon-log'):
        assert text in out, text
    assert not re.search(r'\{[a-z_]+\}', out)


@pytest.mark.skipif(shutil.which('node') is None, reason='node not available')
def test_generated_javascript_is_valid(tmp_path):
    _p, out = run_report(tmp_path)
    scripts = re.findall(r'<script>(.*?)</script>', out, re.DOTALL)
    js = tmp_path / 'report.js'
    js.write_text(scripts[-1], encoding='utf-8')
    res = subprocess.run(['node', '--check', str(js)], check=False, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


# --------------------------------------------------------------------------
# Tuning: recent vs chronic repeats, commit_min_lines
# --------------------------------------------------------------------------
def timed(msg, stamps, off='+0000'):
    return ''.join(f'{t} {off} Error:  {msg}\n' for t in stamps)


def recent_store(n_old, n_recent, boundary='2026-03-09 12:00:00.000'):
    """`n_recent` occurrences at/after the boundary, `n_old` just before it, TSF end 03-10 12:00."""
    old = [f'2026-03-09 11:{i % 60:02d}:00.000' for i in range(n_old)]
    rec = [boundary] * n_recent
    end = '2026-03-10 12:00:00.000 +0000 INFO: end of the log\n'
    return daemon(timed('boom', old + rec) + end)[1]


def test_recent_count_decides_warning_versus_chronic():
    v = evaluate_log_events(recent_store(30, 20))
    assert codes(v) == ['LOG_ERROR_REPEAT']
    f = v['findings'][0]
    assert '20 times in the last 24 h' in f['text'] and '50 in total' in f['text']
    assert v['checks'][1]['status'] == 'warning'
    row = v['logs']['daemons']['rows'][0]
    assert (row['n_recent'], row['n_chronic'], row['level']) == (1, 0, 'warn')
    assert row['messages'][0]['recent'] == 20 and row['messages'][0]['count'] == 50
    v = evaluate_log_events(recent_store(30, 19))
    assert codes(v) == ['LOG_ERROR_CHRONIC'] and v['checks'][1]['status'] == 'ok'
    assert '49 occurrences' in v['findings'][0]['text']


def test_recent_window_boundary_is_exactly_24_hours_inclusive():
    # TSF end = 2026-03-10 12:00:00.000; the window starts at 2026-03-09 12:00:00.000
    on = evaluate_log_events(recent_store(0, 20, '2026-03-09 12:00:00.000'))
    off = evaluate_log_events(recent_store(0, 20, '2026-03-09 11:59:59.999'))
    assert codes(on) == ['LOG_ERROR_REPEAT'] and codes(off) == ['LOG_ERROR_CHRONIC']
    wide = evaluate_log_events(recent_store(0, 20, '2026-03-09 11:59:59.999'),
                               {'log_recent_h': 25})
    assert codes(wide) == ['LOG_ERROR_REPEAT']


def test_no_reference_time_everything_is_chronic():
    v = dview('error: boom\n' * 25)
    assert codes(v) == ['LOG_ERROR_CHRONIC'] and 'No reference time' in v['findings'][0]['text']
    assert v['logs']['daemons']['ref_end'] is None


def test_one_chronic_finding_per_daemon_with_top_three():
    st = new_store()
    end = '2026-03-10 12:00:00.000 +0000 INFO: end\n'
    for name in ('devsrv', 'authd'):
        text = ''.join(timed(f'old problem {k}', [f'2026-03-01 10:{i:02d}:00.000' for i in range(21 + k)])
                       for k in range(5))
        daemon(text + end, name, st, f'{name}.log')
    v = evaluate_log_events(st)
    ch = [f for f in v['findings'] if f['code'] == 'LOG_ERROR_CHRONIC']
    assert sorted(f['subject'] for f in ch) == ['authd (chronic)', 'devsrv (chronic)']
    assert '5 message(s)' in ch[0]['text'] and 'old problem 4' in ch[0]['text']
    assert 'old problem 1' not in ch[0]['text'] or 'old problem 2' in ch[0]['text']
    assert ch[0]['text'].count(' x') == 3
    assert v['logs']['daemons']['n_chronic'] == 10 and v['checks'][1]['status'] == 'ok'


def test_reference_time_is_the_latest_timestamp_of_daemon_logs_and_monitors():
    st = new_store()
    daemon('2026-03-10 02:00:00.000 +0100 INFO: a\nnoise\n2026-03-10 03:00:00.000 +0100 INFO: b\n')
    assert st['last_ts'] is None
    st = daemon('2026-03-10 02:00:00.000 +0100 INFO: a\n2026-03-10 03:00:00.000 +0100 INFO: b\nx\n')[1]
    assert log_events.utc_str(st['last_ts']) == '2026-03-10 02:00:00 UTC'
    list(log_events.tap_offsets(['2026-03-10 04:00:00.000 +0100  --- memory', 'x'], st))
    assert log_events.utc_str(st['last_ts']) == '2026-03-10 03:00:00 UTC'


def test_commit_single_line_discarded_and_two_lines_kept():
    st = ctx_store(commit_lines=False)
    daemon(configd([('02:06:51.000', 'COMMIT a')]), 'configd', st, 'configd.log')
    mp, flag = mp_stub(utc_ms('2026-03-10', '01:07:00'), utc_ms('2026-03-10', '01:07:10'))
    v = evaluate_log_events(st, None, mp, None)
    ctx = v['logs']['context']
    assert ctx['n_windows'] == 0 and ctx['n_discarded_lines'] == 1
    assert 'NEAR_COMMIT' not in codes(v) and flag['text'] == 'Process configd: CPU high.'
    assert all(r['kind'] == 'job' for r in ctx['timeline'])
    assert '1 single line(s) ignored' in v['checks'][2]['value']
    daemon(configd([('02:07:30.000', 'COMMIT b')]), 'configd', st, 'configd.log')
    v = evaluate_log_events(st, None, mp, None)
    assert v['logs']['context']['n_windows'] == 1 and 'NEAR_COMMIT' in codes(v)
    v = evaluate_log_events(st, {'commit_min_lines': 3}, mp_stub(
        utc_ms('2026-03-10', '01:07:00'), utc_ms('2026-03-10', '01:07:10'))[0], None)
    assert v['logs']['context']['n_windows'] == 0 and v['logs']['context']['n_discarded_lines'] == 2


def test_cli_overrides_for_the_new_thresholds(tmp_path):
    _p, out = run_report(tmp_path, '--sys-log-recent-h', '12', '--sys-commit-min-lines', '3')
    th = report_data(out)['sys']['thresholds']
    assert th['log_recent_h'] == 12 and th['commit_min_lines'] == 3
    assert report_data(out)['sys']['logs']['context']['n_windows'] == 0
    assert 'log_recent_h = 12 h' in out and 'commit_min_lines = 3' in out
    for opt in ('--sys-log-recent-h', '--sys-commit-min-lines'):
        with pytest.raises(SystemExit):
            analyzer.main([str(tmp_path / 'x'), '-o', str(tmp_path), opt, '-1'])


def test_report_groups_info_findings_and_collapses_sections(tmp_path):
    _p, out = run_report(tmp_path)
    for text in ('informational finding(s)', "sysEl('details')", 'Commit and job timeline (',
                 'recent of', 'LOG_ERROR_CHRONIC'):
        assert text in out, text

"""Tests for the not-running process vs kernel crash correlation (synthetic data only).

Standard library only; no device is contacted.
"""
from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import tarfile

import pytest

from panos_toolbox.tsf import analyzer, correlations, log_events, system_health
from panos_toolbox.tsf.correlations import evaluate_correlations, names_match, normalize_name


def sw_text(rows, header='Slot 1, Role mp'):
    body = ['> show system software status', '', header, '-' * 40, '',
            'Type     Name                           State    Info', *rows, '']
    return '\n'.join(body)


def kern(*crashes):
    """crashes: (comm, n) pairs of segfault lines."""
    out = []
    for comm, n in crashes:
        out += [f'Mar 10 09:02:{i % 60:02d} fw1 kernel: {comm}[{100 + i}]: segfault at 0 ip 0 sp 0'
                for i in range(n)]
    return out


def build(rows, crashes=None, with_kernel=True, header='Slot 1, Role mp'):
    """System health view (software + kernel log applied) and the correlation applied."""
    st = system_health.new_store()
    if rows is not None:
        system_health.parse_system_health(sw_text(rows, header), 'cli.txt', st, [])
    view = system_health.evaluate_system_health(st)
    ls = log_events.new_store()
    if with_kernel:
        log_events.parse_messages(kern(*(crashes or [])) or ['Mar 10 09:00:00 fw1 kernel: boot'],
                                  'messages', ls, [])
    log_events.apply_to_system_view(view, ls)
    correlations.apply_to_system_view(view)
    return view


def item(view, name):
    return next(i for i in view['correlations']['items'] if i['process'] == name)


def check(view):
    return next(c for c in view['checks'] if c['id'] == 'crash_link')


def link_flags(view):
    return [f for f in view['findings'] if f['code'] == 'CRASH_LINK']


def test_normalize_rules():
    assert normalize_name('  PAN_Task_0 ') == ('pan_task_0', False)
    assert normalize_name('mgmtsrvr+') == ('mgmtsrvr', True)
    assert normalize_name('sysd(ppid:1)') == ('sysd', False)
    assert normalize_name('sysd(ppid:*)') == ('sysd', False)
    # worker index is kept
    assert not names_match('pan_task_1', 'pan_task_0')
    assert names_match('pan_task_0', 'PAN_TASK_0')
    assert not names_match('sysd', 'sysd2') and not names_match('sysd2', 'sysd')


def test_confirmed():
    v = build(['Process  sysd  stopped', 'Process  ok1  running'], [('sysd', 6)])
    it = item(v, 'sysd')
    assert it['status'] == 'confirmed' and it['state'] == 'stopped'
    assert it['slot'] == '1' and it['role'] == 'mp'
    assert [(m['process'], m['type'], m['count']) for m in it['matches']] == [
        ('sysd', 'segfault', 6)]
    assert it['matches'][0]['files'] == ['messages']
    c = check(v)
    assert c['group'] == 'Correlations' and c['status'] == 'ok' and '1 confirmed' in c['value']
    fl = link_flags(v)
    assert len(fl) == 1 and fl[0]['level'] == 'info' and fl[0]['check'] == 'crash_link'


def test_other_flags_untouched():
    rows = ['Process  sysd  stopped']
    v = build(rows, [('sysd', 6)])
    base = build(rows, [('other', 1)])
    strip = lambda view: sorted((f['code'], f['level'], f['subject'], f['text'])
                                for f in view['findings'] if f['code'] != 'CRASH_LINK'
                                and f['code'] not in ('KERNEL_CRASH', 'KERNEL_CRASH_SEEN'))
    assert strip(v) == strip(base)
    assert any(f['code'] == 'PROC_NOT_RUNNING' and f['level'] == 'crit' for f in v['findings'])
    assert any(f['code'] == 'KERNEL_CRASH' and f['level'] == 'crit' for f in v['findings'])
    assert v['status'] == 'critical'


def test_no_match():
    v = build(['Process  sysd  stopped'], [('other', 7)])
    assert item(v, 'sysd')['status'] == 'no_match' and item(v, 'sysd')['matches'] == []
    assert not link_flags(v) and check(v)['status'] == 'ok'
    assert v['correlations']['counts']['no_match'] == 1
    # kernel log without any crash line is still "read"
    assert item(build(['Process  sysd  stopped']), 'sysd')['status'] == 'no_match'


def test_ambiguous_by_prefix():
    comm = 'long_daemon_nam'          # 15 characters
    v = build(['Process  long_daemon_name_a  stopped'],
              [(comm, 1), ('long_daemon_name_a', 2)])
    # the 15-char comm and the exact name are two distinct crash processes
    it = item(v, 'long_daemon_name_a')
    assert it['status'] == 'ambiguous' and len(it['matches']) == 2
    fl = link_flags(v)
    assert len(fl) == 1 and 'ambiguous' in fl[0]['text']
    assert 'ambiguous' in check(v)['value']


def test_not_evaluable_without_kernel_log_and_without_software():
    v = build(['Process  sysd  stopped'], with_kernel=False)
    assert item(v, 'sysd')['status'] == 'not_evaluable'
    c = check(v)
    assert c['status'] == 'no_data' and 'kernel log' in c['note'] and not link_flags(v)
    v = build(None, [('sysd', 3)])
    assert v['correlations']['items'] == [] and check(v)['status'] == 'no_data'
    assert 'No software status' in check(v)['note']
    v = build([], [('sysd', 3)])      # section without rows
    assert check(v)['status'] == 'no_data'


def test_fifteen_char_comm_matches_longer_name():
    comm = 'pan_dha_monitor'           # exactly 15 characters
    assert len(comm) == 15
    v = build(['Process  pan_dha_monitor_x  failed'], [(comm, 2)])
    assert item(v, 'pan_dha_monitor_x')['status'] == 'confirmed'
    # a shorter comm is not a prefix match
    v = build(['Process  pan_dha_monitor_x  failed'], [('pan_dha_mon', 2)])
    assert item(v, 'pan_dha_monitor_x')['status'] == 'no_match'


def test_plus_truncated_name_matches_by_prefix():
    v = build(['Process  very_long_proces+  stopped'], [('very_long_process', 4)])
    assert item(v, 'very_long_proces+')['status'] == 'confirmed'
    v = build(['Process  very_long_proces  stopped'], [('very_long_process', 4)])
    assert item(v, 'very_long_proces')['status'] == 'no_match'
    v = build(['Process  sysd(ppid:1)  stopped'], [('sysd', 4)])
    assert item(v, 'sysd(ppid:1)')['status'] == 'confirmed'


def test_all_running_is_ok_with_note():
    v = build(['Process  sysd  running', 'Group  g  running'], [('sysd', 9)])
    c = check(v)
    assert c['status'] == 'ok' and c['note'] == 'all processes running - nothing to correlate'
    assert v['correlations']['items'] == [] and not link_flags(v)


def test_multiple_slot_blocks_are_kept_separate():
    st = system_health.new_store()
    text = sw_text(['Process  sysd  stopped'], 'Slot 1, Role mp') + '\n' + \
        sw_text(['Process  sysd  running'], 'Slot 2, Role lc').split('\n', 1)[1]
    system_health.parse_system_health(text, 'cli.txt', st, [])
    view = system_health.evaluate_system_health(st)
    ls = log_events.new_store()
    log_events.parse_messages(kern(('sysd', 1)), 'messages', ls, [])
    log_events.apply_to_system_view(view, ls)
    correlations.apply_to_system_view(view)
    assert len(view['correlations']['items']) == 1
    assert evaluate_correlations(view)['items'][0]['slot'] == '1'


def build_tgz(path, rows, crashes):
    members = {
        'tmp/cli/techsupport_fwtest_20260311_1000.txt': sw_text(rows).encode(),
        'var/log/messages': ('\n'.join(kern(*crashes)) + '\n').encode(),
    }
    with tarfile.open(path, 'w:gz') as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))


def run_report(tmp_path):
    p = tmp_path / 'fwtest.tgz'
    build_tgz(p, ['Process  sysd  stopped', 'Process  other  running'], [('sysd', 2)])
    outdir = tmp_path / 'out'
    analyzer.main([str(p), '-o', str(outdir)])
    path = next(outdir.glob('fwtest_*.html'))
    return path.read_text(encoding='utf-8')


def test_report_contains_group_check_and_finding(tmp_path):
    out = run_report(tmp_path)
    m = re.search(r'const D = (\{.*?\});\nconst \$', out, re.DOTALL)
    sysv = json.loads(m.group(1).replace('<\\/', '</'))['sys']
    c = next(c for c in sysv['checks'] if c['id'] == 'crash_link')
    assert c['group'] == 'Correlations' and c['status'] == 'ok'
    assert any(f['code'] == 'CRASH_LINK' for f in sysv['findings'])
    assert sysv['correlations']['items'][0]['status'] == 'confirmed'
    assert 'sysDetailCrashLink' in out and 'crash_link:sysDetailCrashLink' in out
    assert '<code>CRASH_LINK</code>' in out and 'Not-running processes vs kernel crashes' in out
    assert not re.search(r'\{[a-z_]+\}', out.split('<body', 1)[1].split('<script', 1)[0])


@pytest.mark.skipif(shutil.which('node') is None, reason='node not available')
def test_generated_javascript_is_valid(tmp_path):
    out = run_report(tmp_path)
    scripts = re.findall(r'<script>(.*?)</script>', out, re.DOTALL)
    js = tmp_path / 'report.js'
    js.write_text(scripts[-1], encoding='utf-8')
    res = subprocess.run(['node', '--check', str(js)], check=False, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr

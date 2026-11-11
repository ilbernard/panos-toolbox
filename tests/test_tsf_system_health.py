"""Tests for tsf/system_health.py, the list-only archive members and the System health tab.

Synthetic data only (no real TSF content); no device is contacted.
"""
from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer, archive, findings, system_health
from panos_toolbox.tsf.system_health import (
    FLAG_CODES,
    SYS_THRESHOLDS,
    add_core_members,
    evaluate_system_health,
    new_store,
    parse_system_health,
)

SAMPLE = Path(__file__).parent / 'data' / 'cli_system_health_sample.txt'
CLI = 'tmp/cli/techsupport_example_20260105_1000.txt'
CORES = 'opt/dpfs/var/cores/'


def parse(text, store=None, src='cli.txt'):
    store = store or new_store()
    warnings = []
    n = parse_system_health(text, src, store, warnings)
    return n, store, warnings


def view_of(text, th=None):
    return evaluate_system_health(parse(text)[1], th)


def check(view, cid):
    return next(c for c in view['checks'] if c['id'] == cid)


def codes(view):
    return [f['code'] for f in view['findings']]


def software(rows, header='Slot 1, Role mp'):
    body = ['> show system software status', '', header, '-' * 40, '',
            'Type     Name                           State    Info', *rows, '']
    return '\n'.join(body)


def cfg(config='VSYS Config Allocator Usage   :   100KB (10% of  1000KB)',
        policy='POLICY CACHE USAGE            :     20KB ( 2% of   1000KB)'):
    return f'> debug dataplane show cfg-memstat statistics\n\n{config}\n\n{policy}\n'


def nat_global(usable=1000, used=10, pools=('Dynamic IP NAT Pool: 0(0.00%)',
                                            'Dynamic IP/Port NAT Pool: 7(1.00%)')):
    head = ['> show running global-ippool', '', 'Idx  Type',
            'Usable NAT DIP/DIPP shared memory size: ' + str(usable),
            'Used NAT DIP/DIPP shared memory size: ' + f'{used}({used / usable * 100:.2f}%)']
    return '\n'.join([*head, *pools, '', ''])


def nat_rules(rows, header='VSYS 1 has 1 NAT rules, DIP and DIPP rules:'):
    return '\n'.join(['> show running ippool', '', header, 'Rule   Type  Used Available',
                      '------ ----- ---- ---', *rows, '', ''])


# --------------------------------------------------------------------------
# CLI splitting
# --------------------------------------------------------------------------
def test_sections_split_on_commands_and_prompts():
    text = 'noise\n> show a  b\nx\nadmin@fw(active)> show c\ny\n\n> \n'
    assert list(system_health.iter_cli_sections(text.splitlines())) == [
        ('show a b', ['x']), ('show c', ['y', '']), ('', [])]


def test_unknown_commands_are_ignored():
    n, store, _w = parse('> show clock\nMon\n')
    assert n == 0 and not system_health.has_data(store)


def test_first_occurrence_wins_and_other_file_warns():
    _n, store, w = parse(software(['Process  a  running']))
    parse(software(['Process  b  stopped']), store, src='other.txt')
    assert [r['name'] for r in store['software']['blocks'][0]['rows']] == ['a']
    assert any('already read from cli.txt' in x for x in w) is False
    warnings = []
    parse_system_health(software(['Process  b  stopped']), 'other.txt', store, warnings)
    assert any('already read from cli.txt' in x for x in warnings)


# --------------------------------------------------------------------------
# Software status
# --------------------------------------------------------------------------
def test_all_running_is_ok():
    v = view_of(software(['Group    all    running  ', 'Process  authd  running  (pid: 1) ']))
    c = check(v, 'software')
    assert c['status'] == 'ok' and c['value'] == 'all 2 running' and not v['findings']


def test_non_running_process_and_group_is_critical_with_slot_role():
    v = view_of(software(['Group    base    running', 'Group    g1  stopped',
                          'Process  authd  starting  ', 'Process  ok1  running  (pid: 3) ']))
    assert codes(v) == ['PROC_NOT_RUNNING']
    f = v['findings'][0]
    assert f['level'] == 'crit' and 'Slot 1, Role mp' in f['text']
    assert 'g1 (Group, stopped)' in f['text'] and 'authd (Process, starting)' in f['text']
    assert '2 of 4' in f['text'] and check(v, 'software')['status'] == 'critical'
    assert v['status'] == 'critical'


def test_several_slot_blocks_get_one_flag_each():
    second = ['Slot 2, Role dp', '----', 'Type Name State Info', 'Process  b  running',
              'Process  c  dead']
    text = software(['Process  a  stopped'], 'Slot 1, Role mp') + '\n' + '\n'.join(second)
    v = view_of(text)
    assert [f['subject'] for f in v['findings']] == ['Slot 1, Role mp', 'Slot 2, Role dp']
    assert 'Slot 2, Role dp' in v['findings'][1]['text'] and 'c (Process, dead)' in \
        v['findings'][1]['text']
    assert check(v, 'software')['note'] == '2 slot/role blocks.'


def test_empty_software_section_is_no_data_not_ok():
    v = view_of(software([]))
    c = check(v, 'software')
    assert c['status'] == 'no_data' and 'no Group or Process rows' in c['note']
    assert not v['findings']


def test_missing_sections_are_no_data():
    v = view_of('> show clock\nx\n')
    assert [c['status'] for c in v['checks']] == ['no_data'] * 3 + ['no_data']
    assert v['status'] == 'no_data'
    assert 'not found' in check(v, 'software')['note']


# --------------------------------------------------------------------------
# Configuration memory
# --------------------------------------------------------------------------
@pytest.mark.parametrize('pct_text,used,total,expected', [
    ('49%', 499, 1000, None),
    ('50%', 500, 1000, 'warn'),
    ('89%', 899, 1000, 'warn'),
    ('90%', 900, 1000, 'crit'),
    ('100%', 1000, 1000, 'crit'),
])
def test_cfg_memory_boundaries(pct_text, used, total, expected):
    v = view_of(cfg(f'VSYS Config Allocator Usage   :   {used}KB ({pct_text} of  {total}KB)'))
    got = [f['level'] for f in v['findings'] if f['code'] == 'CFG_MEMORY']
    assert got == ([expected] if expected else [])


def test_cfg_memory_percent_is_recomputed_not_the_truncated_one():
    # prints 49% (truncated) but is 49.9%: not yet warn; 50.0 is.
    assert not view_of(cfg('VSYS Config Allocator Usage : 499KB (49% of 1000KB)'))['findings']
    v = view_of(cfg('VSYS Config Allocator Usage : 4999KB (49% of 10000KB)'))
    assert not v['findings']
    v = view_of(cfg('VSYS Config Allocator Usage : 5000KB (49% of 10000KB)'))
    assert codes(v) == ['CFG_MEMORY']


def test_cfg_memory_odd_spacing_and_separate_subjects():
    text = cfg('VSYS Config Allocator Usage:60KB(60%   of   100KB)',
               'POLICY CACHE USAGE  :  95KB (   95%  of  100KB)')
    v = view_of(text)
    by = {f['subject']: f for f in v['findings']}
    assert set(by) == {'config allocator', 'policy cache'}
    assert by['config allocator']['level'] == 'warn' and by['policy cache']['level'] == 'crit'
    assert '60% used (60 KB of 100 KB)' in by['config allocator']['text']
    assert check(v, 'cfg_mem')['status'] == 'critical'
    assert check(v, 'cfg_mem')['value'] == 'config 60%, policy cache 95%'


def test_cfg_memory_active_and_passive_policy_cache_are_two_subjects():
    lines = ['> debug dataplane show cfg-memstat statistics',
             'VSYS Config Allocator Usage   :   10KB (10% of  100KB)', '',
             'VSYS POLICY CACHE Allocator Usage ', '',
             'POLICY CACHE (ACTIVE)         :   100KB ',
             'POLICY CACHE USAGE            :    95KB ( 95% of   100KB)',
             'alloc size 13452, max 13452', '',
             ' POLICY CACHE (PASSIVE)       :   100KB ',
             'POLICY CACHE USAGE            :    55KB ( 55% of   100KB)', '']
    text = '\n'.join(lines)
    v = view_of(text)
    assert len(v['cfg']['blocks']) == 1
    by = {f['subject']: f['level'] for f in v['findings']}
    assert by == {'policy cache (active)': 'crit', 'policy cache (passive)': 'warn'}
    assert check(v, 'cfg_mem')['value'] == 'config 10%, policy cache 95%'


def test_cfg_memory_ok_value_and_empty_section():
    v = view_of(cfg())
    assert check(v, 'cfg_mem')['status'] == 'ok' and check(v, 'cfg_mem')['value'] == \
        'config 10%, policy cache 2%'
    v = view_of('> debug dataplane show cfg-memstat statistics\nnothing useful\n')
    assert check(v, 'cfg_mem')['status'] == 'no_data'


def test_cfg_memory_blocks_per_dp_are_kept_separate():
    alloc, policy = 'VSYS Config Allocator Usage : {0}KB ({0}% of 100KB)', \
        'POLICY CACHE USAGE : 10KB (10% of 100KB)'
    lines = ['> debug dataplane show cfg-memstat statistics', 'DP dp0:', alloc.format(10),
             policy, 'DP dp1:', alloc.format(70), policy, '']
    text = '\n'.join(lines)
    v = view_of(text)
    assert [b['label'] for b in v['cfg']['blocks']] == ['dp0', 'dp1']
    assert len(v['findings']) == 1 and 'dp1' in v['findings'][0]['text']
    assert 'unverified' in check(v, 'cfg_mem')['note']


def test_cfg_memory_repeated_blocks_without_header_are_numbered():
    line = 'VSYS Config Allocator Usage : {}KB ({}% of 100KB)'
    text = '> debug dataplane show cfg-memstat statistics\n' + \
        line.format(80, 80) + '\n' + line.format(20, 20) + '\n'
    v = view_of(text)
    assert [b['label'] for b in v['cfg']['blocks']] == ['block 1', 'block 2']
    assert 'block 1' in v['findings'][0]['text']


def test_cfg_thresholds_override():
    v = view_of(cfg(), {'cfg_mem_warn': 5, 'cfg_mem_crit': 8})
    assert [f['level'] for f in v['findings']] == ['crit']
    assert v['thresholds']['cfg_mem_warn'] == 5


# --------------------------------------------------------------------------
# NAT pools
# --------------------------------------------------------------------------
def test_nat_global_shared_memory_and_pool_lines():
    text = nat_global(1000, 500, ('Dynamic IP NAT Pool: 0(0.00%)',
                                  'Dynamic IP/Port NAT Pool: 7(50.00%)'))
    v = view_of(text)
    assert sorted(f['subject'] for f in v['findings']) == [
        'Dynamic IP/Port pool', 'shared memory']
    assert all(f['level'] == 'warn' and f['code'] == 'NAT_POOL' for f in v['findings'])
    assert v['nat']['shared']['pct'] == 50
    assert check(v, 'nat')['status'] == 'warning'


def test_nat_below_threshold_is_ok_and_shows_value():
    v = view_of(nat_global(1000, 499))
    assert not v['findings'] and check(v, 'nat')['status'] == 'ok'
    assert check(v, 'nat')['value'] == 'shared memory 49.9%'
    assert '"show running ippool" not found' in check(v, 'nat')['note']


def test_nat_rule_names_with_spaces_and_optional_columns():
    rows = ['SNAT. Sample Name   Dynamic IP/Port 17         2900        1234     3',
            'My   spaced  rule Dynamic IP 600 400 100 1 yes 1 10',
            'UNAT.plain    Dynamic IP/Port    41   9959   5555   4     no      ']
    v = view_of(nat_rules(rows))
    by = {r['rule']: r for r in v['nat']['rules']}
    assert set(by) == {'SNAT. Sample Name', 'My   spaced  rule', 'UNAT.plain'}
    r = by['My   spaced  rule']
    assert (r['type'], r['used'], r['avail'], r['pct']) == ('Dynamic IP', 600, 400, 60.0)
    assert (r['persistent'], r['min'], r['max']) == ('yes', 1, 10)
    assert by['SNAT. Sample Name']['persistent'] is None and by['SNAT. Sample Name']['min'] is None
    assert by['UNAT.plain']['persistent'] == 'no' and by['UNAT.plain']['max'] is None
    assert [f['subject'] for f in v['findings']] == ['rule 1/My   spaced  rule']


def test_nat_rules_in_several_vsys_with_aggregation():
    rows1 = [f'RULE{i}   Dynamic IP/Port {500 + i} {500 - i} 20344 2' for i in range(5)]
    text = nat_rules(rows1) + '\n' + nat_rules(
        ['other   Dynamic IP/Port 1 999 20344 2'],
        'VSYS 2 has 1 NAT rules, DIP and DIPP rules:').split('\n', 1)[1]
    v = view_of(text)
    assert [x['vsys'] for x in v['nat']['vsys']] == ['1', '2']
    assert [x['n'] for x in v['nat']['vsys']] == [5, 1]
    assert v['nat']['n_rules'] == 6 and v['nat']['n_over'] == 5
    assert len(v['findings']) == 1 and v['findings'][0]['subject'] == 'rules'
    t = v['findings'][0]['text']
    assert t.startswith('5 NAT rule(s) at or above 50%') and 'RULE4 (VSYS 1' in t
    assert v['nat']['rules'][0]['rule'] == 'RULE4'        # worst first
    assert check(v, 'nat')['value'] == 'busiest rule 50.4%'


def test_nat_top_rules_are_limited_in_flag_and_summary():
    rows = [f'R{i:02d}   Dynamic IP/Port 900 100 20344 2' for i in range(15)]
    v = view_of(nat_rules(rows))
    assert len(v['nat']['top']) == 10 and len(v['nat']['rules']) == 15
    assert v['findings'][0]['text'].count('(VSYS 1') == 10


def test_nat_zero_capacity_rule_has_no_percentage():
    v = view_of(nat_rules(['empty   Dynamic IP 0 0 0 0']))
    assert v['nat']['rules'][0]['pct'] is None and not v['findings']


def test_nat_empty_sections_are_no_data():
    v = view_of('> show running global-ippool\nnothing\n> show running ippool\n')
    assert check(v, 'nat')['status'] == 'no_data'
    v = view_of(nat_rules([], 'VSYS 1 has 0 NAT rules, DIP and DIPP rules:'))
    assert check(v, 'nat')['status'] == 'ok' and check(v, 'nat')['value'] == 'no DIP/DIPP rules'


def test_nat_threshold_override():
    v = view_of(nat_global(1000, 10), {'nat_pool_warn': 1})
    assert 'shared memory' in [f['subject'] for f in v['findings']]


# --------------------------------------------------------------------------
# Core files
# --------------------------------------------------------------------------
def cores_view(files=(), dirs=(), listed=True):
    store = new_store()
    if listed:
        add_core_members(store, files, dirs)
    return evaluate_system_health(store)


def test_cores_dir_only_is_ok_empty():
    v = cores_view(dirs=[CORES.rstrip('/')])
    c = check(v, 'cores')
    assert c['status'] == 'ok' and c['note'] == 'core directory present, empty'
    assert v['cores']['state'] == 'empty' and not v['findings']


def test_cores_absent_is_ok():
    v = cores_view()
    c = check(v, 'cores')
    assert c['status'] == 'ok' and c['note'] == 'no core directory in the archive'
    assert v['cores']['state'] == 'absent'


def test_cores_file_is_critical_with_names_and_sizes():
    v = cores_view(files=[(CORES + 'core.1', 2048), (CORES + 'core.2', None)],
                   dirs=[CORES.rstrip('/')])
    assert codes(v) == ['CORE_FILES'] and v['findings'][0]['level'] == 'crit'
    t = v['findings'][0]['text']
    assert '2 core file(s)' in t and 'core.1 (2.0 KB)' in t and 'core.2 (unknown size)' in t
    assert check(v, 'cores')['status'] == 'critical' and v['status'] == 'critical'
    assert v['cores']['files'][0] == {'name': CORES + 'core.1', 'size': 2048}


def test_cores_not_an_archive_is_no_data():
    v = cores_view(listed=False)
    assert check(v, 'cores')['status'] == 'no_data'


def test_cores_listing_is_capped_in_the_text():
    v = cores_view(files=[(f'var/cores/c{i:03d}', 1) for i in range(40)])
    assert 'and 10 more' in v['findings'][0]['text'] and len(v['cores']['files']) == 40


def test_core_path_kind():
    kind = system_health.core_path_kind
    assert kind('opt/dpfs/var/cores/') == 'dir' and kind('var/cores/') == 'dir'
    assert kind('opt/dpfs/var/cores/core.1') == 'file' and kind('var/cores/a/b') == 'file'
    assert kind('var/cores/x/') == 'dir'
    assert kind('var/cores') is None and kind('var/log/cores/x') is None
    assert kind('tmp/var/cores/x') is None


# --------------------------------------------------------------------------
# Archive layer: list-only members
# --------------------------------------------------------------------------
def build_tgz(path, entries):
    """entries: (name, bytes) files and (name, None) directories."""
    with tarfile.open(path, 'w:gz') as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))


def collect(path):
    warnings = []
    return analyzer.collect(str(path), warnings), warnings


SAMPLE_BYTES = SAMPLE.read_bytes()


def test_archive_with_cli_and_no_cores_is_ok_absent(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tgz(p, [(CLI, SAMPLE_BYTES)])
    col, _w = collect(p)
    v = evaluate_system_health(col.sys_data)
    assert check(v, 'cores')['note'] == 'no core directory in the archive'
    assert col.inventory.families.get('cores') is None


def test_archive_empty_cores_dir_is_not_a_core(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tgz(p, [('./' + CORES, None), ('./var/cores/', None), (CLI, SAMPLE_BYTES)])
    col, _w = collect(p)
    v = evaluate_system_health(col.sys_data)
    assert check(v, 'cores')['note'] == 'core directory present, empty'
    fam = col.inventory.families['cores']
    assert fam.found == [] and len(fam.dirs) == 2


def test_archive_core_file_is_listed_and_never_read(tmp_path, monkeypatch):
    p = tmp_path / 'a.tgz'
    big = b'\x7fELF' + b'0' * 5000
    build_tgz(p, [(CORES, None), (CLI, SAMPLE_BYTES), (CORES + 'core.example.1', big),
                  ('var/cores/core.example.2', big)])
    monkeypatch.setattr(archive, 'MAX_MEMBER_BYTES', 4000)   # would truncate if it were read
    extracted = []
    orig = tarfile.TarFile.extractfile

    def spy(self, member):
        extracted.append(member.name if hasattr(member, 'name') else member)
        return orig(self, member)
    monkeypatch.setattr(tarfile.TarFile, 'extractfile', spy)
    read_before = []
    real_make = archive._Reader.make

    def make(self, name, *a, **kw):
        read_before.append(name)
        return real_make(self, name, *a, **kw)
    monkeypatch.setattr(archive._Reader, 'make', make)
    col, _w = collect(p)
    assert not any('cores' in n for n in extracted + read_before)
    fam = col.inventory.families['cores']
    assert sorted(fam.listed) == [CORES + 'core.example.1', 'var/cores/core.example.2']
    assert fam.found == fam.listed and fam.read == [] and fam.truncated == []
    assert fam.sizes[CORES + 'core.example.1'] == len(big)
    assert col.inventory.bytes_read < 10000                  # only the small CLI file
    assert col.status == 'complete'
    v = evaluate_system_health(col.sys_data)
    assert 'CORE_FILES' in codes(v)
    assert [f['size'] for f in v['cores']['files']] == [len(big)] * 2


def test_directory_input_lists_cores_too(tmp_path):
    d = tmp_path / 'tsf'
    (d / 'opt/dpfs/var/cores').mkdir(parents=True)
    (d / 'tmp/cli').mkdir(parents=True)
    (d / 'tmp/cli/techsupport_x.txt').write_bytes(SAMPLE_BYTES)
    col, _w = collect(d)
    assert check(evaluate_system_health(col.sys_data), 'cores')['note'] == \
        'core directory present, empty'
    (d / 'opt/dpfs/var/cores/core.1').write_bytes(b'x' * 10)
    col, _w = collect(d)
    v = evaluate_system_health(col.sys_data)
    assert v['cores']['files'] == [{'name': 'opt/dpfs/var/cores/core.1', 'size': 10}]


def test_selector_dirs_other_results_are_ignored(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tgz(p, [('logs/', None), ('logs/a.log', b'x\n')])
    from panos_toolbox.tsf.model import Inventory
    inv = Inventory()
    mems = list(archive.iter_members(
        str(p), lambda n: 'logs' if n.endswith(('.log', '/')) else None, inv))
    assert [m.name for m in mems] == ['logs/a.log'] and inv.family('logs').dirs == []


def test_coverage_shows_cores_family(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tgz(p, [(CLI, SAMPLE_BYTES)])
    cov = analyzer.build_coverage(collect(p)[0])
    row = next(f for f in cov['families'] if f['family'] == 'cores')
    assert row['states'] == ['absent']
    build_tgz(p, [('./' + CORES, None), (CLI, SAMPLE_BYTES)])
    cov = analyzer.build_coverage(collect(p)[0])
    row = next(f for f in cov['families'] if f['family'] == 'cores')
    assert row['states'] == ['listed'] and row['dirs'] == [CORES.rstrip('/')]
    build_tgz(p, [(CORES + 'core.1', b'abc'), (CLI, SAMPLE_BYTES)])
    cov = analyzer.build_coverage(collect(p)[0])
    row = next(f for f in cov['families'] if f['family'] == 'cores')
    assert row['states'] == ['listed'] and row['read'] == 0 and row['found'] == 1
    assert row['members'][0]['state'] == 'listed' and row['members'][0]['detail'] == '3 bytes'


# --------------------------------------------------------------------------
# Sample file, report and CLI
# --------------------------------------------------------------------------
def test_sample_file_view():
    v = view_of(SAMPLE.read_text(encoding='utf-8'))
    assert [c['status'] for c in v['checks']] == ['critical', 'critical', 'warning', 'no_data']
    got = sorted((f['code'], f['subject']) for f in v['findings'])
    assert got == [
        ('CFG_MEMORY', 'config allocator'), ('CFG_MEMORY', 'policy cache (active)'),
        ('NAT_POOL', 'Dynamic IP/Port pool'), ('NAT_POOL', 'rule 1/SNAT.example'),
        ('NAT_POOL', 'shared memory'), ('PROC_NOT_RUNNING', 'Slot 1, Role mp')]
    assert 'exampled (Process, stopped)' in v['findings'][0]['text']
    assert [r['rule'] for r in v['nat']['rules']][:2] == ['SNAT.example', 'DIP.small']
    assert {r['vsys'] for r in v['nat']['rules']} == {'1', '2'}
    levels = {f['subject']: f['level'] for f in v['findings'] if f['code'] == 'CFG_MEMORY'}
    assert levels == {'config allocator': 'warn', 'policy cache (active)': 'crit'}
    pol = v['cfg']['blocks'][0]['policies']
    assert [(p['role'], p['size_kb'], p['pct']) for p in pol] == [
        ('active', 30720, 91.24), ('passive', 30720, 4.17)]


def test_findings_convert_with_from_flags():
    v = view_of(SAMPLE.read_text(encoding='utf-8'))
    fs = findings.from_flags(v['findings'], scope='system')
    assert {f.level for f in fs} == {'warning', 'critical'}
    assert findings.module_status(fs, True) == 'critical'


def report_data(out):
    m = re.search(r'const D = (\{.*?\});\nconst \$', out, re.DOTALL)
    return json.loads(m.group(1).replace('<\\/', '</'))


def run_main(tmp_path, *extra, src=SAMPLE):
    outdir = tmp_path / 'out'
    analyzer.main([str(src), '-o', str(outdir), *extra])
    path = next(outdir.glob('*.html'))
    return path, path.read_text(encoding='utf-8')


def test_single_cli_file_gives_sys_report_with_suffix(tmp_path):
    path, out = run_main(tmp_path)
    assert path.name.endswith('_sys.html')
    assert 'id="tab-sys"' in out and 'id="p-sys"' in out and '>System health<' in out
    for sid in ('sys', 'sysflags', 'sysdetail'):
        assert f'id="help-{sid}" hidden' in out
    assert '__HB_' not in out and '__HP_' not in out
    data = report_data(out)
    assert data['kind'] == 'TSF analysis' and data['sys']['status'] == 'critical'
    assert [c['id'] for c in data['sys']['checks']] == ['software', 'cfg_mem', 'nat', 'cores']
    assert data['sys']['cores']['state'] == 'unknown'
    for code in FLAG_CODES:
        assert f'<code>{code}</code>' in out
    assert 'cfg_mem_warn = 50%' in out and 'nat_pool_warn = 50%' in out


def test_archive_report_has_the_tab_and_cores(tmp_path):
    tgz = tmp_path / 'a.tgz'
    build_tgz(tgz, [(CORES + 'core.1', b'abc'), (CLI, SAMPLE_BYTES)])
    outdir = tmp_path / 'out'
    analyzer.main([str(tgz), '-o', str(outdir)])
    out = (outdir / 'a_sys.html').read_text(encoding='utf-8')
    data = report_data(out)
    assert data['sys']['cores']['files'] == [{'name': CORES + 'core.1', 'size': 3}]
    assert 'CORE_FILES' in [f['code'] for f in data['sys']['findings']]
    fam = next(f for f in data['coverage']['families'] if f['family'] == 'cores')
    assert fam['states'] == ['listed']


def test_archive_without_cli_and_cores_has_no_sys_tab(tmp_path):
    d = tmp_path / 'tsf' / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    (d / 'mp-monitor.log').write_text(
        (Path(__file__).parent / 'data' / 'mp_monitor_sample.log').read_text(encoding='utf-8'),
        encoding='utf-8')
    analyzer.main([str(tmp_path / 'tsf'), '-o', str(tmp_path / 'out')])
    out = (tmp_path / 'out' / 'tsf_mp.html').read_text(encoding='utf-8')
    assert report_data(out)['sys'] is None


def test_report_without_sys_data_has_no_sys_view():
    out = analyzer.render_report('t', [], [], set(), [], 0, analyzer.TEMPLATE)
    assert '"sys":null' in out


def test_cli_thresholds_reach_the_view_and_the_help(tmp_path):
    _p, out = run_main(tmp_path, '--sys-cfg-mem-warn', '55', '--sys-cfg-mem-crit', '95',
                       '--sys-nat-pool-warn', '70.5')
    data = report_data(out)
    th = data['sys']['thresholds']
    assert th == {'cfg_mem_warn': 55, 'cfg_mem_crit': 95, 'nat_pool_warn': 70.5}
    levels = {f['subject']: f['level'] for f in data['sys']['findings']
              if f['code'] == 'CFG_MEMORY'}
    assert levels == {'policy cache (active)': 'warn'}
    assert 'cfg_mem_warn = 55%' in out and 'cfg_mem_warn = 50%' not in out
    assert 'nat_pool_warn = 70.5%' in out


def test_cli_rejects_negative_sys_threshold(tmp_path):
    with pytest.raises(SystemExit):
        analyzer.main([str(SAMPLE), '-o', str(tmp_path), '--sys-nat-pool-warn', '-1'])


def test_every_sys_option_exists():
    ap_help = subprocess.run(
        [sys.executable, '-m', 'panos_toolbox.tsf.analyzer', '--help'], check=False,
        capture_output=True, text=True).stdout
    for key in SYS_THRESHOLDS:
        assert '--sys-' + key.replace('_', '-') in ap_help


def test_unknown_threshold_raises():
    with pytest.raises(ValueError):
        evaluate_system_health(new_store(), {'nope': 1})


def test_defaults():
    assert SYS_THRESHOLDS == {'cfg_mem_warn': 50, 'cfg_mem_crit': 90, 'nat_pool_warn': 50}


@pytest.mark.skipif(shutil.which('node') is None, reason='node not available')
def test_generated_javascript_is_valid(tmp_path):
    _p, out = run_main(tmp_path)
    scripts = re.findall(r'<script>(.*?)</script>', out, re.DOTALL)
    js = tmp_path / 'report.js'
    js.write_text(scripts[-1], encoding='utf-8')
    res = subprocess.run(['node', '--check', str(js)], check=False, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr

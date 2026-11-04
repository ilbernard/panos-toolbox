"""Tests for the interface error parser, heuristics, glossary and report integration.

Standard library only; no device is contacted. The fixture is a trimmed, anonymized extract
of a real PA-410 TSF (uptime 18 minutes); other cases are synthesised inline.
"""
import io
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from panos_toolbox.tsf import analyzer, if_glossary, interface_errors, report_template
from panos_toolbox.tsf.interface_errors import (
    IF_THRESHOLDS,
    evaluate_interfaces,
    has_data,
    interface_kind,
    merge_parsed,
    parse_interfaces,
    parse_uptime,
)
from panos_toolbox.tsf.report_help import SECTION_HELP, render_section_help

DATA = Path(__file__).parent / 'data'
FIXTURE = DATA / 'interface_errors_sample.txt'
POW_FIXTURE = DATA / 'pow_sample.txt'
SRC = Path(interface_errors.__file__).read_text(encoding='utf-8')

LOGICAL_KEYS = [
    'bytes received', 'bytes transmitted', 'packets received', 'packets transmitted',
    'receive errors', 'packets dropped', 'packets dropped by flow state check',
    'forwarding errors', 'no route', 'arp not found', 'neighbor not found',
    'neighbor info pending', 'mac not found', 'packets routed to different zone',
    'land attacks', 'ping-of-death attacks', 'teardrop attacks', 'ip spoof attacks',
    'mac spoof attacks', 'ICMP fragment', 'layer2 encapsulated packets',
    'layer2 decapsulated packets', 'tcp cps', 'udp cps', 'sctp cps', 'other cps']
CPU_KEYS = ['bytes received', 'bytes transmitted', 'packets received', 'packets transmitted',
            'receive incoming errors', 'receive discarded', 'receive errors', 'packets dropped']
MAC_KEYS = ['rx-broadcast', 'rx-bytes', 'rx-multicast', 'rx-unicast', 'tx-broadcast', 'tx-bytes',
            'tx-multicast', 'tx-unicast']
DETAIL_KEYS = ['rx packets 64 bytes', 'flow control transmitted', 'flow control received',
               'receive fifo overrun', 'packets with bad crc', 'undersized packets',
               'oversized packets', 'mac receive error', 'bad_octets_rcv', 'collisions',
               'excessive_collisions', 'fragments_pkts', 'jabber_pkts', 'late_collisions',
               'mac_transmit_err', 'sent_deferred', 'sent_multiple']
BAR = '-' * 80


def _kv(keys, values):
    return '\n'.join(f'{k:<40}{values.get(k, 0)}' for k in keys)


def _sysinfo(uptime='3 days, 4:05:06', host='fw-test', model='PA-440', ver='11.1.4'):
    return (f'> show system info\n\nhostname: {host}\ntime: Tue Oct 27 08:20:22 2026\n'
            f'uptime: {uptime}\nmodel: {model}\nsw-version: {ver}\n\n')


def _counters(hw=None, logical=None):
    """`show counter interface all` text. hw/logical: {iface: {counter: value}}."""
    out = ['> show counter interface all', '', 'Hardware interface counters:', BAR, '']
    for name, vals in (hw or {}).items():
        out += [f'Interface: {name}', BAR, '', BAR, 'Physical port counters read from MAC:', BAR,
                _kv(MAC_KEYS, vals), BAR, '', 'Hardware interface counters read from CPU:', BAR,
                _kv(CPU_KEYS, vals), BAR, '']
    out += ['', 'Logical interface counters:', BAR, '']
    for name, vals in (logical or {}).items():
        out += [f'Interface: {name}', 'Logical interface counters read from CPU:', BAR,
                _kv(LOGICAL_KEYS, vals), BAR, '']
    return '\n'.join(out) + '\n\n'


def _detail(name, speed='1000', duplex='full', state='up', cfg='auto/auto/auto', zone='lan',
            ip='10.0.0.1/24', capability='auto, 10Mb/s-half, 100Mb/s-full, 1Gb/s-full',
            counters=None):
    return (f'> show interface {name}\n\n{BAR}\nName: {name}, ID: 24\nLink status:\n'
            f'  Runtime link speed/duplex/state: {speed}/{duplex}/{state}\n'
            f'  Configured link speed/duplex/state: {cfg}\nInterface Type :\n  Port Type: RJ45\n'
            f'Capability : {capability}\nOperation mode: layer3\n{BAR}\nName: {name}, ID: 24\n'
            f'Operation mode: layer3\nVirtual router default\nInterface MTU 1500\n'
            f'Interface IP address: {ip}\nZone: {zone}, virtual system: vsys1\n{BAR}\n{BAR}\n'
            f'Detailed physical port counters read from MAC:\n{BAR}\n'
            f'{_kv(DETAIL_KEYS, counters or {})}\n{BAR}\n\n')


def _ev(text, th=None):
    return evaluate_interfaces(parse_interfaces(text.splitlines(), src='test'), th)


def _row(view, name):
    return next(r for r in view['rows'] if r['name'] == name)


def _codes(row):
    return {f['code']: f['level'] for f in row['flags']}


@pytest.fixture(scope='module')
def sample():
    return _ev(FIXTURE.read_text(encoding='utf-8'))


# ---------------------------------------------------------------- parsing of the real extract
def test_fixture_is_small():
    assert len(FIXTURE.read_text(encoding='utf-8').splitlines()) < 500


def test_system_summary_and_short_uptime_banner(sample):
    s = sample['system']
    assert (s['hostname'], s['model'], s['sw_version']) == ('fw-anon-7894', 'PA-410', '11.2.10-h15')
    assert s['uptime'] == '0 days, 0:18:51' and s['uptime_s'] == 18 * 60 + 51
    assert s['collected_at'] == 'Tue Oct 27 08:20:20 CET 2026'
    top = sample['banner'][0]
    assert top['code'] == 'UPTIME_SHORT' and top['level'] == 'warn'
    assert sample['warnings'] == []


def test_expected_logical_counters(sample):
    want = {
        'ethernet1/1': {'packets dropped': 438, 'no route': 3,
                        'packets routed to different zone': 11, 'ip spoof attacks': 59},
        'ethernet1/2': {'packets dropped': 1276, 'packets dropped by flow state check': 923,
                        'no route': 542, 'arp not found': 152},
        'ethernet1/2.3': {'packets dropped': 749, 'packets dropped by flow state check': 394,
                          'no route': 595},
        'ethernet1/2.9': {'arp not found': 2},
        'ethernet1/7': {'packets dropped': 430, 'no route': 5},
        'ethernet1/7.222': {'packets dropped': 1732, 'no route': 1704},
        'tunnel.2002': {'packets routed to different zone': 66},
    }
    for name, counters in want.items():
        got = _row(sample, name)['logical']
        assert {k: v for k, v in got.items() if k in counters} == counters, name
        assert not set(got) - set(counters), name   # nothing else is non-zero (cps are hidden)


def test_physical_errors_are_zero_and_ports_down(sample):
    for name in ('ethernet1/1', 'ethernet1/2', 'ethernet1/7'):
        assert _row(sample, name)['phys'] == {} and _row(sample, name)['cpu'] == {}
        assert 'PHY_ERRORS' not in _codes(_row(sample, name))
    assert sample['down_ports'] == ['ethernet1/3', 'ethernet1/4', 'ethernet1/5', 'ethernet1/6']
    assert _row(sample, 'ethernet1/4')['link_txt'] == 'down / no traffic'
    assert _row(sample, 'ethernet1/4')['flags'] == []          # nothing configured
    assert _codes(_row(sample, 'ethernet1/3')) == {'DOWN_CONFIGURED': 'info'}
    assert not _row(sample, 'ethernet1/5')['issue']


def test_link_zone_and_address_come_from_the_tables(sample):
    r = _row(sample, 'ethernet1/1')
    assert (r['state'], r['speed'], r['duplex'], r['zone'], r['ip'], r['vr']) == \
        ('up', '1000', 'full', 'wan', '192.168.247.97/24', 'default')
    sub = _row(sample, 'ethernet1/7.222')
    assert (sub['kind'], sub['parent'], sub['zone'], sub['tag']) == \
        ('sub-interface', 'ethernet1/7', 'mgmt-pa', '222')
    assert _row(sample, 'tunnel.2002')['kind'] == 'tunnel'
    assert _row(sample, 'vlan')['kind'] == 'vlan'
    assert _row(sample, 'ethernet1/4')['zone'] == ''     # "N/A" is not a zone


def test_expected_flags_on_the_sample(sample):
    assert _codes(_row(sample, 'ethernet1/1')) == {'IP_SPOOF': 'info', 'ZONE_CHANGE': 'warn'}
    assert _codes(_row(sample, 'ethernet1/2')) == {
        'DROP_PCT': 'warn', 'NO_ROUTE': 'warn', 'ARP_NOT_FOUND': 'warn',
        'FLOW_STATE_CHECK': 'info'}
    assert _codes(_row(sample, 'ethernet1/2.3')) == {'NO_ROUTE': 'warn',
                                                      'FLOW_STATE_CHECK': 'info'}
    assert _codes(_row(sample, 'ethernet1/7.222')) == {'DROP_PCT': 'crit', 'NO_ROUTE': 'warn'}
    assert _codes(_row(sample, 'tunnel.2002')) == {'ZONE_CHANGE': 'info'}
    assert _codes(_row(sample, 'ethernet1/2.9')) == {}        # 2 ARP misses are below the minimum
    assert round(_row(sample, 'ethernet1/2')['drop_pct'], 2) == 1.11


def test_no_route_concentration_text(sample):
    text = next(f['text'] for f in _row(sample, 'ethernet1/7.222')['flags']
                if f['code'] == 'NO_ROUTE')
    assert 'Concentrated here' in text and 'sub-interface' in text
    assert "virtual router 'default'" in text
    other = next(f['text'] for f in _row(sample, 'ethernet1/2')['flags']
                 if f['code'] == 'NO_ROUTE')
    assert 'Concentrated' not in other


def test_crosscheck_matches_global_counters(sample):
    by = {x['label']: x for x in sample['crosscheck']}
    assert (by['ARP not found']['interface_sum'], by['ARP not found']['global_sum']) == (154, 154)
    assert (by['No route']['interface_sum'], by['No route']['global_sum']) == (2849, 2849)
    assert by['Routed to different zone']['global_sum'] == 77
    assert by['IP spoof']['status'] == 'match'
    assert by['Dropped by flow state check']['status'] == 'related'
    assert not any(b['code'] == 'XCHECK_MISMATCH' for b in sample['banner'])
    names = {c['name'] for c in sample['context']}
    assert {'flow_policy_deny', 'flow_fwd_l3_mcast_drop'} <= names


def test_empty_transceiver_and_lacp_are_handled(sample):
    assert sample['transceivers']['rows'] == []
    assert sample['lacp'] == []


def test_column_groups_only_list_counters_that_are_non_zero(sample):
    groups = {g['id']: [c['k'] for c in g['cols']] for g in sample['groups']}
    assert groups['phys'] == [] and groups['cpu'] == []
    assert groups['logical'] == ['packets dropped', 'packets dropped by flow state check',
                                 'no route', 'arp not found', 'packets routed to different zone',
                                 'ip spoof attacks']


def test_evaluate_is_json_serialisable_and_leaves_input_alone():
    parsed = parse_interfaces(FIXTURE.read_text(encoding='utf-8').splitlines())
    before = json.dumps(parsed, sort_keys=True)
    json.dumps(evaluate_interfaces(parsed))
    assert json.dumps(parsed, sort_keys=True) == before


# ---------------------------------------------------------------- synthesised cases
def test_physical_errors_half_duplex_and_slow_link():
    text = _sysinfo() + _counters(
        {'ethernet1/9': {'rx-unicast': 5000, 'tx-unicast': 5000, 'packets received': 5000,
                         'packets transmitted': 5000}},
        {'ethernet1/9': {'packets received': 5000, 'packets transmitted': 5000}}) + _detail(
        'ethernet1/9', speed='100', duplex='half',
        counters={'packets with bad crc': 57, 'late_collisions': 3, 'collisions': 9,
                  'flow control received': 4, 'sent_deferred': 2})
    row = _row(_ev(text), 'ethernet1/9')
    assert row['phys'] == {'flow control received': 4, 'packets with bad crc': 57,
                           'collisions': 9, 'late_collisions': 3, 'sent_deferred': 2}
    codes = _codes(row)
    assert codes['PHY_ERRORS'] == 'crit'
    assert codes['LINK_HALF_DUPLEX'] == 'warn' and codes['LINK_SPEED_LOW'] == 'warn'
    assert codes['PHY_MINOR'] == 'info'
    text = next(f['text'] for f in row['flags'] if f['code'] == 'PHY_ERRORS')
    assert 'packets with bad crc 57' in text and 'late_collisions 3' in text
    assert row['has_phys_data'] and row['issue']


def test_phy_error_min_threshold_and_unknown_threshold():
    text = _sysinfo() + _detail('ethernet1/9', counters={'packets with bad crc': 2})
    assert 'PHY_ERRORS' in _codes(_row(_ev(text), 'ethernet1/9'))
    assert 'PHY_ERRORS' not in _codes(_row(_ev(text, {'phy_error_min': 5}), 'ethernet1/9'))
    with pytest.raises(ValueError):
        _ev(text, {'no_such_key': 1})


def test_configured_link_mismatch():
    text = _sysinfo() + _detail('ethernet1/9', speed='100', duplex='full', cfg='1000/full/up')
    assert _codes(_row(_ev(text), 'ethernet1/9'))['LINK_MISMATCH'] == 'warn'
    ok = _sysinfo() + _detail('ethernet1/9', speed='1000', duplex='full', cfg='1000/full/up')
    assert 'LINK_MISMATCH' not in _codes(_row(_ev(ok), 'ethernet1/9'))


def test_hardware_errors_without_mac_errors():
    text = _sysinfo() + _counters({'ethernet1/1': {'receive discarded': 12,
                                                    'packets received': 10}})
    row = _row(_ev(text), 'ethernet1/1')
    assert row['cpu'] == {'receive discarded': 12}
    assert _codes(row)['HW_ERRORS'] == 'warn'


def test_up_port_without_traffic_and_down_port_with_config():
    text = _sysinfo() + _counters({'ethernet1/1': {}, 'ethernet1/2': {}}) + _detail(
        'ethernet1/1') + _detail('ethernet1/2', speed='unknown', duplex='unknown', state='down')
    view = _ev(text)
    assert _codes(_row(view, 'ethernet1/1')) == {'UP_NO_TRAFFIC': 'info'}
    assert _codes(_row(view, 'ethernet1/2')) == {'DOWN_CONFIGURED': 'info'}
    assert view['down_ports'] == ['ethernet1/2']


def test_drop_percentage_needs_enough_packets():
    base = {'packets received': 200, 'packets dropped': 50}
    assert 'DROP_PCT' not in _codes(_row(_ev(_sysinfo() + _counters(None, {'ethernet1/1': base})),
                                         'ethernet1/1'))
    big = {'packets received': 100000, 'packets dropped': 2000}
    row = _row(_ev(_sysinfo() + _counters(None, {'ethernet1/1': big})), 'ethernet1/1')
    assert row['drop_pct'] == 2.0 and _codes(row)['DROP_PCT'] == 'warn'
    huge = {'packets received': 100000, 'packets dropped': 20000}
    row = _row(_ev(_sysinfo() + _counters(None, {'ethernet1/1': huge})), 'ethernet1/1')
    assert _codes(row)['DROP_PCT'] == 'crit'
    row = _row(_ev(_sysinfo() + _counters(None, {'ethernet1/1': big}), {'drop_pct_warn': 5}),
               'ethernet1/1')
    assert 'DROP_PCT' not in _codes(row)


def test_flow_state_check_level_depends_on_uptime():
    logical = {'ethernet1/1': {'packets received': 10, 'packets dropped by flow state check': 500}}
    young = _row(_ev(_sysinfo(uptime='0 days, 0:10:00') + _counters(None, logical)),
                 'ethernet1/1')
    assert _codes(young)['FLOW_STATE_CHECK'] == 'info'
    assert 'non-SYN' in young['flags'][0]['text']
    old = _row(_ev(_sysinfo() + _counters(None, logical)), 'ethernet1/1')
    assert _codes(old)['FLOW_STATE_CHECK'] == 'warn'


def test_ip_spoof_level_depends_on_zone():
    logical = {'ethernet1/1': {'ip spoof attacks': 3}, 'ethernet1/2': {'ip spoof attacks': 3}}
    tables = ('> show interface all\n\ntotal configured logical interfaces: 2\n\n'
              'name                      id    vsys zone             forwarding               tag    address\n'
              '------------------------- ----- ---- ---------------- ------------------------ ------ ------------------\n'
              'ethernet1/1               16    1    untrust          vr:default               0      1.1.1.1/24\n'
              'ethernet1/2               17    1    lan              vr:default               0      10.0.0.1/24\n')
    view = _ev(_sysinfo() + _counters(None, logical) + tables)
    assert _codes(_row(view, 'ethernet1/1')) == {'IP_SPOOF': 'info'}
    assert _codes(_row(view, 'ethernet1/2')) == {'IP_SPOOF': 'warn'}


def test_attack_forwarding_and_l2_flags():
    logical = {'ethernet1/1': {'land attacks': 1, 'forwarding errors': 2, 'mac not found': 30,
                               'packets routed to different zone': 15}}
    codes = _codes(_row(_ev(_sysinfo() + _counters(None, logical)), 'ethernet1/1'))
    assert codes == {'ATTACK_COUNTERS': 'warn', 'FWD_ERRORS': 'warn', 'L2_RESOLUTION': 'warn',
                     'ZONE_CHANGE': 'warn'}


def test_aggregate_interface_and_sub_interfaces():
    logical = {'ae1': {'packets received': 5000, 'packets transmitted': 10, 'no route': 400},
               'ae1.10': {'packets received': 100, 'arp not found': 90}}
    tables = ('> show interface all\n\ntotal configured hardware interfaces: 1\n\n'
              'name                    id    speed/duplex/state            mac address       \n'
              '--------------------------------------------------------------------------------\n'
              'ethernet1/1             16    1000/full/up                  72:99:c7:d3:38:02 \n'
              '\naggregation groups: 1\n\n'
              'name                    id    speed/duplex/state            mac address       \n'
              '--------------------------------------------------------------------------------\n'
              'ae1                     25    10000/full/up                 72:99:c7:d3:38:09 \n')
    view = _ev(_sysinfo() + _counters(None, logical) + tables)
    ae, sub = _row(view, 'ae1'), _row(view, 'ae1.10')
    assert (ae['kind'], ae['state'], ae['speed']) == ('aggregate', 'up', '10000')
    assert (sub['kind'], sub['parent']) == ('sub-interface', 'ae1')
    assert _codes(ae)['NO_ROUTE'] == 'warn' and _codes(sub)['ARP_NOT_FOUND'] == 'warn'
    assert [r['name'] for r in view['rows']] == ['ae1', 'ae1.10', 'ethernet1/1']


@pytest.mark.parametrize('name,kind,parent', [
    ('ethernet1/1', 'physical', None), ('ethernet1/2.30', 'sub-interface', 'ethernet1/2'),
    ('ae2', 'aggregate', None), ('ae2.5', 'sub-interface', 'ae2'),
    ('tunnel', 'tunnel', None), ('tunnel.1000', 'tunnel', 'tunnel'),
    ('vlan', 'vlan', None), ('vlan.20', 'vlan', 'vlan'), ('loopback.1', 'loopback', 'loopback'),
    ('mgmt', 'other', None)])
def test_interface_kind(name, kind, parent):
    assert interface_kind(name) == (kind, parent)


def test_natural_sort_of_interface_names():
    logical = {n: {'packets received': 1} for n in ('ethernet1/10', 'ethernet1/2', 'ethernet1/2.3',
                                                    'ethernet1/9')}
    view = _ev(_sysinfo() + _counters(None, logical))
    assert [r['name'] for r in view['rows']] == ['ethernet1/2', 'ethernet1/2.3', 'ethernet1/9',
                                                  'ethernet1/10']


def test_crosscheck_mismatch_raises_info_flag():
    glob = ('> show counter global\n\nGlobal counters:\n\nname value rate severity category '
            'aspect description\n' + BAR + '\n'
            'flow_fwd_l3_noarp                        900        0 drop      flow      forward   '
            'Packets dropped: no ARP\n')
    view = _ev(_sysinfo() + glob + _counters(None, {'ethernet1/1': {'arp not found': 100}}))
    x = next(x for x in view['crosscheck'] if x['label'] == 'ARP not found')
    assert x['status'] == 'differs' and x['diff'] == -800
    assert any(b['code'] == 'XCHECK_MISMATCH' for b in view['banner'])
    close = _ev(_sysinfo() + glob.replace('900', '105')
                + _counters(None, {'ethernet1/1': {'arp not found': 100}}))
    assert close['crosscheck'][0]['status'] == 'match'


def test_short_uptime_flag_and_boundary():
    assert _ev(_sysinfo(uptime='0 days, 0:59:59'))['banner'][0]['code'] == 'UPTIME_SHORT'
    assert not any(b['code'] == 'UPTIME_SHORT'
                   for b in _ev(_sysinfo(uptime='0 days, 1:00:00'))['banner'])
    assert parse_uptime('12 days, 3:04:05') == 12 * 86400 + 3 * 3600 + 4 * 60 + 5
    assert parse_uptime('2:00:00') == 7200 and parse_uptime('garbage') is None
    assert parse_uptime(None) is None


# ---------------------------------------------------------------- missing / odd input
def test_missing_commands_are_skipped_with_warnings():
    view = _ev(_counters(None, {'ethernet1/1': {'packets received': 5}}))
    assert view['system']['uptime_s'] is None and view['system']['hostname'] == ''
    msgs = ' | '.join(view['warnings'])
    assert 'show system info not found' in msgs and 'show interface all not found' in msgs
    assert 'show counter global not found' in msgs and view['crosscheck'] == []
    assert not any(b['code'] == 'UPTIME_SHORT' for b in view['banner'])


def test_no_interface_output_means_no_data():
    parsed = parse_interfaces(_sysinfo().splitlines())
    assert not has_data(parsed)
    assert not has_data(parse_interfaces([]))
    assert not has_data(parse_interfaces(POW_FIXTURE.read_text(encoding='utf-8').splitlines()))


def test_empty_sections_do_not_break_the_parser():
    text = ('> show counter interface all\n\nHardware interface counters:\n' + BAR + '\n\n'
            'Logical interface counters:\n' + BAR + '\n\n'
            '> show transceiver all\n\n' + BAR + '\n         Port   Temperature      Voltage\n'
            + BAR + '\n\n> show lacp aggregate-ethernet all\n\n\n'
            '> show interface all\n\ntotal configured hardware interfaces: 0\n')
    view = _ev(text)
    assert view['rows'] == [] and view['crosscheck'] == []
    assert view['transceivers']['header'] == ['Port', 'Temperature', 'Voltage']


def test_transceiver_and_lacp_rows_are_kept():
    text = (_sysinfo() + '> show transceiver all\n\n' + BAR +
            '\n         Port   Temperature      Voltage      Current    Tx Power    Rx Power\n' +
            BAR + '\n    ethernet1/17        38.2         3.3        6.1      -2.1       -3.4\n\n'
            '> show lacp aggregate-ethernet all\n\nAggregate Interface: ae1\n  Member: ethernet1/1\n')
    view = _ev(text)
    assert view['transceivers']['rows'] == [['ethernet1/17', '38.2', '3.3', '6.1', '-2.1', '-3.4']]
    assert view['transceivers']['header'][-1] == 'Rx Power'
    assert len(view['lacp']) == 2


def test_second_dataplane_and_duplicate_sections_are_ignored_with_warning():
    one = {'ethernet1/1': {'packets received': 7, 'no route': 1}}
    other = {'ethernet1/1': {'packets received': 900, 'no route': 800}}
    text = (_sysinfo() + '> show counter interface all\n\nDP dp0:\n' +
            _counters(None, one).split('\n', 1)[1] + 'DP dp1:\n' +
            _counters(None, other).split('\n', 1)[1])
    view = _ev(text)
    assert _row(view, 'ethernet1/1')['logical']['no route'] == 1
    assert any('several dataplanes' in w for w in view['warnings'])
    twice = _sysinfo() + _counters(None, one) + _counters(None, other)
    view = _ev(twice)
    assert _row(view, 'ethernet1/1')['logical']['no route'] == 1
    assert any('second "show counter interface all" ignored' in w for w in view['warnings'])


def test_prompt_prefixed_commands_and_unknown_counters():
    text = _sysinfo().replace('> show', 'admin@PA-440(active)> show') + _counters(
        None, {'ethernet1/1': {'packets received': 5, 'brand new counter': 4}}).replace(
        'tcp cps                                 0',
        'brand new counter                       4\ntcp cps                                 0')
    view = _ev(text.replace('\n> show counter', '\nadmin@PA-440(active)> show counter'))
    assert view['system']['hostname'] == 'fw-test'
    r = _row(view, 'ethernet1/1')
    assert r['logical'].get('brand new counter') == 4
    cols = [c['k'] for g in view['groups'] for c in g['cols']]
    assert 'brand new counter' in cols
    entry = if_glossary.glossary_subset(['brand new counter'])['brand new counter']
    assert entry['f'] == 'U' and entry['u'] == 0 and entry['c'] == 'Unclassified'


def test_merge_parsed_takes_the_first_non_empty_value():
    a = parse_interfaces(_sysinfo(host='first').splitlines(), 'a')
    b = parse_interfaces((_sysinfo(host='second') + _counters(
        None, {'ethernet1/1': {'packets received': 5}})).splitlines(), 'b')
    merged = merge_parsed([a, b])
    assert merged['system']['hostname'] == 'first'
    assert 'ethernet1/1' in merged['counters']


# ---------------------------------------------------------------- glossary
def test_every_counter_the_heuristics_use_has_a_glossary_entry():
    keys = (set(interface_errors.PHY_ERROR_KEYS) | set(interface_errors.PHY_MINOR_KEYS)
            | set(interface_errors.ATTACK_KEYS) | set(interface_errors.L2_KEYS))
    for k in keys:
        assert k in if_glossary.GLOSSARY, k
    for k in interface_errors.HW_ERROR_KEYS:
        assert 'cpu: ' + k in if_glossary.GLOSSARY, k
    for _label, counter, gnames, _kind, _note in interface_errors.XCHECKS:
        assert counter in if_glossary.GLOSSARY
        for g in gnames:
            assert g in if_glossary.GLOBAL_DROP_COUNTERS


def test_glossary_entries_have_a_valid_shape():
    for key, g in if_glossary.GLOSSARY.items():
        assert g['conf'] in 'DGIU' and g['meaning'] and g['category'], key
        assert g['kind'] == 'counter'
    subset = if_glossary.glossary_subset(['no route', 'cpu: packets dropped', 'nonsense'])
    assert subset['no route'] == {'c': if_glossary.CAT_LOG, 'f': 'G',
                                  'm': if_glossary.GLOSSARY['no route']['meaning'],
                                  'k': 'counter', 'u': 1}
    assert subset['cpu: packets dropped']['c'] == if_glossary.CAT_CPU
    assert subset['nonsense']['u'] == 0
    fields = if_glossary.field_entries()
    assert fields['if:drop_pct']['f'] == 'I' and fields['if:zone']['f'] == 'D'
    assert all(k.startswith('if:') and v['m'] for k, v in fields.items())


def test_glossary_has_no_key_clash_with_the_pow_glossary():
    from panos_toolbox.tsf import pow_glossary
    assert not set(if_glossary.GLOSSARY) & set(pow_glossary.GLOSSARY)
    assert not set(if_glossary.field_entries()) & set(pow_glossary.field_entries())


def test_help_table_lists_every_column_counter():
    table = if_glossary.help_table_html()
    for gid, names in if_glossary.GROUP_COUNTERS.items():
        for n in names:
            assert f'<code>{if_glossary.gl_key(gid, n)}</code>' in table, n
    assert '<code>flow_fwd_l3_noarp</code>' in table
    assert '<script' not in table


def test_glossary_keys_cover_the_columns_of_a_view(sample):
    keys = interface_errors.glossary_keys(sample)
    assert {'no route', 'flow_fwd_l3_noroute', 'flow_policy_nofwd', 'arp not found'} <= keys
    assert all(k in if_glossary.GLOSSARY for k in keys)


# ---------------------------------------------------------------- help
def _help():
    return ''.join(render_section_help().values())


def test_every_interface_flag_code_is_documented():
    codes = set(re.findall(r"_flag\(\s*r?\w*,\s*'([A-Z_]+)'", SRC))
    codes |= set(re.findall(r"'code':\s*'([A-Z_]+)'", SRC))
    assert {'PHY_ERRORS', 'DROP_PCT', 'NO_ROUTE', 'ARP_NOT_FOUND', 'IP_SPOOF', 'UPTIME_SHORT',
            'XCHECK_MISMATCH', 'LINK_HALF_DUPLEX', 'DOWN_CONFIGURED'} <= codes
    out = _help()
    missing = sorted(c for c in codes if f'<code>{c}</code>' not in out)
    assert not missing, missing


def test_interface_help_sections_exist_and_are_in_the_template():
    for sid in ('ifc', 'iflags', 'itable', 'ixchk'):
        assert sid in SECTION_HELP
        assert f'__HB_{sid}__' in report_template.TEMPLATE
        assert f'__HP_{sid}__' in report_template.TEMPLATE


def test_interface_help_uses_live_thresholds_and_escapes():
    out = _help()
    assert f"drop_pct_warn = {IF_THRESHOLDS['drop_pct_warn']}%" in out
    changed = ''.join(render_section_help(None, {'drop_pct_warn': 2.5}).values())
    assert 'drop_pct_warn = 2.5%' in changed and 'drop_pct_warn = 1.0%' not in changed
    hostile = ''.join(render_section_help(None, {'min_packets': '<b>x</b>'}).values())
    assert '<b>x</b>' not in hostile and '&lt;b&gt;x&lt;/b&gt;' in hostile
    assert not re.search(r'\{[a-z_]+\}', out)
    with pytest.raises(ValueError):
        render_section_help(None, {'bogus': 1})


def test_help_documents_every_counter_meaning_and_confidence_codes():
    out = render_section_help()['__HP_ifc__']
    assert 'packets with bad crc' in out and 'flow_dos_pf_ipspoof' in out
    assert 'cumulative since boot' in out
    for code in 'DGIU':
        assert f'<b>{code}</b>' in out


# ---------------------------------------------------------------- analyzer / report
def _report(tmp_path, *args):
    outdir = tmp_path / 'out'
    analyzer.main([*map(str, args), '-o', str(outdir)])
    files = list(outdir.glob('*.html'))
    assert len(files) == 1
    return files[0]


def _data(content):
    m = re.search(r'const D = (\{.*?\});\nconst \$ =', content, re.DOTALL)
    return json.loads(m.group(1).replace('<\\/', '</'))


def test_main_writes_an_interfaces_report_for_a_plain_file(tmp_path):
    report = _report(tmp_path, FIXTURE)
    assert report.name.endswith('_interfaces.html')
    content = report.read_text(encoding='utf-8')
    for ph in ('__HB_', '__HP_', '__DATA__', '__TITLE__', '__KIND__'):
        assert ph not in content
    for sid in ('ifc', 'iflags', 'itable', 'ixchk'):
        assert f'id="help-{sid}" hidden' in content
    assert 'id="tab-ifc"' in content and 'Interface Errors' in content
    d = _data(content)
    assert d['kind'] == 'TSF analysis' and d['pow'] is None and d['samples'] == []
    assert d['ifc']['system']['hostname'] == 'fw-anon-7894'
    assert d['gl']['names']['no route']['k'] == 'counter'
    assert d['gl']['names']['flow_fwd_l3_noroute']['f'] == 'D'
    assert 'if:zone' in d['gl']['fields']


def test_main_with_pow_and_interfaces_in_one_file(tmp_path):
    combined = tmp_path / 'both.txt'
    combined.write_text(POW_FIXTURE.read_text(encoding='utf-8') + '\n'
                        + FIXTURE.read_text(encoding='utf-8'), encoding='utf-8')
    report = _report(tmp_path, combined)
    assert report.name.endswith('_tsf.html')
    d = _data(report.read_text(encoding='utf-8'))
    assert d['pow'] is not None and d['ifc'] is not None
    assert 'flow_fastpath' in d['gl']['names'] and 'no route' in d['gl']['names']


def test_pow_only_report_keeps_its_name_and_has_no_interface_data(tmp_path):
    report = _report(tmp_path, POW_FIXTURE)
    assert report.name.endswith('_pow.html')
    d = _data(report.read_text(encoding='utf-8'))
    assert d['ifc'] is None
    assert 'id="help-ifc" hidden' in report.read_text(encoding='utf-8')


def test_main_tgz_reads_cli_files_and_merges_them(tmp_path):
    tsf = tmp_path / 'tsf.tgz'
    parts = {'tsf/tmp/cli/a-sys.txt': _sysinfo(host='from-a'),
             'tsf/tmp/cli/b-ifc.txt': _counters(None, {'ethernet1/1': {'packets received': 5,
                                                                      'no route': 300}})}
    with tarfile.open(tsf, 'w:gz') as tf:
        for name, text in parts.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    d = _data(_report(tmp_path, tsf).read_text(encoding='utf-8'))
    assert d['ifc']['system']['hostname'] == 'from-a'
    assert _row(d['ifc'], 'ethernet1/1')['logical']['no route'] == 300


def test_main_directory_input(tmp_path):
    root = tmp_path / 'tsf' / 'tmp' / 'cli'
    root.mkdir(parents=True)
    shutil.copy(FIXTURE, root / 'show.txt')
    d = _data(_report(tmp_path, tmp_path / 'tsf').read_text(encoding='utf-8'))
    assert 'ethernet1/7.222' in [r['name'] for r in d['ifc']['rows']]


def test_if_threshold_options_and_validation(tmp_path):
    report = _report(tmp_path, FIXTURE, '--if-no-route-min', '5000')
    d = _data(report.read_text(encoding='utf-8'))
    assert d['ifc']['thresholds']['no_route_min'] == 5000
    assert not any(f['code'] == 'NO_ROUTE' for r in d['ifc']['rows'] for f in r['flags'])
    assert 'no_route_min = 5000' in report.read_text(encoding='utf-8')
    with pytest.raises(SystemExit):
        analyzer.main([str(FIXTURE), '--if-no-route-min', '-1', '-o', str(tmp_path / 'x')])


def test_cli_text_without_interface_or_pow_data_writes_nothing(tmp_path):
    f = tmp_path / 'clock.txt'
    f.write_text('> show clock\n\nTue Oct 27 08:20:20 CET 2026\n', encoding='utf-8')
    outdir = tmp_path / 'out'
    analyzer.main([str(f), '-o', str(outdir)])
    assert not outdir.exists() or not any(outdir.iterdir())


@pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')
def test_report_script_has_no_syntax_errors(tmp_path):
    content = _report(tmp_path, FIXTURE).read_text(encoding='utf-8')
    script = re.findall(r'<script>(.*?)</script>', content, re.DOTALL)[-1]
    js = tmp_path / 'report.js'
    js.write_text(script, encoding='utf-8')
    res = subprocess.run(['node', '--check', str(js)], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr

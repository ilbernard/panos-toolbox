"""Tests for gp/checks.py: findings from synthetic configuration and timeline data only."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from panos_toolbox.gp import checks
from panos_toolbox.gp.checks import (
    ERR_AUTH_PORTAL,
    ERR_GW_CERT,
    ERR_GW_UNREACHABLE,
    ERR_RESTORE_GRACE,
    FLAG_HELP,
    GP_THRESHOLDS,
    evaluate,
    status,
    to_dicts,
)
from panos_toolbox.gp.client_config import ClientConfig, Section
from panos_toolbox.gp.timeline import Attempt, Timeline

# The logs carry no UTC offset: all times are naive, like the real data.
# ruff: noqa: DTZ001

NEWEST = datetime(2026, 11, 14, 12, 0, 0)
GW = 'vpn.example.com'


def at(days: float = 0, hours: float = 0) -> datetime:
    return NEWEST - timedelta(days=days, hours=hours)


def attempt(n, start, outcome='connected', kind='login', error='', **kw) -> Attempt:
    a = Attempt(kind=kind, start=start, end=start + timedelta(seconds=5), outcome=outcome,
                portal=GW, gateway=GW, user='jdoe', id=f'a{n:04d}', **kw)
    if error:
        a.error_text = error
        a.error_raw = error
    return a


def healthy_config(**data) -> ClientConfig:
    d = {'connection': {'connected': True}, 'registry': {'settings': {'x': {'value': '1'}}},
         'pangp_adapter': {'present': True}}
    d.update(data)
    return ClientConfig(sections=[Section('registry', 'Registry', [], NEWEST, 'current',
                                          '1 setting(s) found.')],
                        collected_at=NEWEST, newest_record=NEWEST, data=d)


def healthy_timeline(attempts=None, **cov) -> Timeline:
    coverage = {'event_log': {'last': NEWEST.isoformat()},
                'service_log': {'last': NEWEST.isoformat()},
                'event_log_ends_before_detail_s': None}
    coverage.update(cov)
    return Timeline(attempts=attempts or [attempt(1, at(hours=1))], coverage=coverage)


def codes(findings):
    return {f.code for f in findings}


def get(findings, code):
    return [f for f in findings if f.code == code]


def test_healthy_inputs_give_no_findings():
    f = evaluate(healthy_config(), healthy_timeline())
    assert f == [] and status(f) == 'ok'


def test_driver_disabled_levels():
    ev = [{'ts': datetime(2026, 11, 14, 1, 1), 'kind': 'problem', 'device': 'ROOT\\PANGPD\\0000',
           'code': 22, 'meaning': 'device is disabled'}]
    crit = evaluate(healthy_config(driver_events=ev, pangp_adapter={'present': False}),
                    healthy_timeline())
    f = get(crit, 'DRIVER_DISABLED')[0]
    assert f.level == 'critical' and 'code 22 (device disabled)' in f.text
    assert '2026-11-14 01:01:00' in f.text and status(crit) == 'critical'
    warn = evaluate(healthy_config(driver_events=ev), healthy_timeline())
    assert get(warn, 'DRIVER_DISABLED')[0].level == 'warning'
    ok = ev + [{'ts': datetime(2026, 11, 14, 2, 0), 'kind': 'line', 'code': None}]
    assert 'DRIVER_DISABLED' not in codes(evaluate(healthy_config(driver_events=ok),
                                                   healthy_timeline()))


def test_not_connected_at_collection():
    conn = {'connected': False, 'last_state': 'Disconnected', 'last_state_at': datetime(2026, 11, 14, 9)}
    f = get(evaluate(healthy_config(connection=conn), healthy_timeline()),
            'NOT_CONNECTED_AT_COLLECTION')
    assert f and f[0].level == 'info' and "'Disconnected'" in f[0].text
    assert 'NOT_CONNECTED_AT_COLLECTION' not in codes(evaluate(
        healthy_config(connection={'connected': None}), healthy_timeline()))


def test_last_attempt_failed():
    tl = healthy_timeline([attempt(1, at(hours=3)),
                           attempt(2, at(hours=1), 'failed', error=ERR_GW_CERT)])
    f = get(evaluate(healthy_config(), tl), 'LAST_ATTEMPT_FAILED')
    assert f and f[0].ref_ids == ['a0002'] and ERR_GW_CERT in f[0].text
    tl = healthy_timeline([attempt(1, at(hours=3), 'failed', error='x'), attempt(2, at(hours=1))])
    assert 'LAST_ATTEMPT_FAILED' not in codes(evaluate(healthy_config(), tl))
    tl = healthy_timeline([attempt(1, at(hours=1), 'cancelled')])
    assert 'LAST_ATTEMPT_FAILED' not in codes(evaluate(healthy_config(), tl))


def storm(end):
    return {'id': 1, 'start': (end - timedelta(minutes=2)).isoformat(), 'end': end.isoformat(),
            'count': 12, 'median_interval_ms': 900, 'first_attempt': 'a0001',
            'last_attempt': 'a0012', 'by_error': {'Gateway pre-login failed': 12}}


def test_retry_storm_levels():
    old = Timeline(attempts=[attempt(1, at(hours=1))], storms=[storm(at(days=30))],
                   coverage=healthy_timeline().coverage)
    f = get(evaluate(healthy_config(), old), 'RETRY_STORM')[0]
    assert f.level == 'warning' and f.count == 12 and 'Gateway pre-login failed: 12' in f.text
    recent = Timeline(attempts=old.attempts, storms=[storm(at(days=1))], coverage=old.coverage)
    assert get(evaluate(healthy_config(), recent), 'RETRY_STORM')[0].level == 'critical'
    assert 'RETRY_STORM' not in codes(evaluate(healthy_config(), healthy_timeline()))


def failures(error, n, days=1.0):
    return [attempt(10 + i, at(days=days, hours=i), 'failed', error=error) for i in range(n)]


def test_repeated_failure_threshold_and_window():
    tl = healthy_timeline(failures('Tunnel creation failed', 3) + [attempt(1, at(hours=0.1))])
    f = get(evaluate(healthy_config(), tl), 'REPEATED_FAILURE')
    assert len(f) == 1 and f[0].count == 3 and len(f[0].ref_ids) == 3
    two = healthy_timeline(failures('Tunnel creation failed', 2) + [attempt(1, at(hours=0.1))])
    assert 'REPEATED_FAILURE' not in codes(evaluate(healthy_config(), two))
    old = healthy_timeline(failures('Tunnel creation failed', 3, days=20) + [attempt(1, at(hours=0.1))])
    assert 'REPEATED_FAILURE' not in codes(evaluate(healthy_config(), old))
    assert 'REPEATED_FAILURE' in codes(evaluate(healthy_config(), old, {'recent_days': 30}))


def test_repeated_failure_caps_refs_and_one_per_text():
    many = failures('Tunnel creation failed', 15) + failures('Gateway pre-login failed', 3)
    f = get(evaluate(healthy_config(), healthy_timeline(many + [attempt(1, at(hours=0.1))])),
            'REPEATED_FAILURE')
    assert len(f) == 2
    big = next(x for x in f if x.count == 15)
    assert len(big.ref_ids) == int(GP_THRESHOLDS['refs_cap'])


@pytest.mark.parametrize('code,error', [
    ('GW_CERT_FAILURE', ERR_GW_CERT), ('GW_UNREACHABLE', ERR_GW_UNREACHABLE),
    ('AUTH_FAILURE', ERR_AUTH_PORTAL), ('AUTH_FAILURE', 'Portal pre-login: Authentication Failed'),
])
def test_error_class_findings(code, error):
    tl = healthy_timeline(failures(error, 1) + [attempt(1, at(hours=0.1))])
    f = get(evaluate(healthy_config(), tl), code)
    assert f and f[0].level == 'warning' and f[0].count == 1 and GW in f[0].text
    other = healthy_timeline(failures('Tunnel creation failed', 1) + [attempt(1, at(hours=0.1))])
    assert code not in codes(evaluate(healthy_config(), other))
    old = healthy_timeline(failures(error, 1, days=20) + [attempt(1, at(hours=0.1))])
    assert code not in codes(evaluate(healthy_config(), old))
    assert code not in codes(evaluate(healthy_config(), tl, {'class_failure_min': 2,
                                                             'auth_failure_min': 2}))


def test_auth_failure_ignores_chained_credential_prompt():
    chained = attempt(2, at(hours=2), 'connected', cycles=2)
    tl = healthy_timeline([chained, attempt(3, at(hours=1))])
    assert 'AUTH_FAILURE' not in codes(evaluate(healthy_config(), tl))


def restore(n, days, error=ERR_RESTORE_GRACE, outcome='failed'):
    a = attempt(n, at(days=days), outcome, kind='auto-restore', error=error)
    a.details = {'grace_exceeded': {'downtime_ms': 7200000, 'grace_s': 1800}}
    return a


def test_restore_grace_exceeded():
    tl = healthy_timeline([restore(2, 1), restore(3, 2), attempt(1, at(hours=1))])
    f = get(evaluate(healthy_config(), tl), 'RESTORE_GRACE_EXCEEDED')[0]
    assert f.level == 'info' and f.count == 2 and 'slept' in f.text and '1800 s' in f.text
    out = healthy_timeline([restore(2, 20), attempt(1, at(hours=1))])
    assert 'RESTORE_GRACE_EXCEEDED' not in codes(evaluate(healthy_config(), out))
    other = healthy_timeline([restore(2, 1, error='Tunnel restore retries failed'),
                              attempt(1, at(hours=1))])
    other.attempts[0].details = {}
    assert 'RESTORE_GRACE_EXCEEDED' not in codes(evaluate(healthy_config(), other))


def test_low_success_rate_thresholds():
    att = ([attempt(i, at(hours=i + 1)) for i in range(1, 3)]
           + [attempt(10 + i, at(hours=i + 5), 'failed', error=f'e{i}') for i in range(3)]
           + [attempt(20, at(hours=9), 'cancelled')])
    tl = healthy_timeline(att)
    f = get(evaluate(healthy_config(), tl), 'LOW_SUCCESS_RATE')
    assert f and '2 of 5' in f[0].text and '40%' in f[0].text
    assert 'LOW_SUCCESS_RATE' not in codes(evaluate(healthy_config(), tl,
                                                    {'success_rate_min_pct': 30}))
    assert 'LOW_SUCCESS_RATE' not in codes(evaluate(healthy_config(), tl,
                                                    {'success_rate_min_attempts': 6}))
    assert 'LOW_SUCCESS_RATE' not in codes(evaluate(healthy_config(), healthy_timeline(att[:4])))


def test_stale_trb_report():
    sec = Section('troubleshooting', 'Report', [], None, 'historical', '')
    trb = {'_local_time': '2026-07-20 14:08:16', 'portal_address': GW,
           'error_stage': 'Portal pre-login', 'error': 'Authentication Failed.'}
    cfg = healthy_config(troubleshooting=trb)
    cfg.sections.append(sec)
    f = get(evaluate(cfg, healthy_timeline()), 'STALE_TRB_REPORT')
    assert f and f[0].level == 'info' and '2026-07-20' in f[0].text and 'Portal pre-login' in f[0].text
    sec.freshness = 'current'
    assert 'STALE_TRB_REPORT' not in codes(evaluate(cfg, healthy_timeline()))


def test_log_gap_threshold():
    tl = healthy_timeline(event_log_ends_before_detail_s=75000)
    f = get(evaluate(healthy_config(), tl), 'LOG_GAP')
    assert f and f[0].level == 'info' and '20.8 h' in f[0].text
    assert 'LOG_GAP' not in codes(evaluate(healthy_config(), tl, {'log_gap_s': 100000}))
    assert 'LOG_GAP' not in codes(evaluate(healthy_config(), healthy_timeline(
        event_log_ends_before_detail_s=600)))


def test_config_truncated():
    cfg = healthy_config(gateway_configs={GW: {'truncated': True}})
    f = get(evaluate(cfg, healthy_timeline()), 'CONFIG_TRUNCATED')
    assert f and f[0].level == 'info' and GW in f[0].text and f[0].ref_ids == ['gateways']
    ok = healthy_config(gateway_configs={GW: {'truncated': False}}, scan={'truncated_dumps': 0})
    assert 'CONFIG_TRUNCATED' not in codes(evaluate(ok, healthy_timeline()))
    warn = healthy_config()
    warn.warnings.append('pan_gp_hrpt.xml: not a valid XML document')
    assert 'CONFIG_TRUNCATED' in codes(evaluate(warn, healthy_timeline()))


def test_partial_bundle():
    tl = healthy_timeline(event_log=None)
    f = get(evaluate(healthy_config(), tl), 'PARTIAL_BUNDLE')
    assert f and f[0].level == 'warning' and 'event log' in f[0].text
    cfg = healthy_config(registry={})
    cfg.sections[0].note = 'Not in bundle: regval.txt.'
    f = get(evaluate(cfg, healthy_timeline()), 'PARTIAL_BUNDLE')
    assert f and 'registry' in f[0].text and f[0].ref_ids == ['registry']
    assert 'PARTIAL_BUNDLE' not in codes(evaluate(healthy_config(), healthy_timeline()))


def test_recent_window_is_anchored_to_logs_not_clock():
    # Everything is years in the past relative to the wall clock but inside the log window.
    tl = healthy_timeline(failures(ERR_GW_CERT, 1) + [attempt(1, at(hours=0.1))])
    assert 'GW_CERT_FAILURE' in codes(evaluate(healthy_config(), tl))


def test_empty_inputs_never_raise():
    assert isinstance(evaluate(ClientConfig(), Timeline()), list)
    assert isinstance(evaluate(None, None), list)
    assert isinstance(evaluate(object(), object(), {'recent_days': 'bad'}), list)
    assert status([]) == 'ok' and status(None) == 'no_data'


def test_to_dicts_is_json_serialisable():
    cfg = healthy_config(connection={'connected': False, 'last_state': 'x',
                                     'last_state_at': datetime(2026, 11, 14, 9)},
                         gateway_configs={GW: {'truncated': True}})
    tl = healthy_timeline(failures(ERR_GW_UNREACHABLE, 3) + [attempt(1, at(hours=0.1))],
                          event_log_ends_before_detail_s=90000)
    tl.storms = [storm(at(days=1))]
    rows = to_dicts(evaluate(cfg, tl))
    assert rows and json.loads(json.dumps(rows)) == rows
    for r in rows:
        assert set(r) == {'code', 'level', 'title', 'text', 'scope', 'when', 'refs', 'count'}
        assert r['title'] == FLAG_HELP[r['code']][0]
        assert r['when'] is None or isinstance(r['when'], str)
        assert all(isinstance(x, str) for x in r['refs'])
    assert status(evaluate(cfg, tl)) == 'critical'


def test_flag_codes_in_source_are_documented():
    src = Path(checks.__file__).read_text(encoding='utf-8')
    found = set(re.findall(r"'([A-Z][A-Z_]{5,})'", src))
    used = {c for c in found if c in FLAG_HELP or c.endswith(('_FAILURE', '_DISABLED', '_STORM',
                                                              '_REPORT', '_GAP', '_BUNDLE',
                                                              '_TRUNCATED', '_FAILED',
                                                              '_UNREACHABLE', '_EXCEEDED',
                                                              '_RATE', '_COLLECTION'))}
    assert used and used <= set(FLAG_HELP), used - set(FLAG_HELP)
    assert set(FLAG_HELP) <= found
    for code, (title, text) in FLAG_HELP.items():
        assert title and len(text) > 40, code


def test_thresholds_are_complete_and_overridable():
    src = Path(checks.__file__).read_text(encoding='utf-8')
    for key in re.findall(r"_num\(thr, '(\w+)'", src):
        assert key in GP_THRESHOLDS, key
    assert GP_THRESHOLDS['repeated_failure_min'] == 3 and GP_THRESHOLDS['recent_days'] == 7
    assert GP_THRESHOLDS['success_rate_min_pct'] == 70 and GP_THRESHOLDS['log_gap_s'] == 3600

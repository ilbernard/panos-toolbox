"""Findings of the GlobalProtect client analyzer (standard library only).

Turns the structured facts of ``client_config.build_config`` and the attempts of
``timeline.build_timeline`` into a list of findings (code, level, text), using the generic
model of ``tsf/findings.py`` unchanged::

    findings = evaluate(config, timeline)        # never raises
    rows = to_dicts(findings)                    # JSON-serialisable
    state = status(findings)                     # ok / warning / critical / no_data

Every finding is a ``GpFinding``: a ``tsf.findings.Finding`` (code, level, text, scope) plus
``when`` (time of the evidence), ``ref_ids`` (attempt ids and/or configuration section ids)
and ``count``. The generic ``Finding.refs`` (source file and line) is left empty.

The "recent window" (``GP_THRESHOLDS['recent_days']``) is anchored to the newest log record,
never to the wall clock. Error classes are matched on the normalised error texts of
``timeline.normalise_error`` (constants ``ERR_*`` below, defined once). Only facts present in
the data are reported; the help (``FLAG_HELP``) explains in general what a code can mean.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from panos_toolbox.tsf.findings import CRITICAL, INFO, WARNING, Finding, module_status

# Normalised error texts of gp/timeline.py (normalise_error) that identify an error class.
ERR_GW_CERT = 'Gateway certificate could not be verified'
ERR_GW_UNREACHABLE = 'Gateway unreachable or unresponsive'
ERR_AUTH_PORTAL = 'Portal rejected the credentials'
ERR_RESTORE_GRACE = 'Tunnel not restored within the retry grace period'
_AUTH_MARKERS = ('authentication failed', 'auth failed', 'invalid user credential',
                 'rejected the credentials')

GP_THRESHOLDS: dict[str, float] = {
    'recent_days': 7,              # recent window (days before the newest log record)
    'repeated_failure_min': 3,     # same error text on at least N login failures
    'class_failure_min': 1,        # gateway certificate / unreachable failures needed
    'auth_failure_min': 1,         # authentication failures needed
    'restore_grace_min': 1,        # expired (grace period) restores needed
    'restore_failed_min': 1,       # auto-restores with a real failed retry needed
    'success_rate_min_pct': 70,    # login success rate below this percentage is low
    'success_rate_min_attempts': 5,  # attempts (cancelled excluded) needed to judge the rate
    'log_gap_s': 3600,             # event log ends this long before the detailed logs
    'refs_cap': 10,                # attempt ids listed in one finding
}

FLAG_HELP: dict[str, tuple[str, str]] = {
    'DRIVER_DISABLED': (
        'PANGP virtual adapter driver disabled',
        ('The newest PANGP event of setupapi.dev.log is a device problem (for example Code 22). '
         'Windows problem code 22 means "device disabled": this meaning comes from Windows '
         'documentation, not from the file. The GlobalProtect virtual adapter is normally '
         'disabled while the client is not connected, so the level depends on the client state. '
         'Info: the client was not connected at collection; the entry matters only if '
         'connections fail at tunnel creation. Warning: in the recent window login attempts '
         'failed during tunnel creation or adapter setup and a driver problem event exists. '
         'Critical: the client was connected at collection (snapshot or last service state) '
         'while the newest driver event is a problem code or the PANGP adapter is absent. '
         'Check Device Manager (Network adapters, PANGP Virtual Ethernet Adapter), whether the '
         'adapter was disabled by a person, a script or a reinstall, and whether the client can '
         'enable it again.')),
    'NOT_CONNECTED_AT_COLLECTION': (
        'Client not connected at collection',
        ('The connection state rebuilt from the status XML, service start/stop records and the '
         'adapter snapshot says the tunnel was not up when the logs were collected. It is a '
         'state, not an error: it can be a normal disconnect. Compare with the last attempts '
         'and the last service state.')),
    'LAST_ATTEMPT_FAILED': (
        'Most recent login attempt failed',
        ('The newest login attempt of the timeline ended failed or abandoned (cancelled by the '
         'user is not reported). Computed from the login attempts sorted by start; '
         'auto-restores, expired or not, are not login attempts. Check the error text and stage of the attempt and the gateway or '
         'portal it names.')),
    'RETRY_STORM': (
        'Retry storm',
        ('Many failed login attempts, each starting within a few seconds of the previous one '
         '(thresholds in the timeline parameters). Warning; critical when the storm ended '
         'inside the recent window. Typical of an automatic retry loop that keeps hitting the '
         'same error. Check the error breakdown, and what changed on the portal or the client '
         'at that time.')),
    'REPEATED_FAILURE': (
        'Same login failure repeated',
        ('The same normalised error text appears on at least repeated_failure_min failed login '
         'attempts inside the recent window (one finding per text). Check whether the cause is '
         'persistent (configuration, certificate, network path) or one event repeated.')),
    'GW_CERT_FAILURE': (
        'Gateway certificate could not be verified',
        ('Failed login attempts in the recent window ended with the gateway server certificate '
         'check failing. Check the certificate chain and validity on the gateway, that the root '
         'and intermediate CAs are trusted by the client, the system date of the client and '
         'any TLS inspection on the path.')),
    'GW_UNREACHABLE': (
        'Gateway unreachable or unresponsive',
        ('Failed login attempts in the recent window ended with the client reporting the '
         'gateway as unreachable or unresponsive. Check name resolution and reachability of the '
         'gateway from the client network, the firewall or ISP path, and the gateway load.')),
    'AUTH_FAILURE': (
        'Authentication failures',
        ('Failed login attempts in the recent window were rejected at authentication (portal or '
         'gateway). Credential prompts that were followed by a successful attempt in the same '
         'chain are not failures and are not counted. Check the account, the password or '
         'token, the authentication profile and the identity provider logs.')),
    'RESTORE_GRACE_EXCEEDED': (
        'Auto-restore refused: downtime over the grace period',
        ('Automatic tunnel restores in the recent window ended "expired": the log says the '
         'tunnel downtime exceeded the retry grace period and no reconnection was attempted '
         '(the final line is still "Tunnel retry done: failed retry"). This normally means the '
         'PC slept (often "Wait in modern standby until wakeup") or was offline for longer '
         'than the grace period; the user then has to connect again. It is not a VPN '
         'malfunction: no action is needed unless it happens while the PC is awake and '
         'online.')),
    'RESTORE_FAILED': (
        'Auto-restore retry attempted and failed',
        ('In the recent window the client really tried to restore the tunnel automatically '
         '(at least one "Retry connect failed" in the event log) and did not succeed. '
         'Restores that only expired because of the grace period are not counted here (see '
         'RESTORE_GRACE_EXCEEDED). Check the error breakdown: a certificate verification '
         'error points to the gateway certificate or a TLS inspection on the path, others to '
         'the network the PC was on when it tried.')),
    'LOW_SUCCESS_RATE': (
        'Low login success rate',
        ('In the recent window, connected login attempts divided by all login attempts '
         '(cancelled excluded; a cancelled outcome is often only inferred from a user '
         'disconnect) is below success_rate_min_pct, with at least '
         'success_rate_min_attempts attempts. Auto-restores, expired or failed, are not '
         'counted. Check the most '
         'frequent error texts of the window.')),
    'STALE_TRB_REPORT': (
        'Troubleshooting report is historical',
        ('pan_gp_trb.log holds the report of the last failed connection and is overwritten only '
         'at the next failure, so it can be much older than the other logs. Its error must not '
         'be read as the current state. Compare its date with the newest log record.')),
    'LOG_GAP': (
        'Event log ends before the detailed logs',
        ('pan_gp_event.log ends more than log_gap_s before the end of PanGPS/PanGPA. Attempts '
         'after that point come from the detailed logs only (no event log cross-check), and '
         'the event-log based history stops there.')),
    'CONFIG_TRUNCATED': (
        'Configuration source truncated or malformed',
        ('A configuration block found in the logs (for example the gateway configuration XML) '
         'was cut by the logger or could not be parsed. Values after the cut are missing and '
         'are not reported as absent settings. Collect the logs again right after a connection '
         'for a complete block.')),
    'PARTIAL_BUNDLE': (
        'Expected files missing or empty',
        ('The event log, the service log (PanGPS) or the registry dump (regval.txt) is missing '
         'or empty in the bundle. The sections and attempts that depend on it are incomplete. '
         'Collect the logs again, or ask for the missing files.')),
}


@dataclass
class GpFinding(Finding):
    """A ``Finding`` with the extra fields of the GlobalProtect checks."""
    when: datetime | None = None
    ref_ids: list[str] = field(default_factory=list)
    count: int | None = None


# ------------------------------------------------------------------------------ helpers
def _dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.strip().replace('Z', ''))
        except ValueError:
            return None
    return None


def _fmt(ts: datetime | None) -> str:
    return ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'unknown time'


def _num(thr: dict, key: str) -> float:
    try:
        return float(thr[key])
    except (KeyError, TypeError, ValueError):
        return float(GP_THRESHOLDS[key])


def _merge(thresholds: dict | None) -> dict:
    out: dict = dict(GP_THRESHOLDS)
    for k, v in (thresholds or {}).items():
        try:
            out[k] = float(v)
        except (TypeError, ValueError):
            pass
    return out


def _data(config: Any) -> dict:
    d = getattr(config, 'data', None)
    return d if isinstance(d, dict) else {}


def _section(config: Any, sid: str) -> Any:
    for sec in getattr(config, 'sections', None) or []:
        if getattr(sec, 'id', None) == sid:
            return sec
    return None


def _attempts(timeline: Any) -> list:
    return [a for a in (getattr(timeline, 'attempts', None) or []) if _dt(a.start)]


def _anchor(config: Any, timeline: Any, attempts: list) -> datetime | None:
    """Newest log record: configuration, coverage of the logs, else the newest attempt."""
    times = [_dt(getattr(config, 'newest_record', None))]
    cov = getattr(timeline, 'coverage', None) or {}
    for key in ('event_log', 'service_log', 'agent_log'):
        times.append(_dt((cov.get(key) or {}).get('last')))
    times += [_dt(a.start) for a in attempts]
    times += [_dt(getattr(a, 'end', None)) for a in attempts]
    found = [t for t in times if t]
    return max(found) if found else None


def _span(items: list) -> tuple[datetime, datetime]:
    return min(_dt(a.start) for a in items), max(_dt(a.start) for a in items)


def _ids(items: list, cap: int) -> list[str]:
    return [a.id for a in items[:cap] if getattr(a, 'id', '')]


def _range(first: datetime, last: datetime) -> str:
    return f'at {_fmt(first)}' if first == last else f'between {_fmt(first)} and {_fmt(last)}'


def _more(n: int, cap: int) -> str:
    return f' (first {cap} listed)' if n > cap else ''


def _mk(code: str, level: str, text: str, scope: str, when: datetime | None = None,
        refs: list[str] | None = None, count: int | None = None) -> GpFinding:
    return GpFinding(code, level, text, scope, [], when, list(refs or []), count)


def _err(a: Any) -> str:
    return getattr(a, 'error_text', '') or ''


def _is_auth(text: str) -> bool:
    low = text.lower()
    return text == ERR_AUTH_PORTAL or any(m in low for m in _AUTH_MARKERS)


def _gateways(items: list) -> str:
    names = sorted({a.gateway for a in items if getattr(a, 'gateway', '')})
    return ', '.join(names) if names else 'unknown gateway'


# ------------------------------------------------------------------------------ checks
_TUNNEL_SETUP_ERRORS = ('Tunnel creation failed', 'PANGP virtual adapter not found')


def _tunnel_setup_failures(fails: list) -> list:
    """Recent failed logins that stopped at tunnel creation or adapter setup."""
    return [a for a in fails if getattr(a, 'error_stage', '') == 'tunnel'
            or _err(a) in _TUNNEL_SETUP_ERRORS]


def _driver(config: Any, fails: list | None = None, **_: Any) -> list[GpFinding]:
    data = _data(config)
    events = [e for e in data.get('driver_events') or []
              if isinstance(e, dict) and e.get('kind') in ('problem', 'line') and _dt(e.get('ts'))]
    newest = max(enumerate(events), key=lambda p: (_dt(p[1]['ts']), p[0]))[1] if events else None
    problem = newest is not None and newest.get('kind') == 'problem'
    adapter = data.get('pangp_adapter') or {}
    present = bool(adapter.get('present'))
    absent = adapter.get('present') is False
    conn = data.get('connection') or {}
    connected = conn.get('connected')
    if connected is None:
        connected = str(conn.get('last_state') or '').lower() == 'connected' or None
    if not problem and not (connected is True and absent):
        return []
    ts = _dt(newest['ts']) if problem else None
    snapshot = 'present' if present else 'not present'
    if problem:
        code = newest.get('code')
        meaning = ' (device disabled)' if code == 22 else ''
        n = sum(1 for e in events if e.get('kind') == 'problem' and e.get('code') == code)
        text = (f"The newest PANGP driver event is Windows problem code {code}{meaning} on device "
                f"{newest.get('device') or '?'} at {_fmt(ts)} ({n} event(s) with this code in "
                f"setupapi.dev.log). The PANGP adapter is {snapshot} in the collection snapshot.")
    else:
        n = 0
        text = ('The client was connected at collection, but the PANGP adapter is not present '
                'in the collection snapshot.')
    setup = _tunnel_setup_failures(fails or [])
    if connected is True:
        level = CRITICAL
        text += ' The client was connected, so the adapter should be enabled and present.'
    elif setup and problem:
        level = WARNING
        first, last = _span(setup)
        text += (f" {len(setup)} login attempt(s) failed during tunnel creation or adapter setup "
                 f"in the recent window ({_range(first, last)}).")
    else:
        level = INFO
        text += (' The client was not connected at collection: the GlobalProtect virtual adapter '
                 'is normally disabled while GlobalProtect is disconnected, so this entry matters '
                 'only if connections fail at tunnel creation.')
    refs = ['driver'] + _ids(setup, 10) if level == WARNING else ['driver']
    return [_mk('DRIVER_DISABLED', level, text, 'driver', ts, refs, n)]


def _not_connected(config: Any, **_: Any) -> list[GpFinding]:
    conn = _data(config).get('connection') or {}
    if conn.get('connected') is not False:
        return []
    state = conn.get('last_state') or 'unknown'
    at = _dt(conn.get('last_state_at'))
    text = (f"The client was not connected when the logs were collected "
            f"({_fmt(_dt(getattr(config, 'collected_at', None)))}); last service state "
            f"'{state}' at {_fmt(at)}.")
    if conn.get('conclusion'):
        text += f" Conclusion: {conn['conclusion']}."
    return [_mk('NOT_CONNECTED_AT_COLLECTION', INFO, text, 'connection', at, ['summary'])]


def _last_attempt(attempts: list, **_: Any) -> list[GpFinding]:
    logins = sorted((a for a in attempts if a.kind == 'login'), key=lambda a: _dt(a.start))
    if not logins:
        return []
    last = logins[-1]
    if last.outcome not in ('failed', 'abandoned'):
        return []
    err = _err(last) or last.details.get('abandon_reason', '') or 'no error text'
    text = (f"The most recent login attempt ({last.id}, started {_fmt(_dt(last.start))}) ended "
            f"{last.outcome}: {err}")
    if getattr(last, 'gateway', '') or getattr(last, 'portal', ''):
        text += f" (gateway {last.gateway or '-'}, portal {last.portal or '-'})"
    return [_mk('LAST_ATTEMPT_FAILED', WARNING, text + '.', 'attempts', _dt(last.start),
                [last.id], 1)]


def _storms(timeline: Any, anchor: datetime | None, thr: dict, **_: Any) -> list[GpFinding]:
    out = []
    window = timedelta(days=_num(thr, 'recent_days'))
    for s in getattr(timeline, 'storms', None) or []:
        start, end = _dt(s.get('start')), _dt(s.get('end'))
        recent = bool(anchor and end and end >= anchor - window)
        by_err = s.get('by_error') or {}
        breakdown = '; '.join(f'{t}: {c}' for t, c in sorted(by_err.items(), key=lambda kv: -kv[1]))
        text = (f"{s.get('count')} failed login attempts between {_fmt(start)} and {_fmt(end)} "
                f"(median interval {s.get('median_interval_ms')} ms). Errors: "
                f"{breakdown or 'none recorded'}. ")
        text += ('The storm ended inside the recent window.' if recent else
                 'The storm ended before the recent window.')
        refs = [r for r in (s.get('first_attempt'), s.get('last_attempt')) if r]
        out.append(_mk('RETRY_STORM', CRITICAL if recent else WARNING, text, 'attempts', end,
                       refs, s.get('count')))
    return out


def _recent_failures(attempts: list, anchor: datetime | None, thr: dict) -> list:
    if anchor is None:
        return []
    lo = anchor - timedelta(days=_num(thr, 'recent_days'))
    return sorted((a for a in attempts if a.kind == 'login' and a.outcome == 'failed'
                   and _dt(a.start) >= lo), key=lambda a: _dt(a.start))


def _repeated(fails: list, thr: dict, **_: Any) -> list[GpFinding]:
    groups: dict[str, list] = {}
    for a in fails:
        groups.setdefault(_err(a) or '(no error text)', []).append(a)
    cap, out = int(_num(thr, 'refs_cap')), []
    for text, items in groups.items():
        if len(items) < _num(thr, 'repeated_failure_min'):
            continue
        first, last = _span(items)
        out.append(_mk('REPEATED_FAILURE', WARNING,
                       f"'{text}' on {len(items)} login failures {_range(first, last)}. "
                       f"Attempts: {', '.join(_ids(items, cap))}"
                       f"{_more(len(items), cap)}.", 'attempts', last, _ids(items, cap),
                       len(items)))
    return out


def _class(code: str, fails: list, pred: Any, thr: dict, what: str) -> list[GpFinding]:
    items = [a for a in fails if pred(_err(a))]
    if not items or len(items) < _num(thr, 'class_failure_min' if code != 'AUTH_FAILURE'
                                      else 'auth_failure_min'):
        return []
    first, last = _span(items)
    cap = int(_num(thr, 'refs_cap'))
    return [_mk(code, WARNING,
                f"{len(items)} login failure(s) in the recent window: {what} "
                f"{_range(first, last)} (gateway(s): {_gateways(items)}). Attempts: "
                f"{', '.join(_ids(items, cap))}{_more(len(items), cap)}.",
                'attempts', last, _ids(items, cap), len(items))]


def _restore_grace(attempts: list, anchor: datetime | None, thr: dict, **_: Any) -> list[GpFinding]:
    if anchor is None:
        return []
    lo = anchor - timedelta(days=_num(thr, 'recent_days'))
    items = sorted((a for a in attempts if a.kind == 'auto-restore' and a.outcome == 'expired'
                    and _dt(a.start) >= lo),
                   key=lambda a: _dt(a.start))
    if len(items) < _num(thr, 'restore_grace_min') or not items:
        return []
    first, last = _span(items)
    graces = sorted({(a.details or {}).get('grace_exceeded', {}).get('grace_s') for a in items}
                    - {None})
    downs = [(a.details or {}).get('grace_exceeded', {}).get('downtime_ms') for a in items]
    downs = [d for d in downs if isinstance(d, (int, float))]
    extra = ''
    asleep = sum(1 for a in items if (a.details or {}).get('modern_standby'))
    if asleep:
        extra += f" {asleep} of them waited in modern standby."
    if graces:
        extra += f" Grace period: {', '.join(str(g) for g in graces)} s."
    if downs:
        extra += f" Longest downtime: {max(downs) / 3600000:.1f} h."
    cap = int(_num(thr, 'refs_cap'))
    return [_mk('RESTORE_GRACE_EXCEEDED', INFO,
                f"{len(items)} automatic restore(s) in the recent window expired: the tunnel "
                f"downtime exceeded the retry grace period and no reconnection was attempted, "
                f"between {_fmt(first)} and {_fmt(last)}.{extra} This normally means the PC slept or was offline longer "
                f"than the grace period. Attempts: {', '.join(_ids(items, cap))}"
                f"{_more(len(items), cap)}.", 'attempts', last, _ids(items, cap), len(items))]


def _restore_failed(attempts: list, anchor: datetime | None, thr: dict,
                    **_: Any) -> list[GpFinding]:
    if anchor is None:
        return []
    lo = anchor - timedelta(days=_num(thr, 'recent_days'))
    items = sorted((a for a in attempts if a.kind == 'auto-restore' and a.outcome == 'failed'
                    and _dt(a.start) >= lo), key=lambda a: _dt(a.start))
    if not items or len(items) < _num(thr, 'restore_failed_min'):
        return []
    first, last = _span(items)
    errors: dict[str, int] = {}
    for a in items:
        errors[_err(a) or '(no error text)'] = errors.get(_err(a) or '(no error text)', 0) + 1
    breakdown = '; '.join(f'{t}: {c}' for t, c in sorted(errors.items(), key=lambda kv: -kv[1]))
    cap = int(_num(thr, 'refs_cap'))
    return [_mk('RESTORE_FAILED', WARNING,
                f"{len(items)} automatic restore(s) in the recent window attempted to reconnect "
                f"and failed, {_range(first, last)} (gateway(s): {_gateways(items)}). Errors: "
                f"{breakdown}. Attempts: {', '.join(_ids(items, cap))}"
                f"{_more(len(items), cap)}.", 'attempts', last, _ids(items, cap), len(items))]


def _success_rate(attempts: list, anchor: datetime | None, thr: dict, **_: Any) -> list[GpFinding]:
    if anchor is None:
        return []
    lo = anchor - timedelta(days=_num(thr, 'recent_days'))
    logins = [a for a in attempts if a.kind == 'login' and a.outcome != 'cancelled'
              and _dt(a.start) >= lo]
    if not logins or len(logins) < _num(thr, 'success_rate_min_attempts'):
        return []
    ok = sum(1 for a in logins if a.outcome == 'connected')
    rate = 100.0 * ok / len(logins)
    if rate >= _num(thr, 'success_rate_min_pct'):
        return []
    return [_mk('LOW_SUCCESS_RATE', WARNING,
                f"{ok} of {len(logins)} login attempts connected ({rate:.0f}%) in the recent "
                f"window ({_fmt(lo)} to {_fmt(anchor)}, cancelled attempts excluded); the "
                f"threshold is {_num(thr, 'success_rate_min_pct'):g}%.", 'attempts', anchor,
                [], len(logins))]


def _stale_trb(config: Any, **_: Any) -> list[GpFinding]:
    sec = _section(config, 'troubleshooting')
    trb = _data(config).get('troubleshooting')
    if sec is None or getattr(sec, 'freshness', '') != 'historical' or not isinstance(trb, dict) \
            or not trb:
        return []
    when = _dt(trb.get('_local_time')) or _dt((trb.get('report_time') or {}).get('utc'))
    text = (f"The troubleshooting report (pan_gp_trb.log) is dated {_fmt(when)}, older than "
            f"the newest log record ({_fmt(_dt(getattr(config, 'newest_record', None)))}): "
            f"it describes a past failure, not the current state. Portal "
            f"{trb.get('portal_address') or 'unknown'}, error stage "
            f"'{trb.get('error_stage') or 'unknown'}', error "
            f"'{trb.get('error') or 'unknown'}'.")
    return [_mk('STALE_TRB_REPORT', INFO, text, 'troubleshooting', when, ['troubleshooting'])]


def _log_gap(timeline: Any, thr: dict, **_: Any) -> list[GpFinding]:
    cov = getattr(timeline, 'coverage', None) or {}
    gap = cov.get('event_log_ends_before_detail_s')
    if not isinstance(gap, (int, float)) or gap <= _num(thr, 'log_gap_s'):
        return []
    end = _dt((cov.get('event_log') or {}).get('last'))
    return [_mk('LOG_GAP', INFO,
                f"The event log ends at {_fmt(end)}, {gap / 3600:.1f} h before the detailed "
                f"logs (PanGPS/PanGPA); attempts after that come from the detailed logs only.",
                'coverage', end, [], None)]


def _truncated(config: Any, **_: Any) -> list[GpFinding]:
    data, parts, refs = _data(config), [], []
    gws = data.get('gateway_configs') or {}
    cut = sorted(g for g, v in gws.items() if isinstance(v, dict) and v.get('truncated'))
    if cut:
        parts.append(f"gateway configuration XML cut for {', '.join(cut)}")
        refs.append('gateways')
    if isinstance(data.get('portal_settings'), dict) and data['portal_settings'].get('truncated'):
        parts.append('portal configuration XML cut')
        refs.append('portal_settings')
    if isinstance(data.get('troubleshooting'), dict) and data['troubleshooting'].get('_cut'):
        parts.append('troubleshooting report file cut')
        refs.append('troubleshooting')
    scan = data.get('scan') or {}
    if scan.get('truncated_dumps'):
        parts.append(f"{scan['truncated_dumps']} truncated XML dump(s) in the logs")
    if scan.get('xml_errors'):
        parts.append(f"{scan['xml_errors']} XML document(s) in the logs could not be parsed")
    for w in getattr(config, 'warnings', None) or []:
        if 'parse' in w or 'valid XML' in w:
            parts.append(w)
    if not parts:
        return []
    return [_mk('CONFIG_TRUNCATED', INFO,
                'Truncated or malformed configuration source(s): ' + '; '.join(parts) +
                '. Values after the cut are missing.', 'config', None, refs, len(parts))]


def _partial(config: Any, timeline: Any, **_: Any) -> list[GpFinding]:
    cov = getattr(timeline, 'coverage', None) or {}
    missing, refs = [], []
    if 'event_log' in cov and not cov['event_log']:
        missing.append('event log (pan_gp_event.log)')
    if 'service_log' in cov and not cov['service_log']:
        missing.append('service log (PanGPS.log)')
    sec = _section(config, 'registry')
    reg = _data(config).get('registry')
    note = getattr(sec, 'note', '') if sec is not None else ''
    if note.startswith(('Not in bundle', 'No setting')) \
            or (isinstance(reg, dict) and 'registry' in _data(config) and not reg.get('settings')):
        missing.append('registry dump (regval.txt)')
        refs.append('registry')
    if not missing:
        return []
    return [_mk('PARTIAL_BUNDLE', WARNING,
                'Missing or empty in the bundle: ' + ', '.join(missing) + '.', 'bundle', None,
                refs, len(missing))]


_LEVEL_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}


# ------------------------------------------------------------------------------ interface
def evaluate(config, timeline, thresholds=None) -> list[Finding]:
    """All findings for a configuration and a timeline; never raises."""
    thr = _merge(thresholds)
    try:
        attempts = _attempts(timeline)
    except Exception:  # noqa: BLE001 - never raises
        attempts = []
    try:
        anchor = _anchor(config, timeline, attempts)
    except Exception:  # noqa: BLE001 - never raises
        anchor = None
    try:
        fails = _recent_failures(attempts, anchor, thr)
    except Exception:  # noqa: BLE001 - never raises
        fails = []
    ctx: dict[str, Any] = {'config': config, 'timeline': timeline, 'attempts': attempts,
                           'anchor': anchor, 'thr': thr, 'fails': fails}
    steps = [
        (_driver, ctx), (_not_connected, ctx), (_last_attempt, ctx), (_storms, ctx),
        (_repeated, ctx),
        (lambda **c: _class('GW_CERT_FAILURE', c['fails'], lambda t: t == ERR_GW_CERT,
                            c['thr'], 'gateway certificate could not be verified'), ctx),
        (lambda **c: _class('GW_UNREACHABLE', c['fails'], lambda t: t == ERR_GW_UNREACHABLE,
                            c['thr'], 'gateway unreachable or unresponsive'), ctx),
        (lambda **c: _class('AUTH_FAILURE', c['fails'], _is_auth, c['thr'],
                            'authentication failed'), ctx),
        (_restore_grace, ctx), (_restore_failed, ctx), (_success_rate, ctx), (_stale_trb, ctx), (_log_gap, ctx),
        (_truncated, ctx), (_partial, ctx),
    ]
    out: list[Finding] = []
    for fn, c in steps:
        try:
            found = fn(**c)
        except Exception:  # noqa: BLE001 - one broken check must not hide the others
            found = []
        out.extend(found)
    out.sort(key=lambda f: _LEVEL_ORDER.get(f.level, 3))
    return out


def to_dicts(findings) -> list[dict]:
    """JSON-serialisable findings: code, level, title, text, scope, when, refs, count."""
    rows = []
    for f in findings or []:
        when = getattr(f, 'when', None)
        count = getattr(f, 'count', None)
        rows.append({
            'code': f.code, 'level': f.level,
            'title': FLAG_HELP.get(f.code, (f.code, ''))[0], 'text': f.text,
            'scope': f.scope,
            'when': when.isoformat(timespec='seconds') if isinstance(when, datetime) else None,
            'refs': [str(r) for r in getattr(f, 'ref_ids', None) or []],
            'count': int(count) if isinstance(count, (int, float)) else None,
        })
    return rows


def status(findings) -> str:
    """ok / warning / critical via tsf.findings.module_status; no_data for None."""
    return module_status(findings or [], findings is not None)

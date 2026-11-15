"""Tests for gp/timeline.py: attempts, restores, enrichment, storms (synthetic logs only)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from panos_toolbox.gp.bundle import Bundle
from panos_toolbox.gp.timeline import build_timeline, normalise_error

PORTAL = "portal.example.test"
GW = "gw1.example.test"
USER = "alice"
BASE = datetime(2026, 3, 2, 9, 0, 0)  # noqa: DTZ001 - the logs carry no UTC offset


def at(sec: float) -> datetime:
    return BASE + timedelta(seconds=sec)


def ev(sec: float, msg: str, level: str = "Info") -> str:
    t = at(sec)
    return (f"{t:%m/%d/%Y %H:%M:%S}:{t.microsecond // 1000:03d} [{level:<5}]: {msg}")


def svc(sec: float, msg: str, level: str = "Debug", pid: int = 100, tid: int = 200) -> str:
    t = at(sec)
    return (f"(P{pid}-T{tid}){level:<5}(1234): "
            f"{t:%m/%d/%y %H:%M:%S}:{t.microsecond // 1000:03d} {msg}")


def agent(sec: float, msg: str, level: str = "Debug") -> str:
    return svc(sec, msg, level, pid=300, tid=400)


def make_bundle(tmp_path, event=None, service=None, agent_lines=None, event_old=None):
    n = len(list(tmp_path.iterdir()))
    d = tmp_path / f"bundle{n}"
    d.mkdir()
    if event_old is not None:
        (d / "pan_gp_event.log.old").write_text("\r\n".join(event_old) + "\r\n")
    if event is not None:
        (d / "pan_gp_event.log").write_text("\r\n".join(event) + "\r\n")
    if service is not None:
        (d / "PanGPS.log").write_text("\r\n".join(service) + "\r\n")
    if agent_lines is not None:
        (d / "PanGPA.log").write_text("\r\n".join(agent_lines) + "\r\n")
    return Bundle.open(d)


def build(tmp_path, **kw):
    params = {k: kw.pop(k) for k in list(kw) if k not in ("event", "service", "agent_lines",
                                                           "event_old")}
    return build_timeline(make_bundle(tmp_path, **kw), **params)


def prelogin(t: float):
    """Event lines of the portal pre-login and login up to the portal answer."""
    return [
        ev(t, "Started the Portal pre-login"),
        ev(t + 0.2, "Portal pre-login result received"),
        ev(t + 0.3, "Portal Login starts"),
        ev(t + 0.4, "portal status is Connected"),
        ev(t + 0.5, f"Portal login completed with address {PORTAL} and conect method of "
                    "on-demand."),
        ev(t + 0.6, "Discovering external network"),
        ev(t + 0.7, f"Gateway pre-Login Starts to {GW}"),
        ev(t + 0.8, f"Gateway Login starts to {GW}"),
        ev(t + 0.9, f"Auto Gateway login finished with address {GW} and user {USER}"),
    ]


def success(t: float):
    return prelogin(t) + [
        ev(t + 1.0, f"Trying to create tunnel with gateway {GW}"),
        ev(t + 2.0, f"IPSec tunnel creation finished with Gateway {GW}."),
    ]


def attempts(tl):
    return tl.to_dict()["attempts"]


def logins(tl):
    return [a for a in attempts(tl) if a["kind"] == "login"]


def test_simple_success(tmp_path):
    tl = build(tmp_path, event=success(0))
    a = attempts(tl)
    assert len(a) == 1
    x = a[0]
    assert x["kind"] == "login" and x["outcome"] == "connected" and x["cycles"] == 1
    assert x["start"] == "2026-03-02T09:00:00.000"
    assert x["end"] == "2026-03-02T09:00:02.000" and x["duration_ms"] == 2000
    assert x["protocol"] == "IPSec" and x["error"] is None
    assert x["sources"] == ["event_log"] and x["has_detail"] is False and x["steps"] == []
    assert tl.to_dict()["summary"]["by_outcome"]["connected"] == 1


def test_to_dict_is_json_serialisable(tmp_path):
    tl = build(tmp_path, event=success(0))
    d = tl.to_dict()
    assert json.loads(json.dumps(d)) == d
    assert d["version"] == 1 and d["coverage"]["event_log"]["records"] == 11


def test_credential_prompt_cycles_are_one_attempt(tmp_path):
    first = [
        ev(0, "Started the Portal pre-login"),
        ev(0.2, "Portal pre-login result received"),
        ev(0.3, "Portal Login starts"),
        ev(0.4, f"Auth failed empty password for portal {PORTAL}"),
    ]
    second = success(40)
    tl = build(tmp_path, event=first + second)
    a = logins(tl)
    assert len(a) == 1
    assert a[0]["outcome"] == "connected" and a[0]["cycles"] == 2
    assert a[0]["start"] == "2026-03-02T09:00:00.000"


def test_gap_beyond_limit_gives_abandoned_and_new_attempt(tmp_path):
    first = [
        ev(0, "Started the Portal pre-login"),
        ev(0.3, "Portal Login starts"),
        ev(0.4, f"Auth failed empty password for portal {PORTAL}"),
    ]
    lines = first + success(700)
    a = logins(build(tmp_path, event=lines))
    assert [x["outcome"] for x in a] == ["abandoned", "connected"]
    assert all(x["cycles"] == 1 for x in a)


def test_gap_limit_is_a_parameter(tmp_path):
    first = [
        ev(0, "Started the Portal pre-login"),
        ev(0.3, "Portal Login starts"),
        ev(0.4, f"Auth failed empty password for portal {PORTAL}"),
    ]
    a = logins(build(tmp_path, event=first + success(100), chain_gap_s=30))
    assert [x["outcome"] for x in a] == ["abandoned", "connected"]
    a = logins(build(tmp_path, event=first + success(100)))
    assert [x["outcome"] for x in a] == ["connected"]


def test_user_cancel(tmp_path):
    lines = prelogin(0) + [ev(1.0, f"User canceled login to gateway {GW}.")]
    a = logins(build(tmp_path, event=lines))
    assert len(a) == 1 and a[0]["outcome"] == "cancelled"


def test_gateway_failure(tmp_path):
    lines = prelogin(0)[:-1] + [
        ev(1.0, f"Failed to pre-login to the gateway {GW}"),
        ev(1.1, f"Gateway {GW}: The gateway is unreachable or the gateway is unresponsive.",
           "Error"),
    ]
    a = logins(build(tmp_path, event=lines))
    assert len(a) == 1 and a[0]["outcome"] == "failed"
    assert a[0]["error"]["text"] == "Gateway unreachable or unresponsive"
    assert "unreachable" in a[0]["error"]["raw"]
    assert a[0]["gateway"] == GW


def test_certificate_failure(tmp_path):
    lines = prelogin(0)[:-1] + [
        ev(1.0, f"Failed to verify server certificate of gateway {GW}."),
        ev(1.1, "GlobalProtect could not verify the server certificate of the gateway.",
           "Error"),
    ]
    a = logins(build(tmp_path, event=lines))
    assert a[0]["outcome"] == "failed"
    assert a[0]["error"]["text"] == "Gateway certificate could not be verified"


def test_precheck_cert_note_is_not_an_error(tmp_path):
    note = "Unable to verify server cert. Result is self signed certificate in certificate chain"
    sv = [
        svc(0.0, "msgtype = portal"),
        svc(0.01, "----Portal Processing starts----"),
        svc(0.1, "AgentProxyAutoStart: user clicked connect button"),
        svc(0.5, note, "Error"),
        svc(0.7, "----Portal Login starts----"),
        svc(0.8, "portal status is Connected"),
        svc(2.0, "--Set state to Connected"),
    ]
    tl = build(tmp_path, event=success(0.2), service=sv)
    x = logins(tl)[0]
    assert x["outcome"] == "connected" and x["error"] is None
    assert not any("Error-level" in s["text"] for s in x["steps"])
    assert not tl.to_dict()["summary"]["top_errors"]
    assert normalise_error("Failed to verify certificate of the server") == \
        "Server certificate verification failed"


def test_auto_restore_success_and_grace_failure(tmp_path):
    lines = success(0) + [
        ev(100, "Tunnel is down due to network change."),
        ev(101, f"Gateway {GW}: Checking network availability and restoring VPN connection..."),
        ev(105, "Tunnel is restored."),
        ev(300, "Tunnel is down due to network change."),
        ev(301, f"Gateway {GW}: Checking network availability and restoring VPN connection..."),
        ev(320, "Tunnel retry done: failed retry"),
    ]
    tl = build(tmp_path, event=lines)
    r = [a for a in attempts(tl) if a["kind"] == "auto-restore"]
    assert [x["outcome"] for x in r] == ["connected", "failed"]
    assert r[0]["trigger"] == "restore" and r[0]["duration_ms"] == 4000
    assert len(logins(tl)) == 1
    first = logins(tl)[0]
    assert first["disconnect"]["reason"] == "network change"
    assert first["disconnect"]["session_ms"] == 98000
    cov = tl.to_dict()["coverage"]["restores"]
    assert cov["source"]


def test_restore_gateway_name_with_space(tmp_path):
    lines = [
        ev(0, "Gateway Central Site: Checking network availability and restoring VPN connection"),
        ev(4, "Tunnel is restored."),
    ]
    r = attempts(build(tmp_path, event=lines))
    assert len(r) == 1 and r[0]["kind"] == "auto-restore" and r[0]["gateway"] == "Central Site"


def service_login(t: float, click: bool = True):
    out = [svc(t, "msgtype = portal"), svc(t + 0.01, "----Portal Processing starts----")]
    if click:
        out.append(svc(t + 0.1, "AgentProxyAutoStart: user clicked connect button"))
    out += [
        svc(t + 0.2, "--Set state to Retrieving configuration..."),
        svc(t + 0.25, "----Portal Pre-login starts----"),
        svc(t + 0.3, f"Portal {PORTAL}, user {USER}, logonDomain "),
        svc(t + 0.6, "----Portal Login starts----"),
        svc(t + 0.8, "portal status is Connected"),
        svc(t + 0.9, "----Network Discover starts----"),
        svc(t + 1.0, f"One external gateway {GW}, priority=1"),
        svc(t + 1.4, "----Tunnel Creation starts----"),
        svc(t + 1.5, "Set preferred IP 10.0.0.9 for gateway"),
        svc(t + 1.9, "Connected ipsec to 192.0.2.1"),
        svc(t + 2.5, "--Set state to Connected"),
    ]
    return out


def test_detail_enrichment_and_matching(tmp_path):
    lines = success(0.0) + success(500.0)
    sv = service_login(500.3)
    tl = build(tmp_path, event=lines, service=sv)
    a = logins(tl)
    assert len(a) == 2
    first, second = a
    assert first["has_detail"] is False and first["steps"] == []
    assert second["has_detail"] is True
    assert second["sources"] == ["event_log", "service_log"]
    assert second["trigger"] == "user-click" and second["tunnel_ip"] == "10.0.0.9"
    assert second["user"] == USER
    phases = [s["phase"] for s in second["steps"]]
    assert "portal-prelogin" in phases and "tunnel" in phases and "connected" in phases
    stamps = [s["ts"] for s in second["steps"]]
    assert stamps == sorted(stamps)
    assert all(s["source"] in ("pan_gp_event.log", "PanGPS.log") for s in second["steps"])
    assert tl.to_dict()["coverage"]["crosscheck"]["matched"] == 1


def test_attempts_from_detailed_logs_only(tmp_path):
    lines = success(0.0)
    sv = service_login(0.3) + service_login(900.0)
    tl = build(tmp_path, event=lines, service=sv)
    a = logins(tl)
    assert len(a) == 2
    assert a[0]["sources"] == ["event_log", "service_log"]
    late = a[1]
    assert late["sources"] == ["service_log"] and late["has_detail"] is True
    assert late["outcome"] == "connected" and late["steps"]
    cov = tl.to_dict()["coverage"]
    assert cov["crosscheck"]["detail_only"] == 1
    assert cov["event_log_ends_before_detail_s"] is not None


def test_cache_only_portal_block_is_skipped(tmp_path):
    sv = [
        svc(0.0, "msgtype = portal"),
        svc(0.01, "----Portal Processing starts----"),
        svc(0.02, "ProcessServerPortal: szCacheOnly: yes bRetrieveCacheOnly: 1"),
        svc(0.5, "--Set state to Disconnected"),
    ] + service_login(60.0)
    a = logins(build(tmp_path, service=sv))
    assert len(a) == 1 and a[0]["start"].startswith("2026-03-02T09:01:00")


def test_credential_block_continues_failed_portal_block(tmp_path):
    sv = [
        svc(0.0, "msgtype = portal"),
        svc(0.01, "----Portal Processing starts----"),
        svc(0.1, "AgentProxyAutoStart: user clicked connect button"),
        svc(0.2, "--Set state to Retrieving configuration..."),
        svc(0.6, "----Portal Login starts----"),
        svc(0.7, "Auth failed empty password for portal"),
        svc(0.75, "portal status is User authentication failed"),
        svc(0.8, "--Set state to Disconnected"),
        svc(30.0, "msgtype = user_credential"),
        svc(30.01, "----Portal Processing starts----"),
        svc(30.2, "--Set state to Retrieving configuration..."),
        svc(30.6, "----Portal Login starts----"),
        svc(30.8, "portal status is Connected"),
        svc(32.0, "--Set state to Connected"),
    ]
    a = logins(build(tmp_path, service=sv))
    assert len(a) == 1
    assert a[0]["outcome"] == "connected" and a[0]["cycles"] == 2


def failures(n: int, t0: float = 0.0, step: float = 2.0):
    out = []
    for i in range(n):
        t = t0 + i * step
        out += [
            ev(t, "Started the Portal pre-login"),
            ev(t + 0.1, "Portal Login starts"),
            ev(t + 0.2, f"Auth failed for portal {PORTAL}"),
            ev(t + 0.3, "portal status is User authentication failed"),
        ]
    return out


def test_retry_storm_detection(tmp_path):
    lines = success(0) + failures(12, 100) + success(600)
    tl = build(tmp_path, event=lines)
    d = tl.to_dict()
    assert len(d["storms"]) == 1
    storm = d["storms"][0]
    assert storm["count"] == 12
    members = [a for a in d["attempts"] if a["storm"] == storm["id"]]
    assert len(members) == 12 and all(a["outcome"] == "failed" for a in members)
    assert d["summary"]["excluding_storms"]["by_outcome"]["failed"] == 0
    assert d["summary"]["by_outcome"]["failed"] == 12


def test_few_failures_are_not_a_storm(tmp_path):
    d = build(tmp_path, event=failures(5)).to_dict()
    assert d["storms"] == [] and all(a["storm"] is None for a in d["attempts"])
    d = build(tmp_path, event=failures(12, step=60)).to_dict()
    assert d["storms"] == []


def test_summary_per_day_and_top_errors(tmp_path):
    d = build(tmp_path, event=success(0) + failures(3, 100)).to_dict()
    s = d["summary"]
    assert s["total"] == 4 and s["by_kind"]["login"]["failed"] == 3
    assert s["per_day"][0]["date"] == "2026-03-02"
    top = s["top_errors"][0]
    assert top["count"] == 3 and top["first"] <= top["last"]


def test_long_text_is_capped(tmp_path):
    long = "x" * 600
    lines = prelogin(0)[:-1] + [
        ev(1.0, f"Failed to pre-login to the gateway {GW}"),
        ev(1.1, long, "Error"),
    ]
    a = logins(build(tmp_path, event=lines, max_text=50))
    assert len(a[0]["error"]["text"]) <= 50 and len(a[0]["error"]["raw"]) <= 50


def test_agent_click_enriches_attempt(tmp_path):
    ag = [
        agent(499.8, "User clicks connect button"),
        agent(500.4, "Dialog Status is going to change from Not Connected to Connecting."),
        agent(503.0, "Dialog Status is going to change from Connecting to Connected."),
    ]
    tl = build(tmp_path, event=success(500.0), agent_lines=ag)
    x = logins(tl)[0]
    assert x["sources"] == ["event_log", "agent_log"] and x["has_detail"] is True
    assert x["trigger"] == "user-click"
    assert x["details"]["click_time"] == "2026-03-02T09:08:19.800"
    texts = [s["text"] for s in x["steps"]]
    assert any("Connecting" in t for t in texts)

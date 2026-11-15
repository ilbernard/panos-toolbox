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


# ------------------------------------------------------------------ portals are never mixed
def prompt_cycle(t: float, portal: str, cookie: bool = True):
    out = [ev(t, "Started the Portal pre-login")]
    if cookie:
        out.append(ev(t + 0.1, f"Unserialized empty cookie for portal {portal} and user {USER}"))
    out += [ev(t + 0.3, "Portal Login starts"),
            ev(t + 0.4, f"Auth failed empty password for portal {portal}")]
    return out


def connect_cycle(t: float, portal: str, gw: str):
    return [
        ev(t, "Started the Portal pre-login"),
        ev(t + 0.1, f"Unserialized empty cookie for portal {portal} and user {USER}"),
        ev(t + 0.2, "Portal pre-login result received"),
        ev(t + 0.3, "Portal Login starts"),
        ev(t + 0.4, "portal status is Connected"),
        ev(t + 0.5, f"Portal login completed with address {portal} and conect method of "
                    "on-demand."),
        ev(t + 0.7, f"Gateway pre-Login Starts to {gw}"),
        ev(t + 0.9, f"Auto Gateway login finished with address {gw} and user {USER}"),
        ev(t + 1.0, f"Trying to create tunnel with gateway {gw}"),
        ev(t + 2.0, f"IPSec tunnel creation finished with Gateway {gw}."),
    ]


def test_cycles_of_different_portals_are_not_chained(tmp_path):
    lines = prompt_cycle(0, "portal-a.example.test") + \
        connect_cycle(200, "portal-b.example.test", "gw-b.example.test")
    a = logins(build(tmp_path, event=lines))
    assert [x["outcome"] for x in a] == ["abandoned", "connected"]
    assert a[0]["portal"] == "portal-a.example.test" and a[0]["gateway"] == ""
    assert a[0]["details"]["abandon_reason"]
    assert a[1]["portal"] == "portal-b.example.test" and a[1]["gateway"] == "gw-b.example.test"
    assert all(x["cycles"] == 1 for x in a)
    assert a[1]["start"] == "2026-03-02T09:03:20.000"


def test_same_portal_in_other_case_or_unknown_portal_is_chained(tmp_path):
    lines = prompt_cycle(0, "Portal-A.Example.Test") + \
        connect_cycle(60, "portal-a.example.test", GW)
    a = logins(build(tmp_path, event=lines))
    assert len(a) == 1 and a[0]["cycles"] == 2 and a[0]["outcome"] == "connected"
    # the first cycle never names its portal: the next one cannot be told apart, so it chains
    lines = prompt_cycle(0, "ignored", cookie=False) + connect_cycle(60, "portal-b.example.test", GW)
    a = logins(build(tmp_path, event=lines))
    assert len(a) == 1 and a[0]["cycles"] == 2


def test_portal_split_keeps_three_cycle_chain_of_one_portal(tmp_path):
    lines = (prompt_cycle(0, "portal-a.example.test") + prompt_cycle(30, "portal-a.example.test")
             + prompt_cycle(60, "portal-b.example.test")
             + connect_cycle(90, "portal-b.example.test", "gw-b.example.test"))
    a = logins(build(tmp_path, event=lines))
    assert [(x["outcome"], x["cycles"], x["portal"]) for x in a] == [
        ("abandoned", 2, "portal-a.example.test"), ("connected", 2, "portal-b.example.test")]
    assert a[1]["start"] == "2026-03-02T09:01:00.000"


# ------------------------------------------------------------------ cancelled evidence
def test_cancel_evidence_explicit_and_inferred(tmp_path):
    explicit = prelogin(0) + [ev(1.0, f"User canceled login to gateway {GW}.")]
    inferred = [ev(100, "Started the Portal pre-login"), ev(100.3, "Portal Login starts"),
                ev(105, "User disconnecting tunnel starts")]
    a = logins(build(tmp_path, event=explicit + inferred))
    assert [x["outcome"] for x in a] == ["cancelled", "cancelled"]
    assert [x["details"]["cancel_evidence"] for x in a] == ["explicit", "inferred"]
    other = logins(build(tmp_path, event=success(0)))
    assert "cancel_evidence" not in other[0]["details"]


# ------------------------------------------------------------------ restore outcomes
def restore_lines(t: float, *middle: str, end: str = "Tunnel retry done: failed retry"):
    return ([ev(t, f"Gateway {GW}: Checking network availability and restoring VPN connection...")]
            + [ev(t + 1 + i, m) for i, m in enumerate(middle)] + [ev(t + 10, end)])


GRACE = "Tunnel downtime (7200000 milliseconds) exceeds retry grace period (1800 seconds)"


def restores(tl):
    return [a for a in attempts(tl) if a["kind"] == "auto-restore"]


def test_restore_over_grace_period_is_expired(tmp_path):
    lines = success(0) + restore_lines(100, "Wait in modern standy until wakeup", GRACE)
    r = restores(build(tmp_path, event=lines))[0]
    assert r["outcome"] == "expired"
    assert r["details"]["downtime_ms"] == 7200000 and r["details"]["modern_standby"] is True
    assert r["details"]["retries"] == 0
    assert r["error"]["text"] == "Tunnel not restored within the retry grace period"


def test_restore_with_real_retry_failure_is_failed(tmp_path):
    lines = success(0) + restore_lines(
        100, "Retry connect failed first time", "Failed to verify certificate of the server")
    r = restores(build(tmp_path, event=lines))[0]
    assert r["outcome"] == "failed" and r["details"]["retries"] == 1
    assert r["details"]["modern_standby"] is False
    # a retry that failed before the grace period ran out is still a failure
    lines = success(0) + restore_lines(100, "Retry connect failed first time", GRACE)
    assert restores(build(tmp_path, event=lines))[0]["outcome"] == "failed"
    # no reason in the log: the literal "failed retry" stands
    assert restores(build(tmp_path, event=success(0) + restore_lines(100)))[0]["outcome"] == \
        "failed"


def test_expired_is_counted_apart_and_never_a_storm_failure(tmp_path):
    lines = success(0)
    for i in range(12):
        lines += restore_lines(100 + i * 20, GRACE)
    d = build(tmp_path, event=lines).to_dict()
    s = d["summary"]
    assert s["by_outcome"]["expired"] == 12 and s["by_outcome"]["failed"] == 0
    assert s["by_kind"]["auto-restore"]["expired"] == 12
    assert s["by_kind"]["login"]["expired"] == 0
    assert s["per_day"][0]["auto-restore"]["expired"] == 12
    assert d["storms"] == []


def test_service_only_restore_outcome_and_step_wording(tmp_path):
    def blk(t, middle):
        return ([svc(t, f"Show Gateway {GW}: Checking network availability and restoring...")]
                + [svc(t + 1 + i, m) for i, m in enumerate(middle)]
                + [svc(t + 9, "Tunnel retry done: failed retry"),
                   svc(t + 9.1, "--Set state to Disconnected")])
    sv = blk(0, ["Wait in modern standy until wakeup", GRACE]) + \
        blk(100, ["Retry connect failed first time"])
    r = restores(build(tmp_path, service=sv))
    assert [x["outcome"] for x in r] == ["expired", "failed"]
    assert r[0]["details"]["modern_standby"] is True and r[0]["details"]["downtime_ms"] == 7200000
    texts = [s["text"] for s in r[0]["steps"]]
    assert "Log: tunnel retry done, failed retry" in texts
    assert not any("retries exhausted" in t for t in texts)


def test_preferred_ip_step_is_not_called_an_assignment(tmp_path):
    tl = build(tmp_path, event=success(0.2), service=service_login(0))
    texts = [s["text"] for s in logins(tl)[0]["steps"]]
    assert "Preferred IP set: 10.0.0.9" in texts
    assert not any("IP assigned" in t for t in texts)


def test_failed_restore_keeps_the_specific_error(tmp_path):
    lines = success(0) + [
        ev(100, f"Gateway {GW}: Checking network availability and restoring VPN connection..."),
        ev(105, "Retry connect failed first time"),
        ev(108, "Failed to verify certificate", "Error"),
        ev(109, "Retry connect failed second time"),
        ev(109.1, "Tunnel retry done: failed retry"),
    ]
    r = restores(build(tmp_path, event=lines))[0]
    assert r["outcome"] == "failed" and r["details"]["retries"] == 2
    assert r["error"]["text"] == "Server certificate verification failed"


# ------------------------------------------------------------------ service-log-only flows
def svc_src(src: int):
    """A ``svc`` writer with another ``<src>`` number: the engine must not care."""
    def w(sec, msg, level="Debug", pid=100, tid=200):
        return svc(sec, msg, level, pid, tid).replace("(1234)", f"({src})", 1)
    return w


def cycle(w, t, *, user=True, saml=False, portal="vpn.example.com", pid=100):
    """Lines of one portal cycle up to the portal answer."""
    out = [w(t, "----Portal Processing starts----", pid=pid)]
    if not user:
        out.append(w(t + 0.1, "This portal message is from prelogon thread", pid=pid))
    out.append(w(t + 0.2, f"Portal {portal}, user {'jdoe' if user else 'pre-logon'}, "
                 "logonDomain ", pid=pid))
    if saml:
        out += [w(t + 0.3, "Portal's saml request timeout is 60", pid=pid),
                w(t + 0.4, "Saml auth", pid=pid)]
    return out


def tunnel_ok(w, t, gw="gw1.example.com"):
    return [w(t, "----Network Discover starts----"),
            w(t + 0.1, "NetworkDiscoverThread: network type is external."),
            w(t + 0.2, "NetworkDiscoverThread: PortalStatus is 1, HasLoggedOnGateway is 1"),
            w(t + 0.5, f"Tunnel is created with the gateway {gw}"),
            w(t + 1.0, "--Set state to Connected")]


def svc_attempts(tmp_path, lines, **kw):
    return attempts(build(tmp_path, service=lines, **kw))


def test_internal_outcome_is_a_success_class(tmp_path):
    w = svc
    lines = cycle(w, 0) + [
        w(1, "----Network Discover starts----"),
        w(1.1, "NetworkDiscoverThread: network type is internal."),
        w(1.2, "NetworkDiscoverThread: PortalStatus is 1, HasLoggedOnGateway is 1"),
        w(1.3, "gateway gw1.example.com does not need tunnel."),
        w(1.5, "--Set state to Connected")]
    a = svc_attempts(tmp_path, lines)
    assert [(x["kind"], x["outcome"]) for x in a] == [("login", "internal")]
    assert a[0]["sources"] == ["service_log"]


def test_no_dependency_on_the_src_number(tmp_path):
    base = None
    for src in (1234, 8450, 7):
        w = svc_src(src)
        lines = (cycle(w, 0) + tunnel_ok(w, 2) + cycle(w, 100, saml=True)
                 + [w(101, "Portal's saml request timeout is 60")])
        a = svc_attempts(tmp_path, lines)
        shape = [(x["kind"], x["outcome"], x["cycles"]) for x in a]
        base = base or shape
        assert shape == base and shape[0][1] == "connected"


def test_saml_cycles_chain_and_timeout_is_expired(tmp_path):
    w = svc
    lines = cycle(w, 0, saml=True) + cycle(w, 20, saml=True) + [
        w(100, "msgtype = disconnect")]
    a = svc_attempts(tmp_path, lines)
    assert len(a) == 1 and a[0]["cycles"] == 2
    assert a[0]["outcome"] == "expired"
    assert a[0]["details"]["expired_reason"] == "saml-timeout"
    assert a[0]["error_category"] == "timeout"


def test_cycle_beyond_the_saml_timeout_is_not_chained(tmp_path):
    w = svc
    a = svc_attempts(tmp_path, cycle(w, 0, saml=True) + cycle(w, 300, saml=True))
    assert len(a) == 2


def test_sso_starts_is_the_first_cycle_of_a_new_attempt(tmp_path):
    w = svc
    first = cycle(w, 0, saml=True)
    second = [w(20, "----Portal Processing starts----"), w(20.1, "SSO starts."),
              w(20.2, "Portal vpn.example.com, user jdoe, logonDomain ")]
    a = svc_attempts(tmp_path, first + second)
    assert len(a) == 2 and a[1]["trigger"] == "sso"


def test_pre_logon_is_not_chained_with_user_cycles(tmp_path):
    w = svc
    a = svc_attempts(tmp_path, cycle(w, 0, saml=True, user=False) + cycle(w, 10, saml=True))
    assert [x["kind"] for x in a] == ["pre-logon", "login"]
    assert a[0]["outcome"] == "abandoned"


def test_refresh_is_not_an_attempt(tmp_path):
    w = svc
    lines = [w(0, "----Portal refresh configuration starts----"),
             w(1, "Portal vpn.example.com, user jdoe, logonDomain ")]
    assert svc_attempts(tmp_path, lines) == []


def test_tunnel_creation_failure_after_connected_is_not_a_failure(tmp_path):
    w = svc
    lines = cycle(w, 0) + tunnel_ok(w, 2) + [
        w(30, "Failed to create tunnel to gateway gw1.example.com.")]
    a = svc_attempts(tmp_path, lines)
    assert [x["outcome"] for x in a] == ["connected"]
    assert not any("Failed to create tunnel" in s["text"] for s in a[0]["steps"])


def test_certificate_required_is_a_certificate_failure(tmp_path):
    w = svc
    lines = cycle(w, 0) + [
        w(1, "portal status is Client Cert Required."),
        w(1.1, "ProcessServerPortal failed")]
    a = svc_attempts(tmp_path, lines)
    assert a[0]["outcome"] == "failed" and a[0]["error_category"] == "certificate"


def test_gateway_credential_cancel_loop_is_one_cancelled_attempt(tmp_path):
    w = svc
    lines = cycle(w, 0) + [w(1, "msgtype = gateway-credential-cancel"),
                           w(2, "msgtype = gateway-credential-cancel")]
    a = svc_attempts(tmp_path, lines)
    assert len(a) == 1 and a[0]["outcome"] in ("cancelled", "abandoned")


def test_lock_unlock_and_wake_alone_never_start_an_attempt(tmp_path):
    w = svc
    lines = [w(0, "Received session change, event type 7"),
             w(5, "Received session change, event type 8"),
             w(10, "Wakeup from modern standby")]
    assert svc_attempts(tmp_path, lines) == []


def test_agent_only_attempts_come_from_dialog_status(tmp_path):
    w = agent
    lines = [w(0, "Dialog Status is going to change from Disconnected to Connecting."),
             w(5, "Dialog Status is going to change from Connecting to Connected.")]
    a = attempts(build(tmp_path, agent_lines=lines))
    assert len(a) == 1 and a[0]["sources"] == ["agent_log"]
    assert a[0]["outcome"] == "connected"


def test_automatic_rediscoveries_in_agent_only_periods_are_collapsed(tmp_path):
    w = agent
    lines = []
    for i in range(6):
        t = i * 60
        lines += [w(t, "Dialog Status is going to change from Connected to Connecting."),
                  w(t + 5, "Dialog Status is going to change from Connecting to Connected.")]
    a = attempts(build(tmp_path, agent_lines=lines))
    assert len(a) < 6

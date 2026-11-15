"""Build the login timeline: one row per connection attempt.

The backbone is ``pan_gp_event.log`` (long history, one line per step).
Where the verbose service log (``PanGPS.log``) covers the same time span,
its relevant lines are merged into the attempt as detail events.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote

from .logs import EventLine, Record

PHASES = [
    ("portal-prelogin", "Portal pre-login"),
    ("portal-login", "Portal login"),
    ("portal-config", "Portal config"),
    ("gw-prelogin", "Gateway pre-login"),
    ("gw-login", "Gateway login"),
    ("tunnel", "Tunnel"),
]
PHASE_ORDER = {key: i for i, (key, _) in enumerate(PHASES)}

OUTCOMES = {
    "connected": "Connected",
    "failed": "Failed",
    "cancelled": "Cancelled by user",
    "incomplete": "No outcome logged",
    "system": "System event",
}

# (regex, code, phase, level). Phase "" keeps the current phase; phase "aux"
# marks housekeeping lines hidden by default in the report.
_E = re.compile
EVENT_RULES = [
    (_E(r"^Started the Portal pre-login"), "PPL", "portal-prelogin", "info"),
    (_E(r"^Portal pre-login result received"), "PPL_OK", "portal-prelogin", "ok"),
    (_E(r"CheckServerCert return"), "CERTCHK", "", "info"),
    (_E(r"^Failed to pre - ?login to the portal"), "PPL_FAIL", "portal-prelogin", "error"),
    (_E(r"^Portal Login starts"), "PL", "portal-login", "info"),
    (_E(r"^Logging into portal"), "PL_SEND", "portal-login", "info"),
    (_E(r"^Auth failed"), "AUTHFAIL", "portal-login", "error"),
    (_E(r"^portal status is User authentication failed"), "PS_AUTHFAIL", "portal-login", "error"),
    (_E(r"^portal status is Invalid portal"), "PS_INVALID", "", "error"),
    (_E(r"^portal status is Using cached portal config"), "PS_CACHED", "portal-config", "warn"),
    (_E(r"^portal status is Connected"), "PS_OK", "portal-config", "ok"),
    (_E(r"^portal status is "), "PS_OTHER", "portal-config", "info"),
    (_E(r"^User Authenticated but the portal config is null"), "NULLCFG", "portal-config", "warn"),
    (_E(r"^Unable to fetch the latest Portal configuration"), "PCFG_FAIL", "portal-config", "warn"),
    (_E(r"^Portal login completed"), "PL_OK", "portal-config", "ok"),
    (_E(r"^Network discovery started"), "ND", "gw-prelogin", "info"),
    (_E(r"^Discovering (external|internal) network"), "ND_TYPE", "gw-prelogin", "info"),
    (_E(r"^Gateway selection"), "GWSEL", "gw-prelogin", "info"),
    (_E(r"^Gateway pre-Login Starts"), "GPL", "gw-prelogin", "info"),
    (_E(r"^Prelogin to gateway"), "GPL_OK", "gw-prelogin", "ok"),
    (_E(r"^Failed to pre-login to the gateway"), "GPL_FAIL", "gw-prelogin", "error"),
    (_E(r"^Gateway Login starts"), "GL", "gw-login", "info"),
    (_E(r"^Invalid user credential for gateway"), "GW_BADCRED", "gw-login", "warn"),
    (_E(r"^User canceled login to gateway"), "GW_CANCEL", "gw-login", "warn"),
    (_E(r"^(Auto|Manual) Gateway login finished"), "GL_OK", "gw-login", "ok"),
    (_E(r"^Trying to create tunnel"), "TC", "tunnel", "info"),
    (_E(r"^\S+ tunnel creation finished"), "TUN_OK", "tunnel", "ok"),
    (_E(r"^failed to create tunnel", re.IGNORECASE), "TUN_FAIL", "tunnel", "error"),
    (_E(r"failover to SSL|needed to change the connection type"), "SSL_FALLBACK", "session", "warn"),
    (_E(r"^Tunnel is down"), "TDOWN", "session", "warn"),
    (_E(r"^Tunnel is restored"), "TRESTORED", "session", "ok"),
    (_E(r"^Tunnel retry done|^Retry connect failed"), "RETRY", "session", "warn"),
    (_E(r"^Tunnel downtime"), "DOWNTIME", "session", "info"),
    (_E(r"Checking network availability and restoring"), "RESTORING", "session", "info"),
    (_E(r"^User disconnecting tunnel starts"), "UDISC", "session", "info"),
    (_E(r"^User was logged out of Gateway"), "LOGOUT", "session", "info"),
    (_E(r"^User could not be logged out"), "LOGOUT_FAIL", "session", "warn"),
    (_E(r"^GlobalProtect service started"), "SVC_START", "system", "info"),
    (_E(r"^GlobalProtect service stopped"), "SVC_STOP", "system", "info"),
    (_E(r"^GlobalProtect app is disabled"), "DISABLED", "system", "warn"),
    (_E(r"^SSO starts"), "SSO", "system", "info"),
    (_E(r"^Wait in modern stand"), "STANDBY", "system", "info"),
    (_E(r"^Troubleshooting log is generated"), "TRB", "", "error"),
    (_E(r"network connection is unreachable|^No Network Connectivity"), "UNREACH", "", "error"),
    (_E(r"Failed to receive message from remote host"), "RECV_FAIL", "", "error"),
    (_E(r"valid client certificate is required"), "CLIENT_CERT", "", "error"),
    (_E(r"verify (the )?server certificate|^Failed to verify certificate"), "CERT_FAIL", "", "error"),
    (_E(r"HIP Report|hip report", re.IGNORECASE), "HIP", "session", "info"),
    (_E(r"gateway route", re.IGNORECASE), "ROUTE", "session", "info"),
    (_E(r"cookie|decrypted\. File|^Failed to open file|^Connect method is|^prelogon status is"),
     "AUX", "aux", "info"),
    (_E(r"user experience management agent|checked the agent version"), "AUX2", "aux", "info"),
]

# Aliases used only when pan_gp_event.log is missing and the attempts have to
# be rebuilt from the service log.
FALLBACK_RULES = [
    (_E(r"^-+Portal Pre-login starts-+$"), "PPL", "portal-prelogin", "info"),
    (_E(r"^-+Portal Login starts-+$"), "PL", "portal-login", "info"),
    (_E(r"^-+Gateway Pre-login starts-+$"), "GPL", "gw-prelogin", "info"),
    (_E(r"^-+Gateway Login starts-+$"), "GL", "gw-login", "info"),
    (_E(r"^-+Tunnel Creation starts-+$"), "TC", "tunnel", "info"),
    (_E(r"^tunnel to \S+ connected"), "TUN_OK", "tunnel", "ok"),
    (_E(r"^#+ Start PanGPS service"), "SVC_START", "system", "info"),
    (_E(r"^PanGPS service exits"), "SVC_STOP", "system", "info"),
]

_PORTAL_RES = [
    _E(r"for portal (\S+)"),
    _E(r"Portal login completed with address (\S+)"),
    _E(r"to the portal (\S+)"),
    _E(r"Portal configuration from address (\S+)"),
    _E(r"hosted on the Portal (\S+)"),
]
_GATEWAY_RES = [
    _E(r"Gateway pre-Login Starts to (\S+)"),
    _E(r"Gateway Login starts to (\S+)"),
    _E(r"tunnel with gateway (\S+)"),
    _E(r"Gateway login finished with address (\S+)"),
    _E(r"creation finished with Gateway (\S+)"),
    _E(r"credential for gateway (\S+)"),
    _E(r"login to (?:the )?gateway (\S+)"),
]
_USER_RES = [
    _E(r"Gateway login finished with address \S+ and user (.+?)\.?$"),
    _E(r"for portal \S+ and user (\S+)"),
]
_TRB_RE = _E(r"error stage \((.*?)\) and the error detail \((.*)\)")
_DOWN_RE = _E(r"^Tunnel is down due to (.+?)\.?$")
_SVC_VER_RE = _E(r"client version: ([^,)]+)")

TRB_STAGES = {
    "portal pre-login": "portal-prelogin",
    "portal login": "portal-login",
    "portal config": "portal-config",
    "gateway pre-login": "gw-prelogin",
    "gateway login": "gw-login",
    "tunnel": "tunnel",
}


def classify(msg: str, rules=EVENT_RULES):
    for rx, code, phase, level in rules:
        if rx.search(msg):
            return code, phase, level
    return "", "", ""


def _clean_host(value: str) -> str:
    return value.strip().rstrip(".,:;")


@dataclass
class Ev:
    ts: datetime
    level: str
    phase: str
    code: str
    text: str
    src: str
    count: int = 1
    last: datetime | None = None


@dataclass
class Attempt:
    kind: str  # attempt | reconnect | system
    start: datetime
    events: list[Ev] = field(default_factory=list)
    codes: list[str] = field(default_factory=list)
    portal: str = ""
    gateway: str = ""
    user: str = ""
    outcome: str = "incomplete"
    stage: str = ""
    reason: str = ""
    notes: list[str] = field(default_factory=list)
    phases: dict[str, str] = field(default_factory=dict)
    tunnel_up: datetime | None = None
    tunnel_down: datetime | None = None
    end_reason: str = ""
    has_detail: bool = False
    cur_phase: str = ""
    portal_inferred: bool = False

    def has(self, *codes: str) -> bool:
        return any(c in self.codes for c in codes)

    @property
    def end(self) -> datetime:
        last = self.events[-1] if self.events else None
        if last is None:
            return self.start
        return last.last or last.ts

    @property
    def session_ended(self) -> bool:
        if not self.tunnel_up:
            return False
        return self.codes and self.codes[-1] in ("LOGOUT", "LOGOUT_FAIL", "RETRY", "TDOWN", "DOWNTIME")

    def add(self, ev: Ev) -> None:
        prev = self.events[-1] if self.events else None
        if prev and prev.text == ev.text and prev.src == ev.src and prev.level == ev.level:
            prev.count += 1
            prev.last = ev.ts
            return
        self.events.append(ev)


def _fill_identity(att: Attempt, msg: str) -> None:
    if not att.portal:
        for rx in _PORTAL_RES:
            m = rx.search(msg)
            if m:
                att.portal = _clean_host(m.group(1))
                break
    for rx in _GATEWAY_RES:
        m = rx.search(msg)
        if m:
            att.gateway = _clean_host(m.group(1))
            break
    if not att.user or "Gateway login finished" in msg:
        for rx in _USER_RES:
            m = rx.search(msg)
            if m:
                user = unquote(m.group(1).strip())
                if user and user != "pre-logon":
                    att.user = user
                break


def build_attempts(lines: list[EventLine], fallback: bool = False) -> list[Attempt]:
    rules = FALLBACK_RULES + EVENT_RULES if fallback else EVENT_RULES
    rows: list[Attempt] = []
    cur: Attempt | None = None
    for line in lines:
        code, phase, level = classify(line.msg, rules)
        if fallback and (not code or code.startswith("AUX")):
            continue
        if not code:
            level = "error" if line.level.lower() == "error" else "info"
        elif line.level.lower() == "error" and level in ("info", "ok"):
            level = "error"

        if code == "PPL":
            cur = Attempt("attempt", line.ts)
            rows.append(cur)
        elif code in ("SVC_START", "SVC_STOP", "DISABLED"):
            if cur is not None and cur.kind != "system" and code == "SVC_STOP":
                # The stop belongs to the session it ends.
                pass
            else:
                cur = Attempt("system", line.ts)
                rows.append(cur)
        elif code == "GPL" and (cur is None or cur.kind == "system" or cur.session_ended):
            cur = Attempt("reconnect", line.ts)
            rows.append(cur)
        elif cur is None:
            cur = Attempt("system", line.ts)
            rows.append(cur)

        if phase and phase not in ("aux", "system", "session"):
            cur.cur_phase = phase
        elif not phase and code:
            phase = cur.cur_phase
        cur.codes.append(code or "?")
        _fill_identity(cur, line.msg)
        cur.add(Ev(line.ts, level, phase, code, line.msg, line.src))

        if code == "TUN_OK" and cur.tunnel_up is None:
            cur.tunnel_up = line.ts
        elif code == "TRESTORED":
            cur.tunnel_down = None
            cur.end_reason = ""
        elif code == "TDOWN" and cur.tunnel_up and cur.tunnel_down is None:
            cur.tunnel_down = line.ts
            m = _DOWN_RE.match(line.msg)
            cause = m.group(1) if m else "unknown"
            cur.end_reason = "User disconnect" if "UDISC" in cur.codes else f"Tunnel down: {cause}"
        elif code == "SVC_STOP" and cur.kind != "system":
            if cur.tunnel_up and cur.tunnel_down is None:
                cur.tunnel_down = line.ts
                cur.end_reason = "GlobalProtect service stopped"
            cur = None
    for row in rows:
        _evaluate(row)
    infer_portals(rows)
    return rows


def infer_portals(rows: list[Attempt]) -> None:
    """Fill a missing portal when the logged neighbours agree.

    Some attempts never log the portal name. When the nearest earlier and the
    nearest later attempt with a logged portal used the same one, that portal
    is assigned and flagged as inferred.
    """
    attempts = [r for r in rows if r.kind == "attempt"]
    prev = ""
    before: list[str] = []
    for att in attempts:
        before.append(prev)
        if att.portal and not att.portal_inferred:
            prev = att.portal
    nxt = ""
    for att, earlier in zip(reversed(attempts), reversed(before)):
        if att.portal:
            nxt = att.portal
        elif earlier and earlier == nxt:
            att.portal = earlier
            att.portal_inferred = True


def _first(att: Attempt, *codes: str) -> Ev | None:
    for ev in att.events:
        if ev.code in codes:
            return ev
    return None


def _evaluate(att: Attempt) -> None:
    if att.kind == "system":
        att.outcome = "system"
        first = att.events[0] if att.events else None
        att.reason = first.text if first else ""
        return

    reached = [e.phase for e in att.events if e.phase in PHASE_ORDER]
    last_phase = max(reached, key=PHASE_ORDER.get) if reached else ""
    fail: Ev | None = None
    stage = ""

    if att.tunnel_up:
        att.outcome = "connected"
    else:
        gl_ok = att.has("GL_OK")
        checks = [
            (("TUN_FAIL",), "tunnel"),
            (("GPL_FAIL",), "gw-prelogin"),
            (("GW_CANCEL",), "gw-login"),
            (() if gl_ok else ("GW_BADCRED",), "gw-login"),
            (("AUTHFAIL", "PS_AUTHFAIL"), "portal-login"),
            (("PPL_FAIL",), "portal-prelogin"),
            (("TRB",), ""),
            (("CLIENT_CERT", "CERT_FAIL", "UNREACH", "RECV_FAIL", "PS_INVALID"), ""),
            (() if att.has("PL_OK") else ("PCFG_FAIL",), "portal-config"),
        ]
        for codes, st in checks:
            ev = _first(att, *codes) if codes else None
            if ev is not None:
                fail, stage = ev, st or ev.phase or last_phase
                break
        if fail is not None:
            att.outcome = "cancelled" if fail.code == "GW_CANCEL" else "failed"
            att.reason = fail.text
            if fail.code == "TRB":
                m = _TRB_RE.search(fail.text)
                if m:
                    stage = TRB_STAGES.get(m.group(1).strip().lower(), stage)
                    att.reason = f"{m.group(2)} (stage: {m.group(1)})"
            if fail.code == "PS_AUTHFAIL":
                better = _first(att, "AUTHFAIL")
                if better is not None:
                    att.reason = better.text
                elif not att.has("PL_SEND"):
                    att.reason += " (set before any login request was sent)"
        elif att.has("UDISC"):
            att.outcome = "cancelled"
            stage = last_phase
            att.reason = "User disconnected before the tunnel was created"
        else:
            att.outcome = "incomplete"
            stage = last_phase
            label = dict(PHASES).get(last_phase, "the first step")
            att.reason = f"Log stops at {label}"
    att.stage = stage

    # Phase strip: ok / fail / warn / pending / none.
    for key, _label in PHASES:
        evs = [e for e in att.events if e.phase == key]
        if not evs:
            continue
        levels = {e.level for e in evs}
        if att.outcome in ("failed", "cancelled") and key == stage:
            att.phases[key] = "fail"
        elif "ok" in levels:
            att.phases[key] = "warn" if levels & {"warn", "error"} else "ok"
        elif levels & {"warn", "error"}:
            att.phases[key] = "warn"
        else:
            att.phases[key] = "pending"
    if att.outcome in ("failed", "cancelled") and stage and stage not in att.phases:
        att.phases[stage] = "fail"
    # A later phase proves the earlier ones completed.
    if reached:
        top = PHASE_ORDER[last_phase]
        for key, _label in PHASES:
            if PHASE_ORDER[key] < top and att.phases.get(key) == "pending":
                att.phases[key] = "ok"
    if att.kind == "reconnect":
        att.notes.append("Gateway reconnect without a new portal login")
    if att.has("NULLCFG"):
        att.notes.append("Portal returned no configuration for the user")
    if att.has("PS_CACHED"):
        att.notes.append("Cached portal configuration used")
    if att.has("PCFG_FAIL") and att.has("PL_OK"):
        att.notes.append("Latest portal configuration could not be fetched")
    if att.has("GW_BADCRED") and att.has("GL_OK"):
        att.notes.append("Gateway rejected the first credential, then login succeeded")
    if att.has("SSL_FALLBACK"):
        att.notes.append("IPSec to SSL fallback")
    if att.has("TRESTORED"):
        att.notes.append("Tunnel dropped and was restored during the session")
    if att.has("CERT_FAIL") and att.outcome == "connected":
        att.notes.append("Server certificate verification problem logged")


# --------------------------------------------------------------------------
# Detail events from the verbose service log.

_XML_TAG = r"<{0}>([^<]*)</{0}>"


def _xml_fields(body: str, tags: list[str]) -> str:
    parts = []
    for tag in tags:
        m = re.search(_XML_TAG.format(re.escape(tag)), body)
        if m and m.group(1).strip():
            parts.append(f"{tag}={m.group(1).strip()}")
    return ", ".join(parts)


_PRELOGIN_TAGS = ["status", "msg", "saml-auth-method", "saml-auth-status", "authentication-message",
                  "region", "server-ip", "panos-version"]
_GWCFG_TAGS = ["ip-address", "gw-address", "panos-version", "timeout", "lifetime"]

# (regex, phase, level, template). ``{0}``.. are the regex groups; a callable
# template receives (match, record).
DETAIL_RULES = [
    (_E(r"^-{2,}(.+? starts)-{2,}$"), "", "info", "== {0} =="),
    (_E(r"^--Set state to (.+)$"), "", "info", "State: {0}"),
    (_E(r"^REQID=(\d+),IPADDR=([^,]*),PORT=(\d+),URL=([^,]*),.*?VERIFY_CERT=(\d)"), "", "info",
     "HTTPS request #{0}: {1}:{2}{3} (verify cert: {4})"),
    (_E(r"^prelogin to portal result is"), "portal-prelogin", "info",
     lambda m, r: "Portal pre-login response: " + (_xml_fields(r.body, _PRELOGIN_TAGS) or "(empty)")),
    (_E(r"^Pre-login response is"), "gw-prelogin", "info",
     lambda m, r: "Gateway pre-login response: "
     + (_xml_fields(r.msg + "\n" + r.body, _PRELOGIN_TAGS) or "(empty)")),
    (_E(r"^(Portal|Gateway) auth method: (.+?), auth src: (.+)$"), "", "info",
     "{0} authentication method: {1} (source: {2})"),
    (_E(r"^Portal config digest matched"), "portal-config", "info",
     "Portal config unchanged (digest matched): cached copy used"),
    (_E(r"^Restored cached portal config"), "portal-config", "info", "Cached portal config restored"),
    (_E(r"^Saved portal config to file"), "portal-config", "info", "New portal config saved to disk"),
    (_E(r"^Portal config is NULL"), "portal-config", "warn", "Portal config is NULL"),
    (_E(r"^last portal config is restored"), "portal-config", "info", "Last portal config restored from disk"),
    (_E(r"^Failed to parse portal config"), "portal-config", "error", "Failed to parse portal config"),
    (_E(r"^Unable to verify server cert\. Result is (.+?)\s*$"), "", "warn",
     "Server certificate not verified by OpenSSL: {0}"),
    (_E(r"^Open_SSL_connection: (subject|issuer) '(.*)'"), "", "info", "Server certificate {0}: {1}"),
    (_E(r"^CheckServerCert\(\) returns (\S+)"), "", "info", "Server certificate check result: {0}"),
    (_E(r"^Gateway (\S+)\((.*?)\): ipv4 (\S*), ipv6 (\S*),"), "gw-prelogin", "info",
     "Gateway {0} ({1}) resolves to {2} {3}"),
    (_E(r"^NetworkDiscoverThread: network type is (\w+)"), "gw-prelogin", "info", "Network type: {0}"),
    (_E(r"^Discover external gateway: gateway count is (\d+)"), "gw-prelogin", "info",
     "External gateways to probe: {0}"),
    (_E(r"^Gateway selection type is (\w+)"), "gw-login", "info", "Gateway selection type: {0}"),
    (_E(r"^pretunnel latency.* is (\d+)"), "gw-prelogin", "info", "Pre-tunnel latency: {0} ms"),
    (_E(r"^Actual user for gateway login is (.+)$"), "gw-login", "info", "User for gateway login: {0}"),
    (_E(r"^gateway (\S+)'s config is"), "tunnel", "info",
     lambda m, r: f"Gateway {m.group(1)} config received: " + (_xml_fields(r.body, _GWCFG_TAGS) or "(empty)")),
    (_E(r"^Encryption method is (.+)$"), "tunnel", "info", "Tunnel encryption: {0}"),
    (_E(r"^Trying to do ipsec connection to (.+)$"), "tunnel", "info", "IPSec connection attempt to {0}"),
    (_E(r"^Connected ipsec to (.+)$"), "tunnel", "ok", "IPSec connected to {0}"),
    (_E(r"^tunnel to (\S+) connected"), "tunnel", "ok", "Tunnel to {0} connected"),
    (_E(r"^Failed to create tunnel to gateway (\S+?)\.?$"), "tunnel", "error", "Failed to create tunnel to gateway {0}"),
    (_E(r"^Connecting to (\S+) failed"), "tunnel", "error", "Connecting to {0} failed"),
    (_E(r"^(.*(?:fail ?over|fallback) to SSL.*)$", re.IGNORECASE), "tunnel", "warn", "{0}"),
    (_E(r"^failed to receive keep alive"), "session", "warn", "Failed to receive tunnel keep-alive"),
    (_E(r"^Disconnect\((.*)\) called"), "session", "info", "Disconnect requested ({0})"),
    (_E(r"^Logging out gateway, reason is (.+)$"), "session", "info", "Gateway logout, reason: {0}"),
    (_E(r"^failed to logout from gateway (\S+), error: ([^,]+)"), "session", "warn",
     "Logout from gateway {0} failed: {1}"),
    (_E(r"^Received (sleep|resume|resume-auto|shutdown) (?:event|message)"), "system", "info",
     "Power/system event: {0}"),
    (_E(r"^User (.+) logs (in|off) on session (\d+)"), "system", "info", "Windows user {0} logs {1} (session {2})"),
    (_E(r"^#+ Start PanGPS service \(ver: (.+?)\)"), "system", "info", "PanGPS service start (version {0})"),
    (_E(r"^Network is not reachable"), "", "warn", "Network is not reachable"),
    (_E(r"^msgtype = (.+)$"), "", "info", "Request from the app UI: {0}"),
    (_E(r"^(?!no |No )(.*saml.*)$", re.IGNORECASE), "", "info", "{0}"),
    (_E(r"^(.*(?:kerberos|Kerberos) auth.*fail.*)$"), "", "warn", "{0}"),
]
_DETAIL_SKIP = _E(
    r"^portal status is|^Auth failed|Failed to (find|get) attribute|^saml-default-browser|"
    r"saml default browser|msgtype = pan_msg_ping|msgtype = hip|SamlAuthStatus\(\)|IsSamlAuth\(\)"
)
_ERROR_NOISE = _E(
    r"DEM Agent|^ST,|route, set default route|Unknonwn managed status|DRBG selftest|"
    r"Failed to export CDL|accept failed|Failed to send \d+ bytes to client|read\(\) failed"
)


_MARKER_PHASE = {
    "portal pre-login starts": "portal-prelogin",
    "portal login starts": "portal-login",
    "gateway pre-login starts": "gw-prelogin",
    "gateway login starts": "gw-login",
    "tunnel creation starts": "tunnel",
}


def detail_event(rec: Record) -> Ev | None:
    msg = rec.msg
    if _DETAIL_SKIP.search(msg):
        return None
    for rx, phase, level, template in DETAIL_RULES:
        m = rx.search(msg)
        if not m:
            continue
        if callable(template):
            text = template(m, rec)
        else:
            text = template.format(*[(g or "").strip() for g in m.groups()])
        code = "D"
        if text.startswith("== "):
            phase = _MARKER_PHASE.get(text.strip("= ").lower(), "")
            code = "DM" if phase else "D"
        return Ev(rec.ts, level, phase, code, text[:600], rec.src)
    if rec.level.lower() in ("error", "warn") and not _ERROR_NOISE.search(msg) and msg:
        return Ev(rec.ts, "logerr", "", "D", msg[:600], rec.src)
    return None


def merge_details(rows: list[Attempt], details: list[Ev], tolerance_ms: int = 1500) -> int:
    """Attach detail events to the row that was active at their timestamp."""
    if not rows or not details:
        return 0
    starts = [r.start.timestamp() - tolerance_ms / 1000 for r in rows]
    touched: dict[int, list[Ev]] = {}
    for ev in details:
        idx = bisect.bisect_right(starts, ev.ts.timestamp()) - 1
        if idx < 0:
            continue
        touched.setdefault(idx, []).append(ev)
    merged = 0
    for idx, extra in touched.items():
        row = rows[idx]
        cur_phase = ""
        combined = sorted(row.events + extra, key=lambda e: e.ts)
        row.events = []
        for ev in combined:
            if ev.phase in PHASE_ORDER and ev.code != "D":
                cur_phase = ev.phase
            elif not ev.phase:
                ev.phase = cur_phase
            row.add(ev)
        row.has_detail = True
        merged += len(extra)
        if not row.portal or not row.gateway:
            for ev in extra:
                m = re.match(r"HTTPS request #\d+: ([^:]+):\d+(/\S+)", ev.text)
                if m and m.group(2).startswith("/global-protect/") and not row.portal:
                    row.portal = m.group(1)
                elif m and m.group(2).startswith("/ssl-vpn/") and not row.gateway:
                    row.gateway = m.group(1)
    return merged

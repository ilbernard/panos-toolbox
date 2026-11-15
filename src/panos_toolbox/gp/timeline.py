"""Timeline of the connection attempts of a GlobalProtect Windows client (standard library only).

Entry point::

    timeline = build_timeline(bundle)      # gp.bundle.Bundle
    data = timeline.to_dict()              # plain JSON-serialisable data

Specification of the logs: ``docs/gp/log-formats.md`` (sections 3 to 5, 9 and 10).

What is an attempt
------------------
``kind="login"``
    A user-visible login/connection attempt. In the event log (``pan_gp_event.log.old`` then
    ``pan_gp_event.log``, the whole history) a *cycle* starts at ``Started the Portal pre-login``
    and ends at the first terminal marker: tunnel created, tunnel failed, gateway certificate
    failure, cancel, authentication rejected, portal or gateway error. The client first tries
    without a password, so a cycle that ends at a credential prompt (or while waiting for the
    user) is *chained* to the next cycle when that one starts within ``chain_gap_s`` seconds
    (default ``CHAIN_GAP_S``): chained cycles are ONE attempt (``cycles`` counts them). Chaining
    never crosses portals: the portal of a cycle is known a few lines after its start, and when
    it differs (case-insensitive) from the portal of the chain, the earlier cycles close as
    ``abandoned`` and the cycle starts a new attempt (an unknown portal does not split). Portal
    and gateway of an attempt therefore always come from the same chain. A chain that is never
    completed is ``abandoned``.
``kind="auto-restore"``
    An automatic tunnel restore after a network change or sleep (no portal contact). The event
    log carries it for the whole history (start ``Gateway <name>: Checking network availability
    and restoring VPN connection...``, success ``Tunnel is restored.``, failure ``Tunnel retry
    done: failed retry``), so restores come from the event log and are enriched from the service
    log. After the end of the event log they come from the service log alone (``Show Gateway``
    start, ``Retry start succeeded`` / ``Tunnel retry done: failed retry`` end).

Outcomes: ``connected``, ``failed``, ``cancelled``, ``abandoned`` and, only for
``auto-restore``, ``expired``. A restore ends with ``Tunnel retry done: failed retry`` in both
cases; it is ``expired`` when the log says the tunnel downtime exceeded the retry grace period
and no ``Retry connect failed`` was logged (no reconnection was attempted: the PC slept or was
offline; ``details.downtime_ms`` and ``details.modern_standby`` say how long and whether
``Wait in modern standy`` was seen) and ``failed`` when a retry was really attempted and failed
(the error text keeps the specific reason) or the log gives no reason. ``expired`` is never a
failure (not in the failure counters, storms or findings about failures). A ``cancelled`` login
carries ``details.cancel_evidence``: ``explicit`` (a ``User canceled login`` line) or
``inferred`` (deduced from a user disconnect during the attempt). The log level never decides
an outcome (``Unable to verify server cert`` and the benign ``Error`` records of the service log
are not failures); the user-visible ``[Error]`` lines of the event log are the error *text* of
a failure that a marker already established, or the evidence of a gateway failure after the
portal login completed.

Detail enrichment: where the verbose logs overlap (``PanGPS*.log`` about the last 2 or 3 days,
``PanGPA.log``) the attempt gets ordered ``steps`` (phase steps) from all sources; an attempt
with no detailed log has no steps (``has_detail`` is false). Attempts that exist only in the
detailed logs (the event log stops earlier than the other logs) are created from them and the
``sources`` list says so. Time matching tolerance: ``match_tol_s``.

Data model (``Timeline.to_dict()``)
-----------------------------------
All timestamps are the naive local times of the logs, as ISO strings with milliseconds; there
is no time zone conversion. Keys::

    {
      "version": 1,
      "params": {...},                       # parameters used
      "coverage": {
        "event_log":   {"files", "first", "last", "records"} or null,
        "service_log": {...} or null,        # PanGPS family
        "agent_log":   {...} or null,        # PanGPA
        "detail_window": {"first", "last"} or null,
        "event_log_ends_before_detail_s": number or null,
        "restores": {"source", "first", "last", "note"},
        "crosscheck": {"matched", "outcome_agree", "outcome_differ": [ids],
                       "detail_only": n, "event_only_in_detail_window": n},
        "limitations": [text, ...]
      },
      "summary": {
        "total", "by_outcome": {...}, "by_kind": {"login": {...}, "auto-restore": {...}},
        "per_day": [{"date", "login": {...outcomes}, "auto-restore": {...}}],
        "top_errors": [{"text", "count", "first", "last", "kind", "raw_example"}],
        "with_detail", "excluding_storms": {"total", "by_outcome"}
      },
      "storms": [{"id", "start", "end", "count", "median_interval_ms", "by_error": {...}}],
      "attempts": [Attempt.to_dict(), ...]   # sorted by start
    }

An attempt::

    {"id": "a0001", "kind": "login"|"auto-restore", "start", "end", "duration_ms",
     "outcome", "portal", "gateway", "protocol": "IPSec"|"SSL"|"", "user", "trigger",
     "error": {"text": normalised short text, "raw": logged message, "stage": phase} or null,
     "cycles": n, "tunnel_ip", "has_detail": bool, "sources": ["event_log", "service_log",
     "agent_log"], "storm": id or null,
     "disconnect": {"time", "reason", "session_ms", "by_user", ...} or null,
     "details": {...},                       # kind specific facts (restore cause, retries ...)
     "steps": [{"ts", "phase", "text", "source", "level", "count"?, "until"?}]}  # detail only

``trigger``: ``user-click`` (PanGPA click or service ``user clicked connect button``), ``sso``
(``SSO starts.`` within 2 s before the start; an inference), ``auto`` (service portal request
without a click), ``restore`` (auto-restore) or ``unknown`` (event log only: a manual click or
an automatic retry cannot be told apart). ``details.outcome_mismatch`` is present when the
detailed logs disagree with the event log.

Retry storms: ``STORM_MIN_FAILURES`` failed login attempts, each starting at most
``STORM_MAX_GAP_S`` after the previous one, are a storm; the attempts carry its id in ``storm``.

Privacy: user names, host names and tunnel IPs are in clear text; passwords are never read
(the ``<passwd>`` element of the PanGPA commands is not parsed).
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import unquote

from .logs import EventLine, ParseStats, Record, iter_event_log, iter_records

# ---------------------------------------------------------------------------- parameters
CHAIN_GAP_S = 600          # a non-terminal cycle is chained to a start at most this much later
SSO_WINDOW_S = 2           # `SSO starts.` this close before a start marks an SSO trigger
MATCH_TOL_S = 5            # detailed-log start versus event-log start
ERROR_TAIL_S = 10          # an [Error] line this soon after a failure marker is its error text
SETTLE_S = 120             # a tunnel created this soon after a failure/cancel marker wins
HIP_WINDOW_S = 120         # first HIP line this soon after connect becomes a step
STORM_MIN_FAILURES = 10    # failed attempts needed for a retry storm
STORM_MAX_GAP_S = 30       # maximum start-to-start gap inside a storm
MAX_TEXT = 240             # cap of every text kept (steps, errors)
TOP_ERRORS = 10

KIND_LOGIN = "login"
KIND_RESTORE = "auto-restore"
OUTCOMES = ("connected", "failed", "cancelled", "abandoned", "expired")
PHASES = (
    "trigger", "portal-prelogin", "portal-auth", "network-discovery", "gateway-selection",
    "gateway-prelogin", "gateway-login", "tunnel", "connected", "hip", "disconnect",
    "restore", "ui",
)
SRC_EVENT, SRC_SERVICE, SRC_AGENT = "event_log", "service_log", "agent_log"
_SRC_ORDER = (SRC_EVENT, SRC_SERVICE, SRC_AGENT)

EVENT_STEM, SERVICE_STEM, AGENT_STEM = "pan_gp_event", "PanGPS", "PanGPA"


# ---------------------------------------------------------------------------- data model
def _iso(ts: datetime | None) -> str | None:
    return None if ts is None else ts.isoformat(timespec="milliseconds")


def _ms(a: datetime, b: datetime) -> int:
    return round((b - a).total_seconds() * 1000)


_HARD_CAP = 2000     # internal limit; the ``max_text`` parameter is applied at the end


def _cap(text: str, limit: int = _HARD_CAP) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: max(limit - 3, 0)] + "..."


@dataclass
class Step:
    ts: datetime
    phase: str
    text: str
    source: str            # file name the step comes from
    level: str = "info"    # info | ok | warn | error
    count: int = 1
    until: datetime | None = None

    def to_dict(self) -> dict:
        out = {"ts": _iso(self.ts), "phase": self.phase, "text": self.text,
               "source": self.source, "level": self.level}
        if self.count > 1:
            out["count"] = self.count
            out["until"] = _iso(self.until)
        return out


@dataclass
class Attempt:
    kind: str
    start: datetime
    end: datetime | None = None
    outcome: str = "abandoned"
    portal: str = ""
    gateway: str = ""
    protocol: str = ""
    user: str = ""
    trigger: str = "unknown"
    error_text: str = ""
    error_raw: str = ""
    error_stage: str = ""
    cycles: int = 1
    tunnel_ip: str = ""
    disconnect: dict | None = None
    details: dict = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    id: str = ""
    storm: int | None = None
    _post: list[Step] = field(default_factory=list, repr=False)   # steps after the end
    _next_restore: Attempt | None = field(default=None, repr=False)

    @property
    def has_detail(self) -> bool:
        return SRC_SERVICE in self.sources or SRC_AGENT in self.sources

    @property
    def duration_ms(self) -> int | None:
        return None if self.end is None else _ms(self.start, self.end)

    def set_error(self, raw: str, stage: str = "") -> None:
        self.error_raw = _cap(raw)
        self.error_text = normalise_error(raw)
        self.error_stage = stage

    def to_dict(self) -> dict:
        disc = None
        if self.disconnect is not None:
            disc = dict(self.disconnect)
            disc["restored_by"] = self._next_restore.id if self._next_restore else None
        steps = []
        if self.has_detail:
            steps = [s.to_dict() for s in _compress(sorted(self.steps, key=lambda s: s.ts))]
        error = None
        if self.error_text:
            error = {"text": self.error_text, "raw": self.error_raw, "stage": self.error_stage}
        return {
            "id": self.id, "kind": self.kind, "start": _iso(self.start), "end": _iso(self.end),
            "duration_ms": self.duration_ms, "outcome": self.outcome, "portal": self.portal,
            "gateway": self.gateway, "protocol": self.protocol, "user": self.user,
            "trigger": self.trigger, "error": error, "cycles": self.cycles,
            "tunnel_ip": self.tunnel_ip, "has_detail": self.has_detail,
            "sources": sorted(self.sources, key=_SRC_ORDER.index), "storm": self.storm,
            "disconnect": disc, "details": self.details, "steps": steps,
        }


@dataclass
class Timeline:
    attempts: list[Attempt] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    storms: list[dict] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "version": 1, "params": self.params, "coverage": self.coverage,
            "summary": self.summary, "storms": self.storms,
            "attempts": [a.to_dict() for a in self.attempts],
        }


def _compress(steps: list[Step]) -> list[Step]:
    """Merge consecutive identical steps (same phase, text, source, level) into one with a count."""
    out: list[Step] = []
    for s in steps:
        if out and (out[-1].phase, out[-1].text, out[-1].source, out[-1].level) == (
                s.phase, s.text, s.source, s.level):
            out[-1].count += s.count
            out[-1].until = s.until or s.ts
            continue
        out.append(Step(s.ts, s.phase, s.text, s.source, s.level, s.count, s.until))
    return out


# ---------------------------------------------------------------------------- error texts
# Benign Error-level records of the service/agent logs (spec section 9): never an error.
_BENIGN_ERRORS = re.compile(
    r"DEM Agent|^route, set default route|^Failed to send \d+ bytes to client|^ST,ERROR|"
    r"^Failed to export CDL|Unknonwn managed status|^accept failed|DRBG selftest|"
    r"^Check GP disable flag failed|^read\(\) failed|^Unexpected RegQueryValueExW|"
    r"^CSystemTray::SetIcon|^The file .* is not signed|^Unknown child dialog|"
    r"Opswat Error|Proxy Agent fail to clean up|^Failed to (find|get) ")
# Text of the pre-login certificate pre-check that is NOT a failure (spec section 9).
_CERT_NOTE = re.compile(r"^Unable to verify server cert\. Result is (.*?)\s*$")

_ERROR_NORMALISE = [
    (re.compile(r"could not verify the server certificate of the gateway", re.IGNORECASE),
     "Gateway certificate could not be verified"),
    (re.compile(r"^Failed to verify certificate", re.IGNORECASE), "Server certificate verification failed"),
    (re.compile(r"client certificate is required", re.IGNORECASE), "Client certificate required"),
    (re.compile(r"unreachable or the gateway is unresponsive", re.IGNORECASE),
     "Gateway unreachable or unresponsive"),
    (re.compile(r"unreachable or the portal is unresponsive", re.IGNORECASE),
     "Portal unreachable or unresponsive"),
    (re.compile(r"^(Gateway \S+: )?No Network Connectivity", re.IGNORECASE), "No network connectivity"),
    (re.compile(r"Failed to receive message from remote host", re.IGNORECASE),
     "Gateway connection lost (no reply from remote host)"),
    (re.compile(r"session has ended due to inactivity", re.IGNORECASE), "Session ended due to inactivity"),
    (re.compile(r"Failed to find PANGP virtual adapter", re.IGNORECASE), "PANGP virtual adapter not found"),
    (re.compile(r"^Auth failed for portal", re.IGNORECASE), "Portal rejected the credentials"),
    (re.compile(r"^portal status is Invalid portal", re.IGNORECASE), "Invalid portal"),
    (re.compile(r"^Failed to pre - ?login to the portal", re.IGNORECASE), "Portal pre-login failed"),
    (re.compile(r"^Failed to pre-login to the gateway", re.IGNORECASE), "Gateway pre-login failed"),
    (re.compile(r"^failed to create tunnel", re.IGNORECASE), "Tunnel creation failed"),
    (re.compile(r"^Failed to verify server certificate of gateway", re.IGNORECASE),
     "Gateway certificate could not be verified"),
    (re.compile(r"^Tunnel downtime .* exceeds retry grace period", re.IGNORECASE),
     "Tunnel not restored within the retry grace period"),
    (re.compile(r"^Tunnel retry done: failed retry", re.IGNORECASE),
     "Tunnel restore ended with a failed retry"),
]
def restore_outcome(retries: int, grace_seen: bool) -> str:
    """Outcome of an auto-restore that ended with ``Tunnel retry done: failed retry``.

    ``expired``: the downtime exceeded the retry grace period and no retry was attempted (the PC
    slept or was offline). ``failed``: at least one ``Retry connect failed`` was logged, or the
    log gives no reason at all (the literal ``failed retry`` stands).
    """
    return "expired" if grace_seen and retries == 0 else "failed"


_TRB_RE = re.compile(r"^Troubleshooting log is generated with the error stage \((.*?)\) "
                     r"and the error detail \((.*)\)\.?$")
_GW_PREFIX = re.compile(r"^Gateway [^:]+: ")


def normalise_error(raw: str) -> str:
    """Short, stable text for a logged error message (used to group errors)."""
    raw = raw.strip()
    m = _TRB_RE.match(raw)
    if m:
        return _cap(f"{m.group(1).strip()}: {m.group(2).strip().rstrip('.')}")
    for rx, text in _ERROR_NORMALISE:
        if rx.search(raw):
            return text
    return _cap(_GW_PREFIX.sub("", raw))


# ---------------------------------------------------------------------------- event log
# (code, pattern); one alternation finds the code, the per-code pattern extracts the fields.
_EVENT_RULES = [
    ("START", r"Started the Portal pre-login$"),
    ("SSO", r"SSO starts\.$"),
    ("CERT", r"CPanMSService::PreloginPortal CheckServerCert return (0x[0-9a-fA-F]+)"),
    ("PRELOGIN_OK", r"Portal pre-login result received"),
    ("PRELOGIN_FAIL", r"Failed to pre - ?login to the portal (\S+)"),
    ("PORTAL_LOGIN", r"Portal Login starts"),
    ("LOGGING_IN", r"Logging into portal"),
    ("COOKIE", (r"(?:Unserialized|Serialize) (non-empty|empty) cookie for portal (\S+) "
               r"and (?:user (\S+)|pre-logon user)")),
    ("NO_COOKIE_FILE", r"Failed to open file .*PanPUAC_"),
    ("AUTH_EMPTY", r"Auth failed empty password for portal"),
    ("AUTH_REJECT", r"Auth failed for portal"),
    ("PORTAL_STATUS", r"portal status is (.*?)\.?$"),
    ("PORTAL_DONE", r"Portal login completed with address (\S+) and conect method of (\S+?)\.?$"),
    ("PORTAL_CFG_FAIL", r"Unable to fetch the latest Portal configuration from address (\S+?)\.?$"),
    ("ND_START", r"Network discovery started"),
    ("ND_TYPE", r"Discovering (external|internal) network"),
    ("GW_SELECT", r"Gateway selection\("),
    ("GW_PRELOGIN", r"Gateway pre-Login Starts to (\S+)"),
    ("GW_PRELOGIN_OK", r"Prelogin to gateway \(null\) (\S+) without"),
    ("GW_LOGIN", r"Gateway Login starts to (\S+)"),
    ("GW_CRED", r"Invalid user credential for gateway (\S+)"),
    ("GW_LOGIN_OK", r"(Auto|Manual) Gateway login finished with address (\S+) and user (.+?)\.?$"),
    ("GW_CANCEL", r"User canceled login to gateway (\S+?)\.?$"),
    ("GW_PRELOGIN_FAIL", r"Failed to pre-login to the gateway (\S+)"),
    ("GW_CERT_FAIL", r"Failed to verify server certificate of gateway (\S+?)\.?$"),
    ("TUN_START", r"Trying to create tunnel with gateway (\S+)"),
    ("TUN_OK", r"(IPSec|SSL) tunnel creation finished with Gateway (\S+?)\.?$"),
    ("TUN_FAIL", r"[Ff]ailed to create tunnel with gateway (\S+)"),
    ("TUN_FAILOVER", r"IPSec tunnel should failover to SSL\("),
    ("TUN_TYPE_CHG", r"GlobalProtect needed to change the connection type"),
    ("TRB", r"Troubleshooting log is generated with the error stage"),
    ("USER_DISC", r"User disconnecting tunnel starts"),
    ("DOWN", r"Tunnel is down due to (.+?)\.?$"),
    ("DOWNTIME", r"(?:In timeout handling, t|T)unnel downtime is (\d+) miliseconds"),
    ("RESTORE_START", r"Gateway (.+?): Checking network availability and restoring VPN connection"),
    ("RESTORE_RETRY", r"Retry connect failed (\w+) time"),
    ("RESTORE_OK", r"Tunnel is restored"),
    ("RESTORE_DONE", r"Tunnel retry done: failed retry"),
    ("RESTORE_GRACE", (r"Tunnel downtime \((\d+) milliseconds\) exceeds retry grace period "
                       r"\((\d+) seconds\)")),
    ("NO_RETRY", (r"No tunnel retry since tunnel downtime \((\d+) miliseconds\) exceeds "
                  r"configured timeout \((\d+) seconds\)")),
    ("STANDBY", r"Wait in modern standy until wakeup"),
    ("HIP", r"(?:Completed HIP Report check with|HIP Report submitted to the) Gateway (\S+?)\.?$"),
    ("GW_ROUTE", r"Gateway route (\S+) got changed to use virtual IP (\S+) as source IP"),
    ("SVC_START", r"GlobalProtect service started"),
    ("SVC_STOP", r"GlobalProtect service stopped"),
]
_EVENT_ALT = re.compile("|".join(f"(?P<{c}>{p})" for c, p in _EVENT_RULES))
_EVENT_PAT = {c: re.compile(p) for c, p in _EVENT_RULES}


def _event_code(msg: str):
    m = _EVENT_ALT.match(msg)
    if not m:
        return "", None
    code = m.lastgroup
    return code, _EVENT_PAT[code].match(msg)


_CYCLE_CODES = frozenset({
    "CERT", "PRELOGIN_OK", "PRELOGIN_FAIL", "PORTAL_LOGIN", "LOGGING_IN", "COOKIE",
    "NO_COOKIE_FILE", "AUTH_EMPTY", "AUTH_REJECT", "PORTAL_STATUS", "PORTAL_DONE",
    "PORTAL_CFG_FAIL", "ND_START", "ND_TYPE", "GW_SELECT", "GW_PRELOGIN", "GW_PRELOGIN_OK",
    "GW_LOGIN", "GW_CRED", "GW_LOGIN_OK", "GW_CANCEL", "GW_PRELOGIN_FAIL", "GW_CERT_FAIL",
    "TUN_START", "TUN_OK", "TUN_FAIL", "TUN_TYPE_CHG", "TRB", "USER_DISC"})


class _Cycle:
    """One portal cycle of the event log (a chain of cycles is one attempt)."""

    __slots__ = ("cert_code", "disc_during", "end", "err_raw", "errors", "flags", "gateway",
                 "last", "phase", "portal", "protocol", "prov", "result", "ssl_fallback", "sso",
                 "stage", "start", "steps", "tunnel_ts", "user")

    def __init__(self, start: datetime, sso: bool):
        self.start = start
        self.sso = sso
        self.last = start
        self.steps: list[Step] = []
        self.flags: set[str] = set()
        self.portal = self.gateway = self.user = self.protocol = ""
        self.errors: list[tuple[datetime, str]] = []
        self.result = ""        # connected | failed | cancelled | prompt | gw_prompt | awaiting |
        self.end: datetime | None = None   # incomplete
        self.err_raw = ""
        self.stage = ""
        self.phase = "trigger"
        self.ssl_fallback = False
        self.disc_during = False
        self.cert_code = ""
        self.tunnel_ts: datetime | None = None
        # first failure/cancel marker: (result, ts, raw, stage, raw_is_error_text)
        self.prov: tuple | None = None


class _Restore:
    __slots__ = (
        "cause",
        "downtime_ms",
        "end",
        "errors",
        "grace",
        "result",
        "retries",
        "short",
        "slept",
        "start",
        "steps",
    )

    def __init__(self, start: datetime, short: str):
        self.start = start
        self.short = short
        self.cause = ""
        self.downtime_ms: int | None = None
        self.retries = 0
        self.slept = False
        self.grace: tuple[int, int] | None = None
        self.errors: list[str] = []
        self.steps: list[Step] = []
        self.end: datetime | None = None
        self.result = ""


class _Session:
    __slots__ = ("attempt", "hip_done", "up")

    def __init__(self, attempt: Attempt, up: datetime):
        self.attempt = attempt
        self.up = up
        self.hip_done = False


class _EventEngine:
    """Streaming segmentation of the event log (see the module docstring)."""

    def __init__(self, chain_gap_s: float, sso_window_s: float, error_tail_s: float,
                 hip_window_s: float, settle_s: float):
        self.chain_gap = timedelta(seconds=chain_gap_s)
        self.sso_window = timedelta(seconds=sso_window_s)
        self.error_tail = timedelta(seconds=error_tail_s)
        self.hip_window = timedelta(seconds=hip_window_s)
        self.settle = timedelta(seconds=settle_s)
        self.attempts: list[Attempt] = []
        self.cur: _Cycle | None = None
        self.chain: list[_Cycle] = []
        self.last_sso: datetime | None = None
        self.restore: _Restore | None = None
        self.sess: _Session | None = None
        self.last_connected: Attempt | None = None
        self.last_login: Attempt | None = None
        self.user_disc_ts: datetime | None = None
        self.last_down: tuple[datetime, dict, Attempt] | None = None
        self.pending_down: tuple[datetime, str] | None = None
        self.cur_file = ""

    # ------------------------------------------------------------------ helpers
    def _step(self, container, ts, phase, text, level="info"):
        container.append(Step(ts, phase, _cap(text), self.cur_file, level))

    def feed(self, line: EventLine) -> None:
        self.cur_file = line.src
        ts, msg = line.ts, line.msg
        code, m = _event_code(msg)
        is_err = line.level == "Error"

        cyc = self.cur
        if cyc is not None and cyc.prov is not None and ts - cyc.prov[1] > self.settle:
            self._settle(cyc)          # nothing rescued the provisional failure
            cyc = None
        if code in ("SVC_START", "SVC_STOP"):
            self._service(ts, code)
            return
        if code == "START":
            self._start(ts)
            return
        if code == "SSO":
            self.last_sso = ts
            return

        self._restore_line(ts, code, m, msg, is_err)
        self._session_line(ts, code, m, msg, is_err)

        if cyc is not None:
            if is_err or code in _CYCLE_CODES:
                cyc.last = ts
            self._cycle_line(cyc, ts, code, m, msg, is_err)
        elif code == "TUN_OK" and self.last_login is not None:
            ended = self.last_down[0] if self.last_down else None
            if self.sess is not None or (ended and ts - ended <= self.chain_gap):
                sw = self.last_login.details.setdefault("gateway_switches", [])
                sw.append({"time": _iso(ts), "gateway": m.group(2), "protocol": m.group(1)})

    # ------------------------------------------------------------------ lifecycle
    def _service(self, ts, code) -> None:
        if self.cur is not None:
            self.cur.last = ts
            self._close_cycle()
        if self.restore is not None:
            self._end_restore(ts, "abandoned", "service restarted")
        if code == "SVC_STOP" and self.sess is not None:
            self._record_down(ts, "service stopped", by_user=False)

    def _start(self, ts: datetime) -> None:
        if self.cur is not None:
            self._close_cycle()
        if self.restore is not None:
            self._end_restore(ts, "abandoned", "superseded by a new login")
        if self.chain and ts - self.chain[-1].last > self.chain_gap:
            self._finalise(self.chain, "abandoned")
            self.chain = []
        sso = self.last_sso is not None and ts - self.last_sso <= self.sso_window
        cyc = _Cycle(ts, sso)
        self.chain.append(cyc)
        self.cur = cyc
        self._step(cyc.steps, ts, "trigger",
                   "Portal pre-login started" + (" (SSO trigger)" if sso else ""))

    def finish(self) -> list[Attempt]:
        if self.cur is not None:
            self._close_cycle()
        if self.chain:
            self._finalise(self.chain, "abandoned")
            self.chain = []
        if self.restore is not None:
            self._end_restore(self.restore.start, "abandoned", "log ends")
        return self.attempts

    # ------------------------------------------------------------------ cycles
    def _terminal(self, cyc: _Cycle, ts: datetime, result: str, raw: str = "",
                  stage: str = "") -> None:
        cyc.result, cyc.end, cyc.err_raw, cyc.stage = result, ts, raw, stage
        self.cur = None
        self._finalise(self.chain, result)
        self.chain = []

    def _provisional(self, cyc: _Cycle, ts: datetime, result: str, raw: str, stage: str,
                     is_error_text: bool = False) -> None:
        """Remember the first failure/cancel marker of a cycle.

        The client often retries on its own (gateway discovery) and a tunnel can still be
        created within ``settle`` seconds: that success wins. Otherwise the marker stands.
        """
        if cyc.prov is None:
            cyc.prov = (result, ts, raw, stage, is_error_text)
        elif result == "failed" and not cyc.prov[4] and is_error_text and \
                ts - cyc.prov[1] <= self.error_tail:
            cyc.prov = (cyc.prov[0], cyc.prov[1], raw, cyc.prov[3], True)

    def _settle(self, cyc: _Cycle) -> None:
        result, ts, raw, stage, _ = cyc.prov
        self._terminal(cyc, ts, result, raw, stage)

    def _set_portal(self, cyc: _Cycle, portal: str) -> None:
        """Record the portal of a cycle; a cycle for ANOTHER portal never joins the chain.

        The portal of a cycle is known only a few lines after its start. When the first portal
        seen differs (case-insensitive) from the portal of the chain so far, the chain is closed
        as ``abandoned`` and the cycle starts a new attempt. An unknown portal never splits.
        """
        if cyc.portal:
            return
        cyc.portal = portal
        if len(self.chain) < 2 or self.chain[-1] is not cyc:
            return
        prev = next((c.portal for c in reversed(self.chain[:-1]) if c.portal), "")
        if prev and portal and prev.rstrip(".").lower() != portal.rstrip(".").lower():
            self._finalise(self.chain[:-1], "abandoned")
            self.chain = [cyc]

    def _close_cycle(self) -> None:
        """Close the open cycle without a rescuing tunnel (next start, service line, EOF)."""
        cyc = self.cur
        if cyc is None:
            return
        if cyc.prov is not None:
            self._settle(cyc)
            return
        self.cur = None
        fl = cyc.flags
        if "prompt" in fl:
            cyc.result = "prompt"
        elif "prelogin_fail" in fl and "portal_ok" not in fl:
            raw = cyc.errors[-1][1] if cyc.errors else "Failed to pre - login to the portal"
            cyc.result, cyc.end, cyc.err_raw, cyc.stage = "failed", cyc.last, raw, "portal-prelogin"
            self._finalise(self.chain, "failed")
            self.chain = []
        elif "gw_prompt" in fl:
            cyc.result = "gw_prompt"
        elif fl & {"awaiting", "cookie_empty", "logging_in", "no_cookie_file"}:
            cyc.result = "awaiting"
        else:
            cyc.result = "incomplete"
            # not a credential prompt: nothing can continue it, so it is not chained
            self._finalise(self.chain, "abandoned")
            self.chain = []

    def _cycle_line(self, cyc, ts, code, m, msg, is_err) -> None:
        fl = cyc.flags
        step = self._step
        if is_err:
            cyc.errors.append((ts, msg))
            step(cyc.steps, ts, cyc.phase, f"Error shown to the user: {msg}", "error")
            if cyc.prov is not None or "portal_ok" in fl and "prompt" not in fl:
                self._provisional(cyc, ts, "failed", msg, cyc.phase, True)
            return
        if code == "CERT":
            cyc.cert_code = m.group(1)
            if m.group(1).lower() != "0x1002":
                step(cyc.steps, ts, "portal-prelogin",
                     f"Portal certificate check returned {m.group(1)}", "warn")
        elif code == "PRELOGIN_OK":
            cyc.phase = "portal-prelogin"
            step(cyc.steps, ts, "portal-prelogin", "Portal pre-login answered", "ok")
        elif code == "PRELOGIN_FAIL":
            cyc.phase = "portal-prelogin"
            fl.add("prelogin_fail")
            self._set_portal(cyc, m.group(1).rstrip("."))
            step(cyc.steps, ts, "portal-prelogin", f"Portal pre-login failed ({m.group(1)})",
                 "warn")
        elif code == "PORTAL_LOGIN":
            cyc.phase = "portal-auth"
            step(cyc.steps, ts, "portal-auth", "Portal login started")
        elif code == "LOGGING_IN":
            fl.add("logging_in")
        elif code == "COOKIE":
            self._set_portal(cyc, m.group(2).rstrip("."))
            if m.group(3) and m.group(1) == "empty":
                fl.add("cookie_empty")
            if m.group(3) and not cyc.user:
                cyc.user = unquote(m.group(3)).rstrip(".")
        elif code == "NO_COOKIE_FILE":
            fl.add("no_cookie_file")
        elif code == "AUTH_EMPTY":
            fl.add("empty_pw")
            fl.add("awaiting")
            step(cyc.steps, ts, "portal-auth",
                 "Authentication with an empty password failed: credentials requested", "warn")
        elif code == "AUTH_REJECT":
            fl.add("auth_reject")
            fl.add("awaiting")
            step(cyc.steps, ts, "portal-auth", "Portal rejected the credentials", "error")
        elif code == "PORTAL_STATUS":
            status = m.group(1)
            step(cyc.steps, ts, "portal-auth", f"Portal status: {status}",
                 "ok" if status == "Connected" else "warn")
            if status == "User authentication failed":
                if "auth_reject" in fl and "empty_pw" not in fl:
                    self._terminal(cyc, ts, "failed", "Auth failed for portal", "portal-auth")
                else:
                    fl.add("prompt")
            elif status == "Invalid portal":
                self._terminal(cyc, ts, "failed", msg, "portal-prelogin")
            elif status == "Client Cert Required":
                self._provisional(cyc, ts, "failed", msg, "portal-auth")
        elif code == "PORTAL_DONE":
            fl.add("portal_ok")
            self._set_portal(cyc, m.group(1))
            cyc.portal = m.group(1)
            cyc.phase = "portal-auth"
            step(cyc.steps, ts, "portal-auth",
                 f"Portal login completed ({m.group(1)}, connect method {m.group(2)})", "ok")
        elif code == "PORTAL_CFG_FAIL":
            self._set_portal(cyc, m.group(1))
            step(cyc.steps, ts, "portal-auth", "Latest portal configuration could not be fetched",
                 "warn")
        elif code == "ND_START":
            cyc.phase = "network-discovery"
            step(cyc.steps, ts, "network-discovery", "Network discovery started")
        elif code == "ND_TYPE":
            step(cyc.steps, ts, "network-discovery", f"Discovering {m.group(1)} network")
        elif code == "GW_SELECT":
            cyc.phase = "gateway-selection"
            step(cyc.steps, ts, "gateway-selection", msg)
        elif code == "GW_PRELOGIN":
            cyc.phase = "gateway-prelogin"
            cyc.gateway = m.group(1)
            step(cyc.steps, ts, "gateway-prelogin", f"Gateway pre-login to {m.group(1)}")
        elif code == "GW_PRELOGIN_OK":
            step(cyc.steps, ts, "gateway-prelogin", "Gateway pre-login answered", "ok")
        elif code == "GW_LOGIN":
            cyc.phase = "gateway-login"
            cyc.gateway = m.group(1)
            step(cyc.steps, ts, "gateway-login", f"Gateway login to {m.group(1)}")
        elif code == "GW_CRED":
            fl.add("gw_prompt")
            cyc.gateway = m.group(1)
            step(cyc.steps, ts, "gateway-login",
                 f"Gateway {m.group(1)} reported an invalid user credential", "warn")
        elif code == "GW_LOGIN_OK":
            cyc.gateway = m.group(2)
            cyc.user = unquote(m.group(3)).strip().rstrip(".") or cyc.user
            fl.discard("gw_prompt")
            step(cyc.steps, ts, "gateway-login",
                 f"Gateway login finished ({m.group(1).lower()}, user {cyc.user})", "ok")
        elif code == "GW_CANCEL":
            fl.add("explicit_cancel")
            step(cyc.steps, ts, "gateway-login", "Login to the gateway cancelled by the user",
                 "warn")
            self._provisional(cyc, ts, "cancelled", msg, "gateway-login")
        elif code == "GW_PRELOGIN_FAIL":
            step(cyc.steps, ts, "gateway-prelogin", f"Gateway pre-login failed ({m.group(1)})",
                 "error")
            cyc.gateway = cyc.gateway or m.group(1)
            self._provisional(cyc, ts, "failed", msg, "gateway-prelogin")
        elif code == "GW_CERT_FAIL":
            cyc.gateway = cyc.gateway or m.group(1)
            step(cyc.steps, ts, "gateway-prelogin",
                 f"Gateway {m.group(1)}: server certificate verification failed", "error")
            self._provisional(cyc, ts, "failed", msg, "gateway-prelogin")
        elif code == "TUN_START":
            cyc.phase = "tunnel"
            cyc.gateway = m.group(1)
            step(cyc.steps, ts, "tunnel", f"Creating tunnel to {m.group(1)}")
        elif code == "TUN_TYPE_CHG":
            cyc.ssl_fallback = True
            step(cyc.steps, ts, "tunnel", "GlobalProtect changed the connection type",
                 "warn")
        elif code == "TUN_OK":
            cyc.protocol, cyc.gateway, cyc.tunnel_ts = m.group(1), m.group(2), ts
            step(cyc.steps, ts, "connected", f"{m.group(1)} tunnel created with {m.group(2)}", "ok")
            if cyc.prov is not None and cyc.prov[0] == "cancelled":
                cyc.disc_during = True
            self._terminal(cyc, ts, "connected")
        elif code == "TUN_FAIL":
            cyc.gateway = cyc.gateway or m.group(1)
            step(cyc.steps, ts, "tunnel", f"Tunnel creation to {m.group(1)} failed", "error")
            self._provisional(cyc, ts, "failed", msg, "tunnel")
        elif code == "TRB":
            tm = _TRB_RE.match(msg)
            stage = tm.group(1) if tm else ""
            phase = "gateway-prelogin" if "gateway" in stage.lower() else "portal-prelogin"
            step(cyc.steps, ts, phase, f"Troubleshooting report written: {stage}", "error")
            self._provisional(cyc, ts, "failed", msg, phase)
        elif code == "USER_DISC":
            step(cyc.steps, ts, "disconnect", "User disconnect requested", "warn")
            self._provisional(cyc, ts, "cancelled", msg, cyc.phase)

    # ------------------------------------------------------------------ attempts
    def _finalise(self, chain: list[_Cycle], result: str) -> Attempt:
        first, last = chain[0], chain[-1]
        att = Attempt(KIND_LOGIN, first.start, sources=[SRC_EVENT])
        att.cycles = len(chain)
        att.trigger = "sso" if first.sso else "unknown"
        for c in chain:
            att.portal = att.portal or c.portal
            att.steps.extend(c.steps)
        for c in reversed(chain):
            if c.gateway:
                att.gateway = c.gateway
                break
        for c in reversed(chain):
            if c.user:
                att.user = c.user
                break
        att.protocol = last.protocol
        if result == "connected":
            att.outcome, att.end = "connected", last.tunnel_ts
            if last.ssl_fallback:
                att.details["ssl_fallback"] = True
            if last.disc_during:
                att.details["disconnect_requested_during_connect"] = True
            self.sess = _Session(att, last.tunnel_ts)
            self.last_connected = self.last_login = att
        elif result == "failed":
            att.outcome, att.end = "failed", last.end
            att.set_error(last.err_raw or "attempt failed", last.stage)
        elif result == "cancelled":
            att.outcome, att.end = "cancelled", last.end
            att.details["cancel_evidence"] = (
                "explicit" if "explicit_cancel" in last.flags else "inferred")
        else:   # the chain was never completed
            att.outcome, att.end = "abandoned", last.last
            att.details["abandon_reason"] = {
                "prompt": "credential prompt not answered",
                "gw_prompt": "gateway credential prompt not answered",
                "awaiting": "waiting for the user (interactive authentication)",
            }.get(last.result, "no outcome logged")
            if last.errors:
                att.set_error(last.errors[-1][1], last.phase)
        self.attempts.append(att)
        return att

    # ------------------------------------------------------------------ sessions
    def _record_down(self, ts: datetime, reason: str, by_user: bool) -> None:
        sess = self.sess
        self.sess = None
        if sess is None:
            return
        disc = {"time": _iso(ts), "reason": reason, "session_ms": _ms(sess.up, ts),
                "by_user": by_user}
        if sess.attempt.disconnect is None:
            sess.attempt.disconnect = disc
            self.last_down = (ts, disc, sess.attempt)
            sess.attempt._post.append(Step(
                ts, "disconnect", _cap(f"Tunnel down: {reason}"), self.cur_file, "warn"))

    def _session_line(self, ts, code, m, msg, is_err) -> None:
        if code == "USER_DISC":
            self.user_disc_ts = ts
        elif code == "DOWN":
            by_user = (self.user_disc_ts is not None
                       and 0 <= (ts - self.user_disc_ts).total_seconds() <= 5) or bool(
                self.sess and self.sess.attempt.details.get("disconnect_requested_during_connect")
                and self.sess.attempt.disconnect is None)
            self.pending_down = (ts, m.group(1))
            self._record_down(ts, m.group(1), by_user)
        elif code == "DOWNTIME" and self.last_down and ts == self.last_down[0]:
            self.last_down[1]["downtime_ms"] = int(m.group(1))
        elif code == "TUN_FAILOVER" and self.last_down and (ts - self.last_down[0]).total_seconds() <= 2:
            self.last_down[1]["failover_to_ssl"] = True
        elif code == "NO_RETRY" and self.last_down and (ts - self.last_down[0]).total_seconds() <= 2:
            self.last_down[1]["retry"] = "not attempted: downtime exceeds the configured timeout"
        elif is_err and self.last_down and self.cur is None and self.restore is None:
            if (ts - self.last_down[0]).total_seconds() <= 1800 and "message" not in self.last_down[1]:
                self.last_down[1]["message"] = _cap(msg)
        elif code == "HIP" and self.sess is not None and not self.sess.hip_done:
            if ts - self.sess.up <= self.hip_window:
                self.sess.hip_done = True
                self.sess.attempt._post.append(Step(ts, "hip", "HIP report check completed",
                                                    self.cur_file, "info"))
        elif code == "GW_ROUTE" and self.sess is not None and not self.sess.attempt.tunnel_ip:
            self.sess.attempt.tunnel_ip = m.group(2)

    # ------------------------------------------------------------------ restores
    def _restore_line(self, ts, code, m, msg, is_err) -> None:
        if code == "RESTORE_START":
            if self.restore is not None:
                self._end_restore(ts, "abandoned", "another restore started")
            rst = _Restore(ts, m.group(1))
            if self.pending_down and (ts - self.pending_down[0]).total_seconds() <= 2:
                rst.cause = self.pending_down[1]
            if self.last_down and (ts - self.last_down[0]).total_seconds() <= 2:
                rst.downtime_ms = self.last_down[1].get("downtime_ms")
            self.restore = rst
            self._step(rst.steps, ts, "restore",
                       f"Restoring the tunnel to gateway {m.group(1)} "
                       f"(cause: {rst.cause or 'unknown'})")
            return
        rst = self.restore
        if rst is None:
            return
        if is_err:
            rst.errors.append(msg)
            self._step(rst.steps, ts, "restore", f"Error shown to the user: {msg}", "error")
        elif code == "RESTORE_RETRY":
            rst.retries += 1
            self._step(rst.steps, ts, "restore", f"Retry failed ({m.group(1)} time)", "warn")
        elif code == "STANDBY":
            rst.slept = True
            self._step(rst.steps, ts, "restore", "Waiting in modern standby until wake-up", "warn")
        elif code == "RESTORE_GRACE":
            rst.grace = (int(m.group(1)), int(m.group(2)))
            self._step(rst.steps, ts, "restore",
                       f"Tunnel downtime {int(m.group(1)) // 1000} s exceeds the retry grace "
                       f"period ({m.group(2)} s)", "warn")
        elif code == "RESTORE_OK":
            self._step(rst.steps, ts, "connected", "Tunnel restored", "ok")
            self._end_restore(ts, "connected", "")
        elif code == "RESTORE_DONE":
            self._step(rst.steps, ts, "restore", "Log: tunnel retry done, failed retry",
                       "error" if rst.retries else "warn")
            self._end_restore(ts, restore_outcome(rst.retries, rst.grace is not None), "")

    def _end_restore(self, ts: datetime, result: str, note: str) -> None:
        rst = self.restore
        self.restore = None
        if rst is None:
            return
        base = self.last_connected
        att = Attempt(KIND_RESTORE, rst.start, sources=[SRC_EVENT])
        att.trigger = "restore"
        att.end = ts if result != "abandoned" else rst.start
        att.outcome = result
        if base is not None:
            att.portal, att.user, att.protocol = base.portal, base.user, base.protocol
            att.gateway = base.gateway or rst.short
            att.tunnel_ip = base.tunnel_ip
        else:
            att.gateway = rst.short
        att.details["gateway_short"] = rst.short
        att.details["cause"] = rst.cause or "unknown"
        att.details["retries"] = rst.retries
        att.details["modern_standby"] = rst.slept
        if rst.downtime_ms is not None:
            att.details["downtime_at_start_ms"] = rst.downtime_ms
        if rst.grace:
            att.details["grace_exceeded"] = {"downtime_ms": rst.grace[0], "grace_s": rst.grace[1]}
        if rst.grace:
            att.details["downtime_ms"] = rst.grace[0]
        elif rst.downtime_ms is not None:
            att.details["downtime_ms"] = rst.downtime_ms
        if result in ("failed", "expired"):
            if result == "failed" and rst.errors:
                att.set_error(rst.errors[-1], "restore")
            elif rst.grace:
                att.set_error(f"Tunnel downtime ({rst.grace[0]} milliseconds) exceeds retry "
                              f"grace period ({rst.grace[1]} seconds)", "restore")
            else:
                att.set_error("Tunnel retry done: failed retry", "restore")
        elif result == "abandoned" and note:
            att.details["abandon_reason"] = note
        att.steps = rst.steps
        self.attempts.append(att)
        if self.last_down and self.last_down[2] is not None and \
                (rst.start - self.last_down[0]).total_seconds() <= 2:
            self.last_down[2]._next_restore = att
        if result == "connected":
            self.sess = _Session(att, ts)
            self.last_connected = att


# ---------------------------------------------------------------------------- service log
@dataclass
class _Detail:
    """An attempt seen in the verbose logs (PanGPS block chain and/or PanGPA click)."""

    kind: str
    start: datetime
    end: datetime | None = None
    outcome: str = ""             # connected | failed | cancelled | abandoned | expired | ""
    trigger: str = ""
    portal: str = ""
    gateway: str = ""
    user: str = ""
    protocol: str = ""
    tunnel_ip: str = ""
    error_raw: str = ""
    cycles: int = 1
    steps: list[Step] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    disconnect: dict | None = None
    details: dict = field(default_factory=dict)
    portal_outcome: str = ""      # outcome as seen by the service log
    ui_outcome: str = ""          # outcome as seen by the agent


_SVC_KEEP = re.compile(
    r"(?:msgtype = |----|--Set state to |ProcessServerPortal: sz|AgentProxyAutoStart|"
    r"Portal \S+, user |REGION-PRIO, region code|Portal authentication-message|"
    r"Portal auth method|Auth failed|portal status is |Portal config digest matched|"
    r"Restored cached portal|Connect method is|Force discovery|Discover external|"
    r"One external gateway|pretunnel latency|Auth message is|Using portal's user|"
    r"Gateway auth method|Actual user for gateway|Set preferred IP|Configured MTU|"
    r"Encryption method|Trying to do ipsec|Connected ipsec|tunnel to \S+ connected|"
    r"sent HIP report  to|Disconnect\(|Logging out gateway|logout: |User \S+ logs off|"
    r"Received (?:sleep|resume)|Wakeup from|Waked up|Wait in modern|Show Gateway|"
    r"Network changed|NetworkConnectionMonitorThread: route change|"
    r"Received network change event|Retry |Tunnel (?:downtime|retry)|Before ProcMonitor|"
    r"failed to receive keep alive|Unable to verify server cert|#+ Start PanGPS|"
    r"PanGPS service exits|Failed to create tunnel|failed to create tunnel)")

# (pattern, phase, level, text template with {0}.. groups)
_SVC_RULES = [
    (r"AgentProxyAutoStart: user clicked connect button", "trigger", "info",
     "Service received the user's Connect request"),
    (r"----Portal Pre-login starts----", "portal-prelogin", "info", "Portal pre-login starts"),
    (r"Portal (\S+), user (\S*), logonDomain", "portal-prelogin", "info",
     "Portal {0}, user {1}"),
    (r"REGION-PRIO, region code is (\S+)", "portal-prelogin", "info", "Region code {0}"),
    (r"Portal authentication-message is (.*)", "portal-prelogin", "info", "Portal prompt: {0}"),
    (r"Unable to verify server cert\. Result is (.*?)\s*$", "portal-prelogin", "info",
     "Certificate pre-check note (not an error): {0}"),
    (r"----Portal Login starts----", "portal-auth", "info", "Portal login starts"),
    (r"Portal auth method: (.*)$", "portal-auth", "info", "Portal authentication: {0}"),
    (r"Auth failed empty password for portal", "portal-auth", "warn",
     "Authentication with an empty password failed: credentials requested"),
    (r"Auth failed for portal", "portal-auth", "error", "Portal rejected the credentials"),
    (r"portal status is (.*?)\.?$", "portal-auth", "info", "Portal status: {0}"),
    (r"Restored cached portal config", "portal-auth", "info",
     "Cached portal configuration used"),
    (r"Connect method is (.*)$", "portal-auth", "info", "Connect method: {0}"),
    (r"----Network Discover starts----", "network-discovery", "info", "Network discovery starts"),
    (r"Discover external gateway: gateway count is (\d+)", "gateway-selection", "info",
     "External gateway count: {0}"),
    (r"One external gateway (\S+), priority=(\d+)", "gateway-selection", "info",
     "External gateway {0} found (priority {1})"),
    (r"pretunnel latency \(([^)]*)\) is (\d+)", "gateway-selection", "info",
     "Pre-tunnel latency to the gateway: {1} ms ({0})"),
    (r"----Gateway Pre-login starts----", "gateway-prelogin", "info", "Gateway pre-login starts"),
    (r"Auth message is (.*)", "gateway-prelogin", "info", "Gateway prompt: {0}"),
    (r"----Gateway Login starts----", "gateway-login", "info", "Gateway login starts"),
    (r"Using portal's user credential to login to gateway", "gateway-login", "info",
     "Gateway login reuses the portal credentials"),
    (r"Gateway auth method: (.*)$", "gateway-login", "info", "Gateway authentication: {0}"),
    (r"Actual user for gateway login is (\S+)", "gateway-login", "info",
     "Gateway login user: {0}"),
    (r"----Tunnel Creation starts----", "tunnel", "info", "Tunnel creation starts"),
    (r"Set preferred IP (\S+) for gateway", "tunnel", "info", "Preferred IP set: {0}"),
    (r"Configured MTU is (\d+)", "tunnel", "info", "MTU {0}"),
    (r"Encryption method is (\S+)", "tunnel", "info", "Encryption: {0}"),
    (r"Trying to do ipsec connection to", "tunnel", "info", "IPSec tunnel: connecting"),
    (r"Connected ipsec to", "tunnel", "ok", "IPSec tunnel established"),
    (r"tunnel to \S+ connected", "tunnel", "ok", "Tunnel is up"),
    (r"Failed to create tunnel|failed to create tunnel", "tunnel", "error",
     "Tunnel creation failed"),
    (r"sent HIP report  to", "hip", "info", "HIP report sent to the gateway"),
    (r"Disconnect\((.*)\) called", "disconnect", "info", "Disconnect requested (reason: {0})"),
    (r"Logging out gateway, reason is (User logs off)$", "disconnect", "info",
     "Logging out of the gateway (reason: {0})"),
    (r"logout: user=", "disconnect", "info", "Gateway logout sent"),
    (r"User \S+ logs off on session", "disconnect", "info", "Windows user logs off"),
    (r"Received sleep event", "restore", "warn", "System goes to sleep"),
    (r"Received resume(?:-auto)? event|Wakeup from modern standby|Waked up from modern standby",
     "restore", "info", "System wakes up"),
    (r"Wait in modern standy until wakeup", "restore", "warn",
     "Waiting in modern standby until wake-up"),
    (r"NetworkConnectionMonitorThread: route change detected", "restore", "info",
     "Network route change detected"),
    (r"Network changed, break from ProcMonitor", "restore", "warn", "Network changed: connection monitor interrupted"),
    (r"Show Gateway (.+?): Checking network availability", "restore", "info",
     "Restoring the tunnel to gateway {0} when the network is available"),
    (r"Received network change event during retry network checking", "restore", "info",
     "Network change during the retry check"),
    (r"failed to receive keep alive", "restore", "warn", "Keep-alive not received"),
    (r"Retry connect failed (\w+) time", "restore", "warn", "Retry failed ({0} time)"),
    (r"Retry start succeeded", "restore", "ok", "Retry succeeded"),
    (r"Retry finished SetupNetwork", "restore", "ok", "Network setup finished"),
    (r"Tunnel downtime \((\d+) milliseconds\) exceeds retry grace period \((\d+) seconds\)",
     "restore", "warn", "Tunnel downtime exceeds the retry grace period ({1} s)"),
    (r"Tunnel retry done: failed retry", "restore", "warn", "Log: tunnel retry done, failed retry"),
    (r"Before ProcMonitor quit, disconnect vpn", "disconnect", "info", "Disconnecting the VPN"),
]
_SVC_RULES = [(re.compile("^(?:" + p + ")"), ph, lv, tx) for p, ph, lv, tx in _SVC_RULES]
_SVC_STATE_PHASE = {
    "Retrieving configuration...": "portal-auth", "Discovering network...": "network-discovery",
    "Connecting...": "tunnel", "Connected": "connected", "Restoring VPN Connection": "restore",
    "Disconnecting...": "disconnect", "Disconnected": "disconnect",
    "OnDemand mode.": "disconnect", "User logs off": "disconnect",
}
_RE_STATE = re.compile(r"^--Set state to (.*?)\s*$")
_RE_PORTAL_USER = re.compile(r"^Portal (\S+), user (\S*), logonDomain")
_RE_GATEWAY = re.compile(r"^(?:One external gateway|Try to create tunnel with gateway) ([^\s,]+)")
_RE_SET_IP = re.compile(r"^Set preferred IP (\S+) for gateway")
_RE_SHOW_GW = re.compile(r"^Show Gateway (.+?): Checking network availability")
_RE_CACHE_ONLY = re.compile(r"^ProcessServerPortal: szCacheOnly: (\S+) bRetrieveCacheOnly: (\d)")
_RE_DOWNTIME = re.compile(r"^Tunnel downtime is (\d+) miliseconds")
_RE_GRACE = re.compile(r"^Tunnel downtime \((\d+) milliseconds\) exceeds retry grace period "
                       r"\((\d+) seconds\)")
_END_STATES = ("Disconnected", "OnDemand mode.", "User logs off")


class _Block:
    __slots__ = (
        "a",
        "b",
        "cache_only",
        "click",
        "end_ts",
        "kind",
        "msgtype",
        "pid",
        "progress",
        "result",
        "short",
        "ts",
    )

    def __init__(self, kind: str, a: int, ts: datetime, pid: int):
        self.kind, self.a, self.b, self.ts, self.pid = kind, a, a, ts, pid
        self.end_ts = ts
        self.msgtype = ""
        self.cache_only = False
        self.click = False
        self.progress = False
        self.result = ""        # connected | prompt | failed | ended | abandoned
        self.short = ""


def _svc_step(r: Record, source: str, login: bool = False) -> Step | None:
    m = r.msg
    if r.level == "Error" and not _CERT_NOTE.match(m):
        if _BENIGN_ERRORS.search(m):
            return None
        return Step(r.ts, "ui", _cap(f"Error-level record: {m}"), source, "warn")
    sm = _RE_STATE.match(m)
    if sm:
        st = sm.group(1)
        phase = _SVC_STATE_PHASE.get(st, "ui")
        if login and phase in ("disconnect", "restore"):
            phase = "ui"
        return Step(r.ts, phase, f"Client state: {st}", source,
                    "ok" if st == "Connected" else "info")
    for rx, phase, level, text in _SVC_RULES:
        mm = rx.match(m)
        if mm:
            if login and phase == "restore":
                return None
            groups = [(g or "").strip() for g in mm.groups()]
            return Step(r.ts, phase, _cap(text.format(*groups)), source, level)
    return None


def _scan_service(recs: list[Record], chain_gap_s: float, hip_window_s: float) -> list[_Detail]:
    """Segment the service log into kind A (portal login) chains and kind B (auto-restore)."""
    blocks: list[_Block] = []
    last_msgtype: dict = {}
    cur: _Block | None = None
    last_sleep: datetime | None = None
    n = len(recs)

    def close(blk: _Block | None, idx: int, ts: datetime, result: str) -> None:
        if blk is None:
            return
        blk.b, blk.end_ts, blk.result = idx, ts, result
        blocks.append(blk)

    for i, r in enumerate(recs):
        m = r.msg
        if cur is not None and r.pid != cur.pid:
            close(cur, i - 1, recs[i - 1].ts, "abandoned")
            cur = None
        if m.startswith("msgtype = "):
            last_msgtype[(r.pid, r.tid)] = (r.ts, m[10:].strip())
            continue
        if m.startswith("Received sleep event"):
            last_sleep = r.ts
        if m.startswith("----Portal Processing starts----"):
            close(cur, i - 1, recs[i - 1].ts, "abandoned")
            cur = _Block("A", i, r.ts, r.pid)
            mt = last_msgtype.get((r.pid, r.tid))
            if mt and 0 <= (r.ts - mt[0]).total_seconds() <= 0.1:
                cur.msgtype = mt[1]
            continue
        sg = _RE_SHOW_GW.match(m)
        if sg:
            close(cur, i - 1, recs[i - 1].ts, "abandoned")
            cur = _Block("B", i, r.ts, r.pid)
            cur.short = sg.group(1)
            cur.msgtype = "sleep" if (last_sleep and 0 <= (r.ts - last_sleep).total_seconds() <= 5) \
                else "network change"
            continue
        if cur is None:
            continue
        if cur.kind == "A":
            co = _RE_CACHE_ONLY.match(m)
            if co:
                cur.cache_only = co.group(1) == "yes" or co.group(2) == "1"
            elif m.startswith("AgentProxyAutoStart: user clicked connect button"):
                cur.click = True
            elif m.startswith(("portal status is ", "----Portal Login starts")):
                cur.progress = True
            sm = _RE_STATE.match(m)
            if sm:
                st = sm.group(1)
                if st == "Retrieving configuration...":
                    cur.progress = True
                if st == "Connected":
                    close(cur, i, r.ts, "connected")
                    cur = None
                elif st in _END_STATES and (cur.progress or cur.cache_only):
                    close(cur, i, r.ts, "ended")
                    cur = None
            elif m.startswith(("Disconnect(", "PanGPS service exits")):
                close(cur, i, r.ts, "ended")
                cur = None
        else:   # restore
            sm = _RE_STATE.match(m)
            if sm and sm.group(1) == "Connected":
                close(cur, i, r.ts, "connected")
                cur = None
            elif m.startswith("Tunnel retry done: failed retry"):
                j = i
                while j + 1 < n and (recs[j + 1].ts - r.ts).total_seconds() <= 2 and \
                        recs[j + 1].pid == r.pid:
                    j += 1
                    nm = _RE_STATE.match(recs[j].msg)
                    if nm and nm.group(1) == "Disconnected":
                        break
                close(cur, j, recs[j].ts, "failed")
                cur = None
            elif m.startswith("PanGPS service exits"):
                close(cur, i, r.ts, "abandoned")
                cur = None
    if cur is not None:
        close(cur, n - 1, recs[-1].ts, "abandoned")

    details: list[_Detail] = []
    pending: _Detail | None = None       # logical A attempt that ended at a credential prompt
    pending_block: _Block | None = None
    for blk in blocks:
        src_names = {recs[blk.a].src, recs[blk.b].src}
        if blk.kind == "B":
            d = _Detail(KIND_RESTORE, blk.ts, blk.end_ts, trigger="restore")
            d.sources.add(SRC_SERVICE)
            d.details["service_cause"] = blk.msgtype
            d.details["gateway_short"] = blk.short
            retries = 0
            standby = False
            last_err = ""
            lo = blk.a
            while lo > 0 and (blk.ts - recs[lo - 1].ts).total_seconds() <= 5 and \
                    recs[lo - 1].pid == blk.pid:
                lo -= 1
            for j in range(lo, blk.b + 1):
                rr = recs[j]
                if rr.msg.startswith("Retry connect failed"):
                    retries += 1
                if rr.msg.startswith("Wait in modern standy"):
                    standby = True
                if rr.level == "Error" and rr.msg.startswith("Failed to verify"):
                    last_err = rr.msg
                dm = _RE_DOWNTIME.match(rr.msg)
                if dm:
                    d.details["downtime_at_start_ms"] = int(dm.group(1))
                gm = _RE_GRACE.match(rr.msg)
                if gm:
                    d.details["grace_exceeded"] = {"downtime_ms": int(gm.group(1)),
                                                   "grace_s": int(gm.group(2))}
                st = _svc_step(rr, rr.src)
                if st is not None and st.phase in ("restore", "connected", "disconnect"):
                    d.steps.append(st)
            d.details["retries"] = retries
            d.details["modern_standby"] = standby
            d.outcome = {"connected": "connected", "failed": "failed"}.get(blk.result, "abandoned")
            if d.outcome == "failed":
                d.outcome = restore_outcome(retries, "grace_exceeded" in d.details)
            g0 = d.details.get("grace_exceeded")
            if g0:
                d.details["downtime_ms"] = g0["downtime_ms"]
            elif "downtime_at_start_ms" in d.details:
                d.details["downtime_ms"] = d.details["downtime_at_start_ms"]
            if d.outcome in ("failed", "expired"):
                g = d.details.get("grace_exceeded")
                if d.outcome == "failed" and last_err:
                    d.error_raw = last_err
                elif g:
                    d.error_raw = (f"Tunnel downtime ({g['downtime_ms']} milliseconds) exceeds "
                                   f"retry grace period ({g['grace_s']} seconds)")
                else:
                    d.error_raw = "Tunnel retry done: failed retry"
            details.append(d)
            continue
        # kind A
        if blk.cache_only:
            continue
        d = _block_detail(recs, blk, src_names)
        cont = (pending is not None and pending_block is not None
                and blk.msgtype == "user_credential"
                and (blk.ts - pending_block.end_ts).total_seconds() <= chain_gap_s)
        if cont:
            head = pending
            head.steps.extend(d.steps)
            head.end, head.cycles = d.end, head.cycles + 1
            head.portal = head.portal or d.portal
            head.user = d.user or head.user
            head.gateway = d.gateway or head.gateway
            head.protocol = d.protocol or head.protocol
            head.tunnel_ip = d.tunnel_ip or head.tunnel_ip
            head.portal_outcome = d.portal_outcome
            head.error_raw = d.error_raw or head.error_raw
            d = head
        else:
            details.append(d)
        pending, pending_block = (d, blk) if d.portal_outcome == "prompt" else (None, None)
    for d in details:
        if d.kind == KIND_LOGIN:
            d.outcome = {"connected": "connected", "failed": "failed"}.get(
                d.portal_outcome, "abandoned")
            if d.portal_outcome == "prompt":
                d.details["abandon_reason"] = "credential prompt not answered"
    _service_post(recs, details, hip_window_s)
    return details


def _block_detail(recs: list[Record], blk: _Block, src_names: set) -> _Detail:
    d = _Detail(KIND_LOGIN, blk.ts, blk.end_ts)
    d.sources.add(SRC_SERVICE)
    d.trigger = "user-click" if blk.click else "auto"
    d.details["request"] = blk.msgtype or "unknown"
    got_status = ""
    reached_gateway = False
    for j in range(blk.a, blk.b + 1):
        rr = recs[j]
        m = rr.msg
        pu = _RE_PORTAL_USER.match(m)
        if pu:
            d.portal, d.user = pu.group(1), pu.group(2)
        gw = _RE_GATEWAY.match(m)
        if gw:
            d.gateway = gw.group(1).rstrip(",")
        ip = _RE_SET_IP.match(m)
        if ip:
            d.tunnel_ip = ip.group(1)
        if m.startswith("Trying to do ipsec connection"):
            d.protocol = "IPSec"
        if m.startswith(("----Gateway Pre-login starts", "----Network Discover")):
            reached_gateway = True
        ps = re.match(r"^portal status is (.*?)\.?$", m)
        if ps:
            got_status = ps.group(1)
        if m.startswith("Auth failed empty password"):
            d.details["prompt"] = "credentials requested (no stored password)"
        st = _svc_step(rr, rr.src, login=True)
        if st is not None:
            d.steps.append(st)
    if blk.result == "connected":
        d.portal_outcome = "connected"
    elif got_status == "User authentication failed" and "prompt" in d.details:
        d.portal_outcome = "prompt"
    elif reached_gateway or got_status in ("Invalid portal", "Client Cert Required"):
        d.portal_outcome = "failed"
        if got_status:
            d.error_raw = d.error_raw or f"portal status is {got_status}."
    else:
        d.portal_outcome = "ended"
    return d


def _service_post(recs: list[Record], details: list[_Detail], hip_window_s: float) -> None:
    """HIP step after connect and the disconnect that ended the session (detail only)."""
    if not details:
        return
    times = [r.ts for r in recs]
    starts = sorted(d.start for d in details)
    for d in details:
        if d.outcome != "connected" or d.end is None:
            continue
        idx = bisect.bisect_left(times, d.end)
        nxt = starts[bisect.bisect_right(starts, d.start):]
        horizon = nxt[0] if nxt else None
        hip_done = False
        k = idx
        while k < len(recs):
            r = recs[k]
            k += 1
            if horizon is not None and r.ts >= horizon:
                break
            m = r.msg
            if not hip_done and m.startswith("sent HIP report  to") and \
                    (r.ts - d.end).total_seconds() <= hip_window_s:
                hip_done = True
                d.steps.append(Step(r.ts, "hip", "HIP report sent to the gateway", r.src, "info"))
            if m.startswith(("Disconnect(", "Network changed, break")) or \
                    m.startswith("User ") and "logs off on session" in m:
                reason = "network change" if m.startswith("Network changed") else (
                    "user logoff" if m.startswith("User ") else
                    (re.match(r"Disconnect\((.*)\)", m).group(1) or "disconnect").lower())
                d.disconnect = {"time": _iso(r.ts), "reason": reason,
                                "session_ms": _ms(d.end, r.ts), "by_user": None}
                d.steps.append(Step(r.ts, "disconnect", _cap(f"Session ended: {reason}"), r.src,
                                    "warn"))
                break


def _read_service(bundle, st: ParseStats) -> tuple[list[Record], list[str]]:
    names = bundle.rotation(SERVICE_STEM)
    recs: list[Record] = []
    used: list[str] = []
    for name in names:
        text = bundle.read_text(name, "timeline details")
        if not text:
            continue
        used.append(name)
        for r in iter_records(text, name, skip_levels={"Dump"}, stats=st):
            if r.level == "Error" or _SVC_KEEP.match(r.msg):
                recs.append(r)
    return recs, used


# ---------------------------------------------------------------------------- agent log
_AGENT_KEEP = re.compile(
    r"(?:User clicks connect|CPanBaseReceiver::HandleHello - sending portal|"
    r"Command = <request><type>|message type from the service = |"
    r"Dialog Status is going to change|Display the main panel when user attention|"
    r"User try to disconnect|To display error must show message|"
    r"WINHTTP_CALLBACK_STATUS_REQUEST_ERROR)")
_RE_DIALOG = re.compile(r"^Dialog Status is going to change from (.*?) to (.*?)\.\s*$")
_RE_CMD = re.compile(r"^Command = <request><type>([\w-]+)</type>")
_RE_SVCMSG = re.compile(r"^message type from the service = ([\w-]+)")
_RE_TAG = {t: re.compile(rf"<{t}>([^<]*)</{t}>")
           for t in ("state", "error", "protocol", "local-ip", "user-name", "portal")}
_RE_XML_USER = re.compile(r"<user>([^<]*)</user>")
_RE_XML_PORTAL = re.compile(r"<portal>([^<]*)</portal>")
_RE_XML_GATEWAY = re.compile(r"<gateway>([^<]*)</gateway>")
_RE_WINHTTP = re.compile(r"error=(0x[0-9a-fA-F]+)")


@dataclass
class _AgentEv:
    ts: datetime
    kind: str            # click hello cmd svc dialog popup error winhttp disc
    src: str
    a: str = ""
    b: str = ""
    c: str = ""
    d: str = ""
    e: str = ""
    f: str = ""


def _read_agent(bundle, st: ParseStats) -> tuple[list[_AgentEv], list[str]]:
    evs: list[_AgentEv] = []
    used: list[str] = []
    for name in bundle.rotation(AGENT_STEM):
        text = bundle.read_text(name, "timeline details")
        if not text:
            continue
        used.append(name)
        for r in iter_records(text, name, skip_levels={"Dump"}, stats=st):
            m = r.msg
            if r.level == "Error":
                if not _BENIGN_ERRORS.search(m):
                    evs.append(_AgentEv(r.ts, "error", name, _cap(m)))
                continue
            if not _AGENT_KEEP.match(m):
                continue
            if m.startswith("User clicks connect"):
                evs.append(_AgentEv(r.ts, "click", name))
            elif m.startswith("CPanBaseReceiver::HandleHello"):
                evs.append(_AgentEv(r.ts, "hello", name))
            elif m.startswith("Command = "):
                c = _RE_CMD.match(m)
                if c and c.group(1) != "pan_msg_ping":
                    u, p, g = (_RE_XML_USER.search(m), _RE_XML_PORTAL.search(m),
                               _RE_XML_GATEWAY.search(m))
                    evs.append(_AgentEv(r.ts, "cmd", name, c.group(1), u.group(1) if u else "",
                                        p.group(1) if p else "", g.group(1) if g else ""))
            elif m.startswith("message type from the service = "):
                t = _RE_SVCMSG.match(m)
                if not t or t.group(1) in ("https_request", "hip", "hello", "sleep"):
                    continue
                if t.group(1) == "status":
                    body = r.body
                    tags = {k: (rx.search(body).group(1).strip() if rx.search(body) else "")
                            for k, rx in _RE_TAG.items()}
                    evs.append(_AgentEv(r.ts, "svc", name, "status", tags["state"], tags["error"],
                                        tags["protocol"], tags["local-ip"],
                                        tags["user-name"] + "\t" + tags["portal"]))
                else:
                    evs.append(_AgentEv(r.ts, "svc", name, t.group(1)))
            elif m.startswith("Dialog Status"):
                d = _RE_DIALOG.match(m)
                if d:
                    evs.append(_AgentEv(r.ts, "dialog", name, d.group(1), d.group(2)))
            elif m.startswith(("Display the main panel", "To display error")):
                evs.append(_AgentEv(r.ts, "popup", name, _cap(m)))
            elif m.startswith("User try to disconnect"):
                evs.append(_AgentEv(r.ts, "disc", name))
            elif m.startswith("WINHTTP"):
                w = _RE_WINHTTP.search(m)
                evs.append(_AgentEv(r.ts, "winhttp", name, w.group(1) if w else ""))
    return evs, used


def _agent_step(ev: _AgentEv, state: dict) -> Step | None:
    """Step for an agent event; ``state`` remembers the last status text and error shown."""
    k = ev.kind
    if k == "click":
        return Step(ev.ts, "trigger", "User clicked Connect", ev.src, "info")
    if k == "cmd":
        text = {
            "portal": "Window sends the portal request",
            "user_credential": "User submitted the portal credentials",
            "invalid-gateway-credential": "User submitted the gateway credentials",
            "disconnect": "User requested a disconnect",
        }.get(ev.a)
        if text is None:
            return None
        phase = {"portal": "trigger", "user_credential": "portal-auth",
                 "invalid-gateway-credential": "gateway-login", "disconnect": "disconnect"}[ev.a]
        return Step(ev.ts, phase, text, ev.src, "info")
    if k == "svc":
        if ev.a == "user_credential":
            return Step(ev.ts, "portal-auth", "Credential prompt shown (portal)", ev.src, "warn")
        if ev.a == "invalid-gateway-credential":
            return Step(ev.ts, "gateway-login", "Credential prompt shown (gateway)", ev.src,
                        "warn")
        if ev.a == "status":
            if ev.c and ev.c != state.get("error"):
                state["error"] = ev.c
                return Step(ev.ts, "ui", _cap(f"Error shown to the user: {ev.c}"), ev.src, "error")
            if ev.b and ev.b != state.get("state"):
                state["state"] = ev.b
                return Step(ev.ts, _SVC_STATE_PHASE.get(ev.b, "ui"), f"Status shown: {ev.b}",
                            ev.src, "ok" if ev.b == "Connected" else "info")
        return None
    if k == "dialog":
        level = "ok" if ev.b == "Connected" else ("error" if ev.b == "Connection Failed" else "info")
        return Step(ev.ts, "ui", f"Dialog: {ev.a or '(none)'} -> {ev.b or '(none)'}", ev.src, level)
    if k == "popup":
        return Step(ev.ts, "ui", ev.a, ev.src, "warn")
    if k == "error":
        return Step(ev.ts, "ui", f"Error-level record: {ev.a}", ev.src, "warn")
    if k == "winhttp":
        return Step(ev.ts, "ui", f"HTTPS request error {ev.a}", ev.src, "warn")
    if k == "disc":
        return Step(ev.ts, "disconnect", "User asked to disconnect the tunnel", ev.src, "info")
    return None


def _scan_agent(evs: list[_AgentEv], chain_gap_s: float) -> list[_Detail]:
    """PanGPA segmentation: a click starts an attempt; the dialog result ends it."""
    out: list[_Detail] = []
    cur: _Detail | None = None
    state: dict = {}
    last = None

    def finish(d: _Detail, outcome: str, ts: datetime) -> None:
        d.ui_outcome, d.end = outcome, ts
        if outcome == "failed" and not d.error_raw:
            d.error_raw = state.get("error", "")
        out.append(d)

    for ev in evs:
        if cur is not None and last is not None and \
                (ev.ts - last).total_seconds() > chain_gap_s:
            finish(cur, "abandoned", last)
            cur = None
        if ev.kind == "click":
            if cur is not None:
                finish(cur, "abandoned", last or ev.ts)
            cur = _Detail(KIND_LOGIN, ev.ts, trigger="user-click")
            cur.sources.add(SRC_AGENT)
            cur.details["click_time"] = _iso(ev.ts)
            state = {}
            last = ev.ts
        if cur is None:
            continue
        last = ev.ts
        step = _agent_step(ev, state)
        if step is not None:
            cur.steps.append(step)
        if ev.kind == "cmd":
            if ev.a == "user_credential":
                cur.cycles += 1
            if ev.b:
                cur.user = cur.user or ev.b
            if ev.c:
                cur.portal = cur.portal or ev.c
            if ev.a == "disconnect":
                finish(cur, "cancelled", ev.ts)
                cur = None
        elif ev.kind == "svc" and ev.a == "status":
            cur.protocol = ev.d or cur.protocol
            cur.tunnel_ip = ev.e or cur.tunnel_ip
            user, _, portal = ev.f.partition("\t")
            cur.user = cur.user or user
            cur.portal = cur.portal or portal
        elif ev.kind == "disc":
            finish(cur, "cancelled", ev.ts)
            cur = None
        elif ev.kind == "dialog":
            if ev.a == "Connecting" and ev.b == "Connected":
                finish(cur, "connected", ev.ts)
                cur = None
            elif ev.b == "Connection Failed":
                finish(cur, "failed", ev.ts)
                cur = None
    if cur is not None:
        finish(cur, "abandoned", last or cur.start)
    return out


def _agent_restore_steps(evs: list[_AgentEv], times: list[datetime], start: datetime,
                         end: datetime) -> list[Step]:
    """PanGPA steps of an auto-restore window: status text, dialog changes, errors."""
    lo = bisect.bisect_left(times, start - timedelta(seconds=1))
    hi = bisect.bisect_right(times, end + timedelta(seconds=3))
    state: dict = {}
    steps: list[Step] = []
    for ev in evs[lo:hi]:
        if ev.kind in ("svc", "dialog", "popup", "error"):
            if ev.kind == "svc" and ev.a != "status":
                continue
            st = _agent_step(ev, state)
            if st is not None:
                steps.append(st)
    return steps


# ---------------------------------------------------------------------------- merging
def _nearest(starts: list[datetime], used: set, ts: datetime, tol: float) -> int:
    """Index of the unused start nearest to ``ts`` within ``tol`` seconds, or -1."""
    i = bisect.bisect_left(starts, ts)
    best, best_d = -1, None
    for j in (i - 1, i, i + 1, i - 2, i + 2):
        if 0 <= j < len(starts) and j not in used:
            dist = abs((starts[j] - ts).total_seconds())
            if dist <= tol and (best_d is None or dist < best_d):
                best, best_d = j, dist
    return best


def _merge_details(service: list[_Detail], agent: list[_Detail], tol: float) -> list[_Detail]:
    """Join the service chains and the agent clicks that describe the same login attempt."""
    logins = [d for d in service if d.kind == KIND_LOGIN]
    others = [d for d in service if d.kind != KIND_LOGIN]
    starts = [d.start for d in logins]
    used: set = set()
    out: list[_Detail] = list(others)
    for ag in sorted(agent, key=lambda d: d.start):
        j = _nearest(starts, used, ag.start, tol)
        if j < 0:
            out.append(ag)
            continue
        used.add(j)
        sd = logins[j]
        sd.steps.extend(ag.steps)
        sd.sources |= ag.sources
        sd.ui_outcome = ag.ui_outcome
        sd.trigger = "user-click"
        sd.details["click_time"] = ag.details.get("click_time")
        sd.start = min(sd.start, ag.start)
        sd.portal = sd.portal or ag.portal
        sd.user = sd.user or ag.user
        sd.protocol = ag.protocol or sd.protocol
        sd.tunnel_ip = ag.tunnel_ip or sd.tunnel_ip
        sd.error_raw = ag.error_raw or sd.error_raw
        sd.cycles = max(sd.cycles, ag.cycles)
        ends = [x for x in (sd.end, ag.end) if x is not None]
        sd.end = max(ends) if ends else None
    out.extend(logins)
    for d in out:
        if d.kind != KIND_LOGIN:
            continue
        if d.ui_outcome in ("connected", "failed", "cancelled"):
            d.outcome = d.ui_outcome
        else:
            d.outcome = d.outcome or "abandoned"
    return sorted(out, key=lambda d: d.start)


def _attach(att: Attempt, d: _Detail) -> None:
    """Fold a detailed-log attempt into an event-log attempt (event log stays authoritative)."""
    att.sources.extend(s for s in sorted(d.sources) if s not in att.sources)
    att.steps.extend(d.steps)
    att.portal = att.portal or d.portal
    att.user = att.user or d.user
    att.gateway = att.gateway or d.gateway
    att.protocol = att.protocol or d.protocol
    att.tunnel_ip = att.tunnel_ip or d.tunnel_ip
    if att.kind == KIND_LOGIN:
        if d.trigger == "user-click" or (d.trigger == "auto" and att.trigger == "unknown"):
            att.trigger = d.trigger
        if d.disconnect and att.disconnect is None:
            att.disconnect = d.disconnect
        if d.outcome in ("connected", "failed", "cancelled") and d.outcome != att.outcome:
            att.details["outcome_mismatch"] = {"detail_log": d.outcome, "event_log": att.outcome}
        if d.cycles > att.cycles:
            att.details["detail_cycles"] = d.cycles
        if d.error_raw and not att.error_text and att.outcome == "failed":
            att.set_error(d.error_raw)
    for k, v in d.details.items():
        att.details.setdefault(k, v)


def _from_detail(d: _Detail) -> Attempt:
    att = Attempt(d.kind, d.start, d.end, d.outcome or "abandoned")
    att.sources = sorted(d.sources, key=_SRC_ORDER.index)
    att.portal, att.gateway, att.user = d.portal, d.gateway, d.user
    att.protocol, att.tunnel_ip, att.cycles = d.protocol, d.tunnel_ip, d.cycles
    att.trigger = d.trigger or ("restore" if d.kind == KIND_RESTORE else "unknown")
    att.steps = list(d.steps)
    att.disconnect = d.disconnect
    att.details = dict(d.details)
    if d.kind == KIND_RESTORE:
        att.details.setdefault("cause", att.details.get("service_cause", "unknown"))
    if att.outcome in ("failed", "expired"):
        att.set_error(d.error_raw or "attempt failed")
    if att.outcome == "cancelled" and att.kind == KIND_LOGIN:
        att.details.setdefault("cancel_evidence", "inferred")
    return att


# ---------------------------------------------------------------------------- aggregates
def _count(attempts: list[Attempt]) -> dict:
    out = {o: 0 for o in OUTCOMES}
    for a in attempts:
        out[a.outcome] += 1
    return out


def _find_storms(attempts: list[Attempt], min_failures: int, max_gap_s: float) -> list[dict]:
    fails = [a for a in attempts if a.kind == KIND_LOGIN and a.outcome == "failed"]
    groups: list[list[Attempt]] = []
    for a in fails:
        if groups and (a.start - groups[-1][-1].start).total_seconds() <= max_gap_s:
            groups[-1].append(a)
        else:
            groups.append([a])
    storms = []
    for g in groups:
        if len(g) < min_failures:
            continue
        sid = len(storms) + 1
        for a in g:
            a.storm = sid
        gaps = sorted(_ms(x.start, y.start) for x, y in zip(g, g[1:]))
        by_err: dict = {}
        for a in g:
            by_err[a.error_text or "(no error text)"] = by_err.get(a.error_text or "(no error text)",
                                                                  0) + 1
        storms.append({"id": sid, "start": _iso(g[0].start), "end": _iso(g[-1].end or g[-1].start),
                       "count": len(g), "median_interval_ms": gaps[len(gaps) // 2],
                       "first_attempt": g[0].id, "last_attempt": g[-1].id, "by_error": by_err})
    return storms


def _summary(attempts: list[Attempt], top_n: int) -> dict:
    by_kind = {k: _count([a for a in attempts if a.kind == k]) for k in (KIND_LOGIN, KIND_RESTORE)}
    days: dict = {}
    for a in attempts:
        day = days.setdefault(a.start.date().isoformat(),
                              {k: {o: 0 for o in OUTCOMES} for k in (KIND_LOGIN, KIND_RESTORE)})
        day[a.kind][a.outcome] += 1
    errs: dict = {}
    for a in attempts:
        if not a.error_text:
            continue
        e = errs.setdefault(a.error_text, {"text": a.error_text, "count": 0, "first": a.start,
                                           "last": a.start, "kinds": set(), "raw_example": a.error_raw})
        e["count"] += 1
        e["first"] = min(e["first"], a.start)
        e["last"] = max(e["last"], a.start)
        e["kinds"].add(a.kind)
    top = sorted(errs.values(), key=lambda e: (-e["count"], e["text"]))[:top_n]
    rest = [a for a in attempts if a.storm is None]
    return {
        "total": len(attempts), "by_outcome": _count(attempts), "by_kind": by_kind,
        "per_day": [{"date": d, **days[d]} for d in sorted(days)],
        "top_errors": [{"text": e["text"], "count": e["count"], "first": _iso(e["first"]),
                        "last": _iso(e["last"]), "kind": sorted(e["kinds"]),
                        "raw_example": e["raw_example"]} for e in top],
        "with_detail": sum(1 for a in attempts if a.has_detail),
        "excluding_storms": {"total": len(rest), "by_outcome": _count(rest)},
    }


def _coverage_of(names: list[str], st: ParseStats) -> dict | None:
    if not names:
        return None
    return {"files": names, "first": _iso(st.first), "last": _iso(st.last),
            "records": st.records}


# ---------------------------------------------------------------------------- entry point
def build_timeline(bundle, *, chain_gap_s: float = CHAIN_GAP_S, match_tol_s: float = MATCH_TOL_S,
                   max_text: int = MAX_TEXT, storm_min_failures: int = STORM_MIN_FAILURES,
                   storm_max_gap_s: float = STORM_MAX_GAP_S, top_errors: int = TOP_ERRORS,
                   sso_window_s: float = SSO_WINDOW_S, error_tail_s: float = ERROR_TAIL_S,
                   hip_window_s: float = HIP_WINDOW_S, settle_s: float = SETTLE_S) -> Timeline:
    """Build the timeline of a ``gp.bundle.Bundle`` (see the module docstring)."""
    return _build(bundle, chain_gap_s, match_tol_s, max_text, storm_min_failures,
                  storm_max_gap_s, top_errors, sso_window_s, error_tail_s, hip_window_s, settle_s)


def _near(times: list[datetime], ts: datetime, tol: float) -> bool:
    i = bisect.bisect_left(times, ts - timedelta(seconds=tol))
    return i < len(times) and times[i] <= ts + timedelta(seconds=tol)


def _tidy(steps: list[Step]) -> list[Step]:
    """Drop the steps that a more detailed source already says (same phase, about same time).

    Event-log steps of level info/ok that the service log repeats, and agent ``Status shown``
    steps that the service log's ``Client state`` repeats. Warnings and errors are always kept.
    """
    svc_phase: dict = {}
    svc_state: dict = {}
    for st in steps:
        if st.source.startswith(SERVICE_STEM):
            svc_phase.setdefault(st.phase, []).append(st.ts)
            if st.text.startswith("Client state: "):
                svc_state.setdefault(st.text[14:], []).append(st.ts)
    for lst in list(svc_phase.values()) + list(svc_state.values()):
        lst.sort()
    out = []
    for st in steps:
        if st.source.startswith(EVENT_STEM) and st.level in ("info", "ok") and \
                _near(svc_phase.get(st.phase, []), st.ts, 1.5):
            continue
        if st.source.startswith(AGENT_STEM) and st.text.startswith("Status shown: ") and \
                _near(svc_state.get(st.text[14:], []), st.ts, 2.0):
            continue
        out.append(st)
    return out


def _apply_text_cap(attempts: list[Attempt], limit: int) -> None:
    for a in attempts:
        a.error_raw, a.error_text = _cap(a.error_raw, limit), _cap(a.error_text, limit)
        for s in a.steps + a._post:
            s.text = _cap(s.text, limit)


def _build(bundle, chain_gap_s, match_tol_s, max_text, storm_min, storm_gap_s, top_n,
           sso_window_s, error_tail_s, hip_window_s, settle_s) -> Timeline:
    params = {"chain_gap_s": chain_gap_s, "match_tol_s": match_tol_s, "max_text": max_text,
              "storm_min_failures": storm_min, "storm_max_gap_s": storm_gap_s,
              "sso_window_s": sso_window_s, "hip_window_s": hip_window_s,
              "error_tail_s": error_tail_s, "settle_s": settle_s}
    limitations: list[str] = []

    # ---- event log
    ev_names = bundle.rotation(EVENT_STEM)
    ev_stats = ParseStats()
    engine = _EventEngine(chain_gap_s, sso_window_s, error_tail_s, hip_window_s,
                          settle_s)
    used_ev: list[str] = []
    for name in ev_names:
        text = bundle.read_text(name, "timeline")
        if not text:
            continue
        used_ev.append(name)
        for line in iter_event_log(text, name, ev_stats):
            engine.feed(line)
    attempts: list[Attempt] = engine.finish()

    # ---- detailed logs
    svc_stats, agent_stats = ParseStats(), ParseStats()
    svc_recs, used_svc = _read_service(bundle, svc_stats)
    agent_evs, used_agent = _read_agent(bundle, agent_stats)
    svc_details = _scan_service(svc_recs, chain_gap_s, hip_window_s) if svc_recs else []
    agent_details = _scan_agent(agent_evs, chain_gap_s) if agent_evs else []
    details = _merge_details(svc_details, agent_details, match_tol_s)

    # ---- match detailed attempts to event-log attempts
    cross = {"matched": 0, "outcome_agree": 0, "outcome_differ": [], "detail_only": 0,
             "event_only_in_detail_window": 0}
    by_kind = {k: sorted((a for a in attempts if a.kind == k), key=lambda a: a.start)
               for k in (KIND_LOGIN, KIND_RESTORE)}
    used: dict = {KIND_LOGIN: set(), KIND_RESTORE: set()}
    starts = {k: [a.start for a in v] for k, v in by_kind.items()}
    new: list[Attempt] = []
    ev_last = ev_stats.last
    for d in details:
        j = _nearest(starts[d.kind], used[d.kind], d.start, match_tol_s) \
            if by_kind[d.kind] else -1
        if j >= 0:
            used[d.kind].add(j)
            att = by_kind[d.kind][j]
            _attach(att, d)
            cross["matched"] += 1
            if "outcome_mismatch" in att.details:
                cross["outcome_differ"].append(att)
            else:
                cross["outcome_agree"] += 1
        else:
            new.append(_from_detail(d))
            cross["detail_only"] += 1
    attempts.extend(new)

    # ---- agent window steps of auto-restores
    if agent_evs:
        times = [e.ts for e in agent_evs]
        a_first, a_last = times[0], times[-1]
        for a in attempts:
            if a.kind != KIND_RESTORE or not (a_first <= a.start <= a_last):
                continue
            steps = _agent_restore_steps(agent_evs, times, a.start, a.end or a.start)
            if steps:
                a.steps.extend(steps)
                if SRC_AGENT not in a.sources:
                    a.sources.append(SRC_AGENT)

    for a in attempts:
        if a.has_detail:
            a.steps = a.steps + a._post
            if SRC_SERVICE in a.sources:
                a.steps = _tidy(a.steps)
        a._post = []
    _apply_text_cap(attempts, max_text)
    attempts.sort(key=lambda a: (a.start, a.kind))
    for i, a in enumerate(attempts, 1):
        a.id = f"a{i:04d}"
    cross["outcome_differ"] = [a.id for a in cross["outcome_differ"]]

    # ---- coverage
    detail_first = [t for t in (svc_stats.first, agent_stats.first) if t]
    detail_last = [t for t in (svc_stats.last, agent_stats.last) if t]
    window = None
    if detail_first:
        window = {"first": _iso(min(detail_first)), "last": _iso(max(detail_last))}
        lo, hi = min(detail_first), max(detail_last)
        cross["event_only_in_detail_window"] = sum(
            1 for a in attempts if a.sources == [SRC_EVENT] and lo <= a.start <= hi)
    ends_before = None
    if ev_last and detail_last and max(detail_last) > ev_last:
        ends_before = round((max(detail_last) - ev_last).total_seconds(), 1)
        limitations.append("The event log ends before the detailed logs: attempts after it come "
                           "from PanGPS/PanGPA only.")
    if not used_ev:
        limitations.append("No event log: attempts and restores come from the detailed logs only.")
    if used_ev and (used_svc or used_agent):
        limitations.append("Steps exist only where PanGPS/PanGPA overlap the attempt.")
    if used_ev:
        rest = [a for a in attempts if a.kind == KIND_RESTORE and SRC_EVENT in a.sources]
        restores = {"source": "event_log",
                    "first": _iso(rest[0].start) if rest else None,
                    "last": _iso(rest[-1].start) if rest else None,
                    "note": "restores come from the event log for its whole history; after its "
                            "end only from the service log (PanGPS)"}
    else:
        rest = [a for a in attempts if a.kind == KIND_RESTORE]
        restores = {"source": "service_log", "first": _iso(rest[0].start) if rest else None,
                    "last": _iso(rest[-1].start) if rest else None,
                    "note": "restores are visible only inside the service-log window"}
        if used_svc:
            limitations.append("Auto-restores are limited to the PanGPS window (no event log).")
    coverage = {
        "event_log": _coverage_of(used_ev, ev_stats),
        "service_log": _coverage_of(used_svc, svc_stats),
        "agent_log": _coverage_of(used_agent, agent_stats),
        "detail_window": window, "event_log_ends_before_detail_s": ends_before,
        "restores": restores, "crosscheck": cross, "limitations": limitations,
    }

    storms = _find_storms(attempts, storm_min, storm_gap_s)
    return Timeline(attempts, _summary(attempts, top_n), storms, coverage, params)

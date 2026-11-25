"""Command catalogue and allow-list of the runtime analyzer.

The capture can only send the commands listed here (plus ``show session id <n>`` with a numeric
id). There is no way to pass a free-form command from the command line. Every command is
read-only except the inflight monitoring toggle.
"""
from __future__ import annotations

import re

SETUP_CLI = ("set cli pager off", "set cli terminal width 500")

SYSTEM_INFO = "show system info"
CLOCK = "show clock"
MGMT_LOAD = "show system resources | match load"
SESSION_INFO = "show session info"
RESMON = "show running resource-monitor"
POW = "debug dataplane pow performance"
POW_ALL = "debug dataplane pow performance all"
DELTA = "show counter global filter delta yes"
BACKLOG = "show running resource-monitor ingress-backlogs"
PBP = "show session packet-buffer-protection"
PBP_LAT = "show session packet-buffer-protection buffer-latency"
PBP_ZONES = "show session packet-buffer-protection zones"
IFACE_COUNTERS = "show counter interface all"

INFLIGHT_ON = "set session inflight_monitoring yes"
INFLIGHT_OFF = "set session inflight_monitoring no"
INFLIGHT_STATE = "show session inflight_monitoring status"
BACKLOG_THRESHOLD = "show session ingress_backlogs_threshold"
BACKLOG_DURATION = "show session ingress_backlogs_duration"
BACKLOG_TRIGGER = "show session ingress_backlogs_trigger status"

SESSION_ID_RE = re.compile(r"^show session id \d{1,12}$")
# Paged dump of the whole session table: ``start-at`` takes 1-2097152 and shows the next 1K sessions.
SESSIONS_ALL_RE = re.compile(r"^show session all start-at \d{1,7}$")
SESSIONS_ALL_MAX_START = 2097152
SESSIONS_ALL_PAGE = 1024


def sessions_all_cmd(start: int) -> str:
    """``show session all start-at <start>`` (start must be 1-2097152)."""
    if not 1 <= start <= SESSIONS_ALL_MAX_START:
        raise ValueError(f"start-at out of range 1-{SESSIONS_ALL_MAX_START}: {start}")
    return f"show session all start-at {start}"


# command -> file slug (one raw file per slug)
SLUGS = {
    SYSTEM_INFO: "system_info",
    CLOCK: "clock",
    MGMT_LOAD: "mgmt_load",
    SESSION_INFO: "session_info",
    RESMON: "resource_monitor",
    POW: "pow",
    POW_ALL: "pow_all",
    DELTA: "delta",
    BACKLOG: "ingress_backlogs",
    PBP: "pbp",
    PBP_LAT: "pbp_latency",
    PBP_ZONES: "state_pbp_zones",
    IFACE_COUNTERS: "iface_counters",
    INFLIGHT_ON: "inflight_set",
    INFLIGHT_OFF: "inflight_set",
    INFLIGHT_STATE: "state_inflight",
    BACKLOG_THRESHOLD: "state_backlogs_threshold",
    BACKLOG_DURATION: "state_backlogs_duration",
    BACKLOG_TRIGGER: "state_backlogs_trigger",
}
SLUG_SESSION_ID = "session_id"
SLUG_SESSIONS_ALL = "sessions_all"

ALLOWED = frozenset(SETUP_CLI) | frozenset(SLUGS)


def _sessions_all_ok(cmd: str) -> bool:
    return bool(SESSIONS_ALL_RE.match(cmd)) and \
        1 <= int(cmd.rsplit(" ", 1)[1]) <= SESSIONS_ALL_MAX_START


def check_allowed(cmd: str) -> None:
    """Raises ValueError for any command outside the allow-list."""
    if cmd not in ALLOWED and not SESSION_ID_RE.match(cmd) and not _sessions_all_ok(cmd):
        raise ValueError(f"command not in the allow-list: {cmd!r}")


def slug_for(cmd: str) -> str:
    """File slug of an allowed command."""
    check_allowed(cmd)
    if SESSION_ID_RE.match(cmd):
        return SLUG_SESSION_ID
    if SESSIONS_ALL_RE.match(cmd):
        return SLUG_SESSIONS_ALL
    return SLUGS[cmd]

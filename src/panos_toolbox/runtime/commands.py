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

INFLIGHT_ON = "set session inflight_monitoring yes"
INFLIGHT_OFF = "set session inflight_monitoring no"
INFLIGHT_STATE = "show session inflight_monitoring status"
BACKLOG_THRESHOLD = "show session ingress_backlogs_threshold"
BACKLOG_DURATION = "show session ingress_backlogs_duration"
BACKLOG_TRIGGER = "show session ingress_backlogs_trigger status"

SESSION_ID_RE = re.compile(r"^show session id \d{1,12}$")

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
    INFLIGHT_ON: "inflight_set",
    INFLIGHT_OFF: "inflight_set",
    INFLIGHT_STATE: "state_inflight",
    BACKLOG_THRESHOLD: "state_backlogs_threshold",
    BACKLOG_DURATION: "state_backlogs_duration",
    BACKLOG_TRIGGER: "state_backlogs_trigger",
}
SLUG_SESSION_ID = "session_id"

ALLOWED = frozenset(SETUP_CLI) | frozenset(SLUGS)


def check_allowed(cmd: str) -> None:
    """Raises ValueError for any command outside the allow-list."""
    if cmd not in ALLOWED and not SESSION_ID_RE.match(cmd):
        raise ValueError(f"command not in the allow-list: {cmd!r}")


def slug_for(cmd: str) -> str:
    """File slug of an allowed command."""
    check_allowed(cmd)
    if SESSION_ID_RE.match(cmd):
        return SLUG_SESSION_ID
    return SLUGS[cmd]

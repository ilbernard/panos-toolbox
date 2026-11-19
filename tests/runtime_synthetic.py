"""Builds a synthetic capture folder through the real capture engine (FakeTransport).

Everything is invented: no real firewall output is used. ``scenario`` switches on the
interesting cases (offender, special tag, packet buffer protection active, drop counters, ...).
"""
from __future__ import annotations

from test_runtime_parse_pbp import EXTENDED, LATENCY, SHORT
from test_runtime_parse_resmon import _build as resmon_text

from panos_toolbox.runtime import commands as C
from panos_toolbox.runtime.capture import Capture, CaptureConfig
from panos_toolbox.runtime.fake import FakeTransport, SimClock
from panos_toolbox.runtime.store import CaptureWriter

BACKLOG_NONE = "-- SLOT: s1, DP: dp0 --\nUSAGE - ATOMIC: 5.5% TOTAL: 10.25%\n"
BACKLOG_OFFENDER = (
    "-- SLOT: s1, DP: dp0 --\nUSAGE - ATOMIC: 80.5% TOTAL: 95.25%\n\nTOP SESSIONS:\n"
    "SESS-ID PCT GRP-ID COUNT\n4711 80% 1 874\n\nSESSION DETAILS\n")
BACKLOG_SPECIAL = (
    "-- SLOT: s1, DP: dp0 --\nUSAGE - ATOMIC: 50.0% TOTAL: 72.0%\n\nTOP SESSIONS:\n"
    "SESS-ID PCT GRP-ID COUNT Special Notes\n"
    "2149580803 23% pktlog_forwarding 242 Special TAG values, NOT valid session id\n")
SYSTEM_INFO = "hostname: lab-fw\nmodel: PA-DEMO\nsw-version: 11.2.0\nfamily: vm\nuptime: 1 days\n"
HDR = "max-us avg-us count total-us ac-max-us ac-avg-us ac-count ac-total-us"


def session_info(n, util_alloc=250000, cps=7):
    return (f"Number of sessions supported: 1000000\nNumber of allocated sessions: {util_alloc}\n"
            f"Number of active TCP sessions: {100 + n}\nNumber of active UDP sessions: 200\n"
            f"Number of active ICMP sessions: 3\nSession table utilization: 25%\n"
            f"Packet rate: {1000 + n}/s\nThroughput: 2000 kbps\n"
            f"New connection establish rate: {cps} cps\n")


def pow_text(n):
    base = 1_000_000 * n
    lines = ["group " + HDR]
    lines.append(f"flow_fastpath 900 12.0 {1000 * n} {12000 * n} 5000 11.0 {base} {11 * base}")
    lines.append(f"flow_slowpath 100 40.0 {10 * n} {400 * n} 4000 30.0 {base // 10} {3 * base}")
    lines += ["", "func " + HDR,
              f"dfa_match 120 4.0 {500 * n} {2000 * n} 5000 3.6 {base * 3} {base * 11}",
              f"aho_scan 60 2.0 {300 * n} {600 * n} 900 2.1 {base} {base * 2}"]
    return "\n".join(lines) + "\n"


def delta_text(n, drop_rate=0, elapsed=30.0):
    rows = ["pkt_demo_recv                  1000      200 info      packet    pktproc   Packets in",
            (f"flow_demo_drop {drop_rate * 30:>14} {drop_rate:>8} drop      flow      parse     "
            "Packets dropped: demo reason")]
    if n == 2:
        rows.append("late_demo_counter                  5        1 warn      ctd       session   Appears late")
    dash = "-" * 80
    return (f"Global counters:\nElapsed time since last sampling: {elapsed:6.3f} seconds\n\n"
            "name value rate severity category aspect description\n" + dash + "\n"
            + "\n".join(rows) + f"\n{dash}\nTotal counters shown: {len(rows)}\n{dash}\n")


def build_capture(root, scenario=(), interval=30, duration=95, clock=None):
    """Runs a capture on a FakeTransport and returns the capture folder path."""
    clock = clock or SimClock()
    calls = {}

    def counter(cmd):
        calls[cmd] = calls.get(cmd, 0) + 1
        return calls[cmd]

    def backlog(cmd):
        counter(cmd)
        if "offender" in scenario:
            return BACKLOG_OFFENDER if calls[cmd] >= 3 else BACKLOG_NONE
        if "special" in scenario:
            return BACKLOG_SPECIAL
        return BACKLOG_NONE

    def delta(cmd):
        n = counter(cmd)
        return delta_text(n, drop_rate=1500 if "drops" in scenario else 0,
                          elapsed=17.4 if ("foreign" in scenario and n == 2) else 30.0)

    state = {"inflight": "no"}
    responses = {
        C.SYSTEM_INFO: SYSTEM_INFO,
        C.CLOCK: "Thu Jan  1 00:00:00 UTC 2026\n",
        C.MGMT_LOAD: lambda c: f"top - 00:00:00 up 1 day, load average: {counter(c)}.50, 1.00, 1.00\n",
        C.SESSION_INFO: lambda c: session_info(
            counter(c), util_alloc=950000 if "sessions" in scenario else 250000,
            cps=9000 if ("cps" in scenario and calls[c] == 2) else 7),
        C.RESMON: lambda c: (counter(c), resmon_text())[1],
        C.POW: lambda c: pow_text(counter(c)),
        C.DELTA: delta,
        C.BACKLOG: backlog if "no-backlog" not in scenario else "Invalid syntax.\n",
        C.PBP: (EXTENDED if "pbp-active" in scenario else SHORT),
        C.PBP_LAT: LATENCY,
        C.PBP_ZONES: "zone1\n",
        C.BACKLOG_THRESHOLD: "80\n",
        C.BACKLOG_DURATION: "3\n",
        C.BACKLOG_TRIGGER: "Invalid syntax.\n",
        C.INFLIGHT_STATE: lambda c: f"Inflight monitoring: {state['inflight']}\n",
        C.INFLIGHT_ON: lambda c: state.__setitem__("inflight", "yes") or "\n",
        C.INFLIGHT_OFF: lambda c: state.__setitem__("inflight", "no") or "\n",
        "show session id 4711": "Session 4711\n  c2s flow: source: 10.0.0.1 [trust]\n",
    }
    tr = FakeTransport(responses, clock)
    # the allow-list accepts any numeric id: register the fixed answer for the demo offender
    root.mkdir(parents=True, exist_ok=True)
    writer = CaptureWriter(root / "cap")
    cap = Capture(tr, writer, CaptureConfig(interval=interval, duration=duration), clock=clock,
                  reconnect=lambda: tr, out=lambda s: None)
    cap.execute()
    writer.close()
    return root / "cap"

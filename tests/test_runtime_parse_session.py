"""Tests for the ``show session info`` and management load parsers (synthetic data)."""

from __future__ import annotations

from panos_toolbox.runtime.parse_session import parse_mgmt_load, parse_session_info

SESSION = """
target-dp:                                       *.dp0
--------------------------------------------------------------------------------
Number of sessions supported:                    1000000
Number of allocated sessions:                    250000
Number of active TCP sessions:                   100
Number of active UDP sessions:                   200
Number of active ICMP sessions:                  3
Number of active GTPc sessions:                  0
Session table utilization:                       25%
Number of sessions created since bootup:         123456
Packet rate:                                     1000/s
Throughput:                                      2000 kbps
New connection establish rate:                   7 cps
--------------------------------------------------------------------------------
Session timeout
  TCP default timeout:                           3600 secs
"""


def test_session_normal():
    r = parse_session_info(SESSION)
    assert r["ok"] is True
    assert (r["supported"], r["allocated"]) == (1000000, 250000)
    assert (r["active_tcp"], r["active_udp"], r["active_icmp"]) == (100, 200, 3)
    assert r["utilization_reported_pct"] == 25
    assert r["utilization_pct"] == 25.0
    assert (r["pps"], r["kbps"], r["cps"]) == (1000, 2000, 7)
    assert r["created_since_boot"] == 123456


def test_session_utilization_rounding():
    r = parse_session_info("Number of sessions supported:   3\nNumber of allocated sessions:   1\n")
    assert r["utilization_pct"] == 33.33
    assert r["active_tcp"] is None and r["pps"] is None


def test_session_zero_supported_no_division():
    r = parse_session_info("Number of sessions supported: 0\nNumber of allocated sessions: 5\n")
    assert r["utilization_pct"] is None


def test_session_empty_and_garbage():
    for bad in ("", "\n\n", "garbage: nope\n", None):
        r = parse_session_info(bad)  # type: ignore[arg-type]
        assert r["ok"] is False
        assert r["supported"] is None and r["utilization_pct"] is None


def test_mgmt_load():
    r = parse_mgmt_load(
        "\ntop - 10:00:00 up 20 days,  2:53,  1 user,  load average: 3.50, 2.18, 2.07\n"
    )
    assert r == {"ok": True, "load1": 3.5, "load5": 2.18, "load15": 2.07}


def test_mgmt_load_garbage():
    for bad in ("", "nothing here", None):
        r = parse_mgmt_load(bad)  # type: ignore[arg-type]
        assert r == {"ok": False, "load1": None, "load5": None, "load15": None}

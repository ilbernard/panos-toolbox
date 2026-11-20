from __future__ import annotations

from panos_toolbox.runtime.parse_pbp import (
    is_unavailable,
    parse_pbp,
    parse_pbp_latency,
    parse_pbp_zones,
)

DASH = "-" * 60

SHORT = f"""
{DASH}
Packet buffer count based
Congestion: 5/1000 (0.5%)
System resource usage is low, packet buffer protection not activated.
{DASH}
"""

DEACT = f"""{DASH}
Packet buffer count based
Congestion: 600/1000 (60.0%)
Time to deactivate: 12.5
{DASH}
"""

EXTENDED = f"""{DASH}
Packet buffer count based
Congestion: 800/1000 (80.0%)
Drop probability: 10%. Percentage drop threshold: 3.
{DASH}
                   |          |      |            | Drop  |     Packets     |
Session/IP Address |   Zone   | PCS  | Percentage | State | Total | Dropped | Time till discard
{DASH}
4242               | trust    | 900  | 26         | No    | 0     | 0       | 60
10.1.2.3           | untrust  | 70   | 2          | Yes   | 15    | 3       | 45
"""

LATENCY = f"""
Latest latency: 4 ms
Last 10 seconds average/maximum latency (ms):
       1/2       0/0       3/9       0/0       0/0       0/0       0/0       0/0       0/0       5/7
{DASH}
"""


def test_short_inactive():
    r = parse_pbp(SHORT)
    assert r["ok"] is True
    assert r["active"] is False
    assert r["basis"] == "count based"
    assert (r["congestion_used"], r["congestion_total"], r["congestion_pct"]) == (5, 1000, 0.5)
    assert "not activated" in r["message"]
    assert r["entries"] == [] and r["extra"] == {}


def test_deactivate_line_is_active():
    r = parse_pbp(DEACT)
    assert r["active"] is True
    assert r["extra"]["Time to deactivate"] == "12.5"
    assert r["congestion_pct"] == 60.0


def test_extended_table():
    r = parse_pbp(EXTENDED)
    assert r["active"] is True
    assert r["congestion_used"] == 800
    assert "Drop probability" in r["extra"]
    assert len(r["entries"]) == 2
    e = r["entries"][1]
    assert e == {
        "address": "10.1.2.3",
        "zone": "untrust",
        "pcs": "70",
        "percentage": "2",
        "state": "Yes",
        "packets_total": "15",
        "dropped": "3",
        "time_till_discard": "45",
    }
    assert r["entries"][0]["address"] == "4242"


def test_pbp_unavailable_empty_garbage():
    for text in ("Invalid syntax.\n", "", "???\n|||\n\x00", None):
        r = parse_pbp(text)  # type: ignore[arg-type]
        assert r["ok"] is False
        assert r["entries"] == []
    assert is_unavailable("Invalid syntax.")


def test_latency():
    r = parse_pbp_latency(LATENCY)
    assert r["ok"] is True
    assert r["latest_ms"] == 4
    assert r["avg_ms"] == [1, 0, 3, 0, 0, 0, 0, 0, 0, 5]
    assert r["max_ms"] == [2, 0, 9, 0, 0, 0, 0, 0, 0, 7]


def test_latency_bad_input():
    assert parse_pbp_latency("Invalid syntax.")["ok"] is False
    assert parse_pbp_latency("")["ok"] is False
    assert parse_pbp_latency("junk")["avg_ms"] == []


def test_zones_best_effort():
    r = parse_pbp_zones(f"# hdr\n{DASH}\ntrust\nuntrust\n\nadmin@fw(active)> \n")
    assert r == {"ok": True, "zones": ["trust", "untrust"]}
    assert parse_pbp_zones("")["ok"] is False
    assert parse_pbp_zones("Invalid syntax.")["ok"] is False

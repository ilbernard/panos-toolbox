"""Tests for the global counter delta parser (synthetic data)."""

from __future__ import annotations

from panos_toolbox.runtime.parse_counters import parse_delta

TABLE = """
Global counters:
Elapsed time since last sampling: {elapsed} seconds

name                                   value     rate severity  category  aspect    description
--------------------------------------------------------------------------------
pkt_demo_recv                           1000      200 info      packet    pktproc   Packets received by demo
flow_demo_drop                            12        2 drop      flow      parse     Packets dropped: demo reason, with spaces
demo_zero                                  0        0 warn      ctd       session   Zero counter
--------------------------------------------------------------------------------
Total counters shown: 3
--------------------------------------------------------------------------------
"""


def test_normal():
    r = parse_delta(TABLE.format(elapsed="5.64 "))
    assert r["ok"] is True
    assert r["elapsed_s"] == 5.64
    assert r["total_declared"] == 3
    assert list(r["counters"]) == ["pkt_demo_recv", "flow_demo_drop", "demo_zero"]
    assert r["counters"]["pkt_demo_recv"] == {
        "value": 1000,
        "rate": 200,
        "severity": "info",
        "category": "packet",
        "aspect": "pktproc",
        "description": "Packets received by demo",
    }
    assert r["counters"]["flow_demo_drop"]["description"].endswith("with spaces")
    assert r["counters"]["demo_zero"]["value"] == 0


def test_padded_elapsed_variants():
    assert parse_delta(TABLE.format(elapsed="30.19 "))["elapsed_s"] == 30.19
    assert parse_delta(TABLE.format(elapsed="47.697"))["elapsed_s"] == 47.697
    assert parse_delta(TABLE.format(elapsed=" 5.64 "))["elapsed_s"] == 5.64


def test_missing_elapsed():
    text = TABLE.replace("Elapsed time since last sampling: {elapsed} seconds\n", "")
    r = parse_delta(text)
    assert r["elapsed_s"] is None
    assert len(r["counters"]) == 3


def test_no_total_line():
    r = parse_delta(TABLE.format(elapsed="1.0").replace("Total counters shown: 3", ""))
    assert r["total_declared"] is None
    assert len(r["counters"]) == 3


def test_declared_total_may_differ():
    r = parse_delta(TABLE.format(elapsed="1.0").replace("shown: 3", "shown: 140"))
    assert r["total_declared"] == 140
    assert len(r["counters"]) == 3


def test_empty_and_garbage():
    for bad in ("", "\n\n", "random text\nwith lines\n1 2 3\n", None):
        r = parse_delta(bad)  # type: ignore[arg-type]
        assert r == {"ok": False, "elapsed_s": None, "counters": {}, "total_declared": None}

"""Tests for panos_toolbox.runtime.parse_resmon (synthetic data only)."""

from __future__ import annotations

from panos_toolbox.runtime.parse_resmon import parse_resmon, summarize_resmon

UTIL = ["session", "packet buffer", "packet descriptor", "sw tags descriptor"]


def _rows(values: list[int]) -> str:
    lines = []
    for i in range(0, len(values), 15):
        lines.append("".join(f"{v:3d}   " for v in values[i : i + 15]))
    return "\n".join(lines)


def _build(core0_star: bool = False, sw_tags: bool = True, minutes: bool = True) -> str:
    out = [
        "# command: show running resource-monitor",
        "",
        "Resource monitoring sampling data (per second):",
        "",
    ]
    out += [
        "CPU load sampling by group:",
        "flow_lookup                    :     7%",
        "flow_fastpath                  :    12%",
        "nac_result                     :     0%",
        "",
    ]
    out += ["CPU load (%) during last 60 seconds:", "core   0   1   2   3"]
    for i in range(60):
        c0 = "*" if core0_star else str(i % 5)
        out.append(f"       {c0}   {i % 10}   2   3")
    out.append("Resource utilization (%) during last 60 seconds:")
    for n, name in enumerate(UTIL):
        if name.startswith("sw") and not sw_tags:
            continue
        out.append(f"{name}:")
        out.append(_rows([(i + n) % 7 for i in range(60)]))
        out.append("")
    if minutes:
        out += [
            "",
            "Resource monitoring sampling data (per minute):",
            "",
            "CPU load (%) during last 60 minutes:",
            "core    0       1       2       3",
            "     avg max avg max avg max avg max",
        ]
        out += ["       *   *   2   4   3   5   1   9"] * 60
        out.append("Resource utilization (%) during last 60 minutes:")
        for suffix in ("average", "maximum"):
            out.append(f"session ({suffix}):")
            out.append(_rows([1 if suffix == "average" else 2] * 60))
    return "\r\n".join(out) + "\r\n"


def test_normal_output():
    r = parse_resmon(_build())
    assert r["ok"] is True
    assert r["groups"] == {"flow_lookup": 7, "flow_fastpath": 12, "nac_result": 0}
    cores = r["seconds"]["cpu_cores"]
    assert sorted(cores) == [0, 1, 2, 3]
    assert all(len(v) == 60 for v in cores.values())
    assert cores[1][:3] == [0, 1, 2] and cores[2] == [2] * 60
    util = r["seconds"]["util"]
    assert set(util) == {"session", "packet_buffer", "packet_descriptor", "sw_tags_descriptor"}
    assert all(len(v) == 60 for v in util.values())
    m = r["minutes"]
    assert m["cpu_cores"][1] == {"avg": [2] * 60, "max": [4] * 60}
    assert m["cpu_cores"][3]["max"] == [9] * 60
    assert m["util"]["session_avg"] == [1] * 60 and m["util"]["session_max"] == [2] * 60
    assert r["hours"] == {"cpu_cores": {}, "util": {}}


def test_star_core0_is_none():
    r = parse_resmon(_build(core0_star=True))
    assert r["seconds"]["cpu_cores"][0] == [None] * 60
    assert r["minutes"]["cpu_cores"][0]["avg"] == [None] * 60


def test_missing_sw_tags_and_minutes():
    r = parse_resmon(_build(sw_tags=False, minutes=False))
    assert "sw_tags_descriptor" not in r["seconds"]["util"]
    assert r["minutes"] == {"cpu_cores": {}, "util": {}}
    assert r["ok"] is True


def test_empty_and_garbage():
    for bad in ("", "   \n", "garbage\n12 13 14\n", "core 0 1\n1 2\n", None, 42):
        r = parse_resmon(bad)  # type: ignore[arg-type]
        assert r["ok"] is False
        assert r["groups"] == {}
        assert r["seconds"] == {"cpu_cores": {}, "util": {}}


def test_bad_rows_skipped():
    text = "Resource monitoring sampling data (per second):\nCPU load (%) during last 60 seconds:\n"
    text += "core 0 1\n 1 2\n 3\n x y\n 4 5\n"
    r = parse_resmon(text)
    assert r["seconds"]["cpu_cores"] == {0: [1, 4], 1: [2, 5]}


def test_summarize():
    s = summarize_resmon(parse_resmon(_build(core0_star=True)))
    assert s["group_max_pct"] == 12 and s["group_max_name"] == "flow_fastpath"
    assert 0 not in s["core_max_60s"]
    assert s["core_max_60s"][1] == 9 and s["core_max_60s"][2] == 2
    assert s["core_avg_60s"][1] == 4.5
    assert s["util_max_60s"]["session"] == 6
    assert set(s["util_max_60s"]) == {
        "session",
        "packet_buffer",
        "packet_descriptor",
        "sw_tags_descriptor",
    }


def test_summarize_empty():
    s = summarize_resmon(parse_resmon(""))
    assert s["group_max_pct"] is None and s["group_max_name"] is None
    assert s["core_max_60s"] == {} and s["core_avg_60s"] == {}
    assert s["util_max_60s"]["session"] is None
    assert summarize_resmon({})["group_max_pct"] is None

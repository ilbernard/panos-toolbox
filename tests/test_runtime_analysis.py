from datetime import datetime, timezone

from runtime_synthetic import build_capture, iface_text

from panos_toolbox.runtime.analysis import (
    RT_THRESHOLDS,
    _cpu_heat,
    _delta,
    _throughput,
    analyze,
)
from panos_toolbox.runtime.store import Sample


def codes(blob):
    return {f["code"] for f in blob["findings"]}


def test_quiet_capture_has_series_and_no_alarm(tmp_path):
    blob = analyze(build_capture(tmp_path))
    m = blob["meta"]
    assert m["cycles"] == 4 and m["firewall"]["model"] == "PA-DEMO"
    assert m["firewall"]["hostname"] == "lab-fw" and m["generated_utc"]
    assert len(blob["session"]["series"]) == 4 and blob["session"]["series"][0]["util_pct"] == 25.0
    assert len(blob["load"]) == 4
    assert len(blob["resmon"]["series"]) == 4 and blob["resmon"]["last_groups"]
    assert blob["backlog"]["available"] and not blob["backlog"]["offenders"]
    assert blob["pbp"]["available"] and blob["pbp"]["latency"]
    assert not codes(blob) & {"BACKLOG_OFFENDER", "SESSION_UTIL", "PBP_ACTIVE",
                              "COUNTER_DROP_RATE", "INFLIGHT_LEFT_ON"}
    assert blob["thresholds"] == RT_THRESHOLDS


def test_pow_intervals_use_ac_differences(tmp_path):
    blob = analyze(build_capture(tmp_path))
    p = blob["pow"]
    assert len(p["intervals"]) == 3
    # avg per interval = delta ac-total-us / delta ac-count = 11 us for flow_fastpath
    assert p["groups"]["flow_fastpath"]["avg_us"] == [11.0, 11.0, 11.0]
    assert "dfa_match" in p["funcs"] and len(p["funcs"]) <= RT_THRESHOLDS["top_pow_funcs"]


def test_delta_aggregation_and_late_counter(tmp_path):
    blob = analyze(build_capture(tmp_path))
    d = blob["delta"]
    names = {c["name"]: c for c in d["counters"]}
    assert names["pkt_demo_recv"]["samples"] == 4
    assert names["late_demo_counter"]["first_seen"] == 2 and names["late_demo_counter"]["samples"] == 1
    assert d["top"]["series"]["pkt_demo_recv"] == [200, 200, 200, 200]


def test_offender_special_tag_and_details(tmp_path):
    blob = analyze(build_capture(tmp_path, ("offender",)))
    off = blob["backlog"]["offenders"]
    assert [o["id"] for o in off] == ["4711"] and "Session 4711" in off[0]["detail"]
    assert {"BACKLOG_OFFENDER", "BACKLOG_HIGH"} <= codes(blob)
    blob = analyze(build_capture(tmp_path / "s", ("special",)))
    assert not blob["backlog"]["offenders"]
    assert blob["backlog"]["special_tags"][0]["name"] == "pktlog_forwarding"
    assert "BACKLOG_SPECIAL_TAG" in codes(blob) and "BACKLOG_OFFENDER" not in codes(blob)


def test_alarms(tmp_path):
    blob = analyze(build_capture(tmp_path, ("sessions", "cps", "drops", "pbp-active", "foreign")))
    c = codes(blob)
    assert {"SESSION_UTIL", "CPS_SPIKE", "COUNTER_DROP_RATE", "PBP_ACTIVE", "PBP_CONGESTION",
            "DELTA_FOREIGN_SAMPLER"} <= c
    assert blob["pbp"]["entries"]
    levels = {f["code"]: f["level"] for f in blob["findings"]}
    assert levels["COUNTER_DROP_RATE"] == "critical" and levels["SESSION_UTIL"] == "critical"


def test_unavailable_backlog(tmp_path):
    blob = analyze(build_capture(tmp_path, ("no-backlog",)))
    assert not blob["backlog"]["available"]
    assert any(f["code"] == "CMD_NOT_AVAILABLE" and "ingress-backlogs" in f["title"]
               for f in blob["findings"])


def test_capture_log_and_findings_sorted(tmp_path):
    blob = analyze(build_capture(tmp_path, ("sessions",)))
    assert len(blob["capture"]["cycles"]) == 4
    slugs = {c["slug"] for c in blob["capture"]["commands"]}
    assert {"pow", "delta", "ingress_backlogs", "pbp"} <= slugs
    order = {"critical": 0, "warning": 1, "info": 2}
    lv = [order[f["level"]] for f in blob["findings"]]
    assert lv == sorted(lv)


def test_broken_capture_does_not_crash(tmp_path):
    root = build_capture(tmp_path)
    (root / "manifest.json").unlink()
    blob = analyze(root)
    assert blob["meta"]["has_manifest"] is False and blob["meta"]["cycles"] == 4


# ---------------------------------------------------------------- foreign delta samples

def test_foreign_delta_sample_is_left_out_of_series_and_statistics(tmp_path):
    blob = analyze(build_capture(tmp_path, ("foreign", "drops")))
    d = blob["delta"]
    foreign = [i for i, x in enumerate(d["samples"]) if x["foreign"]]
    assert len(foreign) == 1 and d["excluded"] == 1 and d["valid"] == len(d["samples"]) - 1
    top = d["top"]["series"]["flow_demo_drop"]
    assert top[foreign[0]] is None and all(v == 1500 for i, v in enumerate(top) if i != foreign[0])
    c = next(x for x in d["counters"] if x["name"] == "flow_demo_drop")
    assert c["samples"] == d["valid"] and c["mean_rate"] == 1500.0  # divided by valid samples
    assert "DELTA_FOREIGN_SAMPLER" in codes(blob)


def test_counter_only_in_a_foreign_sample_is_not_listed(tmp_path):
    text = ("Global counters:\nElapsed time since last sampling: 1.000 seconds\n\n"
            "name value rate severity category aspect description\n" + "-" * 80 + "\n"
            "only_here 10 10 info packet pktproc Demo\n" + "-" * 80 + "\nTotal counters shown: 1\n")
    s = Sample(1, "2026-01-01T00:00:00.000Z", 0.1, True, text, {"foreign_sampler": "1"})
    d = _delta([s], dict(RT_THRESHOLDS))
    assert d["counters"] == [] and d["excluded"] == 1 and d["valid"] == 0


# ---------------------------------------------------------------- throughput

def test_throughput_total_and_per_interface(tmp_path):
    blob = analyze(build_capture(tmp_path, ("iface",)))
    tp = blob["throughput"]
    assert tp["available"] and len(tp["t"]) > 5
    e1 = tp["interfaces"]["ethernet1/1"]
    assert all(abs(v - 1e6) < 1e4 for v in e1["rx_bps"] if v is not None)
    assert all(abs(v - 2e6) < 1e4 for v in e1["tx_bps"] if v is not None)
    sub = tp["interfaces"]["ethernet1/1.7"]
    assert all(abs(v - 0.5e6) < 1e4 for v in sub["rx_bps"] if v is not None)
    assert "ethernet1/2" not in tp["interfaces"] and tp["skipped_idle"] == 1  # unconfigured, idle
    # the total counts the physical ports once (not the sub-interface)
    assert all(abs(v - 1e6) < 1e4 for v in tp["total"]["rx_bps"] if v is not None)
    assert all(abs(v - 2e6) < 1e4 for v in tp["total"]["tx_bps"] if v is not None)
    assert not any(f["code"] == "CMD_NOT_AVAILABLE" for f in blob["findings"])


def test_counter_going_backwards_is_a_gap():
    ts = [("2026-01-01T00:00:00.000Z", 100), ("2026-01-01T00:00:10.000Z", 110),
          ("2026-01-01T00:00:20.000Z", 5), ("2026-01-01T00:00:30.000Z", 15)]  # reset at #3
    samples = [Sample(i, t, 0.2, True, iface_text(now)) for i, (t, now) in enumerate(ts, 1)]
    tp = _throughput(samples, {})
    rx = tp["interfaces"]["ethernet1/1"]["rx_bps"]
    assert rx[0] and rx[1] is None and rx[2] and tp["resets"] >= 1
    assert tp["total"]["rx_bps"][1] is None


def test_throughput_absent_without_the_command(tmp_path):
    blob = analyze(build_capture(tmp_path))
    assert blob["throughput"]["available"] is False
    assert not any(f["code"] == "CMD_NOT_AVAILABLE" and "interface" in f["title"]
                   for f in blob["findings"])


# ---------------------------------------------------------------- CPU heatmap

def _window(t_sec, cores, length=60):
    """A per-second resource-monitor text: row i (newest first) holds the value of second
    ``t_sec - i`` for each core; the value of core c at second s is ``(s * (c + 3)) % 97``."""
    rows = []
    for i in range(length):
        sec = t_sec - i
        rows.append("       " + "   ".join("*" if c == 0 else str((sec * (c + 3)) % 97)
                                              for c in cores))
    return ("Resource monitoring sampling data (per second):\n\nCPU load (%) during last 60 "
            "seconds:\ncore   " + "   ".join(str(c) for c in cores) + "\n" + "\n".join(rows)
            + "\n")


def test_cpu_heatmap_is_rebuilt_from_overlapping_windows():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    cores = [0, 1, 2]
    # true sampling seconds every 10 s; the local clock stamps jitter by up to two seconds
    true = [1000, 1010, 1020, 1030, 1040]
    jitter = [0, 1.2, -0.8, 2.0, -1.1]
    samples = []
    for n, (ts, j) in enumerate(zip(true, jitter), 1):
        stamp = datetime.fromtimestamp(base + ts + j, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        samples.append(Sample(n, stamp, 0.2, True, _window(ts, cores)))
    h = _cpu_heat(samples)
    assert h["cores"] == [1, 2] and h["unmeasured"] == [0]  # core 0 is '*' everywhere
    assert h["step_s"] == 1 and len(h["cells"]["1"]) == 60 + 40
    first_second = 1000 - 59  # the oldest second of the first window, as an absolute offset
    for core in (1, 2):
        for j, v in enumerate(h["cells"][str(core)]):
            sec = first_second + j
            assert v == (sec * (core + 3)) % 97, (core, j)


def test_cpu_heatmap_gap_between_windows_stays_empty():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    samples = []
    for n, ts in enumerate((1000, 1100), 1):  # 100 s apart: 40 s are not covered
        stamp = datetime.fromtimestamp(base + ts, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        samples.append(Sample(n, stamp, 0.0, True, _window(ts, [1])))
    row = _cpu_heat(samples)["cells"]["1"]
    assert len(row) == 160 and row[60:100].count(None) == 40
    assert _cpu_heat([]) is None

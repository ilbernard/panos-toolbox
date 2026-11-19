from runtime_synthetic import build_capture

from panos_toolbox.runtime.analysis import RT_THRESHOLDS, analyze


def codes(blob):
    return {f["code"] for f in blob["findings"]}


def test_quiet_capture_has_series_and_no_alarm(tmp_path):
    blob = analyze(build_capture(tmp_path))
    m = blob["meta"]
    assert m["cycles"] == 4 and m["firewall"]["model"] == "PA-DEMO"
    assert "hostname" not in str(m) and "lab-fw" not in str(m)
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

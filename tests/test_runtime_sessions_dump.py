import json

import pytest
from runtime_synthetic import build_capture, sessions_page

from panos_toolbox.runtime import analysis
from panos_toolbox.runtime import commands as C
from panos_toolbox.runtime.analyzer import render
from panos_toolbox.runtime.capture import Capture, CaptureConfig
from panos_toolbox.runtime.fake import FakeTransport, SimClock
from panos_toolbox.runtime.parse_sessions_all import parse_sessions_page
from panos_toolbox.runtime.report_help import FLAG_HELP
from panos_toolbox.runtime.store import CaptureReader, CaptureWriter


def test_allow_list_accepts_only_valid_start_at():
    for ok in ("show session all start-at 1", "show session all start-at 2097152"):
        C.check_allowed(ok)
    for bad in ("show session all", "show session all start-at 0",
                "show session all start-at 2097153", "show session all start-at 1; x",
                "show session all start-at -1", "show session all start-at 12345678"):
        with pytest.raises(ValueError):
            C.check_allowed(bad)
    assert C.slug_for("show session all start-at 1025") == "sessions_all"
    with pytest.raises(ValueError):
        C.sessions_all_cmd(0)


def test_parse_page_two_line_records_and_nat():
    rows = parse_sessions_page(sessions_page(7, 3))
    assert [r["id"] for r in rows] == [7, 8, 9]
    r = rows[0]
    assert (r["app"], r["state"], r["type"], r["flags"], r["vsys"]) == \
        ("ssl", "ACTIVE", "FLOW", "NS", "vsys1")
    assert r["src"] == {"ip": "10.1.1.1", "port": 40000, "zone": "trust", "proto": 6}
    assert r["dst"]["zone"] == "untrust" and r["dst"]["port"] == 443
    assert r["nat_src"]["ip"] == "203.0.113.9"


def test_parse_page_tolerates_noise_and_ipv6_and_missing_flag():
    text = ("garbage\n7    dns  ACTIVE  FLOW  2001:db8::1[5353]/lan/17\n"
            "vsys2    2001:db8::53[53]/wan\n12 incomplete\n\nTotal: 1\n")
    rows = parse_sessions_page(text)
    assert len(rows) == 1 and rows[0]["flags"] == "" and rows[0]["vsys"] == "vsys2"
    assert rows[0]["src"]["ip"] == "2001:db8::1" and rows[0]["src"]["proto"] == 17
    assert parse_sessions_page("Invalid syntax.\n") == [] and parse_sessions_page(None) == []


def test_dump_pages_until_the_table_ends(tmp_path):
    root = build_capture(tmp_path, ("dump",), interval=30, duration=35)
    man = json.loads((root / "manifest.json").read_text())
    d = man["sessions_dump"]
    assert d["sessions"] == 2348 and d["duplicates"] == 0 and not d["truncated"]
    assert d["pages"] == 3 + 3  # three full pages plus three empty pages end the dump
    assert not any("session dump" in w for w in man["warnings"])
    blob = analysis.analyze(root)
    sd = blob["sessions_dump"]
    assert sd["available"] and sd["sessions"] == 2348
    assert sd["top"]["app"][0] == {"name": "ssl", "n": 1024 + 300}  # ssl: first page + last page
    assert {"name": "dns", "n": 1024} in sd["top"]["app"]
    assert sd["top"]["src_ip"][0] == {"name": "10.1.1.1", "n": 1024}
    assert sd["nat"] == 2348 and sd["distinct"]["state"] == 1
    # the busiest destination holds every session: reported as a top talker
    assert any(f["code"] == "SESSIONS_TOP_TALKER" and "destination" in f["title"]
               for f in blob["findings"])
    assert "Session dump" in render(blob)


def test_dump_is_optional_and_off_by_default(tmp_path):
    root = build_capture(tmp_path, (), duration=35)
    assert not any(c.startswith("show session all") for s in
                   [CaptureReader(root).slugs()] for c in s)
    sd = analysis.analyze(root)["sessions_dump"]
    assert sd == {"available": False, "requested": False}


def _run(tmp_path, responses, **cfg):
    clock = SimClock()
    tr = FakeTransport(responses, clock)
    cap = Capture(tr, CaptureWriter(tmp_path / "c"),
                  CaptureConfig(interval=30, duration=1, dump_sessions=True, **cfg),
                  clock=clock, reconnect=lambda: tr, out=lambda s: None)
    cap.execute()
    return cap, tr


def test_page_limit_truncates_and_warns(tmp_path):
    resp = {C.sessions_all_cmd(1 + 1024 * i): sessions_page(1 + 1024 * i, 1024)
            for i in range(10)}
    cap, tr = _run(tmp_path, resp, sessions_max_pages=4)
    d = cap.sessions_dump
    assert d["pages"] == 4 and d["truncated"] and d["sessions"] == 4096
    assert any("truncated" in w for w in cap.warnings)
    cmds = [c for c in tr.commands() if c.startswith("show session all")]
    assert cmds == [C.sessions_all_cmd(1 + 1024 * i) for i in range(4)]
    blob = analysis.analyze(tmp_path / "c")
    assert any(f["code"] == "SESSIONS_DUMP_TRUNCATED" for f in blob["findings"])


def test_error_answer_stops_the_dump_and_duplicates_are_counted(tmp_path):
    cap, _ = _run(tmp_path, {C.sessions_all_cmd(1): "Invalid syntax.\n"})
    assert cap.sessions_dump["truncated"] and cap.sessions_dump["pages"] == 1
    page = sessions_page(1, 10)
    cap, _ = _run(tmp_path / "b", {C.sessions_all_cmd(1): page, C.sessions_all_cmd(1025): page})
    assert cap.sessions_dump["sessions"] == 10 and cap.sessions_dump["duplicates"] == 10


def test_inflight_is_still_switched_off_after_the_dump(tmp_path):
    cap, tr = _run(tmp_path, {C.sessions_all_cmd(1): sessions_page(1, 5)})
    assert cap.inflight["off_done"]
    cmds = tr.commands()
    last_dump = max(i for i, c in enumerate(cmds) if c.startswith("show session all"))
    assert C.INFLIGHT_OFF in cmds[last_dump:]


def test_new_flags_are_documented():
    for code in ("SESSIONS_DUMP_TRUNCATED", "SESSIONS_TOP_TALKER"):
        assert code in FLAG_HELP


def test_config_validation():
    with pytest.raises(ValueError):
        CaptureConfig(sessions_max_pages=0)
    with pytest.raises(ValueError):
        CaptureConfig(sessions_pause=-1)

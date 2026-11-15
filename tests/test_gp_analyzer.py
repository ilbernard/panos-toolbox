"""Tests for gp/analyzer.py: blob, CLI, output files (synthetic bundles only)."""
from __future__ import annotations

import json
import re
import zipfile
from datetime import datetime, timedelta

import pytest

from panos_toolbox.gp import analyzer, checks

PORTAL = "vpn.example.com"
USER = "jdoe"
HOST = "LAPTOP-01"
BASE = datetime(2026, 3, 2, 9, 0, 0)  # noqa: DTZ001 - the logs carry no UTC offset


def ev(sec: float, msg: str) -> str:
    t = BASE + timedelta(seconds=sec)
    return f"{t:%m/%d/%Y %H:%M:%S}:{t.microsecond // 1000:03d} [Info ]: {msg}"


def success(t: float, gw: str = "gw1.example.com") -> list[str]:
    return [
        ev(t, "Started the Portal pre-login"),
        ev(t + 0.2, "Portal pre-login result received"),
        ev(t + 0.3, "Portal Login starts"),
        ev(t + 0.4, "portal status is Connected"),
        ev(t + 0.5, f"Portal login completed with address {PORTAL} and conect method of on-demand."),
        ev(t + 0.6, "Discovering external network"),
        ev(t + 0.7, f"Gateway pre-Login Starts to {gw}"),
        ev(t + 0.8, f"Gateway Login starts to {gw}"),
        ev(t + 0.9, f"Auto Gateway login finished with address {gw} and user {USER}"),
        ev(t + 1.0, f"Trying to create tunnel with gateway {gw}"),
        ev(t + 2.0, f"IPSec tunnel creation finished with Gateway {gw}."),
    ]


def make_zip(path, event_lines=None, extra=None):
    lines = event_lines if event_lines is not None else success(0) + success(3600)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("pan_gp_event.log", "\r\n".join(lines) + "\r\n")
        zf.writestr("SystemInfo.txt", f"Host Name:                 {HOST}\r\nOS Name: Microsoft Windows 11\r\n")
        for name, text in (extra or {}).items():
            zf.writestr(name, text)
    return path


@pytest.fixture
def bundle(tmp_path):
    return make_zip(tmp_path / "GlobalProtectLogs_test.zip")


def test_analyze_blob_structure(bundle):
    blob = analyzer.analyze(bundle)
    assert set(blob) >= {"meta", "config", "timeline", "findings", "status", "flag_help",
                         "thresholds", "inventory", "analysis", "key_settings", "identity"}
    assert blob["meta"]["bundle"] == bundle.name
    assert blob["meta"]["anchor"].startswith("2026-03-02T10:00")
    assert blob["meta"]["generated"].endswith("+00:00")
    assert blob["timeline"]["summary"]["total"] == 2
    assert blob["status"] in ("ok", "warning", "critical", "no_data")
    assert set(blob["flag_help"]) == set(checks.FLAG_HELP)
    assert set(blob["thresholds"]) == set(checks.GP_THRESHOLDS)
    assert any(m["name"] == "pan_gp_event.log" and m["status"] == "read" for m in blob["inventory"])
    assert "data" not in blob["config"]
    json.dumps(blob)


def test_threshold_override_in_blob(bundle):
    blob = analyzer.analyze(bundle, {"recent_days": 30})
    assert blob["thresholds"]["recent_days"] == {"value": 30.0, "default": checks.GP_THRESHOLDS["recent_days"]}


def test_main_writes_report_next_to_input(bundle, capsys):
    assert analyzer.main([str(bundle)]) == 0
    out = bundle.with_name("GlobalProtectLogs_test_gp.html")
    assert out.is_file()
    line = capsys.readouterr().out.strip().splitlines()
    assert len(line) == 1 and "2 attempts" in line[0] and "connected 2" in line[0]
    text = out.read_text(encoding="utf-8")
    assert "<!doctype html>" in text and "http://" not in text.replace("http://www.w3.org/2000/svg", "")
    assert "https://" not in text


def test_summary_line_reports_expired(bundle):
    blob = analyzer.analyze(bundle)
    blob["timeline"]["summary"]["by_outcome"]["expired"] = 4
    line = analyzer._summary_line("x", blob, bundle)
    assert "expired 4)" in line and "abandoned" in line


def test_main_outdir_and_folder_input(tmp_path):
    make_zip(tmp_path / "b.zip")
    folder = tmp_path / "extracted"
    with zipfile.ZipFile(tmp_path / "b.zip") as zf:
        zf.extractall(folder)
    out = tmp_path / "out" / "sub"
    assert analyzer.main([str(tmp_path / "b.zip"), str(folder), "-o", str(out)]) == 0
    assert (out / "b_gp.html").is_file() and (out / "extracted_gp.html").is_file()


def test_same_stem_does_not_overwrite(tmp_path):
    (tmp_path / "d1").mkdir()
    (tmp_path / "d2").mkdir()
    a = make_zip(tmp_path / "d1" / "x.zip")
    b = make_zip(tmp_path / "d2" / "x.zip")
    assert analyzer.main([str(a), str(b), "-o", str(tmp_path / "o")]) == 0
    assert sorted(p.name for p in (tmp_path / "o").iterdir()) == ["x_gp.html", "x_gp_2.html"]


def test_exit_code_when_all_inputs_fail(tmp_path, capsys):
    bad = tmp_path / "bad.zip"
    bad.write_text("not a zip")
    assert analyzer.main([str(bad), str(tmp_path / "missing.zip"), "-o", str(tmp_path / "o")]) == 1
    err = capsys.readouterr().err
    assert err.count("[ERROR]") == 2 and not (tmp_path / "o").exists()


def test_exit_code_zero_when_one_input_works(tmp_path, bundle):
    bad = tmp_path / "bad.zip"
    bad.write_text("nope")
    assert analyzer.main([str(bad), str(bundle)]) == 0


def _boom_on(monkeypatch, marker):
    real = analyzer.analyze

    def fake(path, *a, **kw):
        if marker in str(path):
            raise RuntimeError("synthetic failure")
        return real(path, *a, **kw)
    monkeypatch.setattr(analyzer, "analyze", fake)


def test_unexpected_error_does_not_abort_other_inputs(tmp_path, monkeypatch, capsys):
    (tmp_path / "good").mkdir()
    (tmp_path / "bad").mkdir()
    good = make_zip(tmp_path / "good" / "ok.zip")
    bad = make_zip(tmp_path / "bad" / "boom.zip")
    _boom_on(monkeypatch, "boom")
    assert analyzer.main([str(bad), str(good)]) == 0
    cap = capsys.readouterr()
    assert f"[ERROR] {bad}: RuntimeError: synthetic failure" in cap.err
    assert "Traceback" not in cap.err
    assert (tmp_path / "good" / "ok_gp.html").exists()
    assert not (tmp_path / "bad" / "boom_gp.html").exists()


def test_unexpected_error_on_every_input_returns_one(tmp_path, monkeypatch, capsys):
    bad = make_zip(tmp_path / "boom.zip")
    _boom_on(monkeypatch, "boom")
    assert analyzer.main([str(bad)]) == 1
    assert "RuntimeError: synthetic failure" in capsys.readouterr().err


def test_debug_flag_reraises(tmp_path, monkeypatch):
    bad = make_zip(tmp_path / "boom.zip")
    _boom_on(monkeypatch, "boom")
    with pytest.raises(RuntimeError, match="synthetic failure"):
        analyzer.main(["--debug", str(bad)])


def test_threshold_options_generated_from_gp_thresholds():
    ap = analyzer.build_parser()
    for key in checks.GP_THRESHOLDS:
        opt = "--gp-" + key.replace("_", "-")
        assert any(opt in a.option_strings for a in ap._actions), opt
    args = ap.parse_args(["x.zip", "--gp-recent-days", "30", "--chain-gap", "120"])
    assert analyzer.parse_thresholds(args, ap) == {"recent_days": 30.0}
    assert args.chain_gap == 120


def test_negative_threshold_rejected():
    ap = analyzer.build_parser()
    args = ap.parse_args(["x.zip", "--gp-recent-days", "-1"])
    with pytest.raises(SystemExit):
        analyzer.parse_thresholds(args, ap)


def test_threshold_option_reaches_report(tmp_path, bundle):
    assert analyzer.main([str(bundle), "--gp-recent-days", "21", "-o", str(tmp_path / "o")]) == 0
    html = (tmp_path / "o" / "GlobalProtectLogs_test_gp.html").read_text(encoding="utf-8")
    assert '"recent_days":{"value":21.0' in html


def test_chain_gap_changes_params(bundle):
    assert analyzer.analyze(bundle, chain_gap_s=42)["timeline"]["params"]["chain_gap_s"] == 42


def test_key_settings_and_identity_from_config():
    cfg = {"sections": [
        {"id": "registry", "freshness": "current", "sources": ["regval.txt"], "groups": [
            {"title": "S", "rows": [{"label": "traffic-enforcement", "value": "all", "key": "traffic-enforcement", "hint": ""}]}]},
        {"id": "summary", "freshness": "current", "sources": ["x"], "groups": [
            {"title": "Client", "rows": [{"label": "User", "value": USER, "key": "", "hint": ""},
                                         {"label": "Host name", "value": HOST, "key": "", "hint": ""}]}]},
    ], "data": {}}
    keys = {r["label"]: r for r in analyzer.key_settings(cfg)}
    assert keys["Traffic enforcement"]["value"] == "all" and keys["User"]["value"] == USER
    assert "Tunnel MTU" not in keys
    assert {"label": "Host name", "value": HOST} in analyzer.identity(cfg)


def test_partial_analysis_when_file_is_unsafe(tmp_path):
    p = make_zip(tmp_path / "u.zip", extra={"../evil.txt": "x"})
    blob = analyzer.analyze(p)
    assert blob["analysis"]["status"] == "partial" and blob["analysis"]["reasons"]


def test_missing_event_log_is_partial(tmp_path):
    p = tmp_path / "n.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("SystemInfo.txt", f"Host Name: {HOST}\r\n")
    blob = analyzer.analyze(p)
    assert blob["analysis"]["status"] == "partial"
    assert re.search("event log", " ".join(blob["analysis"]["reasons"]))


def test_summary_line_reports_internal(bundle):
    blob = analyzer.analyze(bundle)
    blob["timeline"]["summary"]["by_outcome"]["internal"] = 4
    assert "internal 4" in analyzer._summary_line("x", blob, bundle)

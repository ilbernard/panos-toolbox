"""Tests for the GlobalProtect report: placeholders, help, safety of the injected data."""
from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from panos_toolbox.gp import analyzer, checks, report_help
from panos_toolbox.gp.report_template import TEMPLATE

HOSTILE = "</script><img src=x onerror=alert(1)><!-- \u2028 \u2029 & \"q\" '"
TOKENS = "__DATA__ __TITLE__ __KIND__ __HB_summary__ __HP_config__"

SECTION_IDS = ["summary", "registry", "status", "portal_settings", "gateways", "hip_report",
               "troubleshooting", "host_network", "driver"]


def minimal_blob(**over):
    blob = {
        "meta": {"kind": "GlobalProtect analysis", "bundle": "b.zip", "version": 1, "tool_version": "0",
                 "generated": "2026-03-02T10:00:00+00:00", "anchor": "2026-03-02T10:00:00.000"},
        "config": {"collected_at": None, "newest_record": None, "warnings": [], "sections": []},
        "state": {}, "identity": [], "key_settings": [],
        "timeline": {"version": 1, "params": {"chain_gap_s": 600}, "coverage": {}, "summary": {
            "total": 0, "by_outcome": {}}, "storms": [], "attempts": []},
        "findings": [], "status": "ok", "flag_help": {}, "thresholds": {}, "inventory": [],
        "analysis": {"status": "complete", "reasons": []}, "warnings": [],
    }
    blob.update(over)
    return blob


def script_of(html):
    return re.findall(r"<script>(.*?)</script>", html, re.DOTALL)[-1]


def extract_blob(html):
    m = re.search(r"const D = (\{.*?\});\nconst META", html, re.DOTALL)
    return json.loads(m.group(1))


def test_no_placeholders_left():
    out = analyzer.render(minimal_blob())
    for token in ("__DATA__", "__TITLE__", "__KIND__", "__HB_", "__HP_", "__HELPSTORE__"):
        assert token not in out


def test_config_panels_are_collapsible_and_key_table_has_room():
    assert "CFG_COLLAPSE_ROWS = 40" in TEMPLATE and "cfgtog" in TEMPLATE
    assert "aria-expanded" in TEMPLATE and "paintCfgPanel(p, !!q && vis > 0)" in TEMPLATE
    assert "table.keyt td.val" in TEMPLATE and "table.keyt td.src" in TEMPLATE


def test_template_has_no_dangerous_constructs():
    js = script_of(TEMPLATE)
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js
    assert "eval(" not in js and "document.write" not in js and "new Function" not in js
    assert not re.search(r"\son[a-z]+\s*=", TEMPLATE.replace("onerror", ""))
    assert not re.search(r"(src|href)=[\"']?https?:", TEMPLATE)


def test_hostile_values_are_inert():
    attempt = {"id": "a0001", "kind": "login", "start": "2026-03-02T09:00:00.000", "end": "2026-03-02T09:00:01.000",
               "duration_ms": 1000, "outcome": "failed", "portal": HOSTILE, "gateway": HOSTILE,
               "protocol": "", "user": HOSTILE, "trigger": "unknown",
               "error": {"text": HOSTILE, "raw": HOSTILE, "stage": HOSTILE}, "cycles": 1,
               "tunnel_ip": "", "has_detail": True, "sources": ["event_log"], "storm": None,
               "disconnect": None, "details": {}, "steps": [
                   {"ts": "2026-03-02T09:00:00.100", "phase": "ui", "text": HOSTILE, "source": HOSTILE, "level": "info"}]}
    blob = minimal_blob(
        meta={**minimal_blob()["meta"], "bundle": HOSTILE + TOKENS},
        findings=[{"code": "X", "level": "warning", "title": HOSTILE, "text": HOSTILE + TOKENS,
                   "scope": "", "when": None, "refs": [HOSTILE], "count": 1}])
    blob["timeline"]["attempts"] = [attempt]
    out = analyzer.render(blob)
    # nothing from the data can close the script element or open a comment inside it
    scripts = re.findall(r"<script>(.*?)</script>", out, re.DOTALL)
    assert len(scripts) == 1
    assert "<img" not in out and "<!--" not in script_of(out)
    assert "\u2028" not in script_of(out) and "\u2029" not in script_of(out)
    # the page title is escaped
    title = re.search(r"<title>(.*?)</title>", out).group(1)
    assert "<" not in title and "&lt;/script&gt;" in title
    # the data round-trips unchanged
    data = extract_blob(out)
    assert data["timeline"]["attempts"][0]["error"]["text"] == HOSTILE
    assert data["meta"]["bundle"] == HOSTILE + TOKENS
    # a placeholder token in the data is not substituted a second time
    assert TOKENS in data["findings"][0]["text"]
    assert out.count("const D = ") == 1


def test_blob_json_escapes_markup_characters():
    text = analyzer.blob_json({"a": "</script><!-- & > <", "b": "\u2028\u2029"})
    assert not any(c in text for c in "<>&\u2028\u2029")
    assert json.loads(text) == {"a": "</script><!-- & > <", "b": "\u2028\u2029"}


def test_help_placeholders_all_resolved_and_present_in_template():
    helps = report_help.render_section_help()
    assert set(report_help.SECTION_TITLES) == set(report_help.SECTION_HELP)
    for sid in report_help.SECTION_TITLES:
        assert f"__HB_{sid}__" in TEMPLATE and f"__HP_{sid}__" in TEMPLATE
        assert f"__HB_{sid}__" in helps and f"__HP_{sid}__" in helps
    out = analyzer.render(minimal_blob())
    for sid in report_help.SECTION_TITLES:
        assert f'id="help-{sid}"' in out and f'data-hid="{sid}"' in out


def test_help_text_has_no_unfilled_braces_and_uses_params():
    text = report_help.render_help()
    assert not re.search(r"\{[a-z_]+\}", text)
    assert "600 s" in text
    custom = report_help.render_section_help({"chain_gap_s": 42})["__HP_timeline__"]
    assert "42 s" in custom


def test_every_section_id_has_help():
    for sid in SECTION_IDS:
        assert f"cfg_{sid}" in report_help.SECTION_HELP
    for sid in ("summary", "config", "timeline", "findings", "coverage", "keysettings", "tl_chart",
                "tl_table", "flagref", "cov_inventory", "cov_ranges"):
        assert sid in report_help.SECTION_HELP
    for m in re.finditer(r'data-help="([a-z_]+)"', TEMPLATE):
        assert m.group(1) in report_help.SECTION_HELP


def test_expired_outcome_is_supported_in_the_page_and_help():
    for needle in ("'expired'", "expired:'Expired'", "expired:'#2b6cb0'", ".b-expired",
                   ".chip.o-expired", "cancel_evidence", "gateway_switches"):
        assert needle in TEMPLATE, needle
    # five outcomes: the chart lanes follow OUTS, no hard-coded four lanes
    assert "LANE * 4" not in TEMPLATE
    text = report_help.render_help().lower()
    for word in ("expired", "inferred", "never crosses portals", "grace period"):
        assert word in text, word


def test_help_explains_key_concepts():
    text = report_help.render_help().lower()
    for word in ("cycles", "credential prompt", "auto-restore", "last seen in logs",
                 "time zone", "retry storm", "newest log record", "detailed-log window"):
        assert word in text, word


def test_section_ids_of_client_config_have_help(tmp_path):
    import zipfile

    from panos_toolbox.gp.bundle import Bundle
    from panos_toolbox.gp.client_config import build_config
    p = tmp_path / "b.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("SystemInfo.txt", "Host Name: LAPTOP-01\r\n")
    bundle = Bundle.open(p)
    try:
        ids = [s.id for s in build_config(bundle).sections]
    finally:
        bundle.close()
    assert ids
    for sid in ids:
        assert f"cfg_{sid}" in report_help.SECTION_HELP, sid


def test_flag_help_embedded_for_every_code():
    data = extract_blob(analyzer.render(minimal_blob(flag_help={k: list(v) for k, v in checks.FLAG_HELP.items()})))
    assert set(data["flag_help"]) == set(checks.FLAG_HELP)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_generated_javascript_is_valid(tmp_path):
    js = tmp_path / "report.js"
    js.write_text(script_of(analyzer.render(minimal_blob())), encoding="utf-8")
    res = subprocess.run(["node", "--check", str(js)], check=False, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


def test_end_to_end_report_has_tabs_and_data(tmp_path):
    from test_gp_analyzer import make_zip
    p = make_zip(tmp_path / "b.zip")
    assert analyzer.main([str(p)]) == 0
    html = (tmp_path / "b_gp.html").read_text(encoding="utf-8")
    for label in ("Summary", "Client configuration", "Connection timeline", "Findings", "Source coverage"):
        assert label in html
    assert len(extract_blob(html)["timeline"]["attempts"]) == 2
    assert "localStorage" in html and "catch(e)" in html

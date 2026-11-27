"""Tests for the runtime report: placeholders, help, flag codes, safety, CLI (synthetic data only)."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from runtime_synthetic import build_capture

from panos_toolbox.runtime import analysis, analyzer, report_help
from panos_toolbox.runtime.report_template import TEMPLATE

SCENARIOS = ["offender", "special", "pbp-active", "drops", "foreign", "cps", "sessions",
             "no-backlog"]
HOSTILE = "</script><img src=x onerror=alert(1)><!--   & __DATA__ __HB_overview__"


def script_of(page):
    return re.findall(r"<script>(.*?)</script>", page, re.DOTALL)[-1]


def check_page(page):
    for token in ("__DATA__", "__TITLE__", "__KIND__", "__HB_", "__HP_", "__HELPSTORE__",
                  "__TABS__", "__PANELS__"):
        assert token not in page
    js = script_of(page)
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "document.write",
                "new Function"):
        assert bad not in page
    assert not re.search(r"\son[a-z]+\s*=", TEMPLATE)
    assert js.count("const D = ") == 1


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_render_each_scenario(tmp_path, scenario):
    page = analyzer.render(analysis.analyze(build_capture(tmp_path, (scenario,))))
    check_page(page)
    assert "Runtime report" in page


def test_render_combined_and_node_syntax(tmp_path):
    blob = analysis.analyze(build_capture(
        tmp_path, ("offender", "pbp-active", "drops", "foreign", "cps", "sessions")))
    page = analyzer.render(blob)
    check_page(page)
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    js = tmp_path / "report.js"
    js.write_text(script_of(page), encoding="utf-8")
    res = subprocess.run([node, "--check", str(js)], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr


def test_tabs_and_dataplane_data(tmp_path):
    blob = analysis.analyze(build_capture(tmp_path, ("drops",)))
    page = analyzer.render(blob)
    assert re.findall(r'id="tab-([a-z]+)"', page) == [
        "overview", "findings", "pow", "counters", "dataplane", "sessions"]
    assert "Samples per command" not in page
    # every aggregated counter can be plotted, not only the busiest ones
    delta = blob["delta"]
    assert set(delta["rates"]) == {c["name"] for c in delta["counters"]}
    assert delta["rates"]["pkt_demo_recv"] == {str(i): 200 for i in range(4)}
    # a counter that appears in one sample only is stored for that sample only
    assert list(delta["rates"]["late_demo_counter"]) == ["1"]
    assert all(x["groups"] for x in blob["resmon"]["series"])


def test_counter_rates_beyond_the_busiest(tmp_path):
    blob = analysis.analyze(build_capture(tmp_path, ("drops",)), {"top_counters": 1})
    assert len(blob["delta"]["top"]["series"]) == 1
    assert len(blob["delta"]["rates"]) == len(blob["delta"]["counters"]) > 1


def test_empty_capture_renders(tmp_path):
    folder = tmp_path / "empty"
    (folder / "raw").mkdir(parents=True)
    (folder / "manifest.json").write_text(json.dumps({"tool": "t"}), encoding="utf-8")
    page = analyzer.render(analysis.analyze(folder))
    check_page(page)


def test_hostile_values_are_inert(tmp_path):
    blob = analysis.analyze(build_capture(tmp_path, ("offender",)))
    blob["meta"]["folder"] = HOSTILE
    blob["meta"]["warnings"] = [HOSTILE]
    blob["backlog"]["offenders"][0]["detail"] = HOSTILE
    page = analyzer.render(blob)
    assert len(re.findall(r"<script>", page)) == 1 and "<img" not in page
    js = script_of(page)
    assert "<!--" not in js and " " not in js and "</script" not in js
    title = re.search(r"<title>(.*?)</title>", page).group(1)
    assert "<" not in title and "&lt;/script&gt;" in title
    m = re.search(r"const D = (\{.*?\});\nconst META", js, re.DOTALL)
    data = json.loads(m.group(1))
    assert data["meta"]["folder"] == HOSTILE
    assert data["backlog"]["offenders"][0]["detail"] == HOSTILE
    assert "innerHTML" not in page


def test_blob_json_escapes_markup_characters():
    text = analyzer.blob_json({"a": "</script><!-- & > <", "b": "  "})
    assert not any(c in text for c in "<>&  ")
    assert json.loads(text) == {"a": "</script><!-- & > <", "b": "  "}


def test_flag_codes_documented_both_ways():
    src = Path(analysis.__file__).read_text(encoding="utf-8")
    codes = set(re.findall(r'_finding\("([A-Z_]+)"', src))
    assert codes
    assert codes == set(report_help.FLAG_HELP)
    assert set(report_help.FLAG_KEYS) == codes
    for code, (title, meaning, nxt) in report_help.FLAG_HELP.items():
        assert title and meaning and nxt, code
    for keys in report_help.FLAG_KEYS.values():
        assert set(keys) <= set(analysis.RT_THRESHOLDS)
    text = json.dumps(report_help.FLAG_HELP) + json.dumps(report_help.SECTION_HELP)
    assert "—" not in text and text.isascii()


def test_section_help_ids_match_template():
    assert set(report_help.SECTION_TITLES) == set(report_help.SECTION_HELP)
    helps = report_help.render_section_help()
    script = script_of(TEMPLATE)
    for sid in report_help.SECTION_TITLES:
        assert f"__HB_{sid}__" in TEMPLATE and f"__HP_{sid}__" in TEMPLATE
        assert f"__HB_{sid}__" in helps and f"__HP_{sid}__" in helps
        # and the help is attached to a heading somewhere
        assert f'data-help="{sid}"' in TEMPLATE or f"'{sid}'" in script, sid
    for token in re.findall(r"__H[BP]_([a-z_]+)__", TEMPLATE):
        assert token in report_help.SECTION_TITLES


def test_help_mentions_key_caveats():
    text = report_help.render_help().lower()
    for needle in ("global", "ac-*", "not sessions", "always left off", "utc"):
        assert needle in text or needle.replace("not sessions", "not a session") in text, needle


def test_cli_two_inputs_one_bad(tmp_path, capsys):
    good = build_capture(tmp_path / "g", ("offender",))
    out = tmp_path / "out"
    rc = analyzer.main([str(good), str(tmp_path / "missing"), "-o", str(out)])
    assert rc == 0
    html_file = out / "cap_runtime.html"
    assert html_file.is_file()
    check_page(html_file.read_text(encoding="utf-8"))
    cap = capsys.readouterr()
    assert "cycles" in cap.out and "critical" in cap.out and "missing" in cap.err


def test_cli_all_bad_returns_1(tmp_path):
    assert analyzer.main([str(tmp_path / "nope"), "-o", str(tmp_path / "o")]) == 1


def test_cli_thresholds(tmp_path):
    good = build_capture(tmp_path / "g")
    out = tmp_path / "o"
    assert analyzer.main([str(good), "-o", str(out), "--threshold", "session_util_warn=10",
                          "--threshold", "cps_spike_min=5"]) == 0
    data = re.search(r"const D = (\{.*?\});\nconst META", out.joinpath("cap_runtime.html").read_text(
        encoding="utf-8"), re.DOTALL).group(1)
    blob = json.loads(data)
    assert blob["thresholds"]["session_util_warn"] == 10
    assert any(f["code"] == "SESSION_UTIL" for f in blob["findings"])
    for bad in (["--threshold", "nope=1"], ["--threshold", "session_util_warn=x"],
                ["--threshold", "session_util_warn"]):
        with pytest.raises(SystemExit) as exc:
            analyzer.main([str(good), *bad])
        assert exc.value.code == 2

#!/usr/bin/env python3
"""GlobalProtect client log analyzer.

Reads the bundle produced by "Collect Logs" in the GlobalProtect app (the
``GlobalProtectLogs*.zip`` file, or the folder it extracts to) and writes one
self-contained HTML report with:

* the current client configuration (app settings pushed by the portal,
  registry settings, gateway/tunnel configuration, pre-login responses);
* the timeline of the connection attempts: one row per attempt, with the
  phases reached, the outcome and the log events behind it.

Usage:
    panos-toolbox gp analyze GlobalProtectLogs.zip [more.zip ...] [-o OUTDIR] [--open]

Windows bundles are supported. The report holds everything found in the logs
in clear text (user names, addresses, host names): handle it accordingly.
Standard library only.
"""
from __future__ import annotations

import argparse
import calendar
import json
import os
import re
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

from panos_toolbox import __version__

from .bundle import Bundle, BundleError
from .client_config import (
    ConfigCollector,
    Snapshot,
    parse_hip_report,
    parse_regval,
    parse_systeminfo,
    parse_trb,
)
from .logs import EventLine, iter_records, parse_event_log
from .report_template import render_page
from .timeline import (
    OUTCOMES,
    PHASES,
    Attempt,
    Ev,
    build_attempts,
    classify,
    detail_event,
    merge_details,
)

EVENT_LOG = "pan_gp_event"
SERVICE_LOG = "PanGPS"
KNOWN_UNPARSED = {
    "pangpa": "app UI log: not parsed in this version",
    "pangphip": "HIP collection log: not parsed",
    "pangphipmp": "HIP missing-patch log: not parsed",
    "debug_drv": "virtual adapter driver log: not parsed",
    "logonui": "credential provider log: not parsed",
    "panproxyagent": "proxy agent log: not parsed",
}


def _ms(ts: datetime | None) -> int | None:
    if ts is None:
        return None
    return calendar.timegm(ts.timetuple()) * 1000 + ts.microsecond // 1000


def _fmt(ts: datetime | None) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""


def _groups(rows: list[tuple[str, str, str]]) -> list[dict]:
    out: list[dict] = []
    index: dict[str, dict] = {}
    for group, key, value in rows:
        g = index.get(group)
        if g is None:
            g = {"name": group, "rows": []}
            index[group] = g
            out.append(g)
        g["rows"].append([key, value])
    return out


def _section(sid: str, title: str, source: str, groups: list[dict], ts: datetime | None = None,
             note: str = "") -> dict:
    return {"id": sid, "title": title, "source": source, "ts": _fmt(ts), "groups": groups, "note": note}


def _snap_section(sid: str, title: str, snap: Snapshot, note: str = "") -> dict:
    if snap.truncated:
        note = (note + " " if note else "") + "The document is cut short in the log: its last elements are missing."
    return _section(sid, title, snap.src, _groups(snap.rows), snap.ts, note)


def analyze(path) -> dict:
    """Analyze one bundle and return the data blob rendered in the report."""
    bundle = Bundle.open(path)
    try:
        return _analyze(bundle)
    finally:
        bundle.close()


def _analyze(bundle: Bundle) -> dict:
    warnings: list[str] = []
    coverage: dict[str, dict] = {}

    # ---- event log (timeline backbone)
    lines: list[EventLine] = []
    for name in bundle.rotation(EVENT_LOG):
        text = bundle.read_text(name, "timeline")
        if text is None:
            continue
        parsed, bad = parse_event_log(text, name)
        lines.extend(parsed)
        coverage[name.lower()] = {"lines": len(parsed), "first": _fmt(parsed[0].ts) if parsed else "",
                                  "last": _fmt(parsed[-1].ts) if parsed else ""}
        if bad:
            warnings.append(f"{name}: {bad} line(s) not in the expected format, ignored")

    # ---- service log (details + configuration documents)
    collector = ConfigCollector()
    details: list[Ev] = []
    fallback_lines: list[EventLine] = []
    svc_first = svc_last = None
    for name in bundle.rotation(SERVICE_LOG):
        text = bundle.read_text(name, "timeline details, configuration")
        if text is None:
            continue
        n = 0
        first = last = None
        for rec in iter_records(text, name):
            n += 1
            first = first or rec.ts
            last = rec.ts
            collector.feed(rec)
            ev = detail_event(rec)
            if ev is not None:
                details.append(ev)
            if not lines and rec.msg:
                fallback_lines.append(EventLine(rec.ts, "info", rec.msg, name))
        del text
        coverage[name.lower()] = {"lines": n, "first": _fmt(first), "last": _fmt(last)}
        svc_first = svc_first or first
        svc_last = last or svc_last
    if collector.xml_errors:
        warnings.append(f"{collector.xml_errors} XML document(s) in {SERVICE_LOG}.log could not be parsed")

    fallback = False
    if not lines:
        if fallback_lines:
            fallback = True
            lines = fallback_lines
            warnings.append(
                f"{EVENT_LOG}.log not found: the timeline is rebuilt from {SERVICE_LOG}.log only "
                "(shorter history, fewer outcome messages)")
        else:
            warnings.append(f"neither {EVENT_LOG}.log nor {SERVICE_LOG}.log found: no timeline")
    del fallback_lines
    lines.sort(key=lambda e: e.ts)
    rows = build_attempts(lines, fallback=fallback)
    details.sort(key=lambda e: e.ts)
    merged = merge_details(rows, details)
    if not bundle.rotation(SERVICE_LOG):
        warnings.append(f"{SERVICE_LOG}.log not found: no detail events and no portal/gateway configuration")

    # ---- configuration
    sections: list[dict] = []
    if collector.status:
        sections.append(_snap_section(
            "status", "Client state at the last status update", collector.status,
            "Last status document sent by the service (PanGPS) to the app UI."))
    for portal, snap in sorted(collector.agent_cfg.items(), key=lambda kv: kv[1].ts, reverse=True):
        sections.append(_snap_section(
            f"agent:{portal}", f"App configuration from portal {portal}", snap,
            "App settings as applied by the service after the portal login (portal agent configuration)."))
    if collector.gateway_list:
        sections.append(_snap_section("gwlist", "Gateway list", collector.gateway_list))
    for gw, snap in sorted(collector.gateway_cfg.items(), key=lambda kv: kv[1].ts, reverse=True):
        sections.append(_snap_section(
            f"gwcfg:{gw}", f"Gateway configuration from {gw}", snap,
            "Tunnel settings returned by the gateway at the last successful login."))
    for host, snap in sorted(collector.portal_prelogin.items(), key=lambda kv: kv[1].ts, reverse=True):
        sections.append(_snap_section(f"ppl:{host}", f"Portal pre-login response from {host}", snap))
    for host, snap in sorted(collector.gateway_prelogin.items(), key=lambda kv: kv[1].ts, reverse=True):
        sections.append(_snap_section(f"gpl:{host}", f"Gateway pre-login response from {host}", snap))
    if collector.singles:
        srows = [("", label, f"{value}   [{_fmt(ts)}]") for label, (ts, value) in collector.singles.items()]
        sections.append(_section("runtime", "Runtime values seen in the service log", f"{SERVICE_LOG}.log",
                                 _groups(srows), note="Newest value of each item; the time is when it was logged."))

    reg: dict[str, str] = {}
    data = bundle.read_bytes("regval.txt", "configuration")
    if data is not None:
        reg_sections = parse_regval(data)
        rrows = [(title, k, v) for title, items in reg_sections for k, v in items]
        reg = {k: v for title, items in reg_sections if title == "Settings" for k, v in items}
        sections.append(_section("registry", "Registry settings", "regval.txt", _groups(rrows),
                                 note="Dump of HKLM\\SOFTWARE\\Palo Alto Networks\\GlobalProtect taken at collection time."))
    sysinfo: dict[str, str] = {}
    text = bundle.read_text("SystemInfo.txt", "configuration")
    if text:
        srows2 = parse_systeminfo(text)
        sysinfo = dict(srows2)
        sections.append(_section("system", "System information", "SystemInfo.txt",
                                 _groups([("", k, v) for k, v in srows2])))
    text = bundle.read_text("pan_gp_hrpt.xml", "configuration")
    if text:
        hrows = parse_hip_report(text)
        if hrows:
            sections.append(_section("hip", "Last HIP report (summary)", "pan_gp_hrpt.xml",
                                     _groups([("", k, v) for k, v in hrows])))
    trb: dict[str, str] = {}
    text = bundle.read_text("pan_gp_trb.log", "configuration")
    if text:
        trows = parse_trb(text)
        if trows:
            trb = dict(trows)
            sections.append(_section(
                "trb", "Last troubleshooting report", "pan_gp_trb.log",
                _groups([("", k, v) for k, v in trows]),
                note="Written by the app when a connection fails; it can refer to a different portal "
                     "than the one in use at collection time."))

    # ---- overview
    status = {k: v for _g, k, v in collector.status.rows} if collector.status else {}
    client_version = status.get("product-version", "")
    os_name = ""
    for line in reversed(lines):
        if classify(line.msg)[0] == "SVC_START":
            m = re.search(r"client version: ([^,)]+), OS version: (.+?)\)?\.?$", line.msg)
            if m:
                client_version = client_version or m.group(1).strip()
                os_name = m.group(2).strip()
            break
    last_ts = max([t for t in (lines[-1].ts if lines else None, svc_last) if t], default=None)
    attempts = [r for r in rows if r.kind != "system"]
    last_attempt = attempts[-1] if attempts else None
    connect_method = collector.singles.get("Connect method", (None, ""))[1]
    if not connect_method and reg.get("on-demand"):
        connect_method = "On-Demand" if reg["on-demand"] == "yes" else "not on-demand (see registry)"
    overview = [
        ("GlobalProtect version", client_version or trb.get("gp_version", "")),
        ("Operating system", os_name or sysinfo.get("OS Name", "") or trb.get("os", "")),
        ("Computer", sysinfo.get("Host Name", "") or trb.get("host_name", "")),
        ("Last portal (registry LastUrl)", reg.get("LastUrl", "")),
        ("Portal in the last status", status.get("portal", "")),
        ("User in the last status", status.get("user-name", "")),
        ("Connect method", connect_method),
        ("State at the last status", " / ".join(v for v in (status.get("status", ""), status.get("state", "")) if v)),
        ("Portal status", status.get("portal-status", "")),
        ("Time zone of the client", sysinfo.get("Time Zone", "")),
        ("Last log line", _fmt(last_ts)),
        ("Event log coverage", f"{_fmt(lines[0].ts)} to {_fmt(lines[-1].ts)}" if lines and not fallback else ""),
        ("Service log coverage (detail events)", f"{_fmt(svc_first)} to {_fmt(svc_last)}" if svc_first else ""),
    ]
    overview = [[k, v] for k, v in overview if v]

    # ---- sources
    sources = []
    for key, member in sorted(bundle.members.items()):
        stem = re.sub(r"(\.\d+)?\.(log|txt|xml|dmp)(\.old)?$", "", key)
        note = member.reason or member.used_for
        if not note and member.status == "found":
            note = KNOWN_UNPARSED.get(stem, "not used")
        cov = coverage.get(key, {})
        sources.append({"name": member.name, "size": member.size, "status": member.status, "note": note,
                        "lines": cov.get("lines", ""), "first": cov.get("first", ""), "last": cov.get("last", "")})
    warnings = bundle.warnings + warnings

    src_names: list[str] = []
    src_index: dict[str, int] = {}

    def src_id(name: str) -> int:
        if name not in src_index:
            src_index[name] = len(src_names)
            src_names.append(name)
        return src_index[name]

    def row_blob(r: Attempt) -> dict:
        return {
            "k": r.kind, "s": _ms(r.start), "e": _ms(r.end), "p": r.portal, "g": r.gateway, "u": r.user,
            "o": r.outcome, "st": r.stage, "r": r.reason, "n": r.notes, "ph": r.phases,
            "pi": int(r.portal_inferred),
            "up": _ms(r.tunnel_up), "dn": _ms(r.tunnel_down), "er": r.end_reason, "d": int(r.has_detail),
            "ev": [[_ms(e.ts), e.level, e.phase, e.text, src_id(e.src), e.count, _ms(e.last)] for e in r.events],
        }

    return {
        "meta": {
            "bundle": bundle.path.name, "generated": _fmt(datetime.now()), "tool": __version__,
            "last": _ms(last_ts), "fallback": fallback, "detail_events": merged,
            "detail_from": _ms(svc_first), "detail_to": _ms(svc_last),
        },
        "overview": overview,
        "sections": sections,
        "phases": [list(p) for p in PHASES],
        "outcomes": OUTCOMES,
        "rows": [row_blob(r) for r in rows],
        "srcs": src_names,
        "sources": sources,
        "warnings": warnings,
    }


def render(blob: dict) -> str:
    payload = json.dumps(blob, ensure_ascii=False, separators=(",", ":"))
    # "<" never appears literally in the embedded JSON, so the data cannot
    # close the script element or open a comment.
    payload = payload.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return render_page(blob["meta"]["bundle"], payload)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="panos-toolbox gp analyze",
        description="HTML report from a GlobalProtect client log bundle (Collect Logs): "
                    "current client configuration and timeline of the connection attempts.")
    ap.add_argument("inputs", nargs="+", help="GlobalProtectLogs*.zip bundles or extracted folders")
    ap.add_argument("-o", "--outdir", default="output", help="output directory (default: output)")
    ap.add_argument("--open", action="store_true", help="open the report in the default browser")
    args = ap.parse_args(argv)

    os.makedirs(args.outdir, exist_ok=True)
    written = []
    rc = 0
    for item in args.inputs:
        try:
            blob = analyze(item)
        except (BundleError, OSError) as exc:
            print(f"[ERROR] {item}: {exc}", file=sys.stderr)
            rc = 1
            continue
        stem = Path(item).name
        stem = stem[:-4] if stem.lower().endswith(".zip") else stem
        out = Path(args.outdir) / f"{stem}_gp.html"
        out.write_text(render(blob), encoding="utf-8")
        written.append(out)
        attempts = [r for r in blob["rows"] if r["k"] != "system"]
        ok = sum(1 for r in attempts if r["o"] == "connected")
        print(f"[OK] {item}: {len(attempts)} connection attempts ({ok} connected), "
              f"{len(blob['sections'])} configuration sections -> {out}")
        for w in blob["warnings"]:
            print(f"  [WARN] {w}")
    if args.open and written:
        webbrowser.open(written[0].resolve().as_uri())
    return rc


if __name__ == "__main__":
    sys.exit(main())

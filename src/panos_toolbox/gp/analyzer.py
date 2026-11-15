#!/usr/bin/env python3
"""GlobalProtect client log analyzer.

Reads the bundle produced by "Collect Logs" in the GlobalProtect app (the
``GlobalProtectLogs*.zip`` file, or the folder it extracts to) and writes ONE self-contained
HTML report (no external resources) with:

* the current client configuration and settings, each source with its file, time and freshness;
* the timeline of the connection attempts, with filters and, where detailed logs exist, the
  ordered phase steps of each attempt;
* the findings of the automatic checks and the coverage of the bundle.

Usage:
    panos-toolbox gp analyze GlobalProtectLogs.zip [more.zip ...] [-o OUTDIR] [--open] [--debug]

Output: ``<bundle name>_gp.html`` next to the input, or in OUTDIR. The report holds everything
found in the logs in clear text (user names, addresses, host names): handle it accordingly.
Log times are the local times of the client, without zone conversion. Standard library only.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from panos_toolbox import __version__

from . import checks
from .bundle import Bundle, BundleError
from .client_config import build_config
from .report_help import render_section_help
from .report_template import TEMPLATE
from .timeline import CHAIN_GAP_S, build_timeline

KIND = "GlobalProtect analysis"
SUFFIX = "_gp"
BLOB_VERSION = 1

# (label, [(section id, "key" | "label", text), ...]) first non-empty match wins
_KEY_SPECS = [
    ("Portal", [("status", "key", "portal"), ("summary", "label", "Last portal"),
                ("registry", "key", "LastUrl")]),
    ("Connect method", [("portal_settings", "label", "Connect method")]),
    ("User", [("summary", "label", "User"), ("status", "key", "user-name")]),
    ("Client version", [("summary", "label", "Client version"), ("status", "key", "product-version")]),
    ("Single sign-on (SSO)", [("portal_settings", "key", "use-sso")]),
    ("On-demand", [("portal_settings", "key", "on-demand"), ("registry", "key", "on-demand")]),
    ("Traffic enforcement", [("registry", "key", "traffic-enforcement")]),
    ("Enforce GlobalProtect", [("registry", "key", "enforce-globalprotect")]),
    ("Tunnel MTU", [("portal_settings", "key", "tunnel-mtu"),
                    ("gateways", "label", "MTU (configured in the client)"),
                    ("troubleshooting", "key", "gp_mtu")]),
    ("Split tunnel", [("portal_settings", "key", "split-tunnel-option"),
                      ("registry", "key", "split-tunnel-option")]),
    ("DNS servers (tunnel)", [("gateways", "key", "dns")]),
    ("DNS suffixes (tunnel)", [("gateways", "key", "dns-suffix")]),
]
_IDENTITY = ["Client version", "User", "Host name", "Operating system", "Domain", "Last portal",
             "Time zone (SystemInfo)", "Bundle collected"]


def _norm_ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("T", " "))
    except ValueError:
        return None


def _rows(section: dict):
    for group in section.get("groups", []):
        yield from group.get("rows", [])


def _find_row(sections: dict, sid: str, field: str, text: str):
    sec = sections.get(sid)
    if not sec:
        return None, None
    hits = [r for r in _rows(sec) if r.get(field) == text]
    if not hits:
        return None, None
    best = next((r for r in hits if r.get("value")), hits[0])
    return sec, best


def key_settings(cfg: dict) -> list[dict]:
    """The settings most useful at a glance, with section, freshness and source of each."""
    sections = {s["id"]: s for s in cfg.get("sections", [])}
    out: list[dict] = []
    for label, specs in _KEY_SPECS:
        found = None
        for sid, field, text in specs:
            sec, row = _find_row(sections, sid, field, text)
            if row is None:
                continue
            found = (sec, row)
            if row.get("value"):
                break
        if found is None:
            continue
        sec, row = found
        out.append({"label": label, "value": row.get("value", ""), "section": sec["id"],
                    "freshness": sec.get("freshness", ""),
                    "source": ", ".join(sec.get("sources", [])[:3])
                    + (f" ({row['key']})" if row.get("key") else "")})
    cm = (cfg.get("data") or {}).get("connect_method") or {}
    if cm.get("value") and not any(r["label"] == "Connect method" for r in out):
        out.insert(1, {"label": "Connect method", "value": cm["value"], "section": "portal_settings",
                       "freshness": "last_seen", "source": str(cm.get("source", ""))})
    return out


def identity(cfg: dict) -> list[dict]:
    sections = {s["id"]: s for s in cfg.get("sections", [])}
    summary = sections.get("summary")
    if not summary:
        return []
    rows = {}
    for r in _rows(summary):
        rows.setdefault(r.get("label"), r.get("value", ""))
    return [{"label": k, "value": rows[k]} for k in _IDENTITY if k in rows]


def _anchor(cfg: dict, tl: dict) -> str:
    """Newest log record: the anchor of every relative period (never the wall clock)."""
    cands = [_norm_ts(cfg.get("newest_record"))]
    cov = tl.get("coverage") or {}
    for key in ("event_log", "service_log", "agent_log"):
        if cov.get(key):
            cands.append(_norm_ts(cov[key].get("last")))
    for a in tl.get("attempts", [])[-50:]:
        cands.append(_norm_ts(a.get("end") or a.get("start")))
    cands = [c for c in cands if c is not None]
    return max(cands).isoformat(sep="T", timespec="milliseconds") if cands else ""


def _inventory(bundle: Bundle) -> list[dict]:
    rows = [{"name": m.name, "family": m.family, "size": m.size, "status": m.status,
             "reason": m.reason, "used_for": m.used_for} for m in bundle.inventory()]
    return sorted(rows, key=lambda r: (r["family"], r["name"].lower()))


def _analysis(bundle: Bundle, inventory: list[dict], cfg: dict, tl: dict) -> dict:
    reasons: list[str] = []
    for m in inventory:
        if m["status"] in ("skipped", "truncated"):
            reasons.append(f"{m['name']}: {m['status']}" + (f" ({m['reason']})" if m["reason"] else ""))
    reasons.extend(bundle.warnings)
    reasons.extend(cfg.get("warnings", []))
    if not (tl.get("coverage") or {}).get("event_log"):
        reasons.append("no event log (pan_gp_event): the attempt history is limited to the detailed logs")
    seen: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.append(r)
    return {"status": "partial" if seen else "complete", "reasons": seen[:200]}


def _threshold_table(overrides: dict) -> dict:
    return {k: {"value": overrides.get(k, v), "default": v} for k, v in checks.GP_THRESHOLDS.items()}


def analyze(path, thresholds: dict | None = None, chain_gap_s: float | None = None) -> dict:
    """Analyze one bundle (zip or folder) and return the data blob rendered in the report."""
    overrides = {k: float(v) for k, v in (thresholds or {}).items() if v is not None}
    bundle = Bundle.open(path)
    try:
        config = build_config(bundle)
        kwargs = {} if chain_gap_s is None else {"chain_gap_s": float(chain_gap_s)}
        timeline = build_timeline(bundle, **kwargs)
        findings = checks.evaluate(config, timeline, overrides or None)
        cfg = config.to_dict()
        tl = timeline.to_dict()
        inv = _inventory(bundle)
        analysis = _analysis(bundle, inv, cfg, tl)
        bundle_warnings = list(bundle.warnings)
    finally:
        bundle.close()
    data = cfg.pop("data", {}) or {}
    name = Path(str(path).rstrip("/\\")).name
    return {
        "meta": {
            "kind": KIND, "bundle": name, "version": BLOB_VERSION, "tool_version": __version__,
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "anchor": _anchor(cfg, tl),
        },
        "config": cfg,
        "state": {k: data.get("connection", {}).get(k) for k in
                  ("connected", "conclusion", "last_state", "last_state_at", "evidence")},
        "identity": identity({**cfg, "data": data}),
        "key_settings": key_settings({**cfg, "data": data}),
        "timeline": tl,
        "findings": checks.to_dicts(findings),
        "status": checks.status(findings),
        "flag_help": {k: list(v) for k, v in checks.FLAG_HELP.items()},
        "thresholds": _threshold_table(overrides),
        "inventory": inv,
        "analysis": analysis,
        "warnings": bundle_warnings,
    }


# ------------------------------------------------------------------------------------ render
_PLACEHOLDER = re.compile(r"__(?:KIND|TITLE|DATA|HB_[a-z_]+|HP_[a-z_]+)__")


def blob_json(blob: dict) -> str:
    """JSON that is safe inside a script element: no ``<``, ``>``, ``&``, U+2028 or U+2029."""
    text = json.dumps(blob, separators=(",", ":"), ensure_ascii=True, default=str)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render(blob: dict) -> str:
    """The HTML page. Placeholders are replaced in a single pass, so substituted text (a bundle
    name or a log line that contains a placeholder token) is never interpreted again."""
    params = (blob.get("timeline") or {}).get("params") or {}
    values = dict(render_section_help(params))
    values["__KIND__"] = html.escape(KIND)
    values["__TITLE__"] = html.escape(str(blob.get("meta", {}).get("bundle", "")))
    values["__DATA__"] = blob_json(blob)
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(0), m.group(0)), TEMPLATE)


# ------------------------------------------------------------------------------------- CLI
def _summary_line(name: str, blob: dict, out: Path) -> str:
    by = blob["timeline"]["summary"]["by_outcome"]
    sev = {lv: sum(1 for f in blob["findings"] if f["level"] == lv) for lv in ("critical", "warning", "info")}
    return (f"{name}: {blob['timeline']['summary']['total']} attempts "
            f"(connected {by.get('connected', 0)}, failed {by.get('failed', 0)}, "
            f"cancelled {by.get('cancelled', 0)}, abandoned {by.get('abandoned', 0)}, "
            f"expired {by.get('expired', 0)}); "
            f"findings: {sev['critical']} critical, {sev['warning']} warning, {sev['info']} info; "
            f"status {blob['status']}, analysis {blob['analysis']['status']} -> {out}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="panos-toolbox gp analyze", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", help="GlobalProtectLogs .zip file(s) or extracted folder(s)")
    ap.add_argument("-o", "--outdir", default=None,
                    help="output directory (default: next to each input)")
    ap.add_argument("--open", action="store_true", help="open the report in the default browser")
    ap.add_argument("--debug", action="store_true",
                    help="do not catch unexpected errors: show the full traceback and stop")
    ap.add_argument("--chain-gap", type=float, default=None, metavar="S",
                    help=f"seconds within which login cycles are chained into one attempt [{CHAIN_GAP_S:g}]")
    grp = ap.add_argument_group("finding thresholds",
                                "Tunables of the automatic checks (defaults in brackets; see the "
                                "flag reference in the report).")
    for key, default in checks.GP_THRESHOLDS.items():
        grp.add_argument("--gp-" + key.replace("_", "-"), dest="gp_" + key, metavar="N", type=float,
                         default=None, help=f"{key} [{default:g}]")
    return ap


def parse_thresholds(args: argparse.Namespace, ap: argparse.ArgumentParser) -> dict:
    out = {k: getattr(args, "gp_" + k) for k in checks.GP_THRESHOLDS
           if getattr(args, "gp_" + k) is not None}
    if any(v < 0 for v in out.values()):
        ap.error("thresholds must be >= 0")
    return out


def _stem(path: Path) -> str:
    name = path.name
    return name[:-4] if name.lower().endswith(".zip") else name


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    thresholds = parse_thresholds(args, ap)
    if args.chain_gap is not None and args.chain_gap < 0:
        ap.error("--chain-gap must be >= 0")
    ok = 0
    used: set[Path] = set()
    last: Path | None = None
    for raw in args.inputs:
        src = Path(raw)
        try:
            blob = analyze(src, thresholds, args.chain_gap)
            outdir = Path(args.outdir) if args.outdir else (src.resolve().parent)
            outdir.mkdir(parents=True, exist_ok=True)
            target = outdir / f"{_stem(src)}{SUFFIX}.html"
            n = 1
            while target in used:
                n += 1
                target = outdir / f"{_stem(src)}{SUFFIX}_{n}.html"
            used.add(target)
            target.write_text(render(blob), encoding="utf-8")
        except (BundleError, OSError, ValueError, KeyError) as exc:
            print(f"[ERROR] {raw}: {exc}", file=sys.stderr)
            continue
        except Exception as exc:  # one bad input must not abort the others
            if args.debug:
                raise
            print(f"[ERROR] {raw}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        ok += 1
        last = target
        print(_summary_line(src.name, blob, target))
    if args.open and last is not None:
        webbrowser.open(last.resolve().as_uri())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

"""Runtime capture report: one offline HTML page from a capture folder.

Reads the folder written by ``panos-toolbox runtime capture`` and writes ONE self-contained
HTML report (no external resources) with the overview, findings, POW timing, counters, ingress
backlogs, packet buffer, sessions, resources and the capture log.

Usage:
    panos-toolbox runtime report CAPTURE_DIR [more dirs ...] [-o OUTDIR] [--open]
                                 [--threshold KEY=VALUE ...] [--debug]

Output: ``<folder name>_runtime.html`` next to each input, or in OUTDIR. All times are UTC.
The report holds firewall output (addresses, session details) in clear text: handle it
accordingly. Standard library only.
"""
from __future__ import annotations

import argparse
import html
import json
import math
import re
import sys
import webbrowser
from pathlib import Path

from . import analysis
from .report_help import flag_help_data, render_section_help
from .report_template import TEMPLATE

KIND = "Runtime report"
SUFFIX = "_runtime"

_PLACEHOLDER = re.compile(r"__(?:KIND|TITLE|DATA|HB_[a-z_]+|HP_[a-z_]+)__")


def blob_json(blob: dict) -> str:
    """JSON that is safe inside a script element: no ``<``, ``>``, ``&``, U+2028 or U+2029."""
    text = json.dumps(blob, separators=(",", ":"), ensure_ascii=True, default=str)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render(blob: dict) -> str:
    """The HTML page. Placeholders are replaced in a single pass, so substituted text (a folder
    name or a firewall output line that contains a placeholder token) is never interpreted
    again."""
    data = dict(blob)
    data["flag_help"] = flag_help_data()
    values = dict(render_section_help())
    values["__KIND__"] = html.escape(KIND)
    values["__TITLE__"] = html.escape(str((blob.get("meta") or {}).get("folder", "")))
    values["__DATA__"] = blob_json(data)
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(0), m.group(0)), TEMPLATE)


def _summary_line(name: str, blob: dict, out: Path) -> str:
    sev = {lv: sum(1 for f in blob["findings"] if f["level"] == lv)
           for lv in ("critical", "warning", "info")}
    return (f"{name}: {blob['meta'].get('cycles', 0)} cycles; findings: {sev['critical']} critical, "
            f"{sev['warning']} warning, {sev['info']} info -> {out}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="panos-toolbox runtime report", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+",
                    help="capture folder(s) written by 'runtime capture'")
    ap.add_argument("-o", "--outdir", default=None,
                    help="output directory (default: next to each input)")
    ap.add_argument("--open", action="store_true", help="open the report in the default browser")
    ap.add_argument("--debug", action="store_true",
                    help="do not catch unexpected errors: show the full traceback and stop")
    ap.add_argument("--threshold", action="append", default=[], metavar="KEY=VALUE",
                    help="override a finding threshold (repeatable); keys: "
                         + ", ".join(analysis.RT_THRESHOLDS))
    return ap


def parse_thresholds(items: list[str], ap: argparse.ArgumentParser) -> dict:
    out: dict = {}
    for item in items:
        key, sep, value = item.partition("=")
        key = key.strip()
        if not sep or key not in analysis.RT_THRESHOLDS:
            ap.error(f"--threshold: unknown key or not KEY=VALUE: {item!r} "
                     f"(known keys: {', '.join(analysis.RT_THRESHOLDS)})")
        try:
            num = float(value)
        except ValueError:
            ap.error(f"--threshold {key}: not a number: {value!r}")
        if not math.isfinite(num):
            ap.error(f"--threshold {key}: not a finite number")
        out[key] = int(num) if num.is_integer() and isinstance(
            analysis.RT_THRESHOLDS[key], int) else num
    return out


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    thresholds = parse_thresholds(args.threshold, ap)
    ok = 0
    used: set[Path] = set()
    last: Path | None = None
    for raw in args.inputs:
        src = Path(raw)
        try:
            if not src.is_dir():
                raise ValueError("not a capture folder")
            blob = analysis.analyze(src, thresholds or None)
            outdir = Path(args.outdir) if args.outdir else src.resolve().parent
            outdir.mkdir(parents=True, exist_ok=True)
            name = src.resolve().name
            target = outdir / f"{name}{SUFFIX}.html"
            n = 1
            while target in used:
                n += 1
                target = outdir / f"{name}{SUFFIX}_{n}.html"
            used.add(target)
            target.write_text(render(blob), encoding="utf-8")
        except (OSError, ValueError, KeyError) as exc:
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

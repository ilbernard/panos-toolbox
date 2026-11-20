"""Parser for ``show counter global filter delta yes``.

Layout: a ``Global counters:`` title, ``Elapsed time since last sampling:  N  seconds``,
a blank line, a column header (``name value rate severity category aspect description``),
a dashed line, one row per counter, a dashed line and ``Total counters shown: N``.
Standard library only; tolerant of missing pieces.
"""

from __future__ import annotations

import re

_ELAPSED = re.compile(r"Elapsed time since last sampling:\s+([\d.]+)\s+seconds", re.IGNORECASE)
_TOTAL = re.compile(r"Total counters shown:\s*(\d+)", re.IGNORECASE)


def parse_delta(text: str) -> dict:
    """Parse the delta counter table into ``{name: {...}}`` plus elapsed time and total."""
    text = text if isinstance(text, str) else ""
    out: dict = {"ok": False, "elapsed_s": None, "counters": {}, "total_declared": None}
    m = _ELAPSED.search(text)
    if m:
        try:
            out["elapsed_s"] = float(m.group(1))
        except ValueError:
            pass
    m = _TOTAL.search(text)
    if m:
        out["total_declared"] = int(m.group(1))
    counters: dict = out["counters"]
    for line in text.splitlines():
        parts = line.split(None, 6)
        if len(parts) < 6 or not (parts[1].isdigit() and parts[2].isdigit()):
            continue
        counters[parts[0]] = {
            "value": int(parts[1]),
            "rate": int(parts[2]),
            "severity": parts[3],
            "category": parts[4],
            "aspect": parts[5],
            "description": parts[6].strip() if len(parts) > 6 else "",
        }
    out["ok"] = bool(counters) or out["elapsed_s"] is not None or out["total_declared"] is not None
    return out

"""Parser for the raw output of ``show running resource-monitor`` (standard library only).

Layout of the output (verified on a real 4-core firewall)::

    Resource monitoring sampling data (per second):
    CPU load sampling by group:
    <name padded> :     N%                 one row per group
    CPU load (%) during last 60 seconds:
    core   0   1   2   3                   header: core indexes
           *   3   3   3                   one row per sample, columns = cores
    Resource utilization (%) during last 60 seconds:
    session:                               block header, then 60 values on rows of 15
      0 0 0 ...                            (blocks follow each other, usually with a blank line)
    packet buffer: / packet descriptor: / sw tags descriptor:   (sw tags may be absent)

    Resource monitoring sampling data (per minute|hour|day|week):
    CPU load (%) during last 60 minutes:   (24 hours / 7 days / 13 weeks)
    core    0       1       2       3
         avg max avg max avg max avg max   second header line
         *   *   2   4 ...                 rows are time-major, 2 columns per core
    Resource utilization (%) during last 60 minutes:
    session (average): / session (maximum): / packet buffer (average): ...

Notes:
- Rows are time-major (one row per sample, one column per core), not core-major.
- A literal ``*`` means "not available" (core 0 is typically a management core) -> ``None``.
- Order of values is kept exactly as printed. The tool does not label the direction; callers
  must not assume more than "printed order".
- Utilization blocks wrap at 15 values per row; the last row is shorter, and blocks may be
  glued without blank lines in the hour/day/week sections.
- Lines starting with ``#`` and carriage returns are ignored. Parsing never raises.

Result of :func:`parse_resmon`::

    {
      "ok": bool,                       # True when at least one data section was parsed
      "groups": {name: int_pct},
      "seconds": {"cpu_cores": {core: [v|None, ...]},
                  "util": {"session": [...], "packet_buffer": [...],
                           "packet_descriptor": [...], "sw_tags_descriptor": [...]}},
      "minutes" / "hours" / "days" / "weeks":
                 {"cpu_cores": {core: {"avg": [v|None, ...], "max": [v|None, ...]}},
                  "util": {"session_avg": [...], "session_max": [...], "packet_buffer_avg": ...}},
    }

Missing sections give empty dicts.
"""

from __future__ import annotations

import re
from typing import Any

PERIODS = {
    "second": "seconds",
    "minute": "minutes",
    "hour": "hours",
    "day": "days",
    "week": "weeks",
}

_PERIOD_RE = re.compile(r"^Resource monitoring sampling data \(per (\w+)\):", re.IGNORECASE)
_GROUP_ROW_RE = re.compile(r"^\s*([A-Za-z0-9_\-./ ]+?)\s*:\s*(\d+)\s*%\s*$")
_BLOCK_RE = re.compile(r"^\s*([A-Za-z][A-Za-z ]*?)(?:\s*\((average|maximum)\))?\s*:\s*$")
_INT_RE = re.compile(r"^\d+$")
UTIL_NAMES = ("session", "packet_buffer", "packet_descriptor", "sw_tags_descriptor")


def _cell(tok: str) -> tuple[bool, int | None]:
    """Return (valid, value) for one table cell; ``*`` is valid and maps to None."""
    if tok == "*":
        return True, None
    if _INT_RE.match(tok):
        return True, int(tok)
    return False, None


def _empty_period(period: str) -> dict[str, Any]:
    return {"cpu_cores": {}, "util": {}}


def parse_resmon(text: str) -> dict:
    """Parse raw ``show running resource-monitor`` output. Never raises."""
    result: dict[str, Any] = {"ok": False, "groups": {}}
    for key in PERIODS.values():
        result[key] = _empty_period(key)
    _parse(text if isinstance(text, str) else "", result)
    result["ok"] = bool(
        result["groups"]
        or any(result[k]["cpu_cores"] or result[k]["util"] for k in PERIODS.values())
    )
    return result


def _parse(text: str, result: dict[str, Any]) -> None:
    period: str | None = None
    mode: str | None = None  # groups | cpu | util
    cores: list[int] = []
    pair_mode = False
    util_key: str | None = None
    for raw in text.replace("\r", "").split("\n"):
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _PERIOD_RE.match(s)
        if m:
            period = PERIODS.get(m.group(1).lower())
            mode, util_key = None, None
            continue
        low = s.lower()
        if low.startswith("cpu load sampling by group"):
            mode, util_key = "groups", None
            continue
        if low.startswith("cpu load (%) during last"):
            mode, cores, pair_mode, util_key = "cpu", [], False, None
            continue
        if low.startswith("resource utilization (%) during last"):
            mode, util_key = "util", None
            continue
        if mode == "groups":
            g = _GROUP_ROW_RE.match(s)
            if g:
                result["groups"][g.group(1).strip()] = int(g.group(2))
            continue
        if period is None:
            continue
        if mode == "cpu":
            toks = s.split()
            if toks[0].lower() == "core":
                cores[:] = [int(x) for x in toks[1:] if _INT_RE.match(x)]
            elif toks[0].lower() == "avg":
                pair_mode = True
            else:
                _cpu_row(toks, result[period]["cpu_cores"], cores, pair_mode)
            continue
        if mode == "util":
            b = _BLOCK_RE.match(s)
            if b:
                name = re.sub(r"\s+", "_", b.group(1).strip().lower())
                suffix = {"average": "_avg", "maximum": "_max"}.get(b.group(2) or "", "")
                util_key = name + suffix
                result[period]["util"].setdefault(util_key, [])
                continue
            if util_key is not None:
                toks = s.split()
                if all(_INT_RE.match(t) for t in toks):
                    result[period]["util"][util_key].extend(int(t) for t in toks)


def _cpu_row(toks: list[str], out: dict[int, Any], cores: list[int], pair_mode: bool) -> None:
    """Append one time-major CPU row (one value per core, or avg/max pair per core)."""
    width = 2 if pair_mode else 1
    if not cores or len(toks) != width * len(cores):
        return
    cells = [_cell(x) for x in toks]
    if not all(ok for ok, _ in cells):
        return
    for i, core in enumerate(cores):
        if pair_mode:
            d = out.setdefault(core, {"avg": [], "max": []})
            d["avg"].append(cells[2 * i][1])
            d["max"].append(cells[2 * i + 1][1])
        else:
            out.setdefault(core, []).append(cells[i][1])


def _nums(values: list[int | None]) -> list[int]:
    return [v for v in values if v is not None]


def summarize_resmon(parsed: dict) -> dict:
    """Compact numbers for a report, from the per-second section and :func:`parse_resmon` output."""
    out: dict[str, Any] = {
        "group_max_pct": None,
        "group_max_name": None,
        "core_max_60s": {},
        "core_avg_60s": {},
        "util_max_60s": {},
    }
    if not isinstance(parsed, dict):
        return out
    groups = parsed.get("groups") or {}
    if groups:
        name = max(groups, key=lambda k: groups[k])
        out["group_max_name"], out["group_max_pct"] = name, groups[name]
    sec = parsed.get("seconds") or {}
    for core, vals in (sec.get("cpu_cores") or {}).items():
        n = _nums(vals)
        if n:
            out["core_max_60s"][core] = max(n)
            out["core_avg_60s"][core] = sum(n) / len(n)
    util = sec.get("util") or {}
    for name in UTIL_NAMES:
        n = _nums(util.get(name) or [])
        out["util_max_60s"][name] = max(n) if n else None
    return out

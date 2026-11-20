"""Parsers for ``show session packet-buffer-protection`` output (raw PAN-OS CLI text).

Standard library only. All functions are tolerant and never raise.
"""

from __future__ import annotations

import re

from .parse_backlog import is_unavailable

__all__ = ["is_unavailable", "parse_pbp", "parse_pbp_latency", "parse_pbp_zones"]

_BASIS_RE = re.compile(r"^Packet buffer (.+?)\s*$", re.IGNORECASE)
_CONGESTION_RE = re.compile(r"^Congestion:\s*(\d+)\s*/\s*(\d+)(?:\s*\(([\d.]+)%\))?")
_KV_RE = re.compile(r"^([A-Za-z][A-Za-z /_-]*?):\s*(.*)$")
_DASH_RE = re.compile(r"^-{5,}\s*$")
_PROMPT_RE = re.compile(r"^\S+@\S+[>#]")
_LATEST_RE = re.compile(r"Latest latency:\s*(\d+)\s*ms", re.IGNORECASE)
_PAIR_RE = re.compile(r"(\d+)\s*/\s*(\d+)")
_ENTRY_KEYS = (
    "address",
    "zone",
    "pcs",
    "percentage",
    "state",
    "packets_total",
    "dropped",
    "time_till_discard",
)


def _to_int(value: str):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_pbp(text: str) -> dict:
    """Parse ``show session packet-buffer-protection`` (short or extended form).

    Returns {ok, active, basis, congestion_used, congestion_total, congestion_pct, message,
    extra, entries}. ``active`` is False when the output says protection is not activated,
    True when a table, a "Time to deactivate" line or a drop probability is present, else
    None. ``extra`` holds the other "Key: value" lines (e.g. "Time to deactivate",
    "Drop probability"). ``entries`` rows: address, zone, pcs, percentage, state,
    packets_total, dropped, time_till_discard (strings).
    """
    res: dict = {
        "ok": False,
        "active": None,
        "basis": None,
        "congestion_used": None,
        "congestion_total": None,
        "congestion_pct": None,
        "message": None,
        "extra": {},
        "entries": [],
    }
    try:
        if not text or is_unavailable(text):
            return res
        for raw in text.splitlines():
            line = raw.strip()
            if not line or _DASH_RE.match(line) or line.startswith("#"):
                continue
            if _PROMPT_RE.match(line):
                continue
            if "|" in line:
                cells = [c.strip() for c in line.split("|")]
                if len(cells) == len(_ENTRY_KEYS) and cells[0] and cells[0] != "Session/IP Address":
                    res["entries"].append(dict(zip(_ENTRY_KEYS, cells)))
                continue
            m = _CONGESTION_RE.match(line)
            if m:
                res["congestion_used"] = int(m.group(1))
                res["congestion_total"] = int(m.group(2))
                if m.group(3) is not None:
                    res["congestion_pct"] = float(m.group(3))
                continue
            m = _BASIS_RE.match(line)
            if m and ":" not in line:
                res["basis"] = m.group(1)
                continue
            if "not activated" in line.lower():
                res["message"] = line
                res["active"] = False
                continue
            m = _KV_RE.match(line)
            if m:
                res["extra"][m.group(1).strip()] = m.group(2).strip()
                continue
            if res["message"] is None:
                res["message"] = line
        if res["active"] is None and (
            res["entries"]
            or "Time to deactivate" in res["extra"]
            or any(k.lower().startswith("drop probability") for k in res["extra"])
        ):
            res["active"] = True
        res["ok"] = res["congestion_total"] is not None or res["basis"] is not None
    except Exception:  # noqa: BLE001 - parsers must never raise
        res["ok"] = False
    return res


def parse_pbp_latency(text: str) -> dict:
    """Parse ``show session packet-buffer-protection buffer-latency``.

    Returns {ok, latest_ms, avg_ms, max_ms}; the lists come from the row of ten
    ``avg/max`` pairs under "Last 10 seconds average/maximum latency (ms):".
    """
    res: dict = {"ok": False, "latest_ms": None, "avg_ms": [], "max_ms": []}
    try:
        if not text or is_unavailable(text):
            return res
        in_pairs = False
        for raw in text.splitlines():
            line = raw.strip()
            m = _LATEST_RE.search(line)
            if m:
                res["latest_ms"] = int(m.group(1))
            elif "average/maximum" in line.lower():
                in_pairs = True
            elif in_pairs:
                pairs = _PAIR_RE.findall(line)
                if pairs and not _DASH_RE.match(line):
                    res["avg_ms"].extend(int(a) for a, _ in pairs)
                    res["max_ms"].extend(int(b) for _, b in pairs)
        res["ok"] = res["latest_ms"] is not None or bool(res["avg_ms"])
    except Exception:  # noqa: BLE001
        res["ok"] = False
    return res


def parse_pbp_zones(text: str) -> dict:
    """Best-effort parse of the PBP zone listing: {ok, zones}.

    The layout is not known, so every non-empty line that is not a prompt, a dashed
    separator or a '#' header is returned as a zone entry.
    """
    res: dict = {"ok": False, "zones": []}
    try:
        if not text or is_unavailable(text):
            return res
        for raw in text.splitlines():
            line = raw.strip()
            if not line or _DASH_RE.match(line) or line.startswith("#") or _PROMPT_RE.match(line):
                continue
            res["zones"].append(line)
        res["ok"] = bool(res["zones"])
    except Exception:  # noqa: BLE001
        res["ok"] = False
    return res

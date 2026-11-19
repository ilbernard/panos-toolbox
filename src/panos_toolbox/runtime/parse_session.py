"""Parsers for ``show session info`` and the management-plane load line.

Standard library only. Every function is tolerant: unknown or missing input yields
``None`` values and ``ok=False``, never an exception.
"""

from __future__ import annotations

import re

_INT = r"(\d+)"


def _find_int(text: str, label: str, suffix: str = "") -> int | None:
    m = re.search(rf"^\s*{label}\s*:\s*{_INT}{suffix}", text, re.MULTILINE)
    return int(m.group(1)) if m else None


def parse_session_info(text: str) -> dict:
    """Parse ``show session info`` into counts, utilization and rates."""
    text = text if isinstance(text, str) else ""
    supported = _find_int(text, "Number of sessions supported")
    allocated = _find_int(text, "Number of allocated sessions")
    out: dict = {
        "ok": False,
        "supported": supported,
        "allocated": allocated,
        "active_tcp": _find_int(text, "Number of active TCP sessions"),
        "active_udp": _find_int(text, "Number of active UDP sessions"),
        "active_icmp": _find_int(text, "Number of active ICMP sessions"),
        "utilization_reported_pct": _find_int(text, "Session table utilization", "%"),
        "utilization_pct": None,
        "pps": _find_int(text, "Packet rate", r"/s"),
        "kbps": _find_int(text, "Throughput", r"\s*kbps"),
        "cps": _find_int(text, "New connection establish rate", r"\s*cps"),
        "created_since_boot": _find_int(text, "Number of sessions created since bootup"),
    }
    if supported and allocated is not None:
        out["utilization_pct"] = round(allocated / supported * 100, 2)
    out["ok"] = any(v is not None for k, v in out.items() if k != "ok")
    return out


def parse_mgmt_load(text: str) -> dict:
    """Parse the ``top - ... load average: a, b, c`` line of the management plane."""
    out: dict = {"ok": False, "load1": None, "load5": None, "load15": None}
    text = text if isinstance(text, str) else ""
    m = re.search(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", text)
    if m:
        try:
            out["load1"], out["load5"], out["load15"] = (float(g) for g in m.groups())
            out["ok"] = True
        except ValueError:
            out.update(load1=None, load5=None, load15=None)
    return out

"""Parser for ``show running resource-monitor ingress-backlogs`` (raw PAN-OS CLI output).

Standard library only. Ported from the validated recon prototype.
"""

from __future__ import annotations

import re

_SLOT_RE = re.compile(r"^-- SLOT: (\S+), DP: (\S+) --")
_USAGE_RE = re.compile(r"USAGE - ATOMIC: ([\d.]+)% +TOTAL: ([\d.]+)%")
_TOP_RE = re.compile(r"^(\d+)\s+([\d.]+)%\s+(\S+)\s+(\d+)\s*(.*)$")
_CLOCK_RE = re.compile(r"^[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}$")
_DETAIL_RE = re.compile(
    r"^(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)"
)
_UNAVAILABLE_RE = re.compile(r"invalid syntax|unexpected here", re.IGNORECASE)

# Ids with the high bit set are special tags, not real sessions.
SPECIAL_MIN_ID = 2**31
SPECIAL_NOTE = "not valid session id"


def is_unavailable(text: str) -> bool:
    """True when the output shows the command is not supported ('Invalid syntax' etc.)."""
    return bool(text) and _UNAVAILABLE_RE.search(text) is not None


def is_special_tag(sess_id: int, notes: str) -> bool:
    """True for special TAG values (not real sessions).

    Special when the notes contain 'NOT valid session id' or the id is >= 2**31.
    """
    return SPECIAL_NOTE in (notes or "").lower() or int(sess_id) >= SPECIAL_MIN_ID


def parse_backlog(text: str) -> list:
    """Parse ``show running resource-monitor ingress-backlogs``.

    Returns one dict per "-- SLOT: sX, DP: dpY --" section: slot, dp, fw_time, atomic, total
    (percent or None), top = [{sess_id, pct, grp_id, count, notes, special}], details =
    [{sess_id, proto, zone, src, sport, dst, dport, igr_if, egr_if, type, app}]. A section
    without offending sessions has empty ``top``/``details``. Never raises.

    ``grp_id`` is a number for real sessions and a workgroup name (e.g. pktlog_forwarding)
    for special tags. Special tags (``special`` True) are not sessions, so
    ``show session id`` must not be run on them. The older format without the Special Notes
    column is accepted (``notes`` is then empty).
    """
    out: list = []
    cur = None
    mode = None
    clock = None
    for raw in (text or "").split("\n"):
        line = raw.rstrip()
        if _CLOCK_RE.match(line.strip()):
            clock = line.strip()
            continue
        m = _SLOT_RE.match(line)
        if m:
            cur = {
                "slot": m.group(1),
                "dp": m.group(2),
                "fw_time": clock,
                "atomic": None,
                "total": None,
                "top": [],
                "details": [],
            }
            out.append(cur)
            mode = None
            continue
        if cur is None:
            continue
        m = _USAGE_RE.search(line)
        if m:
            cur["atomic"], cur["total"] = float(m.group(1)), float(m.group(2))
        elif line.startswith("TOP SESSIONS"):
            mode = "top"
        elif line.startswith("SESSION DETAILS"):
            mode = "details"
        elif mode == "top":
            m = _TOP_RE.match(line)
            if m:
                notes = m.group(5).strip()
                cur["top"].append(
                    {
                        "sess_id": m.group(1),
                        "pct": float(m.group(2)),
                        "grp_id": m.group(3),
                        "count": int(m.group(4)),
                        "notes": notes,
                        "special": is_special_tag(int(m.group(1)), notes),
                    }
                )
        elif mode == "details":
            m = _DETAIL_RE.match(line)
            if m:
                cur["details"].append(
                    {
                        "sess_id": m.group(1),
                        "proto": m.group(2),
                        "zone": m.group(3),
                        "src": m.group(4),
                        "sport": m.group(5),
                        "dst": m.group(6),
                        "dport": m.group(7),
                        "igr_if": m.group(8),
                        "egr_if": m.group(9),
                        "type": m.group(10),
                        "app": m.group(11),
                    }
                )
    return out


def offending_ids(sections: list) -> list:
    """Real session ids to query with ``show session id`` (special tags excluded)."""
    ids: list = []
    seen: set = set()
    for sec in sections:
        special = {r["sess_id"] for r in sec["top"] if r["special"]}
        for row in sec["top"] + sec["details"]:
            sid = row["sess_id"]
            if sid not in seen and sid not in special:
                seen.add(sid)
                ids.append(sid)
    return ids


def special_tags(sections: list) -> list:
    """Top rows that are special tags, each extended with the slot and dp of its section."""
    return [
        dict(row, slot=sec["slot"], dp=sec["dp"])
        for sec in sections
        for row in sec["top"]
        if row["special"]
    ]

"""Parser for the pages of ``show session all [start-at N]``.

Standard library only; tolerant: unrecognised lines are ignored, never an exception.

Each session takes two lines::

    ID          Application    State   Type Flag  Src[Sport]/Zone/Proto (translated IP[Port])
    Vsys                                         Dst[Dport]/Zone (translated IP[Port])
"""
from __future__ import annotations

import re

_ADDR_RE = re.compile(r"^(?P<ip>.+)\[(?P<port>\d+)\]/(?P<zone>.+?)(?:/(?P<proto>\d+))?$")
_NAT_RE = re.compile(r"^\((?P<ip>.+)\[(?P<port>\d+)\]\)$")
_ID_RE = re.compile(r"^\d{1,12}$")


def _endpoint(token: str) -> dict | None:
    m = _ADDR_RE.match(token)
    if not m:
        return None
    return {"ip": m.group("ip"), "port": int(m.group("port")), "zone": m.group("zone"),
            "proto": int(m.group("proto")) if m.group("proto") else None}


def _nat(tokens: list[str]) -> dict | None:
    for tok in tokens:
        m = _NAT_RE.match(tok)
        if m:
            return {"ip": m.group("ip"), "port": int(m.group("port"))}
    return None


def parse_sessions_page(text: str) -> list[dict]:
    """Sessions of one page: id, app, state, type, flags, vsys, src/dst (ip, port, zone, proto)
    and the translated source/destination when NAT is shown. Incomplete records are skipped."""
    out: list[dict] = []
    lines = (text if isinstance(text, str) else "").splitlines()
    i = 0
    while i < len(lines) - 1:
        tok = lines[i].split()
        if len(tok) >= 5 and _ID_RE.match(tok[0]):
            src_idx = next((k for k, x in enumerate(tok) if "[" in x and k >= 4), None)
            nxt = lines[i + 1].split()
            dst_idx = next((k for k, x in enumerate(nxt) if "[" in x and k >= 1), None)
            if src_idx is not None and dst_idx is not None:
                src, dst = _endpoint(tok[src_idx]), _endpoint(nxt[dst_idx])
                if src and dst:
                    out.append({
                        "id": int(tok[0]), "app": tok[1], "state": tok[2], "type": tok[3],
                        "flags": " ".join(tok[4:src_idx]), "vsys": " ".join(nxt[:dst_idx]),
                        "src": src, "dst": dst,
                        "nat_src": _nat(tok[src_idx + 1:]), "nat_dst": _nat(nxt[dst_idx + 1:]),
                    })
                    i += 2
                    continue
        i += 1
    return out


def is_end_of_table(text: str, rows: list[dict]) -> bool:
    """True when a page has no session (past the end of the table, or an error answer)."""
    return not rows

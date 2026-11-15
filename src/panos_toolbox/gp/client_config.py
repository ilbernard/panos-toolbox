"""Client configuration and state of a GlobalProtect Windows client, rebuilt from the bundle.

Standard library only. Public entry point::

    cfg = build_config(bundle)      # bundle: gp.bundle.Bundle
    cfg.sections                    # ordered list of Section
    cfg.to_dict()                   # plain JSON-serialisable data

``build_config`` never raises for bad or missing data: a missing file gives a section with a
"Not in bundle" note, unparseable content gives a note and whatever could be recovered.

Model
-----
``ClientConfig`` holds an ordered list of ``Section`` (ids, in order): ``summary``, ``registry``,
``status``, ``portal_settings``, ``gateways``, ``hip_report``, ``troubleshooting``,
``host_network``, ``driver``.

``Section`` fields: ``id``, ``title``, ``sources`` (bundle file names), ``timestamp`` (naive local
datetime of the information, or None), ``freshness``, ``note`` and ``groups``.

``freshness``
  ``current``     state at collection time (static snapshot files, registry dump)
  ``last_seen``   most recent value found in rolling logs (may predate the collection)
  ``historical``  stale artefact (older than the newest log record by more than a day)

``Group`` = ``title`` + ``rows``; ``Row`` = ``label``, ``value`` (str; multi-valued data is joined
with newlines), ``key`` (raw key, e.g. the registry value name or the XML element) and ``hint``
(provenance or INFERENCE remark). Long values are kept whole: the report truncates for display.

``ClientConfig.to_dict()`` returns ``{"collected_at", "newest_record", "warnings", "sections",
"data"}``; datetimes are ISO strings. ``data`` holds the structured facts a later step turns into
findings: ``connection`` (connected yes/no/unknown with evidence), ``pangp_adapter``,
``connect_method``, ``registry``, ``portal_settings``, ``gateway_configs``, ``gateway_list``,
``hip``, ``troubleshooting``, ``host``, ``adapters``, ``routes`` and ``driver_events`` (one dict
per setupapi line that mentions PANGP: ``ts``, ``section``, ``kind``, ``device``, ``code``,
``status``, ``meaning``, ``text``).

Dates are kept as logged (naive local time, no time-zone conversion). The only exception is the
epoch of the troubleshooting report, which is UTC: it is shown in UTC and, when
``host_gmt_timeoffset`` is present, also as local time (offset in minutes: INFERENCE). Locale
dependent formats are parsed defensively; when that fails the raw string is kept.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .bundle import Bundle
from .logs import Record, iter_event_log, iter_records

CURRENT = "current"
LAST_SEEN = "last_seen"
HISTORICAL = "historical"

STALE_AFTER = timedelta(days=1)
MAX_DRIVER_EVENTS = 500
_MARKER = "ResponseToClient.txt_output: "
MAX_COMPACT_GATEWAYS = 12    # longer gateway lists are shown as one compact group
_PANGP_RE = re.compile(r"pangp|palo alto|globalprotect", re.IGNORECASE)


# ------------------------------------------------------------------------- model
@dataclass
class Row:
    label: str
    value: str
    key: str = ""
    hint: str = ""


@dataclass
class Group:
    title: str
    rows: list[Row] = field(default_factory=list)


@dataclass
class Section:
    id: str
    title: str
    sources: list[str]
    timestamp: datetime | None
    freshness: str
    note: str = ""
    groups: list[Group] = field(default_factory=list)


@dataclass
class ClientConfig:
    sections: list[Section] = field(default_factory=list)
    collected_at: datetime | None = None
    newest_record: datetime | None = None
    warnings: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def section(self, sid: str) -> Section | None:
        for sec in self.sections:
            if sec.id == sid:
                return sec
        return None

    def to_dict(self) -> dict[str, Any]:
        return _jsonable({
            "collected_at": self.collected_at,
            "newest_record": self.newest_record,
            "warnings": self.warnings,
            "sections": [
                {"id": s.id, "title": s.title, "sources": s.sources, "timestamp": s.timestamp,
                 "freshness": s.freshness, "note": s.note,
                 "groups": [{"title": g.title,
                             "rows": [{"label": r.label, "value": r.value, "key": r.key,
                                       "hint": r.hint} for r in g.rows]}
                            for g in s.groups]}
                for s in self.sections],
            "data": self.data,
        })


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat(sep=" ")
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _fmt(dt: datetime | None) -> str:
    return "" if dt is None else dt.strftime("%Y-%m-%d %H:%M:%S")


def _row(label: str, value: Any, key: str = "", hint: str = "") -> Row:
    return Row(label, "" if value is None else str(value), key, hint)


def _not_in_bundle(sid: str, title: str, files: list[str], fresh: str) -> Section:
    return Section(sid, title, files, None, fresh,
                   note="Not in bundle: " + ", ".join(files) + ".")


# --------------------------------------------------------------------- dates
_DT_RE = re.compile(
    r"^\s*(\d{1,4})[/.\-](\d{1,2})[/.\-](\d{1,4})[,\s]+(\d{1,2}):(\d\d)(?::(\d\d))?"
    r"(?:[.:](\d+))?\s*([AaPp][Mm])?\s*$")


def parse_datetime(text: str, prefer: str = "mdy",
                   ref: datetime | None = None) -> tuple[datetime | None, bool]:
    """Parse ``a/b/yyyy HH:MM[:SS]`` or ``yyyy/mm/dd HH:MM:SS[.mmm]`` defensively.

    Returns ``(datetime or None, ambiguous)``. When day and month cannot be told apart the
    order ``prefer`` ("mdy" or "dmy") decides, unless ``ref`` is given: then the candidate that
    is not later than ``ref`` (plus one day) and closest to it wins. ``(None, False)`` when the
    text does not parse.
    """
    m = _DT_RE.match(text or "")
    if not m:
        return None, False
    a, b, c = m.group(1), m.group(2), m.group(3)
    hh, mi = int(m.group(4)), int(m.group(5))
    ss = int(m.group(6) or 0)
    frac = (m.group(7) or "0")[:6].ljust(6, "0")
    ampm = (m.group(8) or "").lower()
    if ampm:
        hh = hh % 12 + (12 if ampm == "pm" else 0)
    if len(a) == 4:
        pairs = [(int(a), int(b), int(c))]                  # y, m, d
    else:
        year = int(c) + (2000 if len(c) <= 2 else 0)
        mdy, dmy = (year, int(a), int(b)), (year, int(b), int(a))
        pairs = [mdy, dmy] if prefer == "mdy" else [dmy, mdy]
    found: list[datetime] = []
    for y, mo, d in pairs:
        try:
            dt = datetime(y, mo, d, hh, mi, ss, int(frac))  # noqa: DTZ001 - naive local time
        except ValueError:
            continue
        if dt not in found:
            found.append(dt)
    if not found:
        return None, False
    if len(found) == 1:
        return found[0], False
    if ref is not None:
        ok = [d for d in found if d <= ref + timedelta(days=1)]
        if ok:
            return max(ok), True
    return found[0], True


def _epoch(value: Any) -> datetime | None:
    """Naive UTC datetime of an epoch in seconds (None when it is not a plausible epoch)."""
    try:
        sec = float(value)
        if not 10**8 < sec < 10**11:
            return None
        return datetime.fromtimestamp(sec, tz=timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


# ---------------------------------------------------------------------- XML
def _close_open_tags(text: str) -> str:
    cut = max(text.rfind(">"), -1)
    text = text[:cut + 1]
    stack: list[str] = []
    for m in re.finditer(r"<(/?)([A-Za-z][\w.:-]*)[^<>]*?(/?)>", text):
        if m.group(3):
            continue
        if m.group(1):
            if stack and stack[-1] == m.group(2):
                stack.pop()
        else:
            stack.append(m.group(2))
    return text + "".join(f"</{tag}>" for tag in reversed(stack))


def parse_xml(text: str) -> tuple[ET.Element | None, bool]:
    """Parse an XML document found in a log; ``(root, truncated)`` or ``(None, False)``.

    Leading text before the first ``<`` and the XML declaration are dropped, text after the
    last closing tag of the root is ignored, a document cut by the logger (or by a rotation) is
    closed and flagged ``truncated``. DOCTYPE/ENTITY declarations are refused. Never raises.
    """
    try:
        start = text.find("<")
        if start < 0:
            return None, False
        text = text[start:]
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            return None, False
        text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text).strip()
        m = re.match(r"<([A-Za-z][\w.:-]*)", text)
        if not m:
            return None, False
        closing = f"</{m.group(1)}>"
        end = text.rfind(closing)
        if end >= 0:
            try:
                return ET.fromstring(text[:end + len(closing)]), False
            except ET.ParseError:
                pass
        try:
            return ET.fromstring(_close_open_tags(text)), True
        except ET.ParseError:
            return None, False
    except (ValueError, RecursionError, MemoryError):
        return None, False


def _text(el: ET.Element | None, path: str = "") -> str:
    if el is None:
        return ""
    node = el.find(path) if path else el
    return (node.text or "").strip() if node is not None else ""


def _members(el: ET.Element | None) -> list[str]:
    if el is None:
        return []
    return [(c.text or "").strip() for c in el.findall("member") if (c.text or "").strip()]


def _flat_rows(el: ET.Element, skip: tuple[str, ...] = (), prefix: str = "") -> list[tuple[str, str]]:
    """(path, value) pairs of the leaves below ``el``; ``member`` lists are joined by newlines."""
    out: list[tuple[str, str]] = []
    kids = [c for c in el if c.tag not in skip]
    counts: dict[str, int] = {}
    for c in kids:
        counts[c.tag] = counts.get(c.tag, 0) + 1
    seen: dict[str, int] = {}
    for c in kids:
        name = c.tag
        if counts[name] > 1:
            seen[name] = seen.get(name, 0) + 1
            name = f"{name}[{c.get('name') or seen[name]}]"
        path = f"{prefix}.{name}" if prefix else name
        sub = list(c)
        if not sub:
            out.append((path, (c.text or "").strip()))
        elif all(s.tag == "member" for s in sub):
            out.append((path, "\n".join(_members(c))))
        else:
            out.extend(_flat_rows(c, (), path))
    return out


# ------------------------------------------------------------------ regval.txt
_KEY_FULL = re.compile(rb"([A-Za-z][A-Za-z0-9_.\-]{0,79})=(.*)$", re.DOTALL)
_KEY_ANY = re.compile(rb"(?:^|[^A-Za-z0-9_.\-])([A-Za-z][A-Za-z0-9_.\-]{0,79})=(.*)$", re.DOTALL)
_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z ]{0,40}?)\s*:\s*(.*)$")


@dataclass
class RegSetting:
    key: str
    value: str
    type: str       # "sz" or "dword"


@dataclass
class RegistryDump:
    settings: list[RegSetting] = field(default_factory=list)
    credential_filters: list[dict[str, Any]] = field(default_factory=list)
    states: list[tuple[str, str]] = field(default_factory=list)   # (header, value or sentence)
    duplicates: list[str] = field(default_factory=list)
    garbage_lines: int = 0


def _printable(b: int) -> bool:
    return 32 <= b < 127 or b >= 160


def decode_reg_value(raw: bytes) -> tuple[str, str]:
    """Decode the bytes after ``=``: ``(value, "sz" | "dword")``.

    REG_SZ is the text followed by one NUL (an empty string is a single NUL, text ends at the
    first NUL, garbage after it is dropped). REG_DWORD is 4 raw little-endian bytes
    (INFERENCE): a 4-byte value that ends in two NULs or has a non-printable byte among the first
    three is a DWORD.
    """
    if len(raw) >= 4:
        head = raw[:4]
        if len(raw) == 4 and (head[2:] == b"\x00\x00" or not all(_printable(b) for b in head[:3])):
            return str(int.from_bytes(head, "little")), "dword"
        if not _printable(head[0]) and head[0] != 0 and head[1:4].count(0) >= 2:
            return str(int.from_bytes(head, "little")), "dword"
    text = raw.split(b"\x00", 1)[0]
    return text.decode("latin-1").strip(), "sz"


def parse_regval(data: bytes) -> RegistryDump:
    """Parse the registry dump (see the module spec): every ``key=value`` line is kept."""
    dump = RegistryDump()
    seen: dict[str, int] = {}
    section = ""
    for raw in data.split(b"\r\n"):
        line = raw.lstrip(b"\x00")
        m = _KEY_FULL.match(line)
        if m is None and line and not _printable(line[0]):
            m = _KEY_ANY.search(line)
        if m is not None:
            key = m.group(1).decode("latin-1")
            value, kind = decode_reg_value(m.group(2))
            item = RegSetting(key, value, kind)
            if key in seen:
                dump.duplicates.append(key)
                dump.settings[seen[key]] = item
            else:
                seen[key] = len(dump.settings)
                dump.settings.append(item)
            continue
        text = "".join(ch for ch in line.decode("latin-1") if ch.isprintable()).strip()
        if not text:
            continue
        if section == "settings":
            dump.garbage_lines += 1
            continue
        if text.lower() == "settings":
            section = "settings"
            continue
        if text.count(" | ") == 2:
            path, value, when = (p.strip().strip("\x00") for p in text.split(" | "))
            dt, _ = parse_datetime(" ".join(reversed(when.split(" ", 1))), "mdy")
            dump.credential_filters.append({"path": path, "value": value,
                                            "time": dt, "time_raw": when})
            continue
        hm = _HEADER_RE.match(text) if "\\" not in text else None
        if hm and not text.endswith("!!!"):
            section = hm.group(1).strip()
            if hm.group(2).strip():
                dump.states.append((section, hm.group(2).strip()))
            continue
        if text.endswith("!!!"):
            dump.states.append((section or "General", text.rstrip("! ")))
        else:
            dump.garbage_lines += 1
    return dump


# --------------------------------------------------------------------- logs
@dataclass
class _Doc:
    ts: datetime
    src: str
    root: ET.Element
    truncated: bool
    type: str


_ECHO_LABELS = {
    "connect_method": "Connect method", "portal_auth": "Portal authentication",
    "gateway_auth": "Gateway authentication", "grace": "Tunnel retry grace period",
    "hip_interval": "HIP check interval", "mtu": "Configured tunnel MTU",
    "encryption": "Tunnel encryption", "timeouts": "Timeouts (seconds)",
    "region": "Region code", "prelogon": "Pre-logon enabled (0 = no)",
}
# Further facts echoed by the service log. The patterns are anchored on the message text only:
# the source number in the record prefix changes between client builds. All echoes (this list
# and the basic settings) are matched with ONE alternation: the name of the matched value
# group says which fact it is.
_AUTH_ECHOES = [
    ("saml_method", r"Portal's saml auth method (?P<saml_method>\S+)"),
    ("saml_browser_support", r"Portal's saml default browser support = (?P<saml_browser_support>\S+)"),
    ("use_default_browser", r"Prelogin use-default-browser = (?P<use_default_browser>\S+)"),
    ("saml_timeout", r"Portal's saml request timeout is (?P<saml_timeout>\d+)"),
    ("sso", r"SSO enable status is (?P<sso>\d+)"),
    ("allow_cached_portal", r"allow-cached-portal is (?P<allow_cached_portal>\S+)"),
    ("network_type", r"NetworkDiscoverThread: network type is (?P<network_type>\w+)"),
    ("tunnel_up", r"Connected (?P<tunnel_up>(?:ipsec|ssl) to \S+)"),
    ("last_disconnect", r"Disconnect\((?P<last_disconnect>[^)]*)\) called"),
    ("external_gw_count", r"Discover external gateway: gateway count is (?P<external_gw_count>\d+)"),
    ("internal_gw_count", r"Gateway count is (?P<internal_gw_count>\d+) for internal network"),
]
_AUTH_LABELS = {
    "saml_method": "Portal SAML method", "saml_browser_support": "Portal supports the default browser",
    "use_default_browser": "Prelogin uses the default browser (no = embedded browser)",
    "saml_timeout": "SAML request timeout (s)", "sso": "SSO enabled (1 = yes)",
    "allow_cached_portal": "Cached portal allowed",
}
_ECHO_PATTERNS = [
    r"Connect method is (?P<connect_method>.+)",
    r"Portal auth method: (?P<portal_auth>.+)",
    r"Gateway auth method: (?P<gateway_auth>.+)",
    r"Tunnel retry grace period is (?P<grace>.+)",
    r"Hip check interval is (?P<hip_interval>.+)",
    r"Configured MTU is (?P<mtu>\d+)",
    r"Encryption method is (?P<encryption>\S+)",
    r"Timeout value: (?P<timeouts>.+)",
    r"REGION-PRIO, (?:cached )?region code is (?P<region>\S+)",
    *[pat for _, pat in _AUTH_ECHOES],
]
_ECHO_RE = re.compile("(?:" + "|".join(_ECHO_PATTERNS) + ")")
_PRELOGON_RE = re.compile(r"PrelogonEnabled is (\d)")
_GWPROBE_RE = re.compile(
    r"^gateway (.+?) \((\S+)\), priority=(-?\d+), duration=(\d+) ms, assign (\d+) as its weight")
_PORTAL_RE = re.compile(r"^Portal (\S+), user (\S*), logonDomain ?(\S*)")
_UA_RE = re.compile(r"PAN GlobalProtect/([\d.\-]+) \(([^)]*)\)")
_BANNER_RE = re.compile(r"Start PanGPS service \(ver: ([\d.\-]+)\)")
_GWCFG_RE = re.compile(r"^gateway (\S+)'s config is(.*)$")
_GWENT_RE = re.compile(r"^Gateway (\S+)\(([^)]*)\): ipv4 (\S*), ipv6 (\S*), FQDN (yes|no)")
_STATE_RE = re.compile(r"^--Set state to (.+)$")
_TYPE_RE = re.compile(r"^message type from the service = (\S+)")


class _LogScan:
    """Facts collected from the service and agent logs (newest occurrence of each wins)."""

    def __init__(self) -> None:
        self.complete: dict[str, _Doc] = {}
        self.partial: dict[str, _Doc] = {}
        self.status_with_gateways: _Doc | None = None
        self.status_connected: _Doc | None = None
        self.gateway_cfg: dict[str, _Doc] = {}
        self.gateway_entries: dict[str, dict[str, Any]] = {}
        self.echoes: dict[str, tuple[datetime, str, str]] = {}
        self.state: tuple[datetime, str, str] | None = None
        self.service_start: tuple[datetime, str] | None = None
        self.service_stop: datetime | None = None
        self.versions: dict[str, tuple[datetime, str]] = {}
        self.starts: list[tuple[datetime, str, int, str]] = []   # ts, version, pid, file
        self.stops: list[tuple[datetime, int]] = []
        self.portals: dict[str, list] = {}         # name -> [first, last, count]
        self.methods: dict[str, list] = {}         # connect method -> [first, last, count]
        self.probes: dict[str, dict[str, Any]] = {}
        self.prelogon_user_seen = False
        self.user: tuple[datetime, str, str] | None = None
        self.portal: tuple[datetime, str, str] | None = None
        self.domain = ""
        self.os_agent = ""
        self.xml_errors = 0
        self.orphan_chunks = 0
        self.truncated_dumps = 0
        self.records = 0
        self._bufs: dict[tuple[int, int], list[str]] = {}
        self._bufinfo: dict[tuple[int, int], tuple[datetime, str]] = {}

    # ---- helpers
    def _note(self, key: str, rec: Record, value: str) -> None:
        cur = self.echoes.get(key)
        if cur is None or rec.ts >= cur[0]:
            self.echoes[key] = (rec.ts, value, rec.src)

    def _version(self, source: str, rec: Record, value: str) -> None:
        cur = self.versions.get(source)
        if cur is None or rec.ts >= cur[0]:
            self.versions[source] = (rec.ts, value)

    def add_doc(self, ts: datetime, src: str, text: str, hint_type: str = "") -> None:
        root, truncated = parse_xml(text)
        if root is None:
            self.xml_errors += 1
            return
        rtype = _text(root, "type") or hint_type or "unknown"
        doc = _Doc(ts, src, root, truncated, rtype)
        store = self.partial if truncated else self.complete
        if truncated:
            self.truncated_dumps += 1
        cur = store.get(rtype)
        if cur is None or ts >= cur.ts:
            store[rtype] = doc
        if truncated or rtype not in ("status", "hello", "hip"):
            return
        user = _text(root, "user-name")
        if user and (self.user is None or ts >= self.user[0]):
            self.user = (ts, user, src)
        portal = _text(root, "portal")
        if portal:
            self._seen(self.portals, portal, ts)
        if portal and (self.portal is None or ts >= self.portal[0]):
            self.portal = (ts, portal, src)
        ver = _text(root, "product-version")
        if ver:
            cur_v = self.versions.get("status XML")
            if cur_v is None or ts >= cur_v[0]:
                self.versions["status XML"] = (ts, ver)
        if rtype == "status":
            if root.find("gateway-list/entry") is not None and (
                    self.status_with_gateways is None or ts >= self.status_with_gateways.ts):
                self.status_with_gateways = doc
            is_up = _text(root, "state") == "Connected" or _text(root, "status") == "Connected"
            if is_up and (self.status_connected is None or ts >= self.status_connected.ts):
                self.status_connected = doc

    # ---- service log
    def feed_service(self, rec: Record) -> None:
        self.records += 1
        msg = rec.msg
        if msg.startswith(_MARKER) or (rec.extra and rec.extra[0].startswith(_MARKER)):
            self._chunk(rec)
            return
        m = _STATE_RE.match(msg)
        if m:
            if self.state is None or rec.ts >= self.state[0]:
                self.state = (rec.ts, m.group(1).strip(), rec.src)
            return
        if "Start PanGPS service" in msg:
            m = _BANNER_RE.search(msg)
            if m:
                self._version("service banner", rec, m.group(1))
                self.starts.append((rec.ts, m.group(1), rec.pid, rec.src))
                if self.service_start is None or rec.ts >= self.service_start[0]:
                    self.service_start = (rec.ts, rec.src)
            return
        if msg.startswith(("PanGPS service exits", "Received shutdown message")):
            if msg.startswith("PanGPS service exits"):
                self.stops.append((rec.ts, rec.pid))
            if self.service_stop is None or rec.ts >= self.service_stop:
                self.service_stop = rec.ts
            return
        m = _GWCFG_RE.match(msg)
        if m:
            text = m.group(2) + "\n" + rec.body
            root, truncated = parse_xml(text)
            if root is None:
                self.xml_errors += 1
            else:
                doc = _Doc(rec.ts, rec.src, root, truncated, "gateway-config")
                cur = self.gateway_cfg.get(m.group(1))
                if cur is None or rec.ts >= cur.ts:
                    self.gateway_cfg[m.group(1)] = doc
            return
        m = _GWENT_RE.match(msg)
        if m:
            self.gateway_entries[m.group(1)] = {
                "gateway": m.group(1), "description": m.group(2), "ipv4": m.group(3),
                "ipv6": m.group(4), "fqdn": m.group(5), "ts": rec.ts}
            return
        if msg.startswith("gateway "):
            m = _GWPROBE_RE.match(msg)
            if m:
                self.probes[m.group(2)] = {"region": m.group(1), "priority": m.group(3),
                                           "ms": m.group(4), "weight": m.group(5), "ts": rec.ts}
                return
        m = _PORTAL_RE.match(msg)
        if m:
            if self.portal is None or rec.ts >= self.portal[0]:
                self.portal = (rec.ts, m.group(1), rec.src)
            self._seen(self.portals, m.group(1), rec.ts)
            if m.group(2) == "pre-logon":
                self.prelogon_user_seen = True
            elif m.group(2) and (self.user is None or rec.ts >= self.user[0]):
                self.user = (rec.ts, m.group(2), rec.src)
            self.domain = m.group(3) or self.domain
            return
        if "PAN GlobalProtect/" in msg:
            m = _UA_RE.search(msg)
            if m:
                self._version("user agent", rec, m.group(1))
                self.os_agent = m.group(2)
            return
        m = _ECHO_RE.match(msg)
        if m and m.lastgroup:
            value = m.group(m.lastgroup).strip()
            self._note(m.lastgroup, rec, value)
            if m.lastgroup == "connect_method":
                self._seen(self.methods, value, rec.ts)
            return
        if "PrelogonEnabled is" in msg:
            m = _PRELOGON_RE.search(msg)
            if m:
                self._note("prelogon", rec, m.group(1))

    @staticmethod
    def _seen(store: dict[str, list], key: str, ts: datetime) -> None:
        cur = store.get(key)
        if cur is None:
            store[key] = [ts, ts, 1]
        else:
            cur[0], cur[1], cur[2] = min(cur[0], ts), max(cur[1], ts), cur[2] + 1

    def _chunk(self, rec: Record) -> None:
        """Reassemble the status XML that the service logs in chunks of about 2 KB."""
        if rec.msg.startswith(_MARKER):
            text = rec.msg[len(_MARKER):] + ("\n" + rec.body if rec.extra else "")
        elif rec.extra and rec.extra[0].startswith(_MARKER):
            text = "\n".join([rec.extra[0][len(_MARKER):], *rec.extra[1:]])
        else:
            return          # not a status chunk
        key = (rec.pid, rec.tid)
        head = text.lstrip()
        if head.startswith(("<?xml", "<response")):
            if key in self._bufs:
                self._flush(key)        # the previous dump was cut: use what there is
            self._bufs[key] = [text]
            self._bufinfo[key] = (rec.ts, rec.src)
        elif key in self._bufs:
            self._bufs[key].append(text)
        else:
            self.orphan_chunks += 1     # a dump that started before the first record we have
            return
        joined = "".join(self._bufs[key])
        if joined.rstrip().endswith("</response>"):
            self._flush(key)
        elif len(joined) > 2_000_000:
            self._bufs.pop(key, None)
            self._bufinfo.pop(key, None)

    def _flush(self, key: tuple[int, int]) -> None:
        text = "".join(self._bufs.pop(key, []))
        ts, src = self._bufinfo.pop(key, (None, ""))
        if ts is not None and text.strip():
            self.add_doc(ts, src, text)

    def finish(self) -> None:
        for key in list(self._bufs):
            self._flush(key)

    # ---- agent log
    def feed_agent(self, rec: Record) -> None:
        m = _TYPE_RE.match(rec.msg)
        if m and rec.extra:
            self.add_doc(rec.ts, rec.src, rec.body, m.group(1))


_TS_TAIL_RE = re.compile(r"\): (\d\d)/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d):(\d{3})")
_EV_TAIL_RE = re.compile(r"(?m)^(\d\d)/(\d\d)/(\d{4}) (\d\d):(\d\d):(\d\d):(\d{3}) \[")


def _tail_ts(text: str, rx: re.Pattern[str], two_digit_year: bool) -> datetime | None:
    best = None
    for m in list(rx.finditer(text[-60000:]))[-40:]:
        mo, d, y, h, mi, s, ms = (int(g) for g in m.groups())
        try:
            dt = datetime(y + (2000 if two_digit_year else 0), mo, d, h, mi, s, ms * 1000)  # noqa: DTZ001
        except ValueError:
            continue
        if best is None or dt > best:
            best = dt
    return best


def _scan_logs(bundle: Bundle) -> tuple[_LogScan, dict[str, datetime | None]]:
    scan = _LogScan()
    newest: dict[str, datetime | None] = {}
    for name in bundle.rotation("PanGPS"):
        text = bundle.read_text(name, "client configuration")
        if not text:
            continue
        for rec in iter_records(text, name, skip_levels={"Dump"}, keep_msgs=(_MARKER,)):
            scan.feed_service(rec)
        ts = _tail_ts(text, _TS_TAIL_RE, True)
        if ts and (newest.get("service") is None or ts > newest["service"]):
            newest["service"] = ts
    scan.finish()
    for name in bundle.rotation("PanGPA"):
        text = bundle.read_text(name, "client configuration")
        if not text:
            continue
        for rec in iter_records(text, name):
            scan.feed_agent(rec)
        ts = _tail_ts(text, _TS_TAIL_RE, True)
        if ts and (newest.get("agent") is None or ts > newest["agent"]):
            newest["agent"] = ts
    scan.finish()
    return scan, newest


@dataclass
class _EventFacts:
    newest: datetime | None = None
    connect_method: tuple[datetime, str] | None = None
    service_started: tuple[datetime, str, str] | None = None   # ts, version, os


_EV_START_RE = re.compile(r"service started \(client version: ([^,]+), OS version: (.*?)\)\.?$")
_EV_CONNECT_RE = re.compile(r"^Connect method is (.+)$")


def _scan_events(bundle: Bundle) -> _EventFacts:
    facts = _EventFacts()
    for name in reversed(bundle.rotation("pan_gp_event")):       # newest file first
        text = bundle.read_text(name, "client configuration")
        if not text:
            continue
        if facts.newest is None:
            facts.newest = _tail_ts(text, _EV_TAIL_RE, False)
        need_cm = facts.connect_method is None and "Connect method is " in text
        need_start = facts.service_started is None and "service started (client version" in text
        if need_cm or need_start:
            for line in iter_event_log(text, name):
                if need_cm:
                    m = _EV_CONNECT_RE.match(line.msg)
                    if m and (facts.connect_method is None or line.ts >= facts.connect_method[0]):
                        facts.connect_method = (line.ts, m.group(1).strip())
                if need_start:
                    m = _EV_START_RE.search(line.msg)
                    if m and (facts.service_started is None or line.ts >= facts.service_started[0]):
                        facts.service_started = (line.ts, m.group(1).strip(), m.group(2).strip())
        if facts.connect_method and facts.service_started and facts.newest:
            break
    return facts


# ------------------------------------------------------------ static text files
def parse_systeminfo(text: str) -> dict[str, str]:
    """``systeminfo`` output as ``{label: value}`` (continuation lines joined by newlines)."""
    out: dict[str, str] = {}
    last = ""
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":
            if last:
                out[last] = (out[last] + "\n" + line.strip()).strip("\n")
            continue
        m = re.match(r"^(\S.*?):\s{2,}(.*)$", line) or re.match(r"^(\S[^:]*):\s*$", line)
        if m:
            last = m.group(1).strip()
            out[last] = (m.group(2) if m.lastindex and m.lastindex > 1 else "").strip()
    return out


_ADAPTER_RE = re.compile(r"^(\S.*):\s*$")
_FIELD_RE = re.compile(r"^(\s+)(\S.*?)[ .]*:(?: (.*))?$")


def _clean_addr(value: str) -> str:
    value = re.sub(r"\((?:Preferred|Duplicate|Tentative|Deprecated)\)\s*$", "", value.strip(),
                   flags=re.IGNORECASE)
    return re.sub(r"%\d+$", "", value.strip())


def parse_ipconfig(text: str) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    """``ipconfig /all`` as ``(general fields, adapters)``; field values are lists of strings."""
    general: dict[str, list[str]] = {}
    adapters: list[dict[str, Any]] = []
    cur: dict[str, list[str]] = general
    indent = 0
    last = ""
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] not in " \t":
            m = _ADAPTER_RE.match(line)
            if m:
                adapter = {"name": m.group(1).strip(), "fields": {}}
                adapters.append(adapter)
                cur = adapter["fields"]
                indent, last = 0, ""
            continue
        if indent == 0:
            indent = len(line) - len(line.lstrip())
        lead = len(line) - len(line.lstrip())
        if lead > indent and last:
            cur[last].append(line.strip())
            continue
        m = _FIELD_RE.match(line)
        if m:
            last = m.group(2).strip()
            cur.setdefault(last, [])
            if (m.group(3) or "").strip():
                cur[last].append(m.group(3).strip())
    return general, adapters


def _field(fields: dict[str, list[str]], *patterns: str) -> list[str]:
    for label, values in fields.items():
        if any(re.match(p, label, re.IGNORECASE) for p in patterns):
            return values
    return []


def adapter_info(adapter: dict[str, Any]) -> dict[str, Any]:
    f = adapter["fields"]
    media = _field(f, r"media state")
    return {
        "name": adapter["name"],
        "state": "disconnected" if media else "connected",
        "media_state": media[0] if media else "",
        "description": (_field(f, r"description") or [""])[0],
        "mac": (_field(f, r"physical address") or [""])[0],
        "dhcp": (_field(f, r"dhcp enabled") or [""])[0],
        "ipv4": [_clean_addr(v) for v in _field(f, r"(autoconfiguration )?ipv4 address", r"ip address")],
        "ipv6": [_clean_addr(v) for v in _field(f, r".*ipv6 address")],
        "subnet_mask": _field(f, r"subnet mask"),
        "gateway": [_clean_addr(v) for v in _field(f, r"default gateway") if v],
        "dns": [_clean_addr(v) for v in _field(f, r"dns servers")],
        "dns_suffix": (_field(f, r"connection-specific dns suffix") or [""])[0],
        "lease_obtained": (_field(f, r"lease obtained") or [""])[0],
        "lease_expires": (_field(f, r"lease expires") or [""])[0],
    }


_ROUTE4_RE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s*$")
_ROUTE6_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\S+)(?:\s+(\S+))?\s*$")
_IFACE_RE = re.compile(r"^\s*(\d+)\.\.\.(?:[0-9a-fA-F ]*)\.*(.*)$")


def parse_route_print(text: str) -> dict[str, Any]:
    """``route print``: interface descriptions, IPv4 routes, IPv6 routes, default routes."""
    interfaces: list[str] = []
    v4: list[dict[str, Any]] = []
    v6: list[dict[str, Any]] = []
    persistent: list[str] = []
    section = ""
    sub = ""
    for line in text.splitlines():
        s = line.strip()
        if not s or set(s) == {"="}:
            continue
        low = s.lower()
        if low == "interface list":
            section = "iface"
            continue
        if low == "ipv4 route table":
            section, sub = "v4", ""
            continue
        if low == "ipv6 route table":
            section, sub = "v6", ""
            continue
        if low.startswith("active routes"):
            sub = "active"
            continue
        if low.startswith("persistent routes"):
            sub = "persistent"
            continue
        if section == "iface":
            m = _IFACE_RE.match(line)
            if m and m.group(2).strip():
                interfaces.append(m.group(2).strip("."). strip())
        elif section == "v4" and sub == "active":
            m = _ROUTE4_RE.match(line)
            if m:
                v4.append({"destination": m.group(1), "netmask": m.group(2), "gateway": m.group(3),
                           "interface": m.group(4), "metric": int(m.group(5))})
        elif section == "v4" and sub == "persistent" and low != "none":
            persistent.append(s)
        elif section == "v6" and sub == "active":
            m = _ROUTE6_RE.match(line)
            if m and not low.startswith("if metric"):
                v6.append({"if": int(m.group(1)), "metric": int(m.group(2)),
                           "destination": m.group(3), "gateway": m.group(4) or ""})
            elif v6 and not v6[-1]["gateway"] and re.match(r"^\S+$", s):
                v6[-1]["gateway"] = s
    return {
        "interfaces": interfaces, "ipv4": v4, "ipv6": v6, "persistent": persistent,
        "default_v4": [r for r in v4 if r["destination"] == "0.0.0.0" and r["netmask"] == "0.0.0.0"],
        "default_v6": [r for r in v6 if r["destination"] == "::/0"],
    }


# ------------------------------------------------------------- trb / hip / driver
def parse_trb(text: str) -> tuple[dict[str, Any], bool]:
    """Troubleshooting report as ``(fields, cut)``; falls back to key/value regexes."""
    text = text.replace("\x00", "").strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj, False
    except ValueError:
        pass
    fields: dict[str, Any] = {}
    for m in re.finditer(r'"([\w\-]+)"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null'
                         r"|\[[^\]]*\]|\{[^}]*\})", text):
        try:
            fields[m.group(1)] = json.loads(m.group(2))
        except ValueError:
            fields[m.group(1)] = m.group(2)
    tail = re.search(r'"([\w\-]+)"\s*:\s*"([^"]*)$', text)
    cut = False
    if tail and tail.group(1) not in fields:
        fields[tail.group(1)] = tail.group(2)
        cut = True
    return fields, cut or not text.endswith("}")


_PROBLEM_RE = re.compile(r"Device '([^']+)' has problem\. Code = (\d+), Status = (0x[0-9a-fA-F]+)")
_PROBLEM_MEANING = {
    1: "not configured correctly", 10: "device cannot start", 14: "restart needed",
    18: "drivers must be reinstalled", 21: "Windows is removing the device",
    22: "device is disabled", 24: "device missing or not working", 28: "drivers not installed",
    31: "device not working properly", 37: "driver returned a failure", 39: "driver corrupted",
    43: "device stopped, it reported a problem", 52: "driver signature cannot be verified",
}


def parse_setupapi(text: str) -> list[dict[str, Any]]:
    """Lines of ``setupapi.dev.log`` that mention PANGP, with the timestamp of their section."""
    events: list[dict[str, Any]] = []
    title = ""
    ts: datetime | None = None
    for line in text.splitlines():
        if line.startswith(">>>  [") and "Section start" not in line:
            title = line[6:].rstrip("] \t")
            ts = None
            if re.search(r"pangp", title, re.IGNORECASE):
                events.append({"ts": None, "section": title, "kind": "section", "device": "",
                               "code": None, "status": "", "meaning": "", "text": line.strip()})
            continue
        if line.startswith(">>>  Section start"):
            ts, _ = parse_datetime(line.split("start", 1)[1].strip(), "mdy")
            if events and events[-1]["kind"] == "section" and events[-1]["ts"] is None \
                    and events[-1]["section"] == title:
                events[-1]["ts"] = ts
            continue
        if "pangp" not in line.lower():
            continue
        m = _PROBLEM_RE.search(line)
        event = {"ts": ts, "section": title, "kind": "line", "device": "", "code": None,
                 "status": "", "meaning": "", "text": line.strip()}
        if m:
            code = int(m.group(2))
            event.update(kind="problem", device=m.group(1), code=code, status=m.group(3),
                         meaning=_PROBLEM_MEANING.get(code, ""))
        events.append(event)
    return events


def _category_summary(entry: ET.Element) -> str:
    products = []
    for item in entry.findall("list/entry"):
        info = item.find("ProductInfo")
        prod = info.find("Prod") if info is not None else None
        if prod is None:
            continue
        label = " ".join(x for x in (prod.get("name", ""), prod.get("version", "")) if x)
        flags = []
        if info is not None:
            for tag, short in (("real-time-protection", "real-time"), ("is-enabled", "enabled")):
                if info.find(tag) is not None and _text(info, tag):
                    flags.append(f"{short}={_text(info, tag)}")
            for drive in info.findall("drives/entry"):
                flags.append(f"{_text(drive, 'drive-name')}={_text(drive, 'enc-state')}")
        products.append(label + (f" [{', '.join(flags)}]" if flags else ""))
    parts = []
    if products:
        shown = "; ".join(products[:6]) + (f"; +{len(products) - 6} more" if len(products) > 6 else "")
        parts.append(f"{len(products)} product(s): {shown}")
    patches = entry.findall("missing-patches/entry")
    if patches:
        missing = [p for p in patches if _text(p, "is-installed").lower() != "yes"]
        sev: dict[str, int] = {}
        for p in missing:
            sev[_text(p, "severity") or "?"] = sev.get(_text(p, "severity") or "?", 0) + 1
        parts.append(f"{len(missing)} missing patch(es) of {len(patches)} listed"
                     + (" (severity " + ", ".join(f"{k}:{v}" for k, v in sorted(sev.items())) + ")"
                        if sev else ""))
    return "; ".join(parts) if parts else "no items"


# ------------------------------------------------------------ installer log
_MSI_START_RE = re.compile(r"^=== Logging started: (\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d\d:\d\d)")
_MSI_STOP_RE = re.compile(r"^=== Logging stopped: (\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d\d:\d\d)")
_MSI_RESULT_RE = re.compile(
    r"^MSI \(\w\) \([^)]*\) \[(\d\d:\d\d:\d\d)[:.]?\d*\]: Product: (.+?) -- (.+)$")
_MSI_DONE_RE = re.compile(
    r"Windows Installer (installed|removed|reconfigured|updated|repaired)[^.]* the product\."
    r"(?: Product Name: ([^.]*)\.)?(?: Product Version: ([^.]*(?:\.\d+)*)\. Product Language)?")
_MSI_PROP_RE = re.compile(r"^Property\(S\): (ProductVersion|ProductCode|ProductName|PORTAL) = (.*)$")
_MSI_KINDS = (("install", "Installation"), ("remove", "Removal"), ("configure", "Configuration"),
              ("update", "Update"), ("repair", "Repair"))


def parse_msi_log(text: str, ref: datetime | None = None) -> list[dict[str, Any]]:
    """Install, upgrade, repair and remove events of ``PanGPMsi.log`` (one per installer session).

    The file is a Windows Installer verbose log: sessions between ``=== Logging started: ===``
    and ``=== Logging stopped: ===`` (dates are DD/MM/YYYY, times 24 h), the outcome in
    ``Product: <name> -- Installation|Removal|... completed successfully`` and the version in
    the ``ProductVersion`` property. The MSI log carries no build number.
    """
    events: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None

    def close() -> None:
        nonlocal cur
        if cur is not None and (cur.get("kind") or cur.get("version")):
            cur.setdefault("kind", "other")
            events.append(cur)
        cur = None

    for line in text.replace("\r", "").split("\n"):
        m = _MSI_START_RE.match(line)
        if m:
            close()
            ts, _ = parse_datetime(f"{m.group(1)} {m.group(2)}", "dmy", ref)
            cur = {"ts": ts, "started": ts, "kind": "", "result": "", "result_text": "",
                   "product": "", "version": "", "product_code": "", "portal": ""}
            continue
        if cur is None:
            continue
        if _MSI_STOP_RE.match(line):
            close()
            continue
        m = _MSI_PROP_RE.match(line)
        if m:
            key = {"ProductVersion": "version", "ProductCode": "product_code",
                   "ProductName": "product", "PORTAL": "portal"}[m.group(1)]
            cur[key] = m.group(2).strip()
            continue
        m = _MSI_RESULT_RE.match(line)
        if m and not cur["kind"]:
            text_ = m.group(3).strip()
            for kind, word in _MSI_KINDS:
                if text_.startswith(word):
                    cur["kind"] = kind
                    break
            else:
                cur["kind"] = "other"
            low = text_.lower()
            cur["result"] = ("success" if "completed successfully" in low
                             else "failed" if "fail" in low or "error" in low
                             else "cancelled" if "cancel" in low else "unknown")
            cur["result_text"] = text_.rstrip(".")
            cur["product"] = cur["product"] or m.group(2).strip()
            if cur["started"] is not None:
                hh, mi, ss = (int(x) for x in m.group(1).split(":"))
                ts = cur["started"].replace(hour=hh, minute=mi, second=ss, microsecond=0)
                cur["ts"] = ts if ts >= cur["started"] else ts + timedelta(days=1)
            continue
        m = _MSI_DONE_RE.search(line)
        if m and not cur["version"] and m.group(3):
            cur["version"] = m.group(3).strip()
    close()
    for prev, ev in zip(events, events[1:]):
        if (ev["kind"] == "install" and prev["kind"] == "remove" and ev["ts"] and prev["ts"]
                and ev["ts"] - prev["ts"] <= timedelta(minutes=15)):
            ev["after_removal"] = True
            ev["same_version_as_removed"] = bool(ev["version"] and ev["version"] == prev["version"])
    return events


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


# ------------------------------------------------------------------- builders
def _zip_collection_time(bundle: Bundle) -> tuple[datetime | None, str]:
    """Collection time and user from ``GlobalProtectLogs_<user>_<MMDDYYYYHHMMSS>[.zip]``."""
    m = re.search(r"GlobalProtectLogs_(.+)_(\d{14})(?:\.(?:zip|tgz|tar(?:\.\w+)?))?$",
                  bundle.path.name, re.IGNORECASE)
    if not m:
        return None, ""
    stamp = m.group(2)
    for fmt in ("%m%d%Y%H%M%S", "%d%m%Y%H%M%S"):
        try:
            return datetime.strptime(stamp, fmt), m.group(1)  # noqa: DTZ007 - naive local time
        except ValueError:
            continue
    return None, m.group(1)


def _flat_group(title: str, el: ET.Element | None, skip: tuple[str, ...] = ()) -> Group | None:
    if el is None:
        return None
    rows = []
    for path, value in _flat_rows(el, skip):
        if path.endswith("agent-user-override-key"):
            value = "****" if value else ""
        rows.append(_row(path, value, path))
    return Group(title, rows) if rows else None


def _status_labels(key: str) -> str:
    return {"state": "State", "status": "Status", "protocol": "Tunnel protocol",
            "portal": "Portal", "user-name": "User", "portal-status": "Portal status",
            "product-version": "Client version", "error": "Error", "local-ip": "Tunnel IP",
            "server-ip": "Gateway IP", "username-type": "User name type"}.get(key, key)


class _Builder:
    def __init__(self, bundle: Bundle) -> None:
        self.b = bundle
        self.cfg = ClientConfig()
        self.data = self.cfg.data
        self.scan, self.newest = _scan_logs(bundle)
        self.events = _scan_events(bundle)
        times = [t for t in (*self.newest.values(), self.events.newest) if t]
        self.cfg.newest_record = max(times) if times else None
        self.cfg.collected_at, self.zip_user = _zip_collection_time(bundle)
        self.ref = self.cfg.newest_record or self.cfg.collected_at
        self.collected_basis = "file name" if self.cfg.collected_at else ""
        if self.cfg.collected_at is None and self.cfg.newest_record is not None:
            self.cfg.collected_at = self.cfg.newest_record       # the name carries no timestamp
            self.collected_basis = "newest log record"
        self.reg = parse_regval(bundle.read_bytes("regval.txt", "client configuration") or b"") \
            if bundle.has("regval.txt") else None
        self.sysinfo = self._text_file("SystemInfo.txt", parse_systeminfo, {})
        ip = self._text_file("IpConfig.txt", parse_ipconfig, None)
        self.ip_general, self.adapters = ip if ip is not None else ({}, None)
        self.adapter_info = [adapter_info(a) for a in self.adapters] if self.adapters is not None else None
        self.routes = self._text_file("RoutePrint.txt", parse_route_print, None)
        self.msi = self._msi()
        self.hip_root = self._hip()
        self.trb, self.trb_cut = self._trb()
        self.driver = self._driver()
        self.pangp = self._pangp_adapter()
        self.conn = self._connection()

    # ---- loading
    def _text_file(self, name: str, parser, default):
        if not self.b.has(name):
            return default
        text = self.b.read_text(name, "client configuration")
        if not text or not text.strip():
            return default
        try:
            return parser(text)
        except (ValueError, IndexError, KeyError, re.error):      # defensive: never raise
            self.cfg.warnings.append(f"{name}: could not be parsed")
            return default

    def _msi(self) -> list[dict[str, Any]] | None:
        name = next((m.name for m in self.b.members.values() if m.family == "msi_log"), "")
        if not name or not self.b.has(name):
            return None
        text = self.b.read_text(name, "client configuration")
        if not text or not text.strip():
            return None
        try:
            return parse_msi_log(text, self.ref)
        except (ValueError, IndexError, KeyError, re.error):
            self.cfg.warnings.append(f"{name}: could not be parsed")
            return None

    def _hip(self) -> ET.Element | None:
        if not self.b.has("pan_gp_hrpt.xml"):
            return None
        text = self.b.read_text("pan_gp_hrpt.xml", "client configuration")
        root, _ = parse_xml(text or "")
        if root is None and text and text.strip():
            self.cfg.warnings.append("pan_gp_hrpt.xml: not a valid XML document")
        return root

    def _trb(self) -> tuple[dict[str, Any] | None, bool]:
        if not self.b.has("pan_gp_trb.log"):
            return None, False
        text = self.b.read_text("pan_gp_trb.log", "client configuration")
        if not text or not text.strip("\x00 \r\n\t"):
            return None, False
        fields, cut = parse_trb(text)
        return (fields or None), cut

    def _driver(self) -> list[dict[str, Any]] | None:
        if not self.b.has("setupapi.dev.log"):
            return None
        text = self.b.read_text("setupapi.dev.log", "client configuration")
        return parse_setupapi(text or "")

    # ---- derived facts
    def _pangp_adapter(self) -> dict[str, Any]:
        evidence: list[str] = []
        present: list[str] = []
        checked: list[str] = []
        if self.adapter_info is not None:
            checked.append("IpConfig.txt")
            for a in self.adapter_info:
                if _PANGP_RE.search(a["name"] + " " + a["description"]):
                    present.append(f"IpConfig.txt: {a['name']} ({a['state']})")
        if self.routes is not None:
            checked.append("RoutePrint.txt")
            present += [f"RoutePrint.txt: {i}" for i in self.routes["interfaces"]
                        if _PANGP_RE.search(i)]
        cards = self.sysinfo.get("Network Card(s)", "")
        if cards:
            checked.append("SystemInfo.txt")
            if _PANGP_RE.search(cards):
                present.append("SystemInfo.txt: Network Card(s)")
        evidence = present or [f"not listed in {', '.join(checked)}"] if checked else []
        if present:
            state: bool | None = True
        elif self.adapter_info is None:
            # Without IpConfig.txt the absence of the adapter cannot be told: unknown.
            state = None
            evidence = [*present, "IpConfig.txt is not in the bundle: adapter state unknown"]
        elif checked:
            state = False
        else:
            state = None
        return {"present": state, "evidence": evidence, "checked": checked,
                "status": {True: "present", False: "absent", None: "unknown"}[state]}

    def _service_state(self) -> tuple[str, datetime | None, str]:
        """(state, when, source) of the newest service state (log line or status XML)."""
        best: tuple[datetime, str, str] | None = self.scan.state
        doc = self.scan.complete.get("status")
        if doc is not None:
            value = _text(doc.root, "state") or _text(doc.root, "status")
            if value and (best is None or doc.ts > best[0]):
                best = (doc.ts, value, "status XML")
        if best is None:
            return "", None, ""
        return best[1], best[0], best[2]

    def _connection(self) -> dict[str, Any]:
        state, when, src = self._service_state()
        stop = self.scan.service_stop
        start = self.scan.service_start[0] if self.scan.service_start else None
        stopped = bool(stop and (start is None or stop > start) and (when is None or stop >= when))
        adapter = self.pangp["present"]
        log_connected = None if not state or stopped else state.rstrip(".") == "Connected"
        lines = []
        if state:
            lines.append(f"last service state '{state}' at {_fmt(when)} ({src})")
        if stopped:
            lines.append(f"service stopped at {_fmt(stop)} after the last state")
        if adapter is True:
            lines.append("PANGP adapter present at collection")
        elif adapter is False:
            lines.append("no PANGP adapter at collection")
        if adapter is False:
            connected: bool | None = False
            why = "the PANGP adapter is absent from the collection snapshot"
            if log_connected:
                why += "; the logs end with state Connected, so the logs are older than the snapshot"
        elif adapter is True:
            connected = True if log_connected else None
            why = ("PANGP adapter present and last state Connected" if log_connected
                   else "PANGP adapter present but the last service state is not Connected "
                        "or unknown: evidence disagrees")
        elif log_connected is not None:
            connected = None
            why = (f"unknown: no network snapshot in the bundle (IpConfig.txt); the last service "
                   f"state in the logs is '{state}'")
        else:
            connected, why = None, "unknown: no service state and no network snapshot in the bundle"
        return {"connected": connected, "log_connected": log_connected,
                "status": {True: "connected", False: "not connected", None: "unknown"}[connected], "last_state": state, "last_state_at": when,
                "last_state_source": src, "service_stopped_after": stopped,
                "service_started_at": start, "service_stopped_at": stop,
                "adapter_present": adapter, "evidence": lines, "conclusion": why}

    def _effective_version(self) -> tuple[str, str, list[str]]:
        cands: list[tuple[str, str, str]] = []     # (label, version, when)
        # The service banner ("Start PanGPS service (ver: ...)") is the authority; the status XML
        # follows; the user-agent string can show a stale build, so it comes last.
        for src in ("service banner", "status XML", "user agent"):
            if src in self.scan.versions:
                ts, v = self.scan.versions[src]
                cands.append((src, v, _fmt(ts)))
        ev = self.events.service_started
        if ev:
            cands.append(("event log", ev[1], _fmt(ev[0])))
        if self.hip_root is not None:
            v = _text(self.hip_root.find("categories/entry[@name='host-info']"), "client-version")
            if v:
                cands.append(("HIP report", v, _fmt(self._hip_time())))
        if self.trb and self.trb.get("gp_version"):
            cands.append(("troubleshooting report", str(self.trb["gp_version"]), ""))
        if not cands:
            return "", "", []
        others = [f"{lab} {v}" + (f" ({w})" if w else "") for lab, v, w in cands if v != cands[0][1]]
        return cands[0][1], f"{cands[0][0]} {cands[0][2]}".strip(), others

    def _version_history(self) -> dict[str, Any]:
        """Versions seen at the service starts, oldest first, and the runs of equal versions."""
        starts = sorted(self.scan.starts, key=lambda x: x[0])
        out_starts = [{"ts": ts, "version": v, "pid": pid, "file": f} for ts, v, pid, f in starts]
        runs: list[dict[str, Any]] = []
        for ts, v, _pid, _f in starts:
            if runs and runs[-1]["version"] == v:
                runs[-1]["last_start"] = ts
                runs[-1]["starts"] += 1
                continue
            run = {"version": v, "first_start": ts, "last_start": ts, "starts": 1, "change": ""}
            if runs:
                a, b = _version_key(runs[-1]["version"]), _version_key(v)
                run["change"] = "newer" if b > a else "older" if b < a else "different"
                run["previous"] = runs[-1]["version"]
            runs.append(run)
        distinct = sorted({r["version"] for r in runs})
        return {"starts": out_starts, "runs": runs, "distinct": distinct,
                "changed_in_bundle": len(runs) > 1}

    def _hip_time(self) -> datetime | None:
        if self.hip_root is None:
            return None
        dt, _ = parse_datetime(_text(self.hip_root, "generate-time"), "mdy", self.ref)
        return dt

    def _freshness(self, ts: datetime | None) -> tuple[str, str]:
        if ts is None or self.ref is None:
            return LAST_SEEN, ""
        gap = self.ref - ts
        if gap > STALE_AFTER:
            return HISTORICAL, (f"{_fmt(ts)} is {_gap_text(gap)} older than the newest log "
                                f"record ({_fmt(self.ref)}): not the state at collection.")
        return LAST_SEEN, ""

    # ---- sections
    def build(self) -> ClientConfig:
        self.cfg.sections = [
            self.sec_summary(), self.sec_registry(), self.sec_status(), self.sec_portal_settings(),
            self.sec_gateways(), self.sec_hip(), self.sec_trb(), self.sec_host(), self.sec_driver(),
        ]
        if self.msi is not None:
            self.cfg.sections.append(self.sec_installer())
        d = self.data
        d["client_versions"] = self._version_history()
        d["portals"] = [{"portal": k, "first": v[0], "last": v[1], "seen": v[2]}
                        for k, v in sorted(self.scan.portals.items(), key=lambda kv: kv[1][0])]
        d["installer"] = {"present": self.msi is not None, "events": self.msi or []}
        d["service_stops"] = [{"ts": ts, "pid": pid} for ts, pid in sorted(self.scan.stops)]
        d["connection"] = self.conn
        d["pangp_adapter"] = self.pangp
        d["scan"] = {"service_records": self.scan.records, "xml_errors": self.scan.xml_errors,
                     "truncated_dumps": self.scan.truncated_dumps,
                     "orphan_chunks": self.scan.orphan_chunks}
        if self.scan.xml_errors:
            self.cfg.warnings.append(f"{self.scan.xml_errors} XML document(s) in the logs could not "
                                     "be parsed")
        return self.cfg

    def sec_summary(self) -> Section:
        cfg, sc, conn = self.cfg, self.scan, self.conn
        files = ["regval.txt", "PanGPS.log", "PanGPA.log", "SystemInfo.txt", "IpConfig.txt",
                 "pan_gp_hrpt.xml", "pan_gp_trb.log", "pan_gp_event.log"]
        client = Group("Client")
        ver, ver_src, others = self._effective_version()
        client.rows.append(_row("Client version", ver or "not found", "", ver_src))
        if others:
            client.rows.append(_row("Other version evidence", "\n".join(others), "",
                                    "differs from the version above"))
        portal_reg = self._reg_value("LastUrl")
        portal_log = sc.portal[1] if sc.portal else ""
        client.rows.append(_row("Last portal", portal_reg or portal_log or "not found",
                                "LastUrl" if portal_reg else "",
                                "registry LastUrl" if portal_reg else
                                (f"service log at {_fmt(sc.portal[0])}" if sc.portal else "")))
        if portal_reg and portal_log and portal_reg.lower() != portal_log.lower():
            client.rows.append(_row("Portal in the logs", portal_log, "",
                                    "differs from the registry LastUrl"))
        vh = self._version_history()
        if vh["changed_in_bundle"]:
            lines = []
            for r in vh["runs"]:
                tail = f", {r['change']} than {r['previous']}" if r["change"] else ""
                lines.append(f"{r['version']}: {r['starts']} service start(s), "
                             f"{_fmt(r['first_start'])} .. {_fmt(r['last_start'])}{tail}")
            client.rows.append(_row("Version history", "\n".join(lines), "",
                                    "'Start PanGPS service (ver: ...)' lines; the version changed "
                                    "inside the bundle"))
        if sc.portals and len(sc.portals) > 1:
            client.rows.append(_row("Portals seen", "\n".join(
                f"{n}: {_fmt(v[0])} .. {_fmt(v[1])}" for n, v in sorted(sc.portals.items(),
                                                                        key=lambda kv: kv[1][0])),
                "", "service log and status XML"))
        if self.msi:
            client.rows.append(_row("Installer events", "\n".join(
                self._msi_line(e) for e in self.msi), "", "PanGPMsi.log"))
        user, user_src = self._user()
        client.rows.append(_row("User", user or "not found", "", user_src))
        host = Group("Host")
        sysinfo = self.sysinfo
        host_name = (sysinfo.get("Host Name") or (self.ip_general.get("Host Name") or [""])[0]
                     or _text(self.hip_root, "host-name") or (self.trb or {}).get("host_name", ""))
        host.rows.append(_row("Host name", host_name or "not found"))
        os_name = " ".join(x for x in (sysinfo.get("OS Name"), sysinfo.get("OS Version")) if x)
        if not os_name and self.events.service_started:
            os_name = self.events.service_started[2]
        if not os_name and self.hip_root is not None:
            os_name = _text(self.hip_root.find("categories/entry[@name='host-info']"), "os")
        host.rows.append(_row("Operating system", os_name or "not found",
                              hint="SystemInfo.txt" if sysinfo.get("OS Name") else ""))
        if sysinfo.get("Domain"):
            host.rows.append(_row("Domain", sysinfo["Domain"], "Domain", "SystemInfo.txt"))
        time = Group("Time reference")
        tz = sysinfo.get("Time Zone")
        time.rows.append(_row("Time zone (SystemInfo)", tz or "not found", "Time Zone",
                              "label of the standard time: it does not change with DST (INFERENCE)"))
        if self.trb and self.trb.get("host_gmt_timeoffset") is not None:
            time.rows.append(_row("UTC offset in the troubleshooting report",
                                  f"{self.trb['host_gmt_timeoffset']} minutes",
                                  "host_gmt_timeoffset",
                                  "valid on the report date only; minutes is an INFERENCE"))
        time.rows.append(_row("Log timestamps", "local wall-clock time of the client, no offset",
                              hint="not converted by this analyzer"))
        coll = (_fmt(cfg.collected_at) if cfg.collected_at else "not available")
        if self.collected_basis == "newest log record":
            coll_hint = "the file name carries no timestamp: newest log record used"
        elif cfg.collected_at:
            coll_hint = ("zip name GlobalProtectLogs_<user>_<MMDDYYYYHHMMSS>"
                         + (f", collected by {self.zip_user}" if self.zip_user else ""))
        else:
            coll_hint = "no zip name pattern"
        time.rows.append(_row("Bundle collected", coll, "", coll_hint))
        newest_src = ", ".join(f"{k} log {_fmt(v)}" for k, v in sorted(self.newest.items()) if v)
        if self.events.newest:
            newest_src += (", " if newest_src else "") + f"event log {_fmt(self.events.newest)}"
        time.rows.append(_row("Newest log record", _fmt(cfg.newest_record) or "not available", "",
                              newest_src))
        cgroup = Group("Connection at collection")
        yes = {True: "yes", False: "no", None: "unknown"}[conn["connected"]]
        cgroup.rows.append(_row("Connected", yes, "", conn["conclusion"]))
        cgroup.rows.append(_row("Last service state", conn["last_state"] or "not found", "",
                                f"{_fmt(conn['last_state_at'])} ({conn['last_state_source']})"
                                if conn["last_state_at"] else ""))
        svc = "unknown"
        if conn["service_started_at"] or conn["service_stopped_at"]:
            svc = ("stopped" if conn["service_stopped_after"] else "running")
        cgroup.rows.append(_row("Service", svc, "", "; ".join(filter(None, [
            f"last start {_fmt(conn['service_started_at'])}" if conn["service_started_at"] else "",
            f"last stop {_fmt(conn['service_stopped_at'])}" if conn["service_stopped_at"] else ""]))))
        cgroup.rows.append(_row("PANGP virtual adapter", self._pangp_text(), "",
                                "; ".join(self.pangp["evidence"])))
        ts = cfg.collected_at or cfg.newest_record
        note = "Identity and state at collection time; each row names where it comes from."
        groups = [client, host, time, cgroup]
        fresh = CURRENT
        if self.adapters is None:
            groups.append(self._end_group())
            fresh = LAST_SEEN
            note = ("No network snapshot in the bundle: the state is the one at the end of the "
                    "logs. " + note)
        missing = [f for f in files if f != "pan_gp_event.log" and not self.b.has(f)]
        if missing:
            note += " Not in bundle: " + ", ".join(missing) + "."
        return Section("summary", "Summary", files, ts, fresh, note, groups)

    def _msi_line(self, e: dict[str, Any], with_ts: bool = True) -> str:
        extra = ""
        if e.get("after_removal"):
            extra = (", reinstall of the same MSI version" if e.get("same_version_as_removed")
                     else ", after a removal (upgrade)")
        text = f"{e['kind']} {e['result'] or '?'}, version {e['version'] or 'unknown'}{extra}"
        return f"{_fmt(e['ts'])} {text}" if with_ts else text

    def _end_group(self) -> Group:
        """State at the end of the logs (used when there is no network snapshot)."""
        g = Group("State at the end of the logs")
        conn, sc = self.conn, self.scan
        g.rows.append(_row("Last service state", conn["last_state"] or "not found", "",
                           f"{_fmt(conn['last_state_at'])} ({conn['last_state_source']})"
                           if conn["last_state_at"] else ""))
        for key, label in (("network_type", "Network type (last discovery)"),
                           ("tunnel_up", "Last tunnel set up"), ("last_disconnect", "Last disconnect reason")):
            hit = sc.echoes.get(key)
            if hit:
                g.rows.append(_row(label, hit[1] or "(none logged)", "", f"{_fmt(hit[0])} ({hit[2]})"))
        doc = sc.complete.get("status")
        if doc is not None:
            for tag, label in (("status", "Status XML status"), ("state", "Status XML state"),
                               ("portal-status", "Status XML portal status")):
                if _text(doc.root, tag):
                    g.rows.append(_row(label, _text(doc.root, tag), tag, _fmt(doc.ts)))
        g.rows.append(_row("Connected", conn["status"], "", conn["conclusion"]))
        return g

    def _pangp_text(self) -> str:
        p = self.pangp["present"]
        if p is None:
            return "unknown (no network snapshot in the bundle)"
        return "present" if p else "not present"

    def _user(self) -> tuple[str, str]:
        if self.scan.user:
            return self.scan.user[1], f"{self.scan.user[2]} at {_fmt(self.scan.user[0])}"
        if self.hip_root is not None and _text(self.hip_root, "user-name"):
            return _text(self.hip_root, "user-name"), "HIP report"
        if self.zip_user:
            return self.zip_user, "zip name (who collected the logs)"
        return "", ""

    def _reg_value(self, key: str) -> str:
        if self.reg is None:
            return ""
        for s in self.reg.settings:
            if s.key == key:
                return s.value
        return ""

    def sec_registry(self) -> Section:
        files = ["regval.txt"]
        if self.reg is None:
            self.data["registry"] = {}
            return _not_in_bundle("registry", "Registry settings", files, CURRENT)
        reg = self.reg
        groups = [Group("Settings", [_row(s.key, s.value, s.key, "REG_DWORD" if s.type == "dword" else "")
                                     for s in reg.settings])]
        if reg.states or reg.credential_filters:
            g = Group("Other registry information")
            for name, value in reg.states:
                g.rows.append(_row(name, value))
            for f in reg.credential_filters:
                g.rows.append(_row("Credential provider filter", f["value"], f["path"],
                                   _fmt(f["time"]) or f["time_raw"]))
            groups.append(g)
        note = f"{len(reg.settings)} setting(s) found."
        if reg.duplicates:
            note += f" Duplicate keys (last value kept): {', '.join(sorted(set(reg.duplicates)))}."
        if not reg.settings:
            note = "No setting could be extracted from regval.txt."
        self.data["registry"] = {
            "settings": {s.key: {"value": s.value, "type": s.type} for s in reg.settings},
            "states": [{"name": n, "value": v} for n, v in reg.states],
            "credential_provider_filters": reg.credential_filters,
            "garbage_lines": reg.garbage_lines}
        return Section("registry", "Registry settings", files, self.cfg.collected_at, CURRENT,
                       note, groups)

    def sec_status(self) -> Section:
        files = ["PanGPS.log", "PanGPA.log"]
        title = "Status sent to the UI"
        scan = self.scan
        doc = scan.complete.get("status")
        partial = scan.partial.get("status")
        if doc is None and partial is not None:
            doc, usable = partial, False
        else:
            usable = True
        if doc is None:
            return Section("status", title, files, None, LAST_SEEN,
                           "No status XML found in the service or agent logs.")
        note = ("Last complete status XML sent by the service to the UI (PanGPS "
                "ResponseToClient dump or PanGPA 'message type from the service').")
        if not usable:
            note = "Only a truncated status XML exists; values may be missing. " + note
        elif partial is not None and partial.ts > doc.ts:
            note += f" A later truncated dump at {_fmt(partial.ts)} was ignored."
        root = doc.root
        envelope = Group("Status")
        for c in root:
            if c.tag in ("gateway-list", "hip-report") or len(c):
                continue
            envelope.rows.append(_row(_status_labels(c.tag), (c.text or "").strip(), c.tag))
        groups = [envelope]
        hip = root.find("hip-report")
        if hip is not None:
            groups.append(Group("Embedded HIP report", [_row(
                "generate-time", _text(hip, "generate-time"), "generate-time",
                f"{len(hip.findall('categories/entry'))} categories; see the HIP section")]))
        self.data["status"] = {c.tag: (c.text or "").strip() for c in root
                               if not len(c) and c.tag != "product-code"}
        self.data["status"]["_ts"] = doc.ts
        conn = scan.status_connected
        if conn is not None:
            g = Group("Last connected state seen")
            for tag, label in (("protocol", "Tunnel protocol"), ("server-ip", "Gateway IP"),
                               ("local-ip", "Tunnel IP"), ("uptime", "Uptime (seconds)"),
                               ("connect-mode", "Connect mode")):
                g.rows.append(_row(label, _text(conn.root, tag), tag))
            login = _text(conn.root, "gateway-list/entry/login-time") or _text(conn.root, "login-time")
            g.rows.append(_row("Tunnel up since (UTC)", _fmt(_epoch(login)) or login,
                               "login-time", "epoch seconds, UTC"))
            g.rows.append(_row("Seen at", _fmt(conn.ts), "", conn.src))
            groups.append(g)
            self.data["last_connected"] = {
                "ts": conn.ts, "protocol": _text(conn.root, "protocol"),
                "gateway_ip": _text(conn.root, "server-ip"), "tunnel_ip": _text(conn.root, "local-ip")}
        return Section("status", title, files, doc.ts, LAST_SEEN, note, groups)

    def _connect_method(self) -> dict[str, Any]:
        ts_log = self.scan.echoes.get("connect_method")
        cands = []
        if ts_log:
            cands.append((ts_log[0], ts_log[1],
                          f"service log line 'Connect method is ...' ({ts_log[2]})"))
        if self.events.connect_method:
            ts, val = self.events.connect_method
            cands.append((ts, val, "event log line 'Connect method is ...'"))
        if cands:
            ts, val, how = max(cands, key=lambda c: c[0])
            return {"value": val, "basis": "log", "source": how, "ts": ts}
        doc = self.scan.complete.get("hip")
        vals = {}
        if doc is not None:
            vals = {k: _text(doc.root, k) for k in ("on-demand", "pre-logon-then-on-demand", "use-sso")}
        od = vals.get("on-demand") or self._reg_value("on-demand")
        if vals.get("pre-logon-then-on-demand") == "yes":
            val = "Pre-logon then on-demand"
        elif od == "yes":
            val = "On-Demand"
        elif od == "no":
            val = "not On-Demand (user-logon or pre-logon: not derivable)"
        else:
            return {"value": "", "basis": "unknown", "source": "", "ts": None}
        how = ("INFERENCE from on-demand=" + od + (" in the portal settings"
               if vals.get("on-demand") else " in the registry")
               + ": the bundle has no explicit connect-method value")
        return {"value": val, "basis": "inferred", "source": how, "ts": doc.ts if doc else None}

    def sec_portal_settings(self) -> Section:
        files = ["PanGPS.log", "PanGPA.log"]
        title = "Portal-pushed agent settings"
        cm = self._connect_method()
        self.data["connect_method"] = cm
        doc = self.scan.complete.get("hip") or self.scan.partial.get("hip")
        groups: list[Group] = []
        note = ("Settings delivered by the portal, from the last 'hip'-type block that the service "
                "sent to the UI (it carries the portal configuration, not the HIP report).")
        cm["seen"] = {k: {"first": v[0], "last": v[1], "count": v[2]}
                      for k, v in self.scan.methods.items()}
        cmg = Group("Connect method")
        if cm["basis"] == "unknown":
            cmg.rows.append(_row("Connect method", "not derivable", "",
                                 "no 'Connect method is' line and no on-demand setting found"))
        else:
            cmg.rows.append(_row("Connect method", cm["value"], "", cm["source"]))
        if len(self.scan.methods) > 1:
            cmg.rows.append(_row("Connect methods seen", "\n".join(
                f"{k}: {v[2]} time(s), {_fmt(v[0])} .. {_fmt(v[1])}"
                for k, v in sorted(self.scan.methods.items(), key=lambda kv: kv[1][0])), "",
                "service log; a second portal can use a different method"))
        groups.append(cmg)
        flat: dict[str, str] = {}
        if doc is not None:
            if doc.truncated:
                note += " The block is truncated: some settings may be missing."
            root = doc.root
            top = Group("Portal settings")
            for c in root:
                if c.tag in ("agent-ui", "agent-config", "gateway-list", "hip-report") or len(c):
                    continue
                top.rows.append(_row(c.tag, (c.text or "").strip(), c.tag))
            if top.rows:
                groups.append(top)
            for tag, label in (("agent-ui", "Agent UI (agent-ui)"),
                               ("agent-config", "Agent configuration (agent-config)")):
                g = _flat_group(label, root.find(tag))
                if g:
                    groups.append(g)
            for path, value in _flat_rows(root, ("gateway-list", "hip-report")):
                if not path.endswith("agent-user-override-key"):
                    flat[path] = value
        else:
            note = "No 'hip'-type block (portal settings) found in the logs. " + note
        echo = Group("Other settings echoed by the service log")
        for key, label in _ECHO_LABELS.items():
            hit = self.scan.echoes.get(key)
            if hit:
                echo.rows.append(_row(label, hit[1], "", f"{_fmt(hit[0])} ({hit[2]})"))
        if echo.rows:
            groups.append(echo)
        auth = self._auth_group(flat)
        if auth is not None:
            groups.append(auth)
        self.data["portal_settings"] = flat
        ts = doc.ts if doc else None
        return Section("portal_settings", title, files, ts, LAST_SEEN, note, groups)

    def _auth_group(self, flat: dict[str, str]) -> Group | None:
        """Authentication settings visible in the logs and in the portal-pushed block."""
        g = Group("Authentication (logs and portal settings)")
        data: dict[str, Any] = {}
        for key, label in _AUTH_LABELS.items():
            hit = self.scan.echoes.get(key)
            if hit:
                g.rows.append(_row(label, hit[1], "", f"{_fmt(hit[0])} ({hit[2]})"))
                data[key] = hit[1]
        for key, label in (("portal_auth", "Portal authentication"),
                           ("gateway_auth", "Gateway authentication")):
            hit = self.scan.echoes.get(key)
            if hit:
                data[key] = hit[1]
        if self.scan.prelogon_user_seen:
            data["prelogon_user_seen"] = True
        pat = re.compile(r"cookie|lifetime|saml|sso|2fa|otp|krb|override|authenticat", re.IGNORECASE)
        picked = {p: v for p, v in flat.items() if pat.search(p)
                  and not p.endswith(("portal-timeout", "connect-timeout", "receive-timeout"))}
        for path, value in picked.items():
            g.rows.append(_row(path, value, path, "portal-pushed settings"))
        data["portal_keys"] = picked
        self.data["authentication"] = data
        return g if g.rows else None

    def sec_gateways(self) -> Section:
        files = ["PanGPS.log"]
        title = "Gateways and tunnel configuration"
        scan = self.scan
        groups: list[Group] = []
        gl = scan.status_with_gateways
        gl_data: list[dict[str, str]] = []
        if gl is not None:
            lst = gl.root.find("gateway-list")
            entries = lst.findall("entry") if lst is not None else []
            entries.sort(key=lambda e: (int(_text(e, "priority") or 999)
                                        if _text(e, "priority").isdigit() else 999))
            compact = len(entries) > MAX_COMPACT_GATEWAYS
            crows: list[Row] = []
            for e in entries:
                name = _text(e, "gateway") or e.get("name", "")
                gl_data.append({t: _text(e, t) for t in
                                ("gateway", "description", "priority", "tunnel", "internal",
                                 "authenticated", "last_hip_sent", "manual")})
                if compact:
                    probe = scan.probes.get(name, {})
                    bits = [f"priority {_text(e, 'priority') or '?'}",
                            "internal" if _text(e, "internal") == "yes" else "external"]
                    if _text(e, "tunnel") == "yes":
                        bits.append("tunnel up")
                    if _text(e, "manual") == "yes":
                        bits.append("manual")
                    if probe:
                        bits.append(f"{probe['ms']} ms")
                    crows.append(_row(_text(e, "description") or name, f"{name}; " + ", ".join(bits),
                                      name))
                    continue
                g = Group(f"Gateway {name}")
                for tag in ("description", "priority", "tunnel", "allow-tunnel", "internal",
                            "authenticated", "passwd-expire-days", "last_hip_sent", "manual"):
                    if e.find(tag) is not None:
                        g.rows.append(_row(tag, _text(e, tag), tag))
                ent = scan.gateway_entries.get(name)
                if ent:
                    g.rows.append(_row("Address (service log)",
                                       f"ipv4 {ent['ipv4'] or '-'}, ipv6 {ent['ipv6'] or '-'}, "
                                       f"FQDN {ent['fqdn']}", "", _fmt(ent["ts"])))
                groups.append(g)
            if compact:
                groups.append(Group(f"Gateway list ({len(entries)} entries, by priority)", crows))
            if len(entries) > 1:
                n_int = sum(1 for e in entries if _text(e, "internal") == "yes")
                summ = Group("Gateway list summary", [
                    _row("Entries", len(entries)), _row("Internal", n_int),
                    _row("External", len(entries) - n_int),
                    _row("List type", gl.root.find("gateway-list").get("type", ""), "type")])
                for key, label in (("external_gw_count", "External gateways discovered (log)"),
                                   ("internal_gw_count", "Internal gateways configured (log)")):
                    hit = scan.echoes.get(key)
                    if hit:
                        summ.rows.append(_row(label, hit[1], "", f"{_fmt(hit[0])} ({hit[2]})"))
                groups.insert(0, summ)
                self.data["gateways_summary"] = {
                    "entries": len(entries), "internal": n_int, "external": len(entries) - n_int,
                    "list_type": gl.root.find("gateway-list").get("type", "")}
            if groups:
                groups[0].rows.append(_row("Gateway list seen at", _fmt(gl.ts), "", gl.src))
        elif scan.gateway_entries:
            for name, ent in scan.gateway_entries.items():
                groups.append(Group(f"Gateway {name}", [_row(
                    "Address", f"ipv4 {ent['ipv4'] or '-'}, ipv6 {ent['ipv6'] or '-'}, "
                    f"FQDN {ent['fqdn']}", "", _fmt(ent["ts"]))]))
        self.data["gateway_list"] = gl_data
        configs: dict[str, Any] = {}
        last_ts: datetime | None = None
        for name, doc in sorted(scan.gateway_cfg.items(), key=lambda kv: kv[1].ts):
            g, flat = self._gateway_group(name, doc)
            groups.append(g)
            configs[name] = flat
            last_ts = doc.ts if last_ts is None or doc.ts > last_ts else last_ts
        self.data["gateway_configs"] = configs
        if not groups:
            return Section("gateways", title, files, None, LAST_SEEN,
                           "No gateway configuration or gateway list found in the service log.")
        note = ("Last gateway configuration received by the client ('gateway X's config is'). "
                "It describes the last tunnel setup, not necessarily the state at collection")
        if self.conn["connected"] is False:
            note += ": the client was not connected at collection"
        note += "."
        if any(d.truncated for d in scan.gateway_cfg.values()):
            note += (" A configuration cut by the logger (missing closing tags) is flagged "
                     "'truncated XML': values after the cut are missing.")
        return Section("gateways", title, files, last_ts or (gl.ts if gl else None), LAST_SEEN,
                       note, groups)

    def _gateway_group(self, name: str, doc: _Doc) -> tuple[Group, dict[str, Any]]:
        r = doc.root
        g = Group(f"Tunnel configuration of {name}")

        def add(label: str, value: Any, key: str = "", hint: str = "") -> None:
            g.rows.append(_row(label, value, key, hint))

        add("Received at", _fmt(doc.ts), "", doc.src + (" (truncated XML)" if doc.truncated else ""))
        add("Response status", r.get("status", ""), "status")
        add("Gateway config name", _text(r, "portal"), "portal")
        add("Gateway public address", _text(r, "gw-address"), "gw-address")
        add("Assigned IP", _text(r, "ip-address"), "ip-address")
        add("Netmask", _text(r, "netmask"), "netmask")
        add("Default gateway (tunnel)", _text(r, "default-gateway"), "default-gateway")
        add("DNS servers", "\n".join(_members(r.find("dns"))), "dns")
        add("DNS suffixes", "\n".join(_members(r.find("dns-suffix"))), "dns-suffix")
        mtu_cfg = _text(r, "mtu")
        add("MTU (gateway)", mtu_cfg, "mtu",
            "0 = not set by the gateway, the client MTU applies (INFERENCE)" if mtu_cfg == "0" else "")
        eff = self.scan.echoes.get("mtu")
        agent_mtu = (self.data.get("portal_settings") or {}).get("agent-config.tunnel-mtu", "")
        if eff:
            add("MTU (configured in the client)", eff[1], "", f"service log {_fmt(eff[0])}")
        elif agent_mtu:
            add("MTU (configured in the client)", agent_mtu, "tunnel-mtu", "portal agent setting")
        add("Access routes", "\n".join(_members(r.find("access-routes"))), "access-routes")
        add("Excluded routes", "\n".join(_members(r.find("exclude-access-routes"))),
            "exclude-access-routes")
        for tag, label in (("exclude-split-tunneling-application", "Excluded applications"),
                           ("exclude-split-tunneling-domain", "Excluded domains")):
            vals = _members(r.find(tag))
            if vals:
                add(label, "\n".join(vals), tag)
        for tag, label in (("lifetime", "Session lifetime (s)"), ("timeout", "Inactivity timeout (s)"),
                           ("disconnect-on-idle", "Disconnect on idle (s)"),
                           ("lifetime-notify-prior", "Lifetime notice before (s)"),
                           ("inactivity-notify-prior", "Inactivity notice before (s)"),
                           ("bw-c2s", "Bandwidth client to server"), ("bw-s2c", "Bandwidth server to client"),
                           ("ipv6-connection", "IPv6 connection"),
                           ("no-direct-access-to-local-network", "No direct access to the local network"),
                           ("need-tunnel", "Tunnel needed"), ("ssl-tunnel-url", "SSL tunnel URL"),
                           ("panos-version", "Gateway PAN-OS version"), ("user", "User")):
            if r.find(tag) is not None:
                add(label, _text(r, tag), tag)
        exp = _epoch(_text(r, "user_expires"))
        if exp:
            add("User expires (UTC)", _fmt(exp), "user_expires", "epoch seconds, UTC")
        ipsec = r.find("ipsec")
        if ipsec is not None:
            add("Protocol", "IPSec configured (ESP over UDP)" if _text(ipsec, "udp-port")
                else "IPSec configured", "ipsec", "the protocol in use is in the status XML / event log")
            for path, value in _flat_rows(ipsec):
                add(f"IPSec {path}", value, f"ipsec.{path}")
        else:
            add("Protocol", "SSL only (no ipsec element)", "", "INFERENCE")
        flat = {"received_at": doc.ts, "truncated": doc.truncated}
        flat.update({p: v for p, v in _flat_rows(r) if "message" not in p})
        return g, flat

    def sec_installer(self) -> Section:
        g = Group("Installer sessions")
        for e in self.msi or []:
            g.rows.append(_row(_fmt(e["ts"]), self._msi_line(e, False), e["kind"],
                               e["product_code"] and f"product code {e['product_code']}"))
            if e.get("portal"):
                g.rows.append(_row("PORTAL property of the installer", e["portal"], "PORTAL",
                                   f"session {_fmt(e['ts'])}"))
        ts = max((e["ts"] for e in self.msi or [] if e["ts"]), default=None)
        note = ("Windows Installer log. Dates in the file are day/month/year. The MSI version has "
                "no build number: the build is in the service log.")
        if not self.msi:
            note = "PanGPMsi.log has no installer session. " + note
        return Section("installer", "Installer log (PanGPMsi.log)", ["PanGPMsi.log"], ts,
                       LAST_SEEN, note, [g] if g.rows else [])

    def sec_hip(self) -> Section:
        files = ["pan_gp_hrpt.xml"]
        title = "HIP report snapshot"
        if not self.b.has("pan_gp_hrpt.xml"):
            return _not_in_bundle("hip_report", title, files, HISTORICAL)
        root = self.hip_root
        if root is None:
            return Section("hip_report", title, files, None, HISTORICAL,
                           "pan_gp_hrpt.xml is empty or not valid XML.")
        gen_raw = _text(root, "generate-time")
        ts = self._hip_time()
        fresh, why = self._freshness(ts)
        note = ("Snapshot taken when the client last sent a HIP report, usually while connected. "
                + why).strip()
        hdr = Group("Report")
        hdr.rows.append(_row("Generated", _fmt(ts) or gen_raw, "generate-time", gen_raw))
        for tag, label in (("user-name", "User"), ("domain", "Domain"), ("host-name", "Host name"),
                           ("host-id", "Host id"), ("ip-address", "IP address (tunnel when connected)"),
                           ("ipv6-address", "IPv6 address"), ("hip-report-version", "Report version")):
            hdr.rows.append(_row(label, _text(root, tag), tag))
        groups = [hdr]
        host = root.find("categories/entry[@name='host-info']")
        interfaces: list[dict[str, Any]] = []
        if host is not None:
            g = Group("Host information")
            for tag, label in (("client-version", "Client version"), ("os", "Operating system"),
                               ("os-vendor", "OS vendor"), ("domain", "Domain")):
                g.rows.append(_row(label, _text(host, tag), tag))
            groups.append(g)
            ng = Group("Network interfaces")
            for e in host.findall("network-interface/entry"):
                v4 = [x.get("name", "") for x in e.findall("ip-address/entry")]
                v6 = [x.get("name", "") for x in e.findall("ipv6-address/entry")]
                desc = _text(e, "description")
                mac = _text(e, "mac-address")
                is_gp = bool(_PANGP_RE.search(desc))
                ng.rows.append(_row(desc or e.get("name", ""), "\n".join(v4 + v6), e.get("name", ""),
                                    (f"MAC {mac}" if mac else "") + ("; GlobalProtect adapter" if is_gp else "")))
                interfaces.append({"name": e.get("name", ""), "description": desc, "mac": mac,
                                   "ipv4": v4, "ipv6": v6, "pangp": is_gp})
            groups.append(ng)
        cats = Group("Categories (summary)")
        for e in root.findall("categories/entry"):
            if e.get("name") != "host-info":
                cats.rows.append(_row(e.get("name", ""), _category_summary(e), e.get("name", "")))
        groups.append(cats)
        self.data["hip"] = {
            "generate_time": ts, "generate_time_raw": gen_raw, "user": _text(root, "user-name"),
            "host_name": _text(root, "host-name"), "ip_address": _text(root, "ip-address"),
            "client_version": _text(host, "client-version") if host is not None else "",
            "os": _text(host, "os") if host is not None else "", "interfaces": interfaces,
            "categories": {e.get("name", ""): _category_summary(e)
                           for e in root.findall("categories/entry") if e.get("name") != "host-info"}}
        return Section("hip_report", title, files, ts, fresh, note, groups)

    def sec_trb(self) -> Section:
        files = ["pan_gp_trb.log"]
        title = "Troubleshooting report"
        if not self.b.has("pan_gp_trb.log"):
            return _not_in_bundle("troubleshooting", title, files, HISTORICAL)
        trb = self.trb
        if not trb:
            return Section("troubleshooting", title, files, None, HISTORICAL,
                           "pan_gp_trb.log is empty or could not be parsed.")
        utc = _epoch(trb.get("report_time"))
        off = trb.get("host_gmt_timeoffset")
        local = None
        if utc is not None:
            local = utc + timedelta(minutes=off) if isinstance(off, (int, float)) else utc
        fresh, why = self._freshness(local)
        note = ("Report of the last failed connection (a fixed-size file overwritten at each "
                "failure). " + why).strip()
        if self.trb_cut:
            note += " The file looks truncated: only the fields that could be read are shown."
        g = Group("Report")
        data: dict[str, Any] = {}
        for key, value in trb.items():
            hint = ""
            if key in ("report_time", "error_time") and _epoch(value):
                dt = _epoch(value)
                shown = f"{_fmt(dt)} UTC"
                if isinstance(off, (int, float)):
                    shown += f" ({_fmt(dt + timedelta(minutes=off))} local)"
                hint = f"epoch {value}"
                data[key] = {"epoch": value, "utc": dt}
            elif key == "portal_auth" and isinstance(value, list):
                shown = "\n".join(f"{d.get('method', '')} ({d.get('source', '')})"
                                  if isinstance(d, dict) else str(d) for d in value)
                data[key] = value
            elif isinstance(value, bool):
                shown = "yes" if value else "no"
                data[key] = value
            elif isinstance(value, (list, dict)):
                shown = json.dumps(value, separators=(",", ":"))
                data[key] = value
            else:
                shown = "" if value is None else str(value)
                data[key] = value
            g.rows.append(_row(key, shown, key, hint))
        data["_local_time"] = local
        data["_cut"] = self.trb_cut
        self.data["troubleshooting"] = data
        return Section("troubleshooting", title, files, local, fresh, note, [g])

    def sec_host(self) -> Section:
        files = ["SystemInfo.txt", "IpConfig.txt", "RoutePrint.txt"]
        title = "Host and network at collection"
        groups: list[Group] = []
        si = self.sysinfo
        host_data: dict[str, Any] = {}
        if si:
            g = Group("System")
            for label in ("Host Name", "OS Name", "OS Version", "System Manufacturer", "System Model",
                          "System Type", "BIOS Version", "System Locale", "Input Locale", "Time Zone",
                          "Total Physical Memory", "Domain", "Logon Server"):
                if si.get(label):
                    g.rows.append(_row(label, si[label], label))
                    host_data[label] = si[label]
            boot = si.get("System Boot Time", "")
            if boot:
                dt, amb = parse_datetime(boot, "dmy", self.ref)
                hint = f"as in the file: {boot}" + ("; day/month order guessed" if amb else "")
                g.rows.append(_row("System boot time", _fmt(dt) if dt else boot, "System Boot Time",
                                   hint if dt else "date format not recognised"))
                host_data["boot_time"] = dt or boot
            groups.append(g)
        if self.adapter_info is not None:
            general = Group("IP configuration")
            for label in ("Host Name", "Primary Dns Suffix", "DNS Suffix Search List", "Node Type"):
                vals = _field(self.ip_general, re.escape(label))
                if vals:
                    general.rows.append(_row(label, "\n".join(vals), label))
            if general.rows:
                groups.append(general)
            for a in self.adapter_info:
                g = Group(f"Adapter {a['name']}")
                g.rows.append(_row("State", a["state"], "Media State", a["media_state"]))
                for label, key, val in (
                        ("Description", "description", a["description"]),
                        ("MAC", "mac", a["mac"]), ("DHCP enabled", "dhcp", a["dhcp"]),
                        ("IPv4", "ipv4", "\n".join(a["ipv4"])), ("IPv6", "ipv6", "\n".join(a["ipv6"])),
                        ("Default gateway", "gateway", "\n".join(a["gateway"])),
                        ("DNS servers", "dns", "\n".join(a["dns"])),
                        ("DNS suffix", "dns_suffix", a["dns_suffix"]),
                        ("Lease obtained", "lease_obtained", a["lease_obtained"]),
                        ("Lease expires", "lease_expires", a["lease_expires"])):
                    if val:
                        g.rows.append(_row(label, val, key, "as in the file (regional format)"
                                           if key.startswith("lease") else ""))
                groups.append(g)
        rt = self.routes
        if rt is not None:
            g = Group("Routes")
            g.rows.append(_row("IPv4 active routes", len(rt["ipv4"])))
            g.rows.append(_row("IPv4 default routes", "\n".join(
                f"via {r['gateway']} dev {r['interface']} metric {r['metric']}"
                for r in rt["default_v4"]) or "none"))
            g.rows.append(_row("IPv4 persistent routes", "\n".join(rt["persistent"]) or "none"))
            g.rows.append(_row("IPv6 active routes", len(rt["ipv6"])))
            g.rows.append(_row("IPv6 default routes", "\n".join(
                f"via {r['gateway'] or '?'} metric {r['metric']}" for r in rt["default_v6"]) or "none"))
            groups.append(g)
        p = Group("PANGP virtual adapter")
        p.rows.append(_row("PANGP adapter at collection", self._pangp_text(), "",
                           "; ".join(self.pangp["evidence"])))
        groups.append(p)
        self.data["host"] = host_data
        self.data["adapters"] = self.adapter_info or []
        self.data["routes"] = rt or {}
        missing = [f for f in files if not self.b.has(f)]
        note = "Static snapshot taken when the logs were collected."
        if missing:
            note += " Not in bundle: " + ", ".join(missing) + "."
        if not self.sysinfo and not self.adapter_info and rt is None:
            absent = [f for f in files if f in missing]
            note = "Not in bundle: " + ", ".join(absent) + "." if absent else ""
            empty = [f for f in files if f not in missing]
            if empty:
                note += " Empty or unreadable: " + ", ".join(empty) + "."
            return Section("host_network", title, files, None, CURRENT, note.strip(), groups)
        return Section("host_network", title, files, self.cfg.collected_at, CURRENT, note, groups)

    def sec_driver(self) -> Section:
        files = ["setupapi.dev.log", "setupapi.app.log"]
        title = "PANGP driver (Windows device installation log)"
        events = self.driver
        self.data["driver_events"] = events or []
        if events is None:
            return _not_in_bundle("driver", title, files[:1], LAST_SEEN)
        g = Group("setupapi.dev.log entries mentioning PANGP")
        shown = events[:MAX_DRIVER_EVENTS]
        for e in shown:
            if e["kind"] == "problem":
                meaning = f" ({e['meaning']})" if e["meaning"] else ""
                g.rows.append(_row(_fmt(e["ts"]) or "no timestamp",
                                   f"{e['device']} has problem Code = {e['code']}{meaning}, "
                                   f"Status = {e['status']}", "", e["section"]))
            else:
                g.rows.append(_row(_fmt(e["ts"]) or "no timestamp", e["text"], "", e["section"]))
        groups = [g] if g.rows else []
        note = "Rolling Windows log: the entries are the most recent ones kept by Windows."
        if not events:
            note = "No line mentioning PANGP in setupapi.dev.log. " + note
        if len(events) > len(shown):
            note += f" Only the first {len(shown)} of {len(events)} entries are listed."
        if any(e["code"] == 22 for e in events):
            note += (" Code 22 is CM_PROB_DISABLED (device disabled); the meaning comes from "
                     "Windows documentation, not from the file (INFERENCE).")
        if self.b.has("setupapi.app.log"):
            text = self.b.read_text("setupapi.app.log", "client configuration") or ""
            n = len(re.findall(r"Install finished for \S*PANGP\S*", text, re.IGNORECASE))
            if n:
                self.data["driver_install_finished_count"] = n
                groups.append(Group("setupapi.app.log", [_row(
                    "Install finished (PANGP)", n, "", "no timestamps in this file")]))
        stamps = [e["ts"] for e in events if e["ts"]]
        return Section("driver", title, files, max(stamps) if stamps else None, LAST_SEEN, note, groups)


def _gap_text(gap: timedelta) -> str:
    hours = gap.total_seconds() / 3600
    return f"{hours:.0f} h" if hours < 72 else f"{gap.days} days"


def build_config(bundle: Bundle) -> ClientConfig:
    """Build the client configuration report data from an opened bundle (never raises)."""
    try:
        return _Builder(bundle).build()
    except Exception as exc:  # noqa: BLE001 - last resort: the report must still be produced
        cfg = ClientConfig()
        cfg.warnings.append(f"client configuration could not be built: {type(exc).__name__}: {exc}")
        return cfg

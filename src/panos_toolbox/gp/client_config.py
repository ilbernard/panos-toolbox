"""Current configuration of the GlobalProtect client, rebuilt from the bundle.

Sources: the registry dump (``regval.txt``), the XML documents the service
writes to ``PanGPS.log`` (status sent to the UI, portal and gateway pre-login
responses, gateway configuration), ``SystemInfo.txt``, the HIP report and the
troubleshooting report. For every item the newest occurrence wins.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .logs import Record

_KEY_RE = re.compile(r"^[A-Za-z][\w.-]*$")
_REQ_RE = re.compile(r"^REQID=\d+,IPADDR=([^,]*),PORT=\d+,URL=([^,]*),")
_GWCFG_RE = re.compile(r"^gateway (\S+)'s config is(.*)$")
_RTC_PREFIX = "ResponseToClient.txt_output: "
TRUNCATED = "_truncated"
_SINGLES = [
    (re.compile(r"^Connect method is (.+)$"), "Connect method"),
    (re.compile(r"^Portal auth method: (.+)$"), "Portal authentication"),
    (re.compile(r"^Gateway auth method: (.+)$"), "Gateway authentication"),
    (re.compile(r"^Portal config digest is (\S+)"), "Portal config digest"),
    (re.compile(r"^Timeout value: (.+)$"), "Timeouts (seconds)"),
    (re.compile(r"^CheckPrelogon: Portal is \S+, PrelogonEnabled is (\w+)"), "Pre-logon enabled"),
    (re.compile(r"^CPanMSServiceWin::findJoinDomain: domain is : (.+)$"), "Joined domain"),
    (re.compile(r"^#+ Start PanGPS service \(ver: (.+?)\)"), "PanGPS service version"),
    (re.compile(r"^Encryption method is (.+)$"), "Tunnel encryption"),
    (re.compile(r"^Configured MTU is (\d+)"), "Configured tunnel MTU"),
    (re.compile(r"^Gateway selection type is (\w+)"), "Gateway selection type"),
    (re.compile(r"^(Split tunneling is enabled: .+)$"), "Split tunneling"),
    (re.compile(r"^ipsec-failover-ssl is configured for (.+)$"), "IPSec to SSL failover memory"),
]


@dataclass
class Snapshot:
    ts: datetime
    src: str
    rows: list[tuple[str, str, str]]  # (group, key, value)
    title: str = ""
    truncated: bool = False


@dataclass
class ConfigCollector:
    """Fed with every service-log record; keeps the newest of each document."""

    agent_cfg: dict[str, Snapshot] = field(default_factory=dict)  # per portal
    status: Snapshot | None = None
    gateway_list: Snapshot | None = None
    portal_prelogin: dict[str, Snapshot] = field(default_factory=dict)
    gateway_prelogin: dict[str, Snapshot] = field(default_factory=dict)
    gateway_cfg: dict[str, Snapshot] = field(default_factory=dict)
    singles: dict[str, tuple[datetime, str]] = field(default_factory=dict)
    xml_errors: int = 0
    _chunks: list[str] = field(default_factory=list)
    _last_host: dict[int, tuple[str, str]] = field(default_factory=dict)  # tid -> (host, url)

    def feed(self, rec: Record) -> None:
        msg = rec.msg
        if not msg and rec.extra and rec.extra[0].startswith(_RTC_PREFIX):
            self._feed_chunk(rec)
            return
        m = _REQ_RE.match(msg)
        if m:
            self._last_host[rec.tid] = (m.group(1), m.group(2))
            return
        if msg.startswith("prelogin to portal result is"):
            self._prelogin(rec, rec.body, self.portal_prelogin, "/global-protect/")
            return
        if msg.startswith("Pre-login response is"):
            self._prelogin(rec, msg[len("Pre-login response is"):] + "\n" + rec.body,
                           self.gateway_prelogin, "/ssl-vpn/")
            return
        m = _GWCFG_RE.match(msg)
        if m:
            root = _parse_xml(m.group(2) + "\n" + rec.body)
            if root is None:
                self.xml_errors += 1
            else:
                self.gateway_cfg[m.group(1)] = Snapshot(
                    rec.ts, rec.src, flatten(root), m.group(1), bool(root.get(TRUNCATED)))
            return
        for rx, label in _SINGLES:
            m = rx.match(msg)
            if m:
                self.singles[label] = (rec.ts, m.group(1).strip())
                return

    def _prelogin(self, rec: Record, text: str, store: dict, url_prefix: str) -> None:
        root = _parse_xml(text)
        if root is None:
            self.xml_errors += 1
            return
        host, url = self._last_host.get(rec.tid, ("", ""))
        if not url.startswith(url_prefix):
            host = ""
        store[host or "(host not logged)"] = Snapshot(rec.ts, rec.src, flatten(root), host)

    def _feed_chunk(self, rec: Record) -> None:
        text = "\n".join(rec.extra)[len(_RTC_PREFIX):]
        if text.lstrip().startswith("<?xml"):
            self._chunks = []
        self._chunks.append(text)
        if "</response>" not in text:
            if len(self._chunks) > 200:
                self._chunks = []
            return
        doc = "".join(self._chunks)
        self._chunks = []
        root = _parse_xml(doc)
        if root is None:
            self.xml_errors += 1
            return
        rtype = (root.findtext("type") or "").strip()
        portal = (root.findtext("portal") or "").strip()
        if root.find("agent-config") is not None or root.find("agent-ui") is not None:
            self.agent_cfg[portal or "(portal not logged)"] = Snapshot(rec.ts, rec.src, flatten(root), portal)
        if rtype == "status":
            self.status = Snapshot(rec.ts, rec.src, flatten(root, skip=("gateway-list",)), portal)
            glist = root.find("gateway-list")
            if glist is not None and glist.find("entry") is not None:
                self.gateway_list = Snapshot(rec.ts, rec.src, flatten(glist, attrs=True), portal)


def _parse_xml(text: str) -> ET.Element | None:
    start = text.find("<")
    if start < 0:
        return None
    text = text[start:]
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return None
    text = re.sub(r"^<\?xml[^>]*\?>", "", text.strip()).strip()
    # Keep only the first complete document: log text can follow the closing tag.
    m = re.match(r"<([A-Za-z][\w.-]*)", text)
    if not m:
        return None
    closing = f"</{m.group(1)}>"
    end = text.rfind(closing)
    if end >= 0:
        text = text[: end + len(closing)]
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        pass
    # The logger cuts long documents: close the open elements and retry.
    try:
        root = ET.fromstring(_close_open_tags(text))
    except ET.ParseError:
        return None
    root.set(TRUNCATED, "1")
    return root


def _close_open_tags(text: str) -> str:
    text = text[: text.rfind(">") + 1]
    stack: list[str] = []
    for m in re.finditer(r"<(/?)([A-Za-z][\w.-]*)[^<>]*?(/?)>", text):
        if m.group(3):
            continue
        if m.group(1):
            if stack and stack[-1] == m.group(2):
                stack.pop()
        else:
            stack.append(m.group(2))
    return text + "".join(f"</{tag}>" for tag in reversed(stack))


def flatten(root: ET.Element, skip: tuple[str, ...] = (), attrs: bool = False) -> list[tuple[str, str, str]]:
    """Flatten an XML tree to (group, key, value) rows.

    The group is the first-level container; ``member`` lists are joined and
    ``entry`` lists are numbered.
    """
    rows: list[tuple[str, str, str]] = []

    def walk(el: ET.Element, group: str, path: str) -> None:
        children = list(el)
        if not children:
            rows.append((group, path, (el.text or "").strip()))
            return
        if all(c.tag == "member" for c in children):
            rows.append((group, path, "\n".join((c.text or "").strip() for c in children)))
            return
        counts: dict[str, int] = {}
        for c in children:
            counts[c.tag] = counts.get(c.tag, 0) + 1
        seen: dict[str, int] = {}
        for c in children:
            name = c.tag
            if counts[name] > 1:
                seen[name] = seen.get(name, 0) + 1
                label = c.get("name") or str(seen[name])
                name = f"{name}[{label}]"
            walk(c, group, f"{path}.{name}" if path else name)

    if attrs and root.attrib:
        for k, v in root.attrib.items():
            if k not in ("name", TRUNCATED):
                rows.append(("", f"@{k}", v))
    counts: dict[str, int] = {}
    for child in root:
        counts[child.tag] = counts.get(child.tag, 0) + 1
    seen: dict[str, int] = {}
    for child in root:
        if child.tag in skip:
            continue
        if counts[child.tag] > 1:
            seen[child.tag] = seen.get(child.tag, 0) + 1
            label = child.get("name") or str(seen[child.tag])
            walk(child, f"{child.tag} {label}", "")
            continue
        if len(child) and not all(c.tag == "member" for c in child):
            walk(child, child.tag, "")
        else:
            walk(child, "", child.tag)
    return rows


# ---------------------------------------------------------------- regval.txt
def parse_regval(data: bytes) -> list[tuple[str, list[tuple[str, str]]]]:
    """Parse the registry dump into ``[(section, [(key, value)])]``.

    String values are NUL terminated; DWORD values are dumped as 4 raw bytes.
    Lines that are not ``key=value`` are kept as notes with an empty value.
    """
    sections: list[tuple[str, list[tuple[str, str]]]] = []
    current: list[tuple[str, str]] = []
    sections.append(("General", current))
    for raw in data.split(b"\r\n"):
        if b"=" in raw:
            key_b, _, val_b = raw.partition(b"=")
            key = key_b.decode("latin-1").strip()
            if _KEY_RE.match(key) and len(key) <= 80:
                current.append((key, _reg_value(val_b)))
                continue
        line = "".join(ch for ch in raw.decode("latin-1") if ch.isprintable()).strip()
        if not line or len(line) > 400:
            continue
        if line == "Settings" or (line.endswith(":") and "\\" not in line and len(line) < 60):
            current = []
            sections.append((line.rstrip(": "), current))
            continue
        m = re.match(r"^([A-Za-z][\w -]{0,40}?)\s*:\s*(\S.*)$", line)
        if m and "\\" not in m.group(1):
            current.append((m.group(1).strip(), m.group(2).strip()))
        else:
            current.append((line, ""))
    return [(title, rows) for title, rows in sections if rows]


def _reg_value(val: bytes) -> str:
    text = val.rstrip(b"\x00")
    printable = all(32 <= b < 127 or b in (9,) or b >= 160 for b in text)
    if len(val) == 4 and (not printable or not text):
        return str(int.from_bytes(val, "little"))
    if printable:
        return text.decode("latin-1").strip()
    return "0x" + val.hex()


# ------------------------------------------------------------ other sources
def parse_systeminfo(text: str, limit: int = 45) -> list[tuple[str, str]]:
    rows = []
    for line in text.splitlines():
        m = re.match(r"^([^\s:][^:]{1,45}):\s{2,}(\S.*)$", line)
        if m:
            rows.append((m.group(1).strip(), m.group(2).strip()))
            if len(rows) >= limit:
                break
    return rows


def parse_trb(text: str) -> list[tuple[str, str]]:
    """Flatten the JSON troubleshooting report (``pan_gp_trb.log``)."""
    rows: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip().strip("\x00")
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if rows:
            rows.append(("—", "—"))
        for key, value in obj.items():
            if key.endswith("_time") and isinstance(value, (int, float)) and value > 10**9:
                stamp = datetime.fromtimestamp(value, tz=timezone.utc)
                value = f"{stamp:%Y-%m-%d %H:%M:%S} UTC ({value})"
            elif isinstance(value, (list, dict)):
                value = json.dumps(value)
            elif isinstance(value, bool):
                value = "yes" if value else "no"
            rows.append((key, str(value)))
    return rows


_HIP_TAGS = ["generate-time", "user-name", "domain", "host-name", "host-id", "ip-address",
             "ipv6-address", "hip-report-version"]


def parse_hip_report(text: str) -> list[tuple[str, str]]:
    root = _parse_xml(text)
    if root is None:
        return []
    rows = [(tag, (root.findtext(tag) or "").strip()) for tag in _HIP_TAGS if root.find(tag) is not None]
    for entry in root.iterfind("categories/entry"):
        name = entry.get("name", "")
        if name == "host-info":
            for tag in ("client-version", "os", "os-vendor", "domain", "managed"):
                if entry.find(tag) is not None:
                    rows.append((f"host-info.{tag}", (entry.findtext(tag) or "").strip()))
        else:
            items = entry.findall("list/entry")
            names = [(i.findtext("ProductInfo/Prod/name") or i.get("name") or "").strip() for i in items]
            names = [n for n in names if n]
            rows.append((f"category {name}", ", ".join(names) if names else f"{len(items)} item(s)"))
    return rows

"""Tests for gp/client_config.py (synthetic bundles only: no real names, addresses or ids)."""
from __future__ import annotations

import json
import zipfile
from datetime import datetime

from panos_toolbox.gp.bundle import Bundle
from panos_toolbox.gp.client_config import (
    CURRENT,
    HISTORICAL,
    LAST_SEEN,
    build_config,
    decode_reg_value,
    parse_datetime,
    parse_regval,
    parse_setupapi,
    parse_systeminfo,
    parse_xml,
)

NL = "\r\n"


def rec(level: str, code: int, stamp: str, msg: str = "", pid: int = 100, tid: int = 200) -> str:
    return f"(P{pid}-T{tid}){level.ljust(5)}({code:>4}): {stamp} {msg}"


def log(*records: str) -> str:
    return NL.join(records) + NL


def status_xml(state: str = "Connected", user: str = "jdoe", extra: str = "") -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<response>\n'
        "\t<type>status</type>\n"
        f"\t<status>{state}</status>\n\t<protocol>IPSec</protocol>\n"
        "\t<product-version>6.3.3-828</product-version>\n"
        f"\t<user-name>{user}</user-name>\n\t<state>{state}</state>\n"
        "\t<portal>vpn.example.com</portal>\n"
        '\t<gateway-list name="gateway-list" type="external" user="jdoe">\n'
        '\t\t<entry name="gw1.example.com">\n'
        "\t\t\t<gateway>gw1.example.com</gateway>\n\t\t\t<description>gw1</description>\n"
        "\t\t\t<priority>1</priority>\n\t\t\t<tunnel>yes</tunnel>\n"
        "\t\t\t<login-time>1794477840</login-time>\n"
        "\t\t</entry>\n\t</gateway-list>\n"
        f"\t<local-ip>10.0.0.12</local-ip>\n\t<server-ip>203.0.113.10</server-ip>\n{extra}"
        "</response>\n")


def chunked(xml: str, size: int, stamp: str, tid: int = 300, marker_first_only: bool = False) -> list[str]:
    """Status dump as the service logs it: records of ``size`` chars, cut anywhere."""
    out = []
    for i in range(0, len(xml), size):
        piece = xml[i:i + size].replace("\n", NL)
        out.append(rec("Dump", 8450, stamp, "", tid=tid) + NL + "ResponseToClient.txt_output: " + piece)
    return out


GW_CONFIG = """
\t<response status="success">
\t\t<portal>GP-Gateway-EX</portal>
\t\t<user>jdoe</user>
\t\t<lifetime>43200</lifetime>
\t\t<timeout>10800</timeout>
\t\t<user_expires>1794618396</user_expires>
\t\t<disconnect-on-idle>10800</disconnect-on-idle>
\t\t<panos-version>11.0.0</panos-version>
\t\t<gw-address>203.0.113.10</gw-address>
\t\t<ip-address>10.0.0.12</ip-address>
\t\t<netmask>255.255.255.255</netmask>
\t\t<dns>
\t\t\t<member>10.0.0.53</member>
\t\t\t<member>10.0.0.54</member>
\t\t</dns>
\t\t<dns-suffix>
\t\t\t<member>corp.example.com</member>
\t\t</dns-suffix>
\t\t<mtu>0</mtu>
\t\t<access-routes>
\t\t\t<member>0.0.0.0/0</member>
\t\t</access-routes>
\t\t<exclude-access-routes>
\t\t\t<member>198.51.100.0/24</member>
\t\t</exclude-access-routes>
\t\t<ipsec>
\t\t\t<udp-port>4501</udp-port>
\t\t\t<enc-algo>aes-256-gcm</enc-algo>
\t\t</ipsec>
\t</response>
"""

HIP_CONFIG = """<?xml version="1.0" encoding="UTF-8"?>
<response>
\t<type>hip</type>
\t<status>Disconnected</status>
\t<user-name>jdoe</user-name>
\t<portal>vpn.example.com</portal>
\t<version>6.3.3-1</version>
\t<use-sso>no</use-sso>
\t<on-demand>yes</on-demand>
\t<pre-logon-then-on-demand>no</pre-logon-then-on-demand>
\t<portal-name>GP-Portal-EX</portal-name>
\t<agent-user-override-key>****</agent-user-override-key>
\t<agent-ui>
\t\t<can-save-password>no</can-save-password>
\t</agent-ui>
\t<agent-config>
\t\t<default-browser>no</default-browser>
\t\t<tunnel-mtu>1400</tunnel-mtu>
\t</agent-config>
</response>
"""

HIP_REPORT = """<?xml version="1.0" encoding="UTF-8"?>
<hip-report>
\t<md5-sum>0123456789abcdef0123456789abcdef</md5-sum>
\t<user-name>jdoe</user-name>
\t<host-name>LAPTOP-01</host-name>
\t<host-id>00000000-0000-0000-0000-000000000001</host-id>
\t<ip-address>10.0.0.12</ip-address>
\t<generate-time>11/13/2026 15:07:16</generate-time>
\t<hip-report-version>4</hip-report-version>
\t<categories>
\t\t<entry name="host-info">
\t\t\t<client-version>6.3.3-828</client-version>
\t\t\t<os>Microsoft Windows 11 Pro , 64-bit</os>
\t\t\t<network-interface>
\t\t\t\t<entry name="{AAAA}">
\t\t\t\t\t<description>PANGP Virtual Ethernet Adapter Secure #2</description>
\t\t\t\t\t<mac-address>02-00-00-00-00-01</mac-address>
\t\t\t\t\t<ip-address><entry name="10.0.0.12"/></ip-address>
\t\t\t\t</entry>
\t\t\t</network-interface>
\t\t</entry>
\t\t<entry name="anti-malware">
\t\t\t<list><entry><ProductInfo>
\t\t\t\t<Prod vendor="Example" name="Example AV" version="1.2"/>
\t\t\t\t<real-time-protection>yes</real-time-protection>
\t\t\t</ProductInfo></entry></list>
\t\t</entry>
\t\t<entry name="patch-management">
\t\t\t<missing-patches>
\t\t\t\t<entry><title>KB1</title><severity>3</severity><is-installed>no</is-installed></entry>
\t\t\t</missing-patches>
\t\t</entry>
\t</categories>
</hip-report>
"""

SYSTEMINFO = (
    "\r\nHost Name:                     LAPTOP-01\r\n"
    "OS Name:                       Microsoft Windows 11 Pro\r\n"
    "OS Version:                    10.0.26100 N/A Build 26100\r\n"
    "System Boot Time:              14/11/2026, 01:03:01\r\n"
    "Time Zone:                     (UTC+01:00) Example Standard Time\r\n"
    "Virtual Memory: Max Size:      55.993 MB\r\n"
    "Domain:                        corp.example.com\r\n"
    "Network Card(s):               1 NIC(s) Installed.\r\n"
    "                               [01]: Example Wi-Fi adapter\r\n")

IPCONFIG = (
    "\r\nWindows IP Configuration\r\n\r\n"
    "   Host Name . . . . . . . . . . . . : LAPTOP-01\r\n"
    "   DNS Suffix Search List. . . . . . : corp.example.com\r\n"
    "                                       lab.example.com\r\n\r\n"
    "Wireless LAN adapter Wi-Fi:\r\n\r\n"
    "   Connection-specific DNS Suffix  . : example.net\r\n"
    "   Description . . . . . . . . . . . : Example Wi-Fi adapter\r\n"
    "   Physical Address. . . . . . . . . : 02-00-00-00-00-02\r\n"
    "   DHCP Enabled. . . . . . . . . . . : Yes\r\n"
    "   Link-local IPv6 Address . . . . . : fe80::1%20(Preferred) \r\n"
    "   IPv4 Address. . . . . . . . . . . : 192.0.2.64(Preferred) \r\n"
    "   Default Gateway . . . . . . . . . : 192.0.2.254\r\n"
    "   DNS Servers . . . . . . . . . . . : 192.0.2.254\r\n"
    "                                       192.0.2.253\r\n\r\n"
    "Ethernet adapter Ethernet 2:\r\n\r\n"
    "   Media State . . . . . . . . . . . : Media disconnected\r\n"
    "   Description . . . . . . . . . . . : Example Ethernet\r\n")

IPCONFIG_PANGP = IPCONFIG + (
    "\r\nUnknown adapter Ethernet 3:\r\n\r\n"
    "   Description . . . . . . . . . . . : PANGP Virtual Ethernet Adapter Secure\r\n"
    "   IPv4 Address. . . . . . . . . . . : 10.0.0.12(Preferred) \r\n")

ROUTE_PRINT = """===========================================================================
Interface List
 20...02 00 00 00 00 02 ......Example Wi-Fi adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.0.2.254      192.0.2.64     30
      192.0.2.0    255.255.255.0         On-link       192.0.2.64    286
===========================================================================
Persistent Routes:
  None

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
 20    286 ::/0                     fe80::fe
 20    286 fe80::/64                On-link
===========================================================================
""".replace("\n", "\r\n")

TRB = ('{"report_id":"00000000-0000-0000-0000-00000000000a","report_time":1784549296,'
       '"report_type":"troubleshooting","user_name":"jdoe@example.com","host_name":"LAPTOP-01",'
       '"host_gmt_timeoffset":120,"gp_version":"6.3.3-828","error_stage":"Portal pre-login",'
       '"error":"Authentication Failed. No retries.","portal_address":"vpn.example.com",'
       '"portal_reachable":true,"portal_auth":[{"method":"cert","source":"user store"},'
       '{"method":"credential","source":"saved credential"}]}')

SETUPAPI = (
    ">>>  [Device Install (Hardware initiated) - ROOT\\NET\\0000]\r\n"
    ">>>  Section start 2026/11/14 01:01:29.410\r\n"
    "     ump: Device 'ROOT\\PANGPD\\0000' has problem. Code = 22, Status = 0x00000000.\r\n"
    "<<<  Section end 2026/11/14 01:01:29.500\r\n"
    ">>>  [Enable Device Install]\r\n"
    ">>>  Section start 2026/11/14 01:01:47.410\r\n"
    "     ump: Device 'ROOT\\NET\\0000' has problem. Code = 22, Status = 0x00000000.\r\n"
    "     ump: Device 'ROOT\\PANGPD\\0000' has problem. Code = 22, Status = 0x00000000.\r\n")


def make_bundle(tmp_path, files: dict, name: str = "bundle"):
    root = tmp_path / name
    root.mkdir()
    for fname, content in files.items():
        data = content if isinstance(content, bytes) else content.encode("latin-1")
        (root / fname).write_bytes(data)
    return Bundle.open(root)


def sec(cfg, sid):
    s = cfg.section(sid)
    assert s is not None, sid
    return s


def rows(section) -> dict:
    out = {}
    for g in section.groups:
        for r in g.rows:
            out.setdefault(r.label, r.value)
    return out


def full_service_log() -> str:
    xml = status_xml("Connected")
    return log(
        rec("Info", 100, "11/12/26 08:00:00:000",
            "####################### Start PanGPS service (ver: 6.3.3-828) ####"),
        rec("Debug", 4178, "11/12/26 20:39:41:000", "Portal vpn.example.com, user jdoe, logonDomain EXAMPLE"),
        rec("Info", 10667, "11/12/26 20:39:48:000", "Connect method is On-Demand"),
        rec("Debug", 506, "11/12/26 20:39:49:000", "Configured MTU is 1400"),
        rec("Debug", 3100, "11/12/26 20:39:49:852", "gateway gw1.example.com's config is <?xml version=\"1.0\" encoding=\"UTF-8\" ?>")
        + NL + GW_CONFIG.replace("\n", NL),
        rec("Debug", 8727, "11/12/26 20:39:50:000", "--Set state to Connected"),
        *chunked(xml, 211, "11/12/26 20:39:51:000"),
        rec("Debug", 2622, "11/12/26 20:39:51:100", "Send response to client for request status"),
        rec("Dump", 1160, "11/12/26 20:40:00:000", "HandleDnsCallBack enter..."),
    )


# ------------------------------------------------------------------ regval
def test_decode_reg_value_kinds():
    assert decode_reg_value(b"IT\x00") == ("IT", "sz")
    assert decode_reg_value(b"\x00") == ("", "sz")
    assert decode_reg_value(b"yes\x00") == ("yes", "sz")
    assert decode_reg_value(b"\x05\x00\x00\x00") == ("5", "dword")
    assert decode_reg_value(b"\x00\x00\x00\x00") == ("0", "dword")
    assert decode_reg_value(b"\x1e\x00\x00\x00") == ("30", "dword")
    assert decode_reg_value(b"0\x00") == ("0", "sz")
    assert decode_reg_value(b"") == ("", "sz")


def test_parse_regval_robust():
    html = "<div style=\"font-family:'X';\"><h1>Notice</h1></div>"
    data = (
        b"Credential Provider Filters:\r\n"
        b"SOFTWARE\\Microsoft\\Credential Provider Filters\\{G} | GenericFilter\x00 | 08:28:55 04/01/2024\r\n\r\n"
        b"SSO Cache:\x00\r\nSSO Cache is Empty!!!\r\n\r\n"
        b"PreferredIP:\x00\r\nPreferredIP is not presented!!!\r\n\r\n"
        b"Prelogon :48\r\nWrap CP Guid :\r\nwrap-cp-guid value is not presented!!!\r\n\x00\x00\r\n\r\n"
        b"Settings\r\n"
        b"save-gateway-password=\x00\r\n"
        b"disable-globalprotect=\x00\x00\x00\x00\r\n"
        b"regioncode=IT\x00\r\n"
        b"portal-timeout=\x05\x00\x00\x00\r\n"
        b"traffic-blocking-notification-msg=" + html.encode() + b"\x00\r\n"
        + b"\x00" * 300 + b"\r\n=\r\n" + b"\x00" * 200 + b"\r\n"
        b"]a\xe1p\xfe\x7f\x00\x00SOFTWARE\\Vendor\\Product\\Settings\x00\x00\x00\r\n"
        b"\x00\x00\x00LastUrl=vpn.example.com\x00\r\n"
        b"on-demand=yes\x00\x00\x00\x00garbage\r\n"
        b"default-browser=no\x00")
    dump = parse_regval(data)
    got = {s.key: (s.value, s.type) for s in dump.settings}
    assert list(got) == ["save-gateway-password", "disable-globalprotect", "regioncode",
                         "portal-timeout", "traffic-blocking-notification-msg", "LastUrl",
                         "on-demand", "default-browser"]
    assert got["save-gateway-password"] == ("", "sz")
    assert got["disable-globalprotect"] == ("0", "dword")
    assert got["portal-timeout"] == ("5", "dword")
    assert got["traffic-blocking-notification-msg"] == (html, "sz")      # kept whole, '=' inside
    assert got["LastUrl"] == ("vpn.example.com", "sz")                   # NULs glued to the start
    assert got["on-demand"] == ("yes", "sz")                             # garbage glued to the end
    assert got["default-browser"] == ("no", "sz")                        # no trailing CRLF
    states = dict(dump.states)
    assert states["Prelogon"] == "48"
    assert "Empty" in states["SSO Cache"] and "not presented" in states["PreferredIP"]
    assert dump.credential_filters[0]["value"] == "GenericFilter"
    assert dump.credential_filters[0]["time"] == datetime(2024, 4, 1, 8, 28, 55)  # noqa: DTZ001


def test_registry_section_every_key(tmp_path):
    keys = [f"key-{i}" for i in range(46)]
    body = b"Settings\r\n" + b"".join(k.encode() + b"=v\x00\r\n" for k in keys)
    cfg = build_config(make_bundle(tmp_path, {"regval.txt": body}))
    s = sec(cfg, "registry")
    assert s.freshness == CURRENT
    assert len(s.groups[0].rows) == 46
    assert [r.key for r in s.groups[0].rows] == keys
    assert len(cfg.data["registry"]["settings"]) == 46


# ------------------------------------------------------------- status / portal
def test_status_chunked_and_duplicated(tmp_path):
    xml = status_xml("Connected")
    records = []
    # two threads dump the same document, chunks interleaved; cuts fall inside tags
    a = chunked(xml, 97, "11/12/26 20:39:51:000", tid=300)
    b = chunked(xml, 97, "11/12/26 20:39:51:000", tid=301)
    for x, y in zip(a, b):
        records += [x, y]
    text = log(rec("Info", 100, "11/12/26 08:00:00:000", "x"), *records)
    cfg = build_config(make_bundle(tmp_path, {"PanGPS.log": text}))
    s = sec(cfg, "status")
    assert s.freshness == LAST_SEEN
    assert s.timestamp == datetime(2026, 11, 12, 20, 39, 51)  # noqa: DTZ001
    r = rows(s)
    assert r["State"] == "Connected" and r["Tunnel IP"] == "10.0.0.12" and r["User"] == "jdoe"
    assert cfg.data["last_connected"]["gateway_ip"] == "203.0.113.10"
    gw = sec(cfg, "gateways")
    assert any(g.title == "Gateway gw1.example.com" for g in gw.groups)
    assert cfg.data["gateway_list"][0]["priority"] == "1"
    assert cfg.data["scan"]["xml_errors"] == 0


def test_status_last_complete_wins_and_truncated_final_dump_is_ignored(tmp_path):
    old = status_xml("Disconnected")
    new = status_xml("Connected")
    cut = new[:new.index("<portal>") + 5]            # ends inside the <portal> tag
    text = log(*chunked(old, 150, "11/12/26 10:00:00:000"),
               *chunked(cut, 150, "11/12/26 11:00:00:000"))
    cfg = build_config(make_bundle(tmp_path, {"PanGPS.log": text}))
    s = sec(cfg, "status")
    assert rows(s)["State"] == "Disconnected"
    assert "truncated" in s.note and "ignored" in s.note
    assert cfg.data["scan"]["truncated_dumps"] == 1


def test_only_truncated_status_is_used_with_a_note(tmp_path):
    new = status_xml("Connected")
    cut = new[:new.index("<portal>")]
    text = log(*chunked(cut, 120, "11/12/26 11:00:00:000"))
    cfg = build_config(make_bundle(tmp_path, {"PanGPS.log": text}))
    s = sec(cfg, "status")
    assert "truncated" in s.note.lower()
    assert rows(s)["User"] == "jdoe"


def test_dump_cut_by_a_new_dump_start(tmp_path):
    first = status_xml("Disconnected")[:300]          # never finished, another dump follows
    second = status_xml("Connected")
    text = log(*chunked(first, 100, "11/12/26 10:00:00:000"),
               *chunked(second, 100, "11/12/26 10:05:00:000"))
    cfg = build_config(make_bundle(tmp_path, {"PanGPS.log": text}))
    assert rows(sec(cfg, "status"))["State"] == "Connected"


def test_agent_log_blocks_and_portal_settings(tmp_path):
    agent = log(
        rec("Debug", 314, "11/12/26 20:39:32:239", "message type from the service = hip ")
        + NL + HIP_CONFIG.replace("\n", NL),
        rec("Debug", 314, "11/12/26 20:40:00:000", "message type from the service = status ")
        + NL + status_xml("Disconnected").replace("\n", NL))
    cfg = build_config(make_bundle(tmp_path, {"PanGPA.log": agent}))
    s = sec(cfg, "portal_settings")
    r = rows(s)
    assert (r["on-demand"], r["use-sso"], r["portal-name"]) == ("yes", "no", "GP-Portal-EX")
    assert r["tunnel-mtu"] == "1400"
    cm = cfg.data["connect_method"]
    assert cm["basis"] == "inferred" and cm["value"] == "On-Demand"
    assert "INFERENCE" in rows_hint(s, "Connect method")
    assert cfg.data["portal_settings"]["agent-config.tunnel-mtu"] == "1400"
    assert "agent-user-override-key" not in cfg.data["portal_settings"]


def rows_hint(section, label: str) -> str:
    for g in section.groups:
        for r in g.rows:
            if r.label == label:
                return r.hint
    return ""


def test_connect_method_from_log_line(tmp_path):
    cfg = build_config(make_bundle(tmp_path, {"PanGPS.log": full_service_log(),
                                              "PanGPA.log": log(rec("Info", 1, "11/12/26 20:00:00:000", "x"))}))
    cm = cfg.data["connect_method"]
    assert cm["basis"] == "log" and cm["value"] == "On-Demand"


def test_connect_method_from_event_log(tmp_path):
    ev = ("11/12/2026 20:39:48:000 [Info ]: Connect method is user-logon\n"
          "11/12/2026 20:40:00:000 [Info ]: GlobalProtect service started (client version: 6.3.3-828, "
          "OS version: Microsoft Windows 11 Pro , 64-bit).\n")
    cfg = build_config(make_bundle(tmp_path, {"pan_gp_event.log": ev}))
    assert cfg.data["connect_method"]["value"] == "user-logon"
    assert cfg.newest_record == datetime(2026, 11, 12, 20, 40)  # noqa: DTZ001
    assert rows(sec(cfg, "summary"))["Client version"] == "6.3.3-828"


def test_gateway_config(tmp_path):
    cfg = build_config(make_bundle(tmp_path, {"PanGPS.log": full_service_log()}))
    s = sec(cfg, "gateways")
    assert s.freshness == LAST_SEEN
    r = rows(s)
    assert r["Assigned IP"] == "10.0.0.12"
    assert r["DNS servers"] == "10.0.0.53\n10.0.0.54"
    assert r["DNS suffixes"] == "corp.example.com"
    assert r["Access routes"] == "0.0.0.0/0" and r["Excluded routes"] == "198.51.100.0/24"
    assert r["MTU (gateway)"] == "0" and r["MTU (configured in the client)"] == "1400"
    assert r["Session lifetime (s)"] == "43200" and r["Inactivity timeout (s)"] == "10800"
    assert r["IPSec udp-port"] == "4501" and r["IPSec enc-algo"] == "aes-256-gcm"
    assert r["User expires (UTC)"] == "2026-11-14 01:06:36"
    assert "gw1.example.com" in cfg.data["gateway_configs"]


def test_gateway_config_truncated_by_the_logger(tmp_path):
    cut = GW_CONFIG[:GW_CONFIG.index("\t\t</ipsec>")]
    text = log(rec("Debug", 3100, "11/12/26 20:39:49:852", "gateway gw1.example.com's config is <?xml version=\"1.0\" ?>")
               + NL + cut.replace("\n", NL))
    cfg = build_config(make_bundle(tmp_path, {"PanGPS.log": text}))
    s = sec(cfg, "gateways")
    assert rows(s)["Assigned IP"] == "10.0.0.12"
    assert "truncated" in s.note


def test_malformed_xml_never_raises(tmp_path):
    text = log(
        rec("Debug", 3100, "11/12/26 20:39:49:852", "gateway gw1.example.com's config is <?xml?>")
        + NL + "<response><ip-address>10.0.0.1</ip-address></foo>" + NL,
        rec("Debug", 3100, "11/12/26 20:39:50:852", "gateway gw2.example.com's config is <!DOCTYPE x [<!ENTITY a 'b'>]><response/>"),
        *chunked("<?xml version='1.0'?><response><type>status</type><<<broken</response>", 40,
                 "11/12/26 20:39:51:000"))
    cfg = build_config(make_bundle(tmp_path, {"PanGPS.log": text}))
    assert cfg.data["scan"]["xml_errors"] >= 2
    assert sec(cfg, "gateways").groups == []
    assert parse_xml("not xml") == (None, False)
    assert parse_xml("<a><b>1</b></a>")[0].findtext("b") == "1"
    assert parse_xml("<a><b>1</b>")[1] is True


# -------------------------------------------------------------- static files
def test_hip_report_and_freshness(tmp_path):
    files = {"pan_gp_hrpt.xml": HIP_REPORT,
             "PanGPS.log": log(rec("Info", 1, "11/14/26 21:59:44:000", "x"))}
    cfg = build_config(make_bundle(tmp_path, files))
    s = sec(cfg, "hip_report")
    assert s.timestamp == datetime(2026, 11, 13, 15, 7, 16)  # noqa: DTZ001
    assert s.freshness == HISTORICAL and "older than the newest log record" in s.note
    r = rows(s)
    assert r["Client version"] == "6.3.3-828" and r["User"] == "jdoe"
    assert "10.0.0.12" in r["PANGP Virtual Ethernet Adapter Secure #2"]
    assert r["anti-malware"].startswith("1 product(s): Example AV 1.2")
    assert "1 missing patch(es)" in r["patch-management"]
    assert cfg.data["hip"]["interfaces"][0]["pangp"] is True


def test_hip_report_recent_is_last_seen(tmp_path):
    files = {"pan_gp_hrpt.xml": HIP_REPORT,
             "PanGPS.log": log(rec("Info", 1, "11/13/26 20:00:00:000", "x"))}
    s = sec(build_config(make_bundle(tmp_path, files)), "hip_report")
    assert s.freshness == LAST_SEEN and s.note.count("older") == 0


def test_troubleshooting_report_historical(tmp_path):
    files = {"pan_gp_trb.log": TRB, "PanGPS.log": log(rec("Info", 1, "11/14/26 21:59:44:000", "x"))}
    cfg = build_config(make_bundle(tmp_path, files))
    s = sec(cfg, "troubleshooting")
    assert s.freshness == HISTORICAL and "117 days" in s.note
    assert s.timestamp == datetime(2026, 7, 20, 14, 8, 16)  # noqa: DTZ001
    r = rows(s)
    assert r["report_time"] == "2026-07-20 12:08:16 UTC (2026-07-20 14:08:16 local)"
    assert r["portal_auth"] == "cert (user store)\ncredential (saved credential)"
    assert r["portal_reachable"] == "yes" and len(s.groups[0].rows) == 12


def test_troubleshooting_report_same_day_is_not_historical_and_cut_json(tmp_path):
    files = {"pan_gp_trb.log": TRB[:-120],
             "PanGPS.log": log(rec("Info", 1, "07/20/26 15:00:00:000", "x"))}
    cfg = build_config(make_bundle(tmp_path, files))
    s = sec(cfg, "troubleshooting")
    assert s.freshness == LAST_SEEN
    assert "truncated" in s.note and rows(s)["gp_version"] == "6.3.3-828"


def test_host_network_and_pangp_absent(tmp_path):
    files = {"SystemInfo.txt": SYSTEMINFO, "IpConfig.txt": IPCONFIG, "RoutePrint.txt": ROUTE_PRINT,
             "PanGPS.log": log(rec("Debug", 8727, "11/14/26 20:00:00:000", "--Set state to Connected"))}
    cfg = build_config(make_bundle(tmp_path, files))
    s = sec(cfg, "host_network")
    assert s.freshness == CURRENT
    r = rows(s)
    assert r["System boot time"] == "2026-11-14 01:03:01"      # 14 > 12: day first
    assert parse_systeminfo(SYSTEMINFO)["Virtual Memory: Max Size"] == "55.993 MB"
    assert "[01]: Example Wi-Fi adapter" in parse_systeminfo(SYSTEMINFO)["Network Card(s)"]
    wifi = next(a for a in cfg.data["adapters"] if a["name"].endswith("Wi-Fi"))
    assert wifi["ipv4"] == ["192.0.2.64"] and wifi["ipv6"] == ["fe80::1"]
    assert wifi["dns"] == ["192.0.2.254", "192.0.2.253"] and wifi["state"] == "connected"
    eth = next(a for a in cfg.data["adapters"] if a["name"].endswith("Ethernet 2"))
    assert eth["state"] == "disconnected"
    assert cfg.data["routes"]["default_v4"][0]["gateway"] == "192.0.2.254"
    assert cfg.data["routes"]["default_v6"][0]["gateway"] == "fe80::fe"
    assert cfg.data["pangp_adapter"]["present"] is False
    assert r["PANGP adapter at collection"] == "not present"
    # the logs say Connected but the snapshot has no PANGP adapter: not connected
    conn = cfg.data["connection"]
    assert conn["connected"] is False and conn["last_state"] == "Connected"
    assert "older than the snapshot" in conn["conclusion"]


def test_connected_with_pangp_adapter(tmp_path):
    files = {"IpConfig.txt": IPCONFIG_PANGP,
             "PanGPS.log": log(rec("Debug", 8727, "11/14/26 20:00:00:000", "--Set state to Connected"))}
    cfg = build_config(make_bundle(tmp_path, files))
    assert cfg.data["pangp_adapter"]["present"] is True
    assert cfg.data["connection"]["connected"] is True
    assert rows(sec(cfg, "summary"))["Connected"] == "yes"


def test_connection_unknown_without_evidence(tmp_path):
    cfg = build_config(make_bundle(tmp_path, {"junk.txt": "x"}))
    assert cfg.data["connection"]["connected"] is None
    assert rows(sec(cfg, "summary"))["Connected"] == "unknown"


def test_service_stopped_after_last_state(tmp_path):
    text = log(rec("Debug", 8727, "11/14/26 20:00:00:000", "--Set state to Connected"),
               rec("Info", 271, "11/14/26 20:30:00:000", "PanGPS service exits"))
    cfg = build_config(make_bundle(tmp_path, {"PanGPS.log": text}))
    conn = cfg.data["connection"]
    assert conn["service_stopped_after"] is True and conn["connected"] is None


def test_driver_entries(tmp_path):
    events = parse_setupapi(SETUPAPI)
    assert [(e["ts"], e["code"], e["device"]) for e in events] == [
        (datetime(2026, 11, 14, 1, 1, 29, 410000), 22, "ROOT\\PANGPD\\0000"),  # noqa: DTZ001
        (datetime(2026, 11, 14, 1, 1, 47, 410000), 22, "ROOT\\PANGPD\\0000")]  # noqa: DTZ001
    assert events[0]["meaning"] == "device is disabled" and events[0]["status"] == "0x00000000"
    files = {"setupapi.dev.log": SETUPAPI,
             "setupapi.app.log": "[BeginLog]\r\n     dvi: Install finished for ROOT\\PANGPD\\0000\r\n"}
    cfg = build_config(make_bundle(tmp_path, files))
    s = sec(cfg, "driver")
    assert s.freshness == LAST_SEEN and s.timestamp == datetime(2026, 11, 14, 1, 1, 47, 410000)  # noqa: DTZ001
    assert len(cfg.data["driver_events"]) == 2 and "INFERENCE" in s.note
    assert cfg.data["driver_install_finished_count"] == 1


# ---------------------------------------------------- missing files and output
def test_missing_files_give_sections_not_exceptions(tmp_path):
    cfg = build_config(make_bundle(tmp_path, {"junk.txt": "x"}))
    assert [s.id for s in cfg.sections] == [
        "summary", "registry", "status", "portal_settings", "gateways", "hip_report",
        "troubleshooting", "host_network", "driver"]
    assert "Not in bundle: regval.txt" in sec(cfg, "registry").note
    assert "Not in bundle: pan_gp_hrpt.xml" in sec(cfg, "hip_report").note
    assert "Not in bundle: pan_gp_trb.log" in sec(cfg, "troubleshooting").note
    assert "Not in bundle" in sec(cfg, "host_network").note
    assert "Not in bundle: setupapi.dev.log" in sec(cfg, "driver").note
    assert sec(cfg, "status").groups == [] and sec(cfg, "gateways").groups == []
    assert sec(cfg, "hip_report").freshness == HISTORICAL


def test_empty_and_garbage_static_files(tmp_path):
    files = {"regval.txt": b"", "pan_gp_hrpt.xml": "<hip-report><oops", "pan_gp_trb.log": b"\x00" * 64,
             "SystemInfo.txt": "", "IpConfig.txt": "\r\n", "setupapi.dev.log": ""}
    cfg = build_config(make_bundle(tmp_path, files))
    assert len(cfg.sections) == 9
    json.dumps(cfg.to_dict())


def test_summary_collection_time_from_zip_name_and_to_dict(tmp_path):
    zpath = tmp_path / "GlobalProtectLogs_jdoe_11142026215949.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("PanGPS.log", full_service_log())
        z.writestr("regval.txt", b"Settings\r\nLastUrl=vpn.example.com\x00\r\n")
        z.writestr("pan_gp_trb.log", TRB)
    cfg = build_config(Bundle.open(zpath))
    assert cfg.collected_at == datetime(2026, 11, 14, 21, 59, 49)  # noqa: DTZ001
    s = sec(cfg, "summary")
    r = rows(s)
    assert r["Bundle collected"] == "2026-11-14 21:59:49"
    assert r["Last portal"] == "vpn.example.com" and r["User"] == "jdoe"
    assert r["Client version"] == "6.3.3-828"
    assert sec(cfg, "troubleshooting").freshness == HISTORICAL
    d = json.loads(json.dumps(cfg.to_dict()))
    assert d["collected_at"] == "2026-11-14 21:59:49"
    assert d["sections"][0]["id"] == "summary" and d["sections"][0]["groups"][0]["rows"][0]["label"]
    assert set(d["sections"][0]) == {"id", "title", "sources", "timestamp", "freshness", "note", "groups"}


def test_parse_datetime_formats():
    ref = datetime(2026, 11, 14, 21, 0)  # noqa: DTZ001
    assert parse_datetime("11/13/2026 15:07:16") == (datetime(2026, 11, 13, 15, 7, 16), False)  # noqa: DTZ001
    assert parse_datetime("14/11/2026, 01:03:01", "dmy")[0] == datetime(2026, 11, 14, 1, 3, 1)  # noqa: DTZ001
    assert parse_datetime("2026/11/14 01:01:29.410")[0] == datetime(2026, 11, 14, 1, 1, 29, 410000)  # noqa: DTZ001
    assert parse_datetime("11/14/2026, 1:03:01 PM")[0] == datetime(2026, 11, 14, 13, 3, 1)  # noqa: DTZ001
    # 03/04: ambiguous; the reference date picks the candidate that is not in the future
    dt, amb = parse_datetime("03/04/2026, 10:00:00", "dmy", ref)
    assert amb and dt == datetime(2026, 4, 3, 10, 0)  # noqa: DTZ001
    assert parse_datetime("sabato 14 novembre 2026 01:03:32") == (None, False)
    assert parse_datetime("") == (None, False)


# ------------------------------------------------- bundles with only PanGPS / PanGPA (tar)
def make_tgz(path, files: dict[str, str | bytes]):
    import io
    import tarfile
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            data = content if isinstance(content, bytes) else content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def gw_status(n: int) -> str:
    entries = "".join(
        f"<entry><gateway>gw{i}.example.com</gateway><description>Region {i}</description>"
        f"<priority>{i % 5}</priority><tunnel>no</tunnel><internal>{'yes' if i == 0 else 'no'}</internal>"
        f"{'<manual>yes</manual>' if i % 2 else ''}</entry>" for i in range(n))
    return ('<?xml version="1.0"?><response><type>status</type><status>Disconnected</status>'
            "<product-version>6.2.8-982</product-version><state>Discovery complete</state>"
            "<portal>vpn.example.com</portal><user-name>jdoe</user-name>"
            f'<gateway-list name="gateway-list" type="external">{entries}</gateway-list></response>')


def service_log_only() -> str:
    ts = "09/01/26 08:00:00:000"
    recs = [
        rec("Info", 10, "09/01/26 08:00:00:000", "####### Start PanGPS service (ver: 6.2.8-982) #######", pid=11),
        rec("Info", 11, ts, "Connect method is user-logon", pid=11),
        rec("Debug", 12, ts, "Portal vpn.example.com, user jdoe, logonDomain ", pid=11),
        rec("Debug", 13, ts, "Portal's saml auth method REDIRECT", pid=11),
        rec("Debug", 14, ts, "Portal's saml request timeout is 600", pid=11),
        rec("Debug", 15, ts, "Prelogin use-default-browser = no", pid=11),
        rec("Debug", 16, ts, "Portal's saml default browser support = yes", pid=11),
        rec("Debug", 17, ts, "Portal auth method: saml, auth src: IDP", pid=11),
        rec("Debug", 18, ts, "Discover external gateway: gateway count is 14, cutoff time is 5", pid=11),
        rec("Debug", 19, ts, "gateway Region 3 (gw3.example.com), priority=3, duration=70 ms, assign 100 as its weight", pid=11),
        rec("Debug", 20, "09/01/26 08:00:05:000", "--Set state to Connected", pid=11),
        rec("Debug", 21, "09/01/26 08:00:06:000", "NetworkDiscoverThread: network type is external.", pid=11),
        rec("Info", 22, "09/05/26 09:00:00:000", "####### Start PanGPS service (ver: 6.2.8-1084) #######", pid=12),
        rec("Info", 23, "09/05/26 09:00:01:000", "Connect method is On-Demand", pid=12),
        rec("Debug", 24, "09/05/26 09:00:02:000", "Portal vpn2.example.com, user pre-logon, logonDomain ", pid=12),
        rec("Debug", 25, "09/05/26 09:00:09:000", "--Set state to Disconnected", pid=12),
    ]
    return log(*recs)


def agent_log_only() -> str:
    return log(rec("Debug", 1, "09/05/26 09:00:03:000", "message type from the service = status", pid=30)
               + NL + gw_status(14).replace("><", ">" + NL + "<"))


def test_log_only_tar_bundle(tmp_path):
    t = make_tgz(tmp_path / "logs.tgz", {"x/PanGPS.log": service_log_only(), "x/PanGPA.log": agent_log_only()})
    b = Bundle.open(t)
    cfg = build_config(b)
    d = cfg.data
    # version history from the service banner, with the in-bundle change
    runs = d["client_versions"]["runs"]
    assert [r["version"] for r in runs] == ["6.2.8-982", "6.2.8-1084"] and runs[1]["change"] == "newer"
    assert [s["pid"] for s in d["client_versions"]["starts"]] == [11, 12]
    summary = {r.label: r for g in cfg.section("summary").groups for r in g.rows}
    assert summary["Client version"].value == "6.2.8-1084" and "service banner" in summary["Client version"].hint
    assert "Version history" in summary and "Portals seen" in summary
    # connect method, portals
    assert d["connect_method"]["value"] == "On-Demand"
    assert set(d["connect_method"]["seen"]) == {"user-logon", "On-Demand"}
    assert {p["portal"] for p in d["portals"]} >= {"vpn.example.com", "vpn2.example.com"}
    assert cfg.data["status"]["_ts"]
    # authentication
    auth = d["authentication"]
    assert auth["saml_method"] == "REDIRECT" and auth["saml_timeout"] == "600"
    assert auth["use_default_browser"] == "no" and auth["saml_browser_support"] == "yes"
    assert auth["portal_auth"].startswith("saml") and auth["prelogon_user_seen"] is True
    # compact gateway list, complete in .data
    gw = cfg.section("gateways")
    compact = [g for g in gw.groups if g.title.startswith("Gateway list (14 entries")]
    assert compact and len(compact[0].rows) == 14
    assert len(d["gateway_list"]) == 14 and d["gateways_summary"]["internal"] == 1
    assert any("70 ms" in r.value for r in compact[0].rows)
    # no network snapshot: unknown, never "not connected"
    assert d["connection"]["connected"] is None and d["connection"]["status"] == "unknown"
    assert d["pangp_adapter"]["present"] is None and d["pangp_adapter"]["status"] == "unknown"
    assert "Not in bundle: SystemInfo.txt, IpConfig.txt, RoutePrint.txt." in cfg.section("host_network").note
    assert cfg.section("registry").note == "Not in bundle: regval.txt."
    assert cfg.section("installer") is None
    # collection time falls back to the newest log record
    assert cfg.collected_at == datetime(2026, 9, 5, 9, 0, 9)  # noqa: DTZ001
    assert any(g.title == "State at the end of the logs" for g in cfg.section("summary").groups)
    json.dumps(cfg.to_dict())


def test_status_chunks_do_not_depend_on_source_number(tmp_path):
    xml = status_xml("Connected")
    pieces = [rec("Dump", 4321, "11/12/26 20:00:00:000", "ResponseToClient.txt_output: " + xml[i:i + 300].replace("\n", NL),
                  tid=7) for i in range(0, len(xml), 300)]
    svc = log(*pieces)
    b = Bundle.open(make_zip_bundle(tmp_path, {"PanGPS.log": svc}))
    cfg = build_config(b)
    assert cfg.data["status"]["state"] == "Connected"


def make_zip_bundle(tmp_path, files):
    path = tmp_path / "b.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return path


MSI_TEXT = (
    "=== Logging started: 20/07/2026  12:55:38 ===\r\nAction start 12:55:38: INSTALL.\r\n"
    "Property(S): ProductName = GlobalProtect\r\nProperty(S): ProductVersion = 6.2.8\r\n"
    "Property(S): ProductCode = {00000000-0000-0000-0000-000000000001}\r\n"
    "MSI (s) (60:94) [12:55:50:990]: Product: GlobalProtect -- Removal completed successfully.\r\n"
    "MSI (s) (60:94) [12:55:50:991]: Windows Installer removed the product. Product Name: GlobalProtect. "
    "Product Version: 6.2.8. Product Language: 1033. Manufacturer: Example.\r\n"
    "=== Logging stopped: 20/07/2026  12:55:50 ===\r\n"
    "=== Logging started: 20/07/2026  12:56:00 ===\r\n"
    "Property(S): ProductVersion = 6.3.0\r\nProperty(S): PORTAL = vpn.example.com\r\n"
    "MSI (s) (60:40) [12:56:14:527]: Product: GlobalProtect -- Installation completed successfully.\r\n"
    "=== Logging stopped: 20/07/2026  12:56:14 ===\r\n")


def test_msi_log_events_in_damaged_utf16(tmp_path):
    raw = b"\xef\xbf\xbd\xef\xbf\xbd" + MSI_TEXT.encode("utf-16-le")
    t = make_tgz(tmp_path / "logs.tgz", {"PanGPS.log": service_log_only(), "PanGPMsi.log": raw})
    cfg = build_config(Bundle.open(t))
    ev = cfg.data["installer"]["events"]
    assert [(e["kind"], e["result"], e["version"]) for e in ev] == [
        ("remove", "success", "6.2.8"), ("install", "success", "6.3.0")]
    assert ev[0]["ts"] == datetime(2026, 7, 20, 12, 55, 50)  # noqa: DTZ001
    assert ev[1]["after_removal"] is True and ev[1]["same_version_as_removed"] is False
    sec = cfg.section("installer")
    assert sec is not None and any(r.key == "PORTAL" for g in sec.groups for r in g.rows)
    assert "Installer events" in {r.label for g in cfg.section("summary").groups for r in g.rows}


def test_collection_time_from_file_name_wins_over_newest_record(tmp_path):
    t = make_tgz(tmp_path / "GlobalProtectLogs_jdoe_09062026101010.tgz", {"PanGPS.log": service_log_only()})
    cfg = build_config(Bundle.open(t))
    assert cfg.collected_at == datetime(2026, 9, 6, 10, 10, 10)  # noqa: DTZ001

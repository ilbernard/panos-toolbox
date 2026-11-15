# GlobalProtect Windows client: log bundle format specification

Audience: developers of `src/panos_toolbox/gp/` (offline analyzer for the "Collect Logs" zip of a
GlobalProtect Windows client, GP 6.3.x).

This specification was derived from **one sample bundle** (client 6.3.3-828, Windows 11, On-Demand connect
method, one portal, one gateway, username/password authentication, IPSec tunnel). Every count, percentage
and date range below was "measured on one sample bundle". Where a statement is not literally present in the
files it is marked **(INFERENCE)**. Section 12 lists what the sample did not contain: the spec is
**incomplete** for those cases and must not be extended by guessing.

All example values are synthetic. Conventions used in examples:

| Real kind | Placeholder |
|---|---|
| portal host | `vpn.example.com` (portal name `GP-Portal-EX`) |
| gateway host / short name | `gw1.example.com` / `gw1` (gateway config name `GP-Gateway-EX`) |
| user | `jdoe`, `EXAMPLE\jdoe`, `jdoe@example.com` |
| host name / AD domain | `LAPTOP-01` / `corp.example.com`, NetBIOS `EXAMPLE` |
| gateway public IP | `203.0.113.10` (other public: `198.51.100.x`) |
| tunnel IP / DNS | `10.0.0.12` / `10.0.0.53` |
| LAN IP / default gateway | `192.0.2.64` / `192.0.2.254` |
| MAC / host-id / serial | `02-00-00-00-00-01` / `00000000-0000-0000-0000-000000000001` / `SERIAL0001` |
| hashes / ids | `0123456789abcdef0123456789abcdef` |

---

## 1. Bundle inventory

| File | Purpose | Used by the analyzer |
|---|---|---|
| `pan_gp_event.log`, `pan_gp_event.log.old` | High-level event log (one line per event) | Yes: primary attempt timeline |
| `PanGPA.log` | UI agent (PanGPA.exe) log: clicks, dialog states, status XML | Yes: enrichment (click, UI outcome) |
| `PanGPS.log`, `PanGPS.1.log` ... `PanGPS.8.log` | Service (PanGPS.exe) log, very verbose | Yes: detailed flow, settings, tunnel facts, restore attempts |
| `regval.txt` | Dump of GlobalProtect registry values | Yes: client settings |
| `pan_gp_hrpt.xml` | Last HIP report | Yes: host/interface snapshot (stale) |
| `pan_gp_trb.log` | JSON troubleshooting report (last failed connection only) | Yes: auth methods, error stage (stale) |
| `SystemInfo.txt` | `systeminfo` output | Yes: host, OS, time zone |
| `IpConfig.txt` | `ipconfig /all` | Optional: live network snapshot |
| `RoutePrint.txt` | `route print` | Optional: live routes |
| `NicDetails.txt` | per-interface IP parameters | No |
| `NetStat.txt` | `netstat` (TCP IPv4, no PID) | No |
| `TcpipBind.txt` | TCP/IP adapter bind list (UTF-16LE) | No |
| `PanProxyAgent.log` | Proxy agent service log, never rotated | No (could date service starts) |
| `LogonUI.log`, `LogonUI.log.old` | Credential provider trace at logon/unlock | No (shows pre-logon disabled) |
| `PanGpHip.log`, `PanGpHip.1.log` | HIP collection process | No |
| `PanGpHipMp.log`, `PanGpHipMp.1.log` | HIP missing-patch collector | No |
| `debug_drv.log` | PANGP virtual adapter driver (mostly packet counters) | No |
| `setupapi.app.log`, `setupapi.dev.log` | Windows device install logs | No |
| `PanGPA.dmp` | Minidump of PanGPA (old crash) | No |
| `DriverInfo.txt`, `NicConfig.txt`, `ProcessInfo.txt`, `ServiceInfo.txt`, `PanGPS.dmp` | Zero-byte in the sample | No; tolerate empty files |

Rules for the loader:

- Every file is optional. Zero-byte and missing files must not raise errors.
- The static snapshot files (`IpConfig`, `RoutePrint`, `NicDetails`, `NetStat`, `SystemInfo`) describe the
  moment of collection. In the sample they showed the client **not connected** (no PANGP adapter).
- `pan_gp_hrpt.xml` (1 day older than collection), `pan_gp_trb.log` (4 months older), `PanGPA.dmp` and the
  setupapi logs are older artefacts. Never present them as "current".

## 2. Common conventions across the log files

- **Time zone**: all log timestamps are the PC's **local wall-clock time** with no offset and no zone name.
  Evidence (INFERENCE, strong): `pan_gp_trb.log` holds epoch `1784549296` (2026-07-20 12:08:16 UTC) with
  `host_gmt_timeoffset` 120, and the event log has the matching local line `07/20/2026 14:08:16:154`
  (UTC+2, summer). In November the offset is UTC+1 (file mtimes are 1 h earlier than the last record).
  The DST-end ambiguous hour was not observed to cause inversions. Do not convert to UTC unless the offset
  is known; the zone can be taken from `SystemInfo.txt` ("Time Zone") only as a hint.
- **Millisecond separator is a colon**: `HH:MM:SS:mmm`. Python: `strptime(s, "%m/%d/%y %H:%M:%S:%f")`
  (`%f` accepts the 3-digit field).
- **Date order is month/day** everywhere in the logs. Year is 4 digits in the event log, 2 digits in all other
  logs.
- **Line endings are CRLF.** Stray lone `\r` exist inside XML payloads (`\r\r\n` in PanGPS, 568 lone CR in
  PanGPA). Read bytes, normalise `\r+\n` to `\n`, then split. Python universal-newline mode miscounts lines.
- **Encoding**: ASCII (7-bit) for all logs; no BOM, no NUL bytes. Decode `ascii` or `latin-1` with
  `errors="replace"`; never assume UTF-8 for `regval.txt`.
- **Not strictly monotonic**: a few small inversions between threads (1 to 13 ms) and one 3 min 36 s
  inversion in the old event log. Keep file order, tolerate negative deltas, never sort globally.
- **Rotation order**: un-numbered file is the newest; `.old` or a higher number is older. Chronological order
  for PanGPS is `.8, .7, ..., .1, PanGPS.log`; for the event log `.old` then the current file.
- **Source number** `(NNNN)` in the service/agent prefix is the source line of the logging call in the
  binary (INFERENCE): a stable fingerprint per message text, not a log line number.

## 3. `pan_gp_event.log` and `pan_gp_event.log.old`

### 3.1 Record format

```
MM/DD/YYYY HH:MM:SS:mmm [Info ]: message
MM/DD/YYYY HH:MM:SS:mmm [Error]: message
```

```python
EV = re.compile(r'^(\d\d)/(\d\d)/(\d{4}) (\d\d):(\d\d):(\d\d):(\d{3}) \[(Info|Error)\s*\]: (.*)$')
```

- Level token is `Info ` (one trailing space inside the brackets) or `Error`. No other levels.
- No pid, thread, source line, portal, user or attempt id in the prefix. Context comes from sequence only.
- Messages can have trailing spaces (`CheckServerCert return 0x1002 `, `invalid user auth cookie. `);
  match with whitespace tolerance but keep the literal text otherwise.
- Multi-line records: practically none. A blank line can follow an `[Error]` record whose text ends with a
  newline: treat empty lines as noise.
- Measured on one sample bundle: old file 23,294 lines, 2025-08-17 to 2026-05-28; current file 14,590 lines,
  2026-05-28 to 2026-11-14 01:03:25; 97 distinct normalised message templates; the two files are contiguous.
- **The event log can end earlier than the other logs** (sample: it stops at the last service start while
  PanGPA/PanGPS run about 21 h longer). Do not assume it covers the whole bundle.
- Client versions change inside the log (`service started (client version: ...)`).

### 3.2 Message templates relevant to the timeline

Literal text, typos included (the parser matches them). `<gw>` is a gateway FQDN, `<name>` a short gateway
name, `<portal>` a portal FQDN, `<N>` an integer.

| Template | Meaning |
|---|---|
| `Started the Portal pre-login` | **Start of a portal cycle** (see 3.3) |
| `SSO starts.` | Optional trigger hint within 2 s before the start. INFERENCE: automatic/SSO trigger; absent in all user-click attempts of the sample |
| `CPanMSService::PreloginPortal CheckServerCert return 0x1002 ` | Portal pre-login certificate/reachability code. INFERENCE: `0x1002` portal reached OK, `0x1000` TLS/certificate error, `0x4000` cannot connect, `0x0` no result (cross-checked against PanGPA WinHTTP errors) |
| `Portal pre-login result received` | Portal pre-login answered |
| `Failed to pre - login to the portal <portal>` | Portal pre-login failed (note the spaces around the hyphen) |
| `Portal Login starts` | Portal getconfig/login phase begins |
| `File is successfully decrypted. File: C:\Users\jdoe\AppData\Local\Palo Alto Networks\GlobalProtect\PanPUAC_<id>.dat` | Stored auth cookie file read; noise, but `<id>` is a stable per-portal id (INFERENCE: unpadded MD5 of the portal) |
| `Failed to open file ...PanPUAC_<id>.dat` | No stored cookie for that portal |
| `Unserialized non-empty cookie for portal <portal> and user <user>` / `... and pre-logon user.` | Cookie present; user is URL-encoded (`jdoe%40example.com`). The pre-logon wording is used even when pre-logon is disabled |
| `Unserialized empty cookie for portal <portal> and user <user>` | No cookie |
| `Serialize non-empty cookie for portal <portal> and pre-logon user` / `Serialize empty cookie ...` | Cookie written |
| `Logging into portal` | Portal login request sent |
| `Auth failed empty password for portal` | Client had no password: the UI will prompt. INFERENCE: a prompt, not a rejection |
| `Auth failed for portal` | INFERENCE: credentials rejected (only in the old file) |
| `User Authenticated but the portal config is null` | Precedes `portal status is Using cached portal config.` |
| `portal status is Connected.` | Portal phase OK |
| `portal status is User authentication failed.` | With `Auth failed empty password` = credential prompt (non-terminal); with `Auth failed for portal` = real failure |
| `portal status is Using cached portal config.` | Portal unreachable or no config; cached config used |
| `portal status is Invalid portal.` | Portal failure |
| `portal status is Client Cert Required.` | Client certificate demanded (seen in old file only) |
| `Connect method is On-Demand` / `Connect method is user-logon` | Connect method (the only place besides PanGPS) |
| `Portal login completed with address <portal> and conect method of <method>.` | **Only success marker of the portal phase**; carries the portal FQDN (`conect` is a typo) |
| `prelogon status is <N>` | Pre-logon state |
| `Unable to fetch the latest Portal configuration from address <portal>.` | Portal config refresh failed |
| `Network discovery started.` | Gateway discovery begins |
| `Discovering external network.` / `Discovering internal network.` | Network type |
| `Gateway selection(Priority-TCP-SSL-Weight): <name>(<P>-<TCP>-<SSL>-<W>), ...` | Several gateways only; lists gateway **names** |
| `Gateway pre-Login Starts to <gw>` | Gateway pre-login |
| `Prelogin to gateway (null) <gw> without ipv6` | Gateway pre-login detail |
| `Gateway Login starts to <gw>` | Gateway login |
| `Invalid user credential for gateway <gw>` | Gateway asks for credentials again: non-terminal prompt |
| `Auto Gateway login finished with address <gw> and user <user>.` | Gateway login OK (user decoded, e.g. `jdoe@example.com`) |
| `Manual Gateway login finished with address <gw> and user <user>.` | User picked the gateway (old file only) |
| `User canceled login to gateway <gw>.` | Cancelled |
| `Failed to pre-login to the gateway <gw>` | Gateway pre-login failed |
| `Failed to verify server certificate of gateway <gw>.` | Gateway certificate failure |
| `Trying to create tunnel with gateway <gw>` | Tunnel creation begins |
| `IPSec tunnel creation finished with Gateway <gw>.` / `SSL tunnel creation finished with Gateway <gw>.` | **Success marker**; protocol is the only tunnel fact |
| `IPSec tunnel should failover to SSL(keepalive count <N>, error packet count <N>, quit reason <N>)` | IPSec to SSL failover; a second tunnel line follows |
| `failed to create tunnel with gateway <gw>` | Tunnel failure |
| `Gateway route 203.0.113.10 got changed to use virtual IP 10.0.0.12 as source IP: gateway route was removed` | Only place in this log with gateway public IP and tunnel IP |
| `Completed HIP Report check with Gateway <gw>.` / `HIP Report submitted to the Gateway <gw>.` | HIP, about hourly; noise for attempts |
| `User disconnecting tunnel starts` | User-initiated disconnect |
| `Tunnel is down due to <reason>.` | Reasons seen: `disconnection`, `network change`, `keep-alive timeout`, `packet sending failure`, `socket closed`, `packet receiving failure`, `idle timeout` |
| `Tunnel downtime is <N> miliseconds` | Follows the line above (typo `miliseconds`) |
| `In timeout handling, tunnel downtime is <N> miliseconds` | Variant |
| `User was logged out of Gateway <gw>.` / `User could not be logged out of Gateway <gw>.` | Logout; also appears at the start of a manual reconnect |
| `Gateway <name>: Checking network availability and restoring VPN connection when network is available.` | Automatic restore starts (short gateway name) |
| `Retry connect failed first time` / `second time` / `third time` | Restore retries |
| `Tunnel retry done: failed retry` | Restore failed |
| `Tunnel is restored.` | Restore succeeded |
| `Tunnel downtime (<N> milliseconds) exceeds retry grace period (<N> seconds)` (also with trailing `.`) | Restore abandoned (grace period 1800 s in the sample) |
| `No tunnel retry since tunnel downtime (<N> miliseconds) exceeds configured timeout (<N> seconds)` | Variant (typo) |
| `Wait in modern standy until wakeup` | Sleep (typo `standy`) |
| `Troubleshooting log is generated with the error stage (<stage>) and the error detail (<detail>).` | Troubleshooting report written; stage seen: `Portal pre-login`, `Gateway pre-login`; details `Authentication Failed. No retries.`, `Authentication Failed.`, `TCP connection timed-out` |
| `GlobalProtect service started (client version: 6.3.3-828, OS version: Microsoft Windows 11 Pro , 64-bit).` / `GlobalProtect service stopped.` | Service lifecycle; the only place with OS and version in this log |
| `GlobalProtect app is disabled.` | Client disabled |

`[Error]` records are the user-visible texts (equal to the PanGPA `<error>` element), with an optional
`Gateway <name>: ` prefix and no portal:

- `The network connection is unreachable or the gateway is unresponsive. Check the network connection and reconnect.`
- `The network connection is unreachable or the portal is unresponsive. Check the network connection and reconnect.`
- `Gateway <name>: Failed to receive message from remote host`
- `No Network Connectivity. Please verify your network connection and try again.`
- `Failed to verify certificate`
- `Gateway <name>: Could not verify the server certificate of the gateway. If the issue persists, contact your administrator.`
- `A valid client certificate is required for authentication. If the issue persists, contact your administrator.`
- `Gateway <name>: Your GlobalProtect session has ended due to inactivity.`
- `Failed to find PANGP virtual adapter interface`

### 3.3 Segmentation rule (validated on the sample)

A user-visible attempt is a **chain of cycles**: the client first tries with no password, the UI prompts, and
a second cycle starts when the user submits. Counting `Started the Portal pre-login` therefore double counts;
counting tunnel-creation lines ignores failures.

1. **Cycle start** = `Started the Portal pre-login`. If `SSO starts.` is at most 2 s earlier: trigger
   `sso/auto`, else `manual-or-restore` (INFERENCE).
2. **Cycle end** (first match wins; stop collecting at the terminal marker, because later lines belong to the
   session, not the attempt):
   - `(IPSec|SSL) tunnel creation finished with Gateway G.` -> SUCCESS (if several tunnel lines occur in one
     cycle, use the last: IPSec to SSL failover).
   - `failed to create tunnel with gateway G` -> FAIL_TUNNEL.
   - `Failed to verify server certificate of gateway G.` (+ the matching `[Error]`) -> FAIL_GW_CERT.
   - `User canceled login to gateway G.` or `User disconnecting tunnel starts` before any tunnel -> CANCELLED.
   - `Troubleshooting log is generated ...` right after `Portal pre-login result received` and without
     `Portal Login starts` -> FAIL_PRELOGIN_TS (stage and detail are the error text).
   - `portal status is User authentication failed.` -> non-terminal AUTH_PROMPT if `Auth failed empty password
     for portal` precedes it; AUTH_FAIL (terminal) if `Auth failed for portal` precedes it.
   - `portal status is Invalid portal.` or `Failed to pre - login to the portal P` with no later `Portal login
     completed` -> FAIL_PORTAL.
   - `Portal login completed ...` followed by an `[Error]` line before any tunnel line -> FAIL_GW_UNREACH
     (observed 2 to 123 s after the cycle start, once 841 s).
   - `Invalid user credential for gateway G` -> non-terminal GW_AUTH_PROMPT.
   - Portal login stopping at `Failed to open file ...PanPUAC_<id>.dat`, at `Unserialized empty cookie ...
     and user ...` without `Logging into portal`, or at `Logging into portal` with nothing after ->
     non-terminal AWAITING_USER (INFERENCE: interactive password or SAML/browser step outside the log).
3. **Attempt** = chain: cycle N+1 joins the attempt when cycle N ended non-terminal and
   `start(N+1) - last_event(N) <= 600 s`. The attempt outcome is the outcome of its last cycle; an attempt
   ending non-terminal is ABANDONED. Measured on one sample bundle, the outcome counts are insensitive to the
   gap (60 s to 3600 s gives 836 to 781 attempts, SUCCESS 590 in every case; only ABANDONED moves).
4. **Fields**: portal = first FQDN in cookie lines, `Portal login completed with address` or `Failed to pre -
   login to the portal` (unresolved for some attempts; the PanPUAC id map can resolve a few); gateway and
   protocol from the gateway/tunnel lines; user = decoded UPN from `... login finished ... and user U.`
   (URL-decode `%40` in cookie lines); duration = end minus first start (includes the time the user typed
   credentials).
5. **Enrichment** from PanGPA (section 5) only where PanGPA covers the time.

Measured on one sample bundle (1,590 cycles): AUTH_PROMPT 614, SUCCESS 590, AWAITING_USER 202,
FAIL_PRELOGIN_TS 55, CANCELLED 47, FAIL_GW_UNREACH 31, AUTH_FAIL 25, FAIL_PORTAL 16, FAIL_TUNNEL 5,
unclassified 3, FAIL_GW_CERT 2. After chaining at 600 s: 787 attempts, SUCCESS 590 (75.0 %), FAIL 134,
CANCELLED 47, ABANDONED/unclassified 16. 55 of the 134 failures were one retry storm (the client repeated the
portal pre-login about every 1.5 s for 100 s, each ending with `Authentication Failed. No retries.`).
For the 10 attempts inside the window shared with PanGPA the result was 7 SUCCESS, 2 FAIL_GW_UNREACH,
1 FAIL_GW_CERT, matching PanGPA's 10 clicks (7 Connected, 3 Connection Failed) one to one.

Typical sequence (user click, password prompt, success):

```
11/11/2026 17:18:50:995 [Info ]: Started the Portal pre-login
11/11/2026 17:18:51:195 [Info ]: CPanMSService::PreloginPortal CheckServerCert return 0x1002 
11/11/2026 17:18:51:734 [Info ]: Portal pre-login result received
11/11/2026 17:18:51:735 [Info ]: Portal Login starts
11/11/2026 17:18:51:819 [Info ]: Unserialized non-empty cookie for portal vpn.example.com and pre-logon user.
11/11/2026 17:18:51:819 [Info ]: Logging into portal
11/11/2026 17:18:52:043 [Info ]: Auth failed empty password for portal
11/11/2026 17:18:52:043 [Info ]: portal status is User authentication failed.      <- cycle 1 ends, UI prompts
11/11/2026 17:18:58:428 [Info ]: Started the Portal pre-login                       <- cycle 2 (user submitted)
...
11/11/2026 17:19:32:203 [Info ]: Portal login completed with address vpn.example.com and conect method of on-demand.
11/11/2026 17:19:32:219 [Info ]: Network discovery started.
11/11/2026 17:19:32:232 [Info ]: Gateway pre-Login Starts to gw1.example.com
11/11/2026 17:19:32:671 [Info ]: Gateway Login starts to gw1.example.com
11/11/2026 17:19:33:752 [Info ]: Invalid user credential for gateway gw1.example.com   <- second prompt
11/11/2026 17:19:44:273 [Info ]: Auto Gateway login finished with address gw1.example.com and user jdoe@example.com.
11/11/2026 17:19:44:273 [Info ]: Trying to create tunnel with gateway gw1.example.com
11/11/2026 17:19:49:972 [Info ]: IPSec tunnel creation finished with Gateway gw1.example.com.    <- SUCCESS
```

Failure example (gateway unreachable, cached portal config):

```
11/12/2026 09:50:49:961 [Info ]: Started the Portal pre-login
11/12/2026 09:50:50:008 [Info ]: CPanMSService::PreloginPortal CheckServerCert return 0x4000 
11/12/2026 09:50:50:265 [Info ]: Failed to pre - login to the portal vpn.example.com
11/12/2026 09:50:50:634 [Info ]: portal status is Using cached portal config.
11/12/2026 09:50:52:384 [Info ]: Portal login completed with address vpn.example.com and conect method of on-demand.
11/12/2026 09:50:52:444 [Info ]: Gateway pre-Login Starts to gw1.example.com
11/12/2026 09:50:52:465 [Error]: Gateway gw1: The network connection is unreachable or the gateway is unresponsive. Check the network connection and reconnect.
```

### 3.4 What the event log does not carry

No attempt id, no session id, no click event, no authentication method (SAML or not), no tunnel IP at
connect. Portal is missing on most lines. It cannot tell a wrong password from a prompt except through
`Auth failed for portal` (not seen after 2026-05-28 in the sample).

## 4. `PanGPS.log` family (service log)

### 4.1 Record format

```
(P6864-T12588)Debug(3526): 11/12/26 20:38:12:533 AgentProxyAutoStart: user clicked connect button. ...
(P6864-T12588)Info ( 564): 11/12/26 20:38:12:533 msgtype = portal
(P6864-T20960)Dump (1160): 11/12/26 16:30:18:886 HandleDnsCallBack enter...
```

```python
PREFIX = re.compile(
    r'\(P(?P<pid>\d+)-T(?P<tid>\d+)\)(?P<lvl>[A-Za-z]+) ?\(\s*(?P<src>\d+)\): '
    r'(?P<mo>\d\d)/(?P<d>\d\d)/(?P<y>\d\d) (?P<H>\d\d):(?P<M>\d\d):(?P<S>\d\d):(?P<ms>\d{3}) ')
```

- Levels: `Debug`, `Info ` (trailing space), `Error`, `Dump ` (padded to 5, so the regex allows an optional
  space). No Warn/Fatal/Trace. **The level is not an importance indicator**: e.g. `Unable to verify server
  cert...`, `Auth failed empty password for portal`, `portal status is User authentication failed.` and
  `Tunnel retry done: failed retry` are all `Debug`. No `Error` record marked a failed login in the sample.
- `P<pid>` is the service process id (changes at service restart); `T<tid>` the thread id. Ids are reused
  across restarts: key by `(pid, tid)`. Follow one flow by thread: the portal flow runs on one thread, then
  network discovery, gateway and tunnel on another, and restore on a third.
- **Multi-line records**: a record's message runs until the next `PREFIX` match. Continuation lines have no
  prefix. Kinds: XML dumps (`ResponseToClient.txt_output`, `prelogin to portal result is`, `Pre-login response
  is`, `gateway X's config is`, `Write HIP policy:`, full HIP report, `Logout response:`, HTTP POST dumps) and
  route-table dumps.
- **Glued records**: 17 times in the sample a new record starts in the middle of a physical line because the
  previous record lacked its terminator. Tokenise with `PREFIX.finditer` over the whole text, never
  `line.startswith("(P")`.
- **Chunked dumps**: the status XML `ResponseToClient.txt_output:` is cut into records of about 2.1 KB, possibly
  mid-tag; reassemble by concatenating the text after the marker over consecutive records with the same source
  number, ending at `</response>`.
- Empty messages occur (`... 20:39:48:721 ` followed by CRLF).
- Measured on one sample bundle: 9 files, 436,435 records, 42.2 MB; 98.6 % `Dump`, 1.3 % `Debug`, 0.08 %
  `Info`, 0.007 % `Error`; 589 multi-line records; max physical line 413 chars (multi-line records up to
  about 11 KB); coverage 53.5 h with no gap above 4.2 s.
- **Rotation**: by size (about 5.2 MB per file); files split on record boundaries. Tolerate a continuation
  line at the top of a file anyway. Duration per file varies from 1.5 h to 17 h with the DNS noise rate.
- **Noise**: 96.6 % of records are `Dump`-level split-DNS and driver callbacks (`HandleDnsCallBack ...`,
  `HandleDnsCallback ...`, `ST,...`, `EnforceSplitDns ...`, `Received DNS request for <fqdn> with type <N>`).
  Drop early: level `Dump` and message starting with `HandleDnsCall`, `handleDnsCall`, `ST,`,
  `EnforceSplitDns`, `Received DNS request`, `Received a DNS`. Other frequent noise: `Writing the process
  execution path of GPS`, `try verify file ... PanGPA.exe` blocks before each GUI message, `Failed to find
  attribute '<x>'`, `Failed to get <x> from config, try local`, `SSL_connect:` progress lines, route table
  dumps, `Traffic Enforcement: ...` lines.
- `Setting debug level to 6` = maximum verbosity (explains the `Dump` flood).

### 4.2 Message patterns by phase

Regexes apply to the first line of the message (text after the prefix).

**Service**

| Pattern | Meaning |
|---|---|
| `#{5,} Start PanGPS service \(ver: (?P<ver>[\d.\-]+)\) #{5,}` | Service start with version |
| `^Received shutdown message`, `^PanGPS service exits` | Service stop |
| `^Start ServerThread` | GUI can attach |
| `^msgtype = (\S+)$` | GUI request type: `hello`, `portal`, `user_credential`, `sleep`, `pan_msg_ping` |
| `PAN GlobalProtect/(?P<ver>[\d.\-]+) \((?P<os>[^)]*)\)` | User agent: client version and OS |
| `^Received sleep event`, `^Received resume( -auto)? event`, `Wakeup from modern standby` | Power events |
| `^Received session change, event type (\d+), session (\d+)` | Windows session event; type 6 = logoff is confirmed by the log, 7 = lock, 8 = unlock are INFERENCE (WTS codes) |
| `^User (?P<u>\S+) logs off on session` | User logoff |

**Trigger and mode**

| Pattern | Meaning |
|---|---|
| `^AgentProxyAutoStart: user clicked connect button` | User clicked Connect (present on the non-cache-only `portal` request) |
| `^ProcessServerPortal: szCacheOnly: (?P<c>\S+) bRetrieveCacheOnly: (?P<b>\d)` | `yes`/`1` = cache-only load at GUI start, **not an attempt** |
| `^bCheckCachedPortalForPrelogon: (\d), m_bOnDemand: (\d)` | Mode flags |
| `^Connect method is (?P<m>.*)` | `Connect method is On-Demand` (Info) |
| `^On-demand mode is true\.`, `^Pre-logon-then-on-demand value is no`, `PrelogonEnabled is 0` | Pre-logon disabled |

**Portal**

| Pattern | Meaning |
|---|---|
| `^----Portal Processing starts----` (src 3512) | **Start anchor for kind A attempts** |
| `^Portal (?P<portal>\S+), user (?P<user>\S*), logonDomain (?P<dom>\S*), saved user (?P<su>\S*), path ` | Portal, user, domain, profile path |
| `^Portal's ipv4 address (?P<ip>\S+)` | Portal IP |
| `^REQID=(?P<id>\d+),IPADDR=(?P<host>[^,]+),PORT=(?P<port>\d+),URL=(?P<url>[^,]+),POST=(?P<post>\d),PROXY_AUTO=\d,.*VERIFY_CERT=(?P<vc>\d),ADDITIONAL_CHECK=(?P<ac>\d)` | One HTTPS request (global counter; `PROXY_PASS=****` already masked). URLs: `/global-protect/prelogin.esp`, `/global-protect/getconfig.esp`, `/ssl-vpn/prelogin.esp`, `/ssl-vpn/login.esp`, `/ssl-vpn/getconfig.esp`. Answer: `^retid =(\d+)` then `^reqid matchs, continue\.\.\.` |
| `^----Portal Pre-login starts----` | Portal pre-login |
| `^Check cert of server (\S+)`, `^X509_verify_cert result is (\d+)`, `^Unable to verify server cert\. Result is (.*)$`, `^CheckServerCert\(\) returns (0x[0-9a-fA-F]+)` | Certificate check (see non-errors, section 10) |
| `^prelogin to portal result is ` | Multi-line `<prelogin-response>`; `<status>Success</status>`, `<authentication-message>`, `<region>`, `<auth-api>`, `<saml-default-browser>` |
| `^pre-login is done!` | Pre-login complete |
| `^REGION-PRIO, region code is (\S+)` | Region (sample value `XX`) |
| `^No saml-auth-status\.`, `^No saml-request\.`, `^No prelogin-cookie\.`, `^Prelogin use-default-browser = (yes\|no)`, `^auth-api is (yes\|no)`, `^cas-auth is (yes\|no)` | All negative in the sample = credential auth |
| `^Portal authentication-message is (.*)` | Prompt text |
| `^----Portal Login starts----`, `^Login\.\.\.` | Portal login |
| `^Portal auth method: (?P<m>.*)$` | Sample: `Portal auth method: credential, auth src: saved credential` |
| `^Auth failed empty password for portal` | Prompt request (see event log) |
| `^Portal config is NULL\.` | After the line above |
| `^portal status is (?P<s>.*?)\.?$` | `User authentication failed.`, `Connected.` |
| `Portal config digest matched`, `Cached portal is validated`, `Restored cached portal config` | Cached config reused; the raw portal config is **not** dumped |
| `^(Serialize\|Unserialized) non-empty cookie for portal (\S+) and (user (\S+)\|pre-logon user)` | Cookie bookkeeping (value never logged) |
| `^--Set state to Connected$` | See state backbone below |

**Gateway**

| Pattern | Meaning |
|---|---|
| `^Force discovery, set NetworkDiscoverEvent`, `^----Network Discover starts----` | Discovery |
| `^Parse gateway list for user (\S+)` | Gateway list |
| `^Gateway (?P<gw>\S+)\((?P<desc>[^)]*)\): ipv4 (?P<ip4>\S*), ipv6 (?P<ip6>\S*), FQDN (yes\|no)` | Gateway entry |
| `^Discover external gateway: gateway count is (\d+), cutoff time is (\d+)` | Count of gateways |
| `^One external gateway (?P<gw>\S+), priority=(\d+), manual is (\d)` | Single gateway chosen |
| `^pretunnel latency \((?P<kind>[^)]*)\) is (?P<ms>\d+)` | Measured TCP time |
| `^----Gateway Pre-login starts----`, `^----Gateway Login starts----` | Gateway phases |
| `^Using portal's user credential to login to gateway\.` | Credential reuse |
| `^Gateway auth method: (.*)`, `^Gateway selection type is (\w+)`, `^Actual user for gateway login is (\S+)` | Gateway login details |
| `^Get gateway config\.`, `^gateway (\S+)'s config is <\?xml` | Gateway config XML (tunnel IP, DNS, routes, timers) |

There is **no explicit "gateway login success/failed" line** in the sample. Success is inferred from
`retid` for `login.esp`, a gateway cookie `Serialize non-empty cookie ...`, and `<response status="success">`
in the gateway config. A failure would likely show `<response status="error">` (INFERENCE, seen only in the
logout error reply).

**Tunnel**

| Pattern | Meaning |
|---|---|
| `^----Tunnel Creation starts----`, `^Try to create tunnel with gateway (\S+)` | Tunnel begins |
| `^Configured MTU is (\d+)`, `^Encryption method is (\S+)` | Tunnel parameters |
| `^Trying to do ipsec connection to (?P<ip>[\d.]+)\[(?P<port>\d+)\]` | IPSec attempt |
| `^Connected ipsec to (?P<ip>[\d.]+)\((?P<port>\d+)\)` (Info) | IPSec up |
| `^tunnel to (?P<ip>\S+) connected` (Info) | Tunnel up |
| `^--Set state to Connected$` | UI state Connected, 4.6 to 8 s after `Tunnel Creation starts` in the sample |
| `^Set preferred IP (\S+) for gateway (\S+) user (\S+)` | Assigned tunnel IP |

**Disconnect / restore**

| Pattern | Meaning |
|---|---|
| `^Disconnect\((?P<reason>[^)]*)\) called` | Tear-down; reason `Network change` or empty |
| `^CPanMSService::Disconnect\(\): reason is (.*?),` | Reason repeated |
| `^Logging out gateway, reason is (.*)$` | Values `StopThreads`, `Network discover`, `User logs off` |
| `^logout: user=(\S+), portal=(\S+), gateway=(\S+), domain=` | Logout |
| `^failed to logout from gateway (\S+), error: (?P<e>[^,]+), original msg:` | Example error: `Invalid user name` (session already expired) |
| `^tunnel statistics: send bytes\(...` | Tear-down counters |
| `^failed to receive keep alive` | Keep-alive loss |
| `^Show Gateway (?P<g>\S+): Checking network availability and restoring VPN connection` | **Kind B start** |
| `^Retry start succeeded`, `^Retry finished SetupNetwork` | Restore OK |
| `^Tunnel downtime \((\d+) milliseconds\) exceeds retry grace period \((\d+) seconds\)`, `^Tunnel retry done: failed retry`, `^Before ProcMonitor quit, disconnect vpn` | Restore failed |
| `NetworkConnectionMonitorThread: route change detected`, `^Network changed, break from ProcMonitor`, `Detected route change, but skip network discovery` | Network change handling |

**HIP** (hourly while connected, and once after connect; noise for attempts): `^Time to send hip report to
gateway (\S+)`, `^sent HIP report check to (\S+)\.`, `^Response status of HIP report check is (\S+), gateway`,
`^Hip report is not  needed for gateway (\S+)\.` (two spaces), `^sent HIP report  to (\S+)\.` (two spaces),
`^Response status of HIP report  is (\S+), gateway`. POST dumps use
`^Msg length is (\d+)\. Sending POST (/ssl-vpn/\w+\.esp\??) HTTP/1\.1` (level `Dump`, multi-line,
`authcookie=` masked with asterisks).

### 4.3 State backbone

`--Set state to X` (Debug, source 8727) is the cleanest timeline source:
`Connected`, `Restoring VPN Connection`, `Disconnecting...`, `Disconnected` (usually 3 lines in a row),
`Retrieving configuration...` (portal in progress), `Discovering network...`, `Connecting...` (tunnel
creation), `User logs off`, `OnDemand mode.` (idle, waiting for Connect). The same states appear in the
status XML `<state>`, but prefer the log line for timestamps and ordering.

### 4.4 Segmentation (validated on the sample)

Two kinds of attempt exist; a parser must model both.

**Kind A: portal login (user-driven)**
- START: `----Portal Processing starts----`; take `msgtype` from the preceding record of the same thread
  within 0.1 s.
  - `msgtype = portal` plus `AgentProxyAutoStart: user clicked connect button` = user click.
  - `msgtype = portal` plus `szCacheOnly: yes bRetrieveCacheOnly: 1` = GUI start-up cache load, **exclude**;
    it ends at `--Set state to OnDemand mode.` with no network contact.
  - `msgtype = user_credential` = credentials the user typed after a `portal` request that ended in
    `User authentication failed.`; link it to that request (same logical attempt) when they are within a few
    minutes with no intervening success.
- END (first of): SUCCESS `--Set state to Connected` (preceded by `tunnel to <ip> connected`); portal FAILURE
  `portal status is User authentication failed.` (+ `--Set state to Disconnected`), where the error text is
  the preceding `Auth failed empty password for portal`; otherwise the next START, a `Disconnect(` call,
  `--Set state to User logs off`, `PanGPS service exits` or end of data close it with outcome unknown.

**Kind B: automatic tunnel restore (network change or sleep; no portal contact)**
- START: `Show Gateway <gw>: Checking network availability and restoring VPN connection` (after `Network
  changed, break from ProcMonitor` and `--Set state to Restoring VPN Connection`).
- END SUCCESS: `Retry start succeeded` ... `Retry finished SetupNetwork` + `--Set state to Connected`.
- END FAILURE: `Tunnel downtime (<ms> milliseconds) exceeds retry grace period (1800 seconds)` + `Tunnel
  retry done: failed retry` + `Before ProcMonitor quit, disconnect vpn` + `Disconnect(Network change)
  called` (+ `--Set state to Disconnected`).

Disconnect events of an established session (`Disconnect(Network change) called`, `Disconnect() called`,
`logout: user=...`) end the **connected period**, not an attempt.

Algorithm: tokenise files in chronological order; drop noise early; state machine on `--Set state to X` with
boundaries at the two START markers; a change of `pid` or `PanGPS service exits` closes any open attempt as
"service restart". Never use the log level or `Unable to verify server cert` as a failure criterion.

Measured on one sample bundle: 10 START markers = 5 kind A (2 `portal` clicks, 2 `user_credential`, 1
cache-only) + 5 kind B. Outcomes: 2 logical login attempts, both connected; 5 restores: 3 succeeded, 2 failed
because the laptop slept longer than the 1800 s grace period.

### 4.5 Settings and addresses visible in PanGPS

The raw portal config XML is not logged. Effective settings are visible in:

- `ResponseToClient.txt_output:` status XML (best source). Marker: record with source 8450, level `Dump`,
  empty message on the prefix line, then `ResponseToClient.txt_output: <?xml ...` on the next physical line;
  always followed by `Send response to client for request <type>`. `<type>` values: `status`, `hip`,
  `user_credential`, `sleep`, `hello`. 72 dumps in the sample; 0.7 to 1.9 KB (short status) or 10 to 11 KB
  (with the full `<hip-report>`).
- `gateway <gw>'s config is <?xml ...` (Debug, source 3100): `ip-address`, `dns`, `dns-suffix`,
  `access-routes`, `exclude-access-routes`, `lifetime`, `timeout`, `disconnect-on-idle`, `mtu`, `ipsec`
  (UDP port, `enc-algo`, `hmac-algo`), gateway PAN-OS version.
- `Write HIP policy:` (portal hip-collection) and `---------------Full hip report ---------` ...
  `---------------End of full hip report ---------`.
- Single-line echoes: `Hip check interval is <N> ms.`, `Tunnel retry grace period is <N> seconds`,
  `split-tunnel-option is <v>`, `Timeout value: portal <N>, connect <N>, receive <N>, retry <N>`,
  `RefreshPortalConfig is yes, RefreshPortalConfigInterval is <N> hours`, `Traffic enforcement type is <v>`,
  `ipsec-failover-ssl is configured for <N> hours`, `Connect method is <v>`.

Time formats inside XML differ from the log prefix: `last_hip_sent` and HIP `generate-time` use
`MM/DD/YYYY HH:MM:SS`; `login-time` and `user_expires` are epoch seconds UTC.

## 5. `PanGPA.log` (UI agent)

- Prefix: `(P<pid>-T<tid>)<Level>(<src>): MM/DD/YY HH:MM:SS:mmm <message>`, same as PanGPS but levels
  `Debug`, `Info`, `Dump`, `Error`:

  ```python
  A = re.compile(r'^\(P(\d+)-T(\d+)\)(Debug|Info|Error|Dump)\s*\(\s*(\d+)\): '
                 r'(\d\d)/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d):(\d{3}) (.*)$')
  ```
- Measured on one sample bundle: 35,992 physical lines, 11,466 records; 68.1 % are XML continuation lines (300
  blocks of 22 to 343 lines). Records starting `message type from the service = <type> ` are followed by
  `<?xml ...` and a tab-indented `<response>` document. 568 lone `\r` (read in binary).
- Several PanGPA processes per file (one per GUI start); each begins with `PanGPA launched, display status
  Window, init status is -3.`. No `.old` file in the sample: history is short (3.5 days).

### 5.1 Markers used for the timeline

| Marker (literal) | Meaning |
|---|---|
| `User clicks connect. sending portal message` | **Click** (start of a user attempt) |
| `CPanBaseReceiver::HandleHello - sending portal message...` | Automatic portal request at GUI start, not a user attempt |
| `Command = <request><type>T</type>...` | UI to service. Types: `portal`, `user_credential`, `invalid-gateway-credential`, `disconnect`, `sleep`, `hello`, `pan_msg_ping` (noise). The `<passwd>` content is asterisks; **their count equals the password length** (never print) |
| `message type from the service = <type> ` | Service to UI; types `status`, `https_request`, `hip`, `sleep`, `user_credential`, `hello`, `invalid-gateway-credential`, `disconnect`. Type `hip` actually carries the portal/agent settings, not the HIP report |
| `Dialog Status is going to change from <A> to <B>.` | Dialog state machine; A or B may be empty (restore/none). Seen: `Not Connected to Connecting`, `Connecting to Not Connected`, `Connecting to Connected`, `Connecting to Connection Failed`, `Connection Failed to Connecting`, `Connected to Disconnecting`, `Disconnecting to Not Connected`, ` to Connected` (restore) |
| `text_desc is - X` | UI text: `Connecting...`, `Disconnected`, `Not Connected`, `Connected`, `Disconnecting...` |
| `===> response sent to GPI = <response><type>status</type><state>X</state><error>E</error><disabled>no</disabled></response>` | Status to the UI; `<error>` has the user-visible error text |
| `<response><type>user_credential</type><error></error><auth-message>Enter login credentials</auth-message>...` | Credential prompt (portal) |
| `<response><type>invalid-gateway-credential</type>...<auth-message>Authentication Failed. Enter login credentials</auth-message><gateway>gw1</gateway>...` | Gateway credential prompt |
| `Display the main panel when user attention(connection failed) is required.` | Error popup |
| `To display error must show message The connection from this device to GlobalProtect Gateway has been interrupted for the keep-alive timeout duration. Please check your network connectivity and re-connect..` | Keep-alive popup |
| `User try to disconnect current tunnel in ondemand mode.` | User disconnect |
| `received WM_POWERBROADCAST message = 0x7` | Resume from sleep |
| `Window session changed with state 7` / `8` | Lock / unlock (INFERENCE from WTS codes) |
| `http request status code = N` | Result of an HTTPS call done for the service |

Status strings seen in `<state>`: `Disconnected`, `Retrieving configuration...`, `Connected`, `Restoring VPN
Connection`, `Discovering network...`, `OnDemand mode.`, `Connecting...`, `Disconnecting...`.

### 5.2 Segmentation (validated)

- START: `User clicks connect. sending portal message` (it precedes the event-log `Started the Portal
  pre-login` by 0.4 to 1.1 s).
- Interim: `Connecting to Not Connected` with `message type from the service = user_credential` = credential
  prompt; `invalid-gateway-credential` = gateway prompt.
- SUCCESS: `Dialog Status is going to change from Connecting to Connected.`
- FAILURE: `... from Connecting to Connection Failed.`, with the `<error>` text in the preceding status XML.
- Automatic restores never have a click: they show `state` = `Restoring VPN Connection` and
  `Dialog Status ... from  to Connected.` (empty source state).
- Measured on one sample bundle: 10 clicks = 7 Connected + 3 Connection Failed.

### 5.3 Status XML elements

Envelope (all types): `type`, `status`, `protocol` (empty, `IPSec` or `SSL`), `portal-config-version`,
`error-must-show`, `error-must-show-level` (`info`|`error`), `error`, `product-version`, `product-code`,
`portal-status`, `user-name`, `username-type` (`regular`, `sso`), `state`, `check-version`, `portal`,
`discover-ready`, `mdm-is-enabled`.

`status` additionally: `gateway-list` (`entry`: `gateway`, `tunnel`, `description`, `allow-tunnel`,
`passwd-expire-days`, `priority`, `internal`, `authenticated`, `last_hip_sent`), `hip-report` (large),
`proxy-agent-*`, `cdl-log`, `no-direct-access-to-local-network`, `pre-vpn-*-error`, and when connected:
`uptime`, `byte-received`, `byte-sent`, `packet-received`, `packet-sent`, `incorrect-packet-*`, `server-ip`
(gateway public IP), `local-ip` (tunnel IP), `local-ipv6`, `connect-mode`, `login-time` (epoch UTC, tunnel
up), `lifetime`.

`hip`-type (config) blocks carry the portal-delivered settings; there is **no `connect-method` element**.
The connect method is derived from `<on-demand>`, `<pre-logon-then-on-demand>` and `<use-sso>`.

`https_request` blocks carry `<https-request>REQID=...,IPADDR=<host>,PORT=443,URL=<path>,...` (host, port and
path only; no query or body, so no cookies). The `IPADDR` tells which portal/gateway a request went to.

## 6. Static files

### 6.1 `regval.txt` (client settings)

- 2,974 bytes in the sample; CRLF; **decode latin-1**. Contains raw bytes after `=`: REG_SZ is the text plus
  one terminating NUL; an empty string is a single NUL; REG_DWORD is 4 raw little-endian bytes (INFERENCE:
  width 4 with non-printable bytes means DWORD; a single NUL means empty string; `captive-portal-exception-timeout=0\x00` is a string).
- Garbage in the middle of the Settings block: NUL runs, a stray `=`, a pointer-like byte run and a copy of a
  registry path (a reused collector buffer, not a section header). Parser: split on CRLF, drop NULs, keep only
  lines matching `^[A-Za-z][A-Za-z0-9-]*=`, split on the first `=` only, strip trailing NULs. Garbage can be
  glued to the end or start of a real line: strip NULs first.
- The dump appears truncated by the collector (INFERENCE); the file ends without a trailing CRLF.
- Section headers (verbatim, inconsistent): `Credential Provider Filters:`, `SSO Cache:` (+ NUL),
  `PreferredIP:` (+ NUL), `Prelogon :48` (space before the colon), `Wrap CP Guid :`, `Settings` (no colon).
  Empty-state sentences: `SSO Cache is Empty!!!`, `PreferredIP is not presented!!!`,
  `wrap-cp-guid value is not presented!!!`. Non-empty variants were not in the sample (format unknown).
- Credential provider filter record: `<registry path> | <value> | HH:MM:SS MM/DD/YYYY` (month-first assumed,
  INFERENCE).
- 46 keys in the sample (file order, `""` = empty string, DW = DWORD):

  `save-gateway-password`, `disable-globalprotect` (DW), `regioncode`, `krb-auth-fail-fallback`,
  `ext-key-usage-oid-for-client-cert`, `portal-timeout` (DW), `connect-timeout` (DW), `receive-timeout`
  (DW), `logout-remove-sso`, `certificate-store-lookup`, `retain-connection-smartcard-removal`,
  `ipv6-preferred`, `change-password-message`, `use-proxy`, `override-cc-username`, `split-tunnel-option`
  (DW), `dem-agent`, `traffic-enforcement`, `enforce-globalprotect`, `captive-portal-exception-timeout`,
  `traffic-blocking-notification-delay`, `traffic-blocking-notification-msg` (one-line HTML),
  `allow-traffic-blocking-notification-dismissal`, `display-traffic-blocking-notification-msg`,
  `display-captive-portal-detection-msg`, `captive-portal-notification-delay`, `enforcer-exception-list`,
  `captive-portal-login-url`, `enforcer-exception-list-domain`, `enforcer-exception-application`,
  `use-sso-pin`, `on-demand`, `LastUrl`, `enable-hip-remediation` (DW), `allow-extend-session`,
  `hip-send-retry` (DW), `intelligent-portal`, `portal-country-map`, `cas-skip-hub-page`,
  `intelligent-portal-service`, `agent-user-override`, `hip-remediation-integrity-check`,
  `hip-remediation-retry` (DW), `dem-agent-action`, `access-gateway-from-agent-only`, `default-browser`.

  Typing is mixed (timeouts are DWORD; captive-portal timers are REG_SZ digits).
- Useful for the client configuration: `LastUrl` (last portal used, e.g. `vpn.example.com`), `on-demand`,
  `use-proxy`, `ipv6-preferred`, `traffic-enforcement`, `enforce-globalprotect`, `certificate-store-lookup`,
  `agent-user-override`, `disable-globalprotect`, `regioncode`, the three timeouts, `split-tunnel-option`,
  `krb-auth-fail-fallback`, `logout-remove-sso`, `use-sso-pin`, `intelligent-portal`,
  `access-gateway-from-agent-only`, `dem-agent*`, HIP keys.
- There is **no connect-method key** (no pre-logon / user-logon / always-on value); `on-demand=yes` is the
  only hint (INFERENCE). Take the connect method from the logs (`Connect method is ...`).
- No per-portal subkeys, no pre-logon values, no SSO entries in the sample.

### 6.2 `pan_gp_trb.log` (JSON troubleshooting report)

- Exactly 1024 bytes in the sample (INFERENCE: fixed-size buffer; another survey saw it cut mid-value, so
  **do not assume valid JSON**: try `json.loads`, fall back to key/value regexes), ASCII, no newline.
- Keys: `report_id`, `report_time`, `report_type`, `user_name`, `host_name`, `host_id`,
  `host_gmt_timeoffset`, `serial_number`, `os`, `locale`, `gp_version`, `error_stage`, `error`,
  `error_details`, `error_time`, `network_access`, `network_type`, `internet_access`, `internal_network`,
  `captive_portal`, `dual_stack_network`, `dns_reachable`, `network_latency`, `gp_mtu`, `portal_address`,
  `portal_reachable`, `portal_server_cert`, `portal_status`, `portal_cached_config`,
  `portal_config_refresh`, `portal_auth` (array of `{method, source}`).
- Synthetic example:

  ```
  {"report_id":"00000000-0000-0000-0000-00000000000a","report_time":1784549296,"report_type":"troubleshooting",
  "user_name":"jdoe@example.com","host_name":"LAPTOP-01","host_id":"00000000-0000-0000-0000-000000000001",
  "host_gmt_timeoffset":120,"serial_number":"SERIAL0001","os":"Microsoft Windows 11 Pro , 64-bit",
  "gp_version":"6.3.3-828","error_stage":"Portal pre-login","error":"Authentication Failed. No retries.",
  "portal_address":"vpn.example.com","portal_status":"Invalid portal",
  "portal_auth":[{"method":"cert","source":"user store"},{"method":"credential","source":"saved credential"}]}
  ```
- `report_time`/`error_time` are epoch seconds UTC; `host_gmt_timeoffset` is INFERENCE minutes (120 = UTC+2).
- It is the **only** file that states authentication methods, but it holds only the last report and in the
  sample was months old and for a different portal and user than the rest of the bundle. Label it stale.

### 6.3 `pan_gp_hrpt.xml` (HIP report)

- XML, declared UTF-8, tab indentation, CRLF, root `<hip-report>`, `<hip-report-version>4</hip-report-version>`.
- Header: `md5-sum`, `user-name`, `domain`, `host-name`, `host-id`, `ip-address` (tunnel IP when connected),
  `ipv6-address`, `generate-time` (`MM/DD/YYYY HH:MM:SS`, local, no zone), `hip-report-version`, `categories`.
- `categories/entry[@name]`: `host-info`, `anti-malware`, `disk-backup`, `disk-encryption`, `firewall`,
  `patch-management`, `data-loss-prevention`. `host-info`: `client-version`, `os` (note the space before the
  comma: `Microsoft Windows 11 Pro , 64-bit`), `os-vendor`, `domain`, `host-name`, `host-id`,
  `network-interface/entry[@name="{GUID}"]` with `description`, `mac-address`, `ip-address/entry`,
  `ipv6-address/entry`.
- Other elements: `Prod` (attributes `vendor`, `name`, `version`, `defver`, `engver`, `datemon`, `dateday`,
  `dateyear`, `prodType`, `osType`), `ProductInfo`, `real-time-protection`, `last-full-scan-time`,
  `last-backup-time`, `drives/drive-name/enc-state`, `is-enabled`, `missing-patches/entry/{title,
  description, product, vendor, info-url, kb-article-id, security-bulletin-id, severity, category,
  is-installed}`. Empty elements are common; `n/a` means unknown.
- The PANGP adapter appears with description `PANGP Virtual Ethernet Adapter Secure #2` (the suffix can vary)
  and a locally administered MAC such as `02-00-00-00-00-01`.
- The HIP report is a snapshot taken while connected (sample: one day before collection); it can contradict
  the live snapshot.

### 6.4 Other static files (not used; format notes)

- `SystemInfo.txt`: ASCII CRLF, first line empty, `Label:` padded so values start at column 32; continuation
  lines indented 31 spaces. Labels include `Host Name`, `OS Name`, `OS Version`, `System Boot Time`,
  `System Locale`, `Input Locale`, `Time Zone` (e.g. `(UTC+01:00) ...`, standard-time label that does not
  change with DST, INFERENCE), `Total Physical Memory` (`32.441 MB` uses `.` as thousands separator),
  `Domain`, `Logon Server`, `Network Card(s)`. Dates use the **regional format** (`DD/MM/YYYY, HH:MM:SS` in
  the sample) while labels stay English.
- `IpConfig.txt`: `ipconfig /all`; adapter blocks `<Type> adapter <Name>:` at column 0, fields indented 3
  spaces as `Label . . . : value`; pitfalls: trailing space after `(Preferred) `, `%<idx>` zone on IPv6,
  continuation lines indented 39 spaces, empty values, **regional date text** for lease times, uppercase
  dashed MACs.
- `RoutePrint.txt`: sections `Interface List`, `IPv4 Route Table`, `Persistent Routes`, `IPv6 Route Table`;
  IPv6 gateway may wrap to the next line.
- `NicDetails.txt`: blocks `^Interface (.+) Parameters$` with 30 `Key : value` lines; values carry units.
- `NetStat.txt`: TCP IPv4 only, no PID.
- `TcpipBind.txt`: **UTF-16LE, no BOM, no separators**; 12 fixed records of 24 chars, each `\Device\{` + 14
  GUID characters (truncated by the collector, INFERENCE). Decode `utf-16-le`, slice by 24.
- `setupapi.dev.log`: standard sections `>>>  [<title>]`, `>>>  Section start YYYY/MM/DD HH:MM:SS.mmm`;
  times are local. In the sample the only PANGP lines were `ump: Device 'ROOT\PANGPD\0000' has problem. Code
  = 22, Status = 0x00000000.` (INFERENCE: code 22 = device disabled, from Windows documentation).
  `setupapi.app.log` has only `dvi: Waiting for NetSetupSvc ...` / `dvi: Install finished for
  ROOT\PANGPD\0000` pairs, no timestamps.
- `PanGPA.dmp`: minidump (`MDMP`), 8 months older than the bundle in the sample; not analysed.
- `PanProxyAgent.log`: format `(P<pid>-T<tid>)<level5><MM/DD/YY> <HH:MM:SS:mmm> (<src>): <msg>` where the
  5-char level (`info `, `debug`, `warni`, `error`, `trace`) is glued to the date for all but `info `;
  never rotated (sample from 2024); boilerplate.
- `LogonUI.log`: PanGPA-style records (credential provider trace). `GPPrelogon: Prelogon is disabled.` proves
  pre-logon is off.
- `PanGpHip*.log`, `PanGpHipMp*.log`: PanGPA-style records, about 82 % JSON/XML continuation lines;
  `Opswat Error(-23)` lines are harmless.
- `debug_drv.log`: `(P<pid>-T<tid>)MM/DD/YY HH:MM:SS:mmm[<Level> <src>]: <msg>` (timestamp first, level
  inside brackets); 99.9 % packet-counter `Dump` noise; useful lines `Disable adapter be called.`,
  `Found pangpd device ROOT\PANGPD\0000, remove it now.`.

## 7. Where each client setting comes from

| Setting | Primary source | Alternatives / notes |
|---|---|---|
| Client version | PanGPS banner `Start PanGPS service (ver: ...)` | User agent `PAN GlobalProtect/<ver>`; HIP `client-version`; event log `service started`; trb `gp_version` |
| OS | event log `service started (... OS version: ...)` | SystemInfo `OS Name`/`OS Version`; HIP `os` |
| Portal | registry `LastUrl` | PanGPS `Portal <host>, user ...`; event log `Portal login completed with address`; status XML `<portal>`; trb `portal_address` (stale) |
| Portal name, gateway config name | status XML `<portal-name>`, gateway config `<portal>` | |
| Gateway(s) | PanGPS `Gateway <fqdn>(<name>): ipv4 ...`, status XML `gateway-list` | Gateway selection event line when several |
| Connect method | event log `Connect method is ...`; PanGPS `Connect method is ...` | Status XML `<on-demand>`, `<pre-logon-then-on-demand>`, `<use-sso>`; registry `on-demand` (hint only) |
| Authentication method | PanGPS `Portal auth method: ...`, `Gateway auth method: ...`, prelogin SAML negatives | trb `portal_auth`; PanGPA `user_credential` prompt. Event log never states it |
| Tunnel protocol | event log `IPSec|SSL tunnel creation finished`; status XML `<protocol>` | PanGPS `Trying to do ipsec connection to ...` |
| Tunnel IP, DNS, routes, MTU, lifetime, idle timeout | gateway config XML in PanGPS | Status XML `local-ip`, `server-ip`; PanGPS `Configured MTU is`; `ipsec-failover-ssl` |
| Timeouts, retry, grace period, HIP interval, split tunnel, traffic enforcement | status XML `agent-config` | Registry; PanGPS echo lines |
| Region | PanGPS `REGION-PRIO, region code is ...` | Registry `regioncode` |
| User, host, domain | PanGPS `Portal <host>, user <u>, logonDomain <d>`; SystemInfo | HIP; event log |
| Time zone | SystemInfo | trb `host_gmt_timeoffset` (point in time) |

## 8. Time handling summary

| Source | Format | Zone |
|---|---|---|
| event log | `MM/DD/YYYY HH:MM:SS:mmm` | local |
| PanGPA, PanGPS, other agent logs | `MM/DD/YY HH:MM:SS:mmm` | local |
| `debug_drv.log` | `MM/DD/YY HH:MM:SS:mmm` (before the bracketed level) | local |
| `pan_gp_trb.log` | epoch seconds | UTC |
| status XML `login-time`, `user_expires` | epoch seconds | UTC |
| HIP `generate-time`, status `last_hip_sent` | `MM/DD/YYYY HH:MM:SS` | local |
| `SystemInfo.txt` | `DD/MM/YYYY, HH:MM:SS` (regional) | local |
| `IpConfig.txt` leases | regional long date text | local |
| `regval.txt` | `HH:MM:SS MM/DD/YYYY` | local |
| `setupapi.dev.log` | `YYYY/MM/DD HH:MM:SS.mmm` | local |

## 9. Known non-errors (do not report as failures)

- `Unable to verify server cert. Result is self signed certificate in certificate chain ` followed by
  `CheckServerCert() returns 0x1002`: appears on **every successful** portal and gateway pre-login in the
  sample. The portal presented a publicly signed certificate, the client then matched the name against the
  wildcard pattern and carried on. The log text is a pre-login diagnostic, not a failure (INFERENCE about the
  cause).
- `Auth failed empty password for portal` + `portal status is User authentication failed.` + `Portal config
  is NULL.`: the normal first step of an on-demand connect with no saved password.
- `Error` records in PanGPS (all benign in the sample): `DEM Agent: GetDemProductVersion - failed to open DEM
  agent version string ...` (DEM agent not installed), `route, set default route in callback`, `Failed to send
  <N> bytes to client` (GUI gone at logoff), `ST,ERROR! failed to service manager with error code 0000045b`
  (service stop), `Failed to export CDL client cert.`, `Unknonwn managed status ` (sic), `accept failed:
  10004(...)`, `DRBG selftest: FAILED, error: ...` (FIPS self test at start), `Check GP disable flag failed.
  User profile is not found`, `read() failed: 10054` (PanGPA went away).
- `Failed to find attribute '<x>'`, `Failed to get <x> from config, try local`, `Portal config does not exist,
  try registry/plist`: optional attributes absent.
- Captive portal lines (`StopCaptivePortalDetection() captive portal detection is in progress`): housekeeping.
- `Failed to open file ...PanPUAC_<id>.dat`: no stored cookie; it is a prompt precursor, not an error by itself.
- `Tunnel is down due to disconnection` without a preceding user line: INFERENCE service stop or shutdown.
- `Wait in modern standy until wakeup`, `Received sleep event`: sleep, not a network fault; a restore that
  lasts through sleep fails by the grace period.
- `Opswat Error(-23)` in HIP logs, `Proxy Agent fail to clean up. Error: 1`.

## 10. Pitfalls

1. **Typos and double spaces are part of the format**; copy literals exactly: `miliseconds`, `conect method`,
   `Failed to pre - login`, `standy`, `Unknonwn`, `misssing`, `Waked up`, `PacManger`, `ProcessHipRpoert`,
   `Hip report is not  needed`, `sent HIP report  to` (two spaces). Use `\s+` where a double space exists.
2. Timestamp colon before milliseconds, month/day order, 2-digit year outside the event log, no zone,
   possible 1 h ambiguity at DST end.
3. Level token quirks: `Info ` with trailing space (PanGPS/PanGPA) and `[Info ]` in the event log; the
   PanProxyAgent level is glued to the date.
4. Never sort across files or within a file; handle inversions.
5. Glued records and continuation lines in PanGPS; chunked status XML.
6. The event log may stop before the other logs; PanGPA starts late (short history). Cross-checking is
   possible only in the overlap.
7. Several logical attempts can share one wall-clock burst (retry storms); do not treat each cycle as an
   attempt.
8. Same `Started the Portal pre-login` fires for user clicks, SSO triggers, automatic retries after timeout
   (follow `User was logged out of Gateway`) and wake-up.
9. Cookie lines show URL-encoded users (`jdoe%40example.com`), login-finished lines the decoded form.
10. Rotated PanGPS files can share the same timestamp at the boundary (same ms, different records).
11. `regval.txt` binary content (section 6.1); `TcpipBind.txt` UTF-16LE; `pan_gp_trb.log` may be truncated.
12. **Privacy**: PanGPS logs every DNS name resolved by the machine (`Received DNS request for <fqdn>`,
    `qname=<fqdn>`), the Windows hosts file entries, the Windows profile path, host name, host id, MAC
    addresses, local IPs, HIP software and patch inventory. PanGPA masks `<passwd>` but the **asterisk count
    equals the password length**; `PROXY_PASS`, `authcookie` and `agent-user-override-key` are masked by the
    client. A parser must never echo whole XML blocks, and reports should be able to redact user, host,
    host-id, MACs and IPs.
13. Zero-byte files and absent rotations are normal.

## 11. Inferences collected

1. `SSO starts.` marks an automatic/SSO trigger rather than a user click.
2. `CheckServerCert` codes: `0x1002` OK, `0x1000` TLS/certificate error, `0x4000` cannot connect, `0x0` none.
3. `Auth failed empty password` is a prompt, not a rejection; `Auth failed for portal` is a rejection.
4. `PanPUAC_<id>.dat` ids are per-portal hashes (probably unpadded MD5).
5. `Tunnel is down due to disconnection` with no user line is a service stop.
6. Attempts stalling at a missing/empty cookie wait for interactive authentication (password, or SAML/browser).
7. Logs are local time with DST.
8. The source number in the prefix is a source line number.
9. Windows session change codes 7/8 are lock/unlock.
10. `regval.txt` DWORD vs string by value width; the Settings dump is truncated by the collector.
11. `host_gmt_timeoffset` is minutes; `SystemInfo` time-zone label does not change with DST.
12. `TcpipBind.txt` GUIDs are truncated by the collector; setupapi problem code 22 means disabled.
13. A failed gateway login would appear as `<response status="error">`.

## 12. What the sample did not contain (spec is incomplete here)

The sample bundle had no instance of the following; no parsing rule may be derived from it, and any support
must be validated on new bundles:

- **SAML / browser authentication**: only negative lines (`No saml-auth-status.`, `No saml-request.`,
  `No prelogin-cookie.`, `auth-api is no`, `cas-auth is no`, `GetSamlAttribute - samlsessionid = ,
  samlusername = `); no SAML result, cookie or dialog text, no `Still Working` dialog.
- **Client certificate authentication**: only `Optional client-cert does not exist` and config echoes in
  PanGPS; the event log has `Client Cert Required.` texts from other (older) data but no PanGPS detail.
- **SSL tunnel and IPSec to SSL fallback in PanGPS**: only IPSec was used; the event log has the fallback
  lines (section 3.2) but their PanGPS counterparts were not observed.
- **Several gateways / best-gateway selection / internal gateways / internal host detection (positive)**: one
  external gateway only; PanGPS has no response-time table.
- **Pre-logon** and always-on connect methods (`PrelogonEnabled is 0`, On-Demand only).
- **Real wrong-password rejections** at portal or gateway in PanGPS (`Authentication Failed`), numeric portal
  errors, `Invalid portal` in PanGPS, SSL handshake failures, genuine timeouts, lifetime-expiry and idle
  disconnects (the event log has some of these texts, but PanGPS context is missing).
- **Non-empty SSO cache, `PreferredIP`, wrap-CP-GUID** values in `regval.txt`.
- **Portal config XML** (never dumped when the cached config digest matches).
- Windows editions or locales other than the one sample, and other client versions (the old event log shows
  6.2.7 texts, but the PanGPS/PanGPA formats were only checked on 6.3.3).

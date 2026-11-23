# Command notes

Observed output of the sampled commands (PAN-OS 11.2.10-h17 VM-Series lab and a historical log
from a physical firewall). All examples are synthetic; real captures contain hostnames, IPs and
serials and must never be copied into the repository.

## CLI behaviour

- The CLI redraws `prompt + partial command` at every word: drop everything up to the **last**
  line ending with the command.
- Inline help needs a space before `?` (`show session ?`). It reveals mandatory keywords:
  `show session inflight_monitoring ?` and `show session ingress_backlogs_trigger ?` show
  `* status`; `set session inflight_monitoring ?` shows `no` / `yes`.
- `set cli pager off` and `set cli terminal width 500` before sampling.

## Commands

| Command | Notes |
|---|---|
| `debug dataplane pow performance` | 0.15 to 0.3 s, about 33.5 KB. Tables `group` (17 rows) and `func` (227 rows) with current and `ac-*` columns. `all` adds about 70 histograms (about 69 KB). Readable by `tsf.pow_perf.parse_pow`. |
| `show counter global filter delta yes` | 17 to 25 KB. Only counters with a non-zero delta. Header line `Elapsed time since last sampling:  5.64  seconds` (padded). Columns `name value rate severity category aspect description`; ends with `Total counters shown: N`. |
| `show session info` | About 4.3 KB. `Number of sessions supported`, `allocated`, active TCP/UDP/ICMP, `Session table utilization` (integer %), `Packet rate`, `Throughput`, `New connection establish rate`. |
| `show running resource-monitor` | About 12 KB. Sections per second, per minute, per hour: CPU load by group (`name : N%`), CPU load per core (matrix, first column is `*` for core 0), resource utilization (session, packet buffer, packet descriptor, sw tags descriptor). |
| `show system resources \| match load` | One `top - ... load average: a, b, c` line. |
| `show running resource-monitor ingress-backlogs` | Physical firewalls only. See below. `Invalid syntax.` on the lab VM. |
| `show session packet-buffer-protection` | Short form when inactive: `Packet buffer count based`, `Congestion: 3/14666 (0.02%)`, `System resource usage is low, packet buffer protection not activated.` Extended form (from the historical log): congestion, drop probability and threshold, table `Session/IP Address | Zone | PCS | Percentage | State | Packets Total | Dropped | Time till discard`. |
| `show session packet-buffer-protection buffer-latency` | `Latest latency: N ms`, `Last 10 seconds average/maximum latency (ms):` and ten `avg/max` pairs. |
| `show session packet-buffer-protection zones` | Enabled zones. |
| `show counter interface all` | Cumulative per-interface counters (MAC, CPU and logical blocks), parsed by `tsf.interface_errors`; used for the throughput charts (`bytes received` / `bytes transmitted`, else `rx-bytes` / `tx-bytes`). Size and duration on a production firewall still to be measured (read once per fast tick, last and dropped first when late). |
| `show session all start-at N` | Optional (`--dump-sessions`), once at the end. `<1-2097152>` "Show next 1K sessions". Two lines per session: `ID Application State Type Flag Src[Sport]/Zone/Proto (xlate[port])` then `Vsys Dst[Dport]/Zone (xlate[port])`. Paged with N = 1, 1025, 2049, ...; not an atomic snapshot. Format and paging semantics still to be confirmed on the lab. |
| `show session ingress_backlogs_threshold` / `_duration` | Single number (lab: 80 and 3). |

## ingress-backlogs

```
Tue Apr 21 17:27:22 2026

-- SLOT: s1, DP: dp0 --
USAGE - ATOMIC: 47.75390625% TOTAL: 91.796875%

TOP SESSIONS:
SESS-ID         PCT     GRP-ID          COUNT           Special Notes
2149580803      23%     pktlog_forwarding       242             Special TAG values, NOT valid session id
```

- Percentages are floats; `GRP-ID` is a number for real sessions and a workgroup name for
  special tags; the `Special Notes` column appears with special tags.
- A special tag has the high bit set (id >= 2^31) and is not a session; `show session id` on it
  answers `Bad Key`.
- An optional `SESSION DETAILS` block follows when an offender exists.

# Runtime analyzer

Two commands: `panos-toolbox runtime capture` samples a firewall over SSH and stores the raw
outputs; `panos-toolbox runtime report` turns a capture folder into one offline HTML report.
Plan and decisions: [plan.md](plan.md). Command formats: [command-notes.md](command-notes.md).

## Capture

```bash
pip install 'panos-toolbox[runtime]'          # paramiko, capture only
panos-toolbox runtime capture --host FW --user USER --duration 600
# or from a checkout, no installation (needs only: pip install paramiko):
python scripts/runtime_analyzer.py --host FW --user USER --duration 0 --open
```

When the capture ends (duration, `--max-cycles`, **or Ctrl+C**) the HTML report is built
automatically next to the capture folder. Ctrl+C is a clean stop: the inflight monitoring is
switched off, the manifest is written and the report is generated (a second Ctrl+C during that
shutdown is ignored). If the connection is lost mid-capture the report is built from what was
collected. The report header shows the firewall hostname (from `show system info`) and the
generation time (UTC). Use `--no-report` to skip it, `--open` to open it in the browser.

The password is asked at the prompt (or use `--key-file`). Nothing secret is accepted on the
command line, printed or written to disk. An unknown SSH host key is rejected unless you pass
`--accept-new-hostkey`.

| Option | Default | Meaning |
|---|---|---|
| `--interval X` | 30 | Seconds between full cycles |
| `--backlog-interval B` | X/6, minimum 1 | Seconds between fast ticks |
| `--duration S` | 120 | Total seconds (0 = until Ctrl+C) |
| `--max-cycles N` | 0 | Stop after N full cycles |
| `--pow-all` | off | Also run `debug dataplane pow performance all` (histograms, doubles the POW size) |
| `--no-inflight-monitoring` | off | Do not touch `session inflight_monitoring` |
| `--max-offenders N` | 10 | `show session id` queries per fast tick |
| `--no-compress` | off | Plain text raw files instead of gzip |
| `--outdir DIR` | `.` | Where `runtime_<host>_<UTC>/` is created |
| `--no-report` | off | Do not build the HTML report at the end |
| `--open` | off | Open the report in the browser |

What runs:

- **Every X seconds (full cycle):** `debug dataplane pow performance`,
  `show counter global filter delta yes`, `show session info`, `show running resource-monitor`,
  `show system resources | match load`.
- **Every X/6 seconds (fast tick, at least 1 s apart):**
  `show running resource-monitor ingress-backlogs`, `show session packet-buffer-protection`,
  `show session packet-buffer-protection buffer-latency`. For every real session listed by
  ingress-backlogs the tool also runs `show session id <id>` once. Special tags are not sessions
  and are never queried.
- **Once:** `show system info`, `show clock`, and the inflight monitoring, packet buffer zones
  and ingress backlog threshold, duration and trigger settings.

A command the firewall rejects with `Invalid syntax` (for example ingress-backlogs on a
VM-Series running 11.2) is tried once and then skipped; the report says so.

**The only change the tool makes on the firewall** is `set session inflight_monitoring yes` at
the start and `... no` at the end (also on Ctrl+C or an error). The setting is always left OFF,
even if it was ON before the capture; the manifest records that. If the final `no` cannot be
confirmed, the tool prints a loud warning with the command to run by hand.

**Load and size.** A full cycle takes about 1.5 to 2 s of CLI time and a fast tick about
0.3 s on a lab VM; with the default interval that is well under the period. If a cycle
exceeds half the interval the report flags it, and ticks that would start a full period late are
skipped and counted. A full cycle is about 70 to 75 KB of text (about 215 MB per day at 30 s
uncompressed); raw files are gzip by default.

**Other clients.** The delta baseline of `show counter global filter delta yes` is global on the
firewall: any other client running the same command (a monitoring system, another admin) resets
it, and so does this capture for them. The tool reads the elapsed time printed by the firewall
and flags windows that do not match its own interval (`DELTA_FOREIGN_SAMPLER`).

The capture folder holds real hostnames, IPs, serials and session details. Keep it out of
repositories and tickets, or review it first (`runtime_*/` is in `.gitignore`).

## Report

```bash
panos-toolbox runtime report runtime_FW_20260101T000000Z --open
```

One offline HTML file next to the folder (`<folder>_runtime.html`), standard library only.
Tabs: Overview, Findings, POW, Counters, Ingress backlogs, Packet buffer, Sessions, Resources,
Capture log. Every tab and panel has its own collapsed help. Times are UTC.

- **POW** shows per-interval average microseconds, computed from differences of the `ac-count`
  and `ac-total-us` columns between consecutive samples (the "current window" columns keep
  growing and are not comparable between samples).
- **Counters** aggregates the delta counters over the capture; rates are the firewall's own.
- **Ingress backlogs** shows atomic and total usage, special tags (workgroups) and offending
  sessions with the `show session id` output.
- Thresholds can be overridden with `--threshold KEY=VALUE` (repeatable); the keys are
  `RT_THRESHOLDS` in `analysis.py`.

## Findings

Each finding has a code; the report's Findings tab explains every code (`FLAG_HELP`).

| Code | Level | Meaning |
|---|---|---|
| `BACKLOG_OFFENDER` | critical | A real session holds a share of the ingress backlog |
| `BACKLOG_HIGH` | warning | Atomic or total backlog usage above the thresholds |
| `BACKLOG_SPECIAL_TAG` | info | A workgroup (not a session) occupies the backlog |
| `PBP_ACTIVE` | critical | Packet buffer protection was active |
| `PBP_CONGESTION` | warning | Packet buffer congestion above the threshold |
| `PBP_LATENCY_HIGH` | warning / critical | Packet buffer latency above 1 s / 3 s |
| `SESSION_UTIL` | warning / critical | Session table above 70 % / 90 % |
| `CPS_SPIKE` | warning | Connection rate peak far above the median |
| `CPU_CORE_HIGH` | warning / critical | Data plane core average above 80 % / 95 % |
| `CPU_GROUP_HIGH` | warning | A POW group above 80 % CPU |
| `COUNTER_DROP_RATE` | warning / critical | A drop counter above 100 / 1000 per second |
| `POW_FINDING` | warning / info | Item from the shared POW evaluation (`tsf/pow_perf.py`) |
| `DELTA_FOREIGN_SAMPLER` | warning | Another client reset the delta counters |
| `INFLIGHT_LEFT_ON` | critical | The final `inflight_monitoring no` was not confirmed |
| `SAMPLE_GAP` | warning | Gaps between cycles or skipped ticks |
| `CYCLE_SLOW` | warning | A cycle took more than half of the interval |
| `CMD_FAILED` | warning | Samples without a prompt back (partial output) |
| `CMD_NOT_AVAILABLE` | info | The firewall does not support the command |

## Limitations

- SSH only. The XML API transport is a future item.
- Multi-DP firewalls and a real ingress-backlogs offender have not been validated against a live
  device (the formats come from a historical log and a screenshot); the tests use synthetic data.
- The wording of `show session inflight_monitoring status` is unverified: if it is not
  recognised the state is "not verifiable" and the final `no` is still sent.
- Resource monitor rows are kept in printed order (the CLI does not say which end is newest),
  so only order-independent figures (maximum, average) are used.

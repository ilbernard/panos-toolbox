# Runtime analyzer: plan

Status document for the `runtime` tool (`panos-toolbox runtime capture` / `runtime report`).
Update the step table at the end of each step. The Italian working copy with the full
reconnaissance log lives in the "FWs Toolbox" Claude project
(`claude/runtime-analyzer-piano-esecuzione.md`).

## Goal

Sample a firewall over SSH at a fixed interval, store every raw output, and aggregate the
samples into one offline HTML report in the style of `tsf analyze` and `gp analyze`.

Every `X` seconds (`--interval`, default 30), the full cycle:

- `debug dataplane pow performance`
- `show counter global filter delta yes`
- `show session info`
- `show running resource-monitor`
- `show system resources | match load`

Every `X/6` seconds (`--backlog-interval`, minimum 1 s), the fast tick:

- `show running resource-monitor ingress-backlogs` (optional: invalid on VM-Series 11.2.10)
- `show session packet-buffer-protection`
- `show session packet-buffer-protection buffer-latency`

For every **real** session reported by `ingress-backlogs` the tool also runs
`show session id <id>`. Special tags (id >= 2^31, "Special TAG values, NOT valid session id")
are not sessions and are never queried.

## Decisions

| Topic | Decision |
|---|---|
| Transport | SSH only for now (paramiko, optional extra `runtime`). The XML API is a future item (see below). |
| Capture / report | Two CLI entries. `capture` needs paramiko; `report` is standard library only. |
| Inflight monitoring | `set session inflight_monitoring yes` at start, `... no` at the end (also on Ctrl+C or error), always left OFF. State is read with `show session inflight_monitoring status`. If the final `no` is not confirmed, a loud warning on screen and in the manifest. `--no-inflight-monitoring` leaves the setting untouched. It is the only state change the tool makes. |
| Optional commands | A command answering `Invalid syntax` is probed once, flagged `CMD_NOT_AVAILABLE`, and skipped. The report works without it. |
| Delta counters | The baseline of `show counter global filter delta yes` is global on the firewall. Rates use the `Elapsed time since last sampling: N seconds` line (note the padded number: `\s+` before `seconds`), not the local clock. The first sample is kept. A mismatch with the local gap above `max(2 s, 15 %)` raises `DELTA_FOREIGN_SAMPLER`. |
| POW | Per-interval figures come from differences of the `ac-count` and `ac-total-us` columns. `tsf.pow_perf.parse_pow` / `evaluate` are reused. Default without `all`; `--pow-all` adds the histogram variant. |
| Storage | One folder per capture, one file per command, samples delimited, gzip by default (about 70 to 75 KB per full cycle uncompressed). |
| Secrets | Password from `getpass` (or SSH key file); never in argv, logs, manifest or exception text. |
| Tests | Synthetic data only, `FakeTransport` with a simulated clock; no test touches a device. |

## Sampling model

Two periods in one scheduler with absolute times from `t0` (no drift): full cycle every `X`,
fast tick every `B = max(1, X/6)`. The full cycle ends with a fast tick, which covers the
coincident tick. A tick more than one full period late is skipped and counted
(`skipped_ticks`); a tick less than one period late runs immediately. `--duration 0` runs until
Ctrl+C; the `finally` block always switches inflight monitoring off, with a second attempt on a
fresh SSH session.

## Storage format

```
runtime_<host>_<UTC>/
  manifest.json            # parameters, counts, availability, warnings (no banner, no prompt)
  raw/<slug>.txt.gz        # or .txt with --no-compress
```

Each raw file is a sequence of samples:

```
#### SAMPLE n=<int> t=<UTC ISO> dur=<seconds> ok=<0|1> [key=value ...]
<raw command output>
#### END
```

Slugs: `system_info`, `clock`, `state_inflight`, `state_backlogs_threshold`,
`state_backlogs_duration`, `state_backlogs_trigger`, `state_pbp_zones`, `mgmt_load`,
`session_info`, `resource_monitor`, `pow`, `pow_all`, `delta`, `ingress_backlogs`, `pbp`,
`pbp_latency`, `session_id` (one sample per offender, attribute `id=<session id>`).

## Steps

| # | Step | Status |
|---|---|---|
| 0 | Branch `feature/runtime-analyzer`, this plan | Done |
| 1 | Reconnaissance (lab VM, historical log), `command-notes.md` | Done |
| 2 | `transport.py`, `ssh.py`, allow-list, `FakeTransport` | To do |
| 3 | `store.py`, `capture.py` (scheduler, inflight, offenders), CLI `capture` | To do |
| 4 | Parsers: session, counters, backlog, packet buffer, resource monitor | To do |
| 5 | `analysis.py`: time series, thresholds, findings | To do |
| 6 | Report HTML, per-section help, flag documentation test | To do |
| 7 | CLI registration, `pyproject` extra, README, `CLAUDE.md`, user docs, ruff | To do |
| 8 | Live validation on the lab, independent spot check | To do |
| 9 | Merge into `develop` | Only on Alberto's order |
| Future | XML API transport (keygen from user/password, POST body, key kept in memory; run keygen before opening SSH because a new key can end the user's sessions), via Panorama with `target=<serial>`; validation on a physical firewall with a real offender | Deferred |

## Open points

- Who runs the other delta sampler seen on the lab in every run (not blocking).
- Wording of `show session inflight_monitoring status` (not yet seen; unknown wording means
  "state not verifiable", the final `no` is still sent).
- Real offender row format (seen only in an old screenshot and in a historical log with special
  tags only); packet-buffer-protection with protection active (historical log only);
  multi-DP firewalls.

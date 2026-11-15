# GlobalProtect client log analyzer

`panos-toolbox gp analyze` reads the bundle produced by **Collect Logs** in the GlobalProtect
app (`GlobalProtectLogs*.zip`, or the folder it extracts to) and writes one self-contained HTML
report: no external resources, works offline. Specification of the log files:
[log-formats.md](log-formats.md).

## Purpose

Answer, from a single client-side bundle: what is the client configured to do, what happened at
every connection attempt (and why it failed), and is anything in the logs worth acting on. The
report presents facts found in the logs; the findings are leads, not verdicts.

## Usage

```bash
panos-toolbox gp analyze GlobalProtectLogs.zip [more.zip ...] [-o OUTDIR] [--open]
python scripts/gp_analyzer.py GlobalProtectLogs.zip      # zero-install launcher, from a checkout
```

The output is `<bundle name>_gp.html` next to each input, or in `OUTDIR`. Two inputs with the
same name get a numeric suffix instead of overwriting each other.

| Option | Meaning |
|---|---|
| `-o`, `--outdir DIR` | Output directory (default: next to each input). |
| `--open` | Open the last report written in the default browser. |
| `--chain-gap S` | Seconds within which login cycles are chained into one attempt (default 600). |
| `--gp-<threshold> N` | Override a finding threshold, one option per entry of `GP_THRESHOLDS` (table below). |
| `--debug` | Do not catch unexpected errors: show the full traceback and stop. |

Exit code: 0 when at least one input was analysed, 1 when every input failed. An input that
cannot be read, or fails unexpectedly, is reported as `[ERROR] <input>: <message>` on stderr and
the other inputs are still processed; use `--debug` to get the traceback of an unexpected error.

### Thresholds (`GP_THRESHOLDS` in `gp/checks.py`)

| Option | Default | Meaning |
|---|---|---|
| `--gp-recent-days` | 7 | Recent window, in days before the newest log record. |
| `--gp-repeated-failure-min` | 3 | Same error text on at least N login failures. |
| `--gp-class-failure-min` | 1 | Gateway certificate / unreachable failures needed. |
| `--gp-auth-failure-min` | 1 | Authentication failures needed. |
| `--gp-restore-grace-min` | 1 | Expired (grace period) restores needed. |
| `--gp-restore-failed-min` | 1 | Auto-restores with a failed retry needed. |
| `--gp-success-rate-min-pct` | 70 | Login success rate below this percentage is low. |
| `--gp-success-rate-min-attempts` | 5 | Attempts (cancelled excluded) needed to judge the rate. |
| `--gp-log-gap-s` | 3600 | Event log ends this many seconds before the detailed logs. |
| `--gp-refs-cap` | 10 | Attempt ids listed in one finding. |

## The report, tab by tab

Every tab and panel has its own collapsed help (a "Help" button) written in `report_help.py`.

- **Summary**: identity and state at collection (client version, user, host, OS, domain,
  portal, connection state, last service state, newest log record), the key settings (portal,
  connect method, SSO, on-demand, enforcement, MTU, split tunnel, DNS) each with its freshness
  badge and source file, outcome counters of the last 7 days, and the findings overview.
- **Client configuration**: the key settings, a filter over all settings, and one panel per
  source: summary, registry, status sent to the UI, portal-pushed settings, gateways and tunnel
  configuration, HIP report, troubleshooting report, host and network, PANGP driver. Panels
  with more than 40 rows start collapsed; the filter expands the panels that contain matches.
- **Connection timeline**: all attempts of the bundle, with period presets (24 h, 7 d, 30 d,
  All, custom range), outcome and kind filters, text search and a chart of attempts over time.
  A row opens the details: ordered phase steps (where detailed logs exist), error text and
  stage, disconnect reason and session duration, why an attempt is `cancelled` or `expired`, and
  the manual gateway switches of a session. Retry storms are collapsed into one group row.
- **Findings**: the automatic checks grouped by level, with links to the attempts and
  configuration sections they refer to, and the flag reference with the thresholds in use.
- **Source coverage**: the bundle inventory (every file, whether it was read, skipped or
  truncated and why, what it feeds) and the time range and record count of each log family.

## How an attempt is defined

Implemented in `gp/timeline.py` (the module docstring is the authority).

- **Kinds**: `login` (a connection attempt with a user session), `pre-logon` (before a user signed
  in), `auto-reconnect` (a portal discovery the client started itself: network change, sign-out,
  unlock, rediscovery) and `auto-restore` (an automatic tunnel restore, no portal contact). The
  finer cause is in `trigger` (`user-click`, `sso`, `gui-start`, `sign-out`, `rediscovery`,
  `network-change`, `unlock`, `service-start`, `user-switch`, `software-upgrade`), else `unknown`.
- **Where attempts come from**: the event log when present (authoritative history); otherwise the
  service log alone, which is first-class. Service rules match on the message text only and never
  on the `<src>` number of a record, which differs between client builds. Details of the service
  and agent logs are attached to event attempts by start time.
- **Boundaries** (the logs have no explicit "attempt begins" marker, so they are inferred): a
  portal cycle starts at `----Portal Processing starts----`; an attempt without a portal contact
  starts at `----Network Discover starts----` when no attempt is open. `----Portal refresh
  configuration starts----` is a refresh, not an attempt. Lock, unlock and wake alone never start
  one. `SSO starts.` marks the first cycle of a new attempt. `Failed to create tunnel to gateway X.`
  after the state Connected is not a failure.
- **Chaining**: a cycle is chained to the previous one only if the previous ended without an
  outcome (credential or SAML prompt, retry), in the same process and for the same portal, never
  between a pre-logon cycle and a user cycle, and within the logged SAML timeout or, without one,
  `--chain-gap` seconds (600 by default). Chained cycles are ONE attempt (`cycles` counts them). A
  prompt is not a failure. Otherwise the earlier attempt closes as `abandoned`.
- **Agent-only periods**: where only the agent log covers a period, attempts come from the
  `Dialog Status` transitions (`sources = ["agent_log"]`). Automatic rediscoveries closer than
  15 minutes that end the same way are collapsed into one row (`details.collapsed` counts them).
- **Outcomes**: `connected`, `internal`, `failed`, `cancelled`, `abandoned` (never completed) and
  `expired`. The log level never decides an outcome; only the markers do.
  - `internal`: the client detected the internal network and created no tunnel on purpose
    (`network type is internal`, `gateway X does not need tunnel`). It is a success class.
  - `expired`: an auto-restore that ended with `Tunnel retry done: failed retry` while the log
    says the downtime exceeded the retry grace period and no retry was attempted (`details`:
    `downtime_ms`, `modern_standby`); or a login whose SAML prompt timed out
    (`details.expired_reason = saml-timeout`). Never a failure.
  - `failed` (restore): a retry was really attempted and failed, or the log gives no reason.
  - `cancelled` carries `details.cancel_evidence`: `explicit` (a `User canceled login` line) or
    `inferred` (deduced from a user disconnect during the attempt).
- **Error category** (`error_category`): `auth`, `saml`, `certificate`, `portal-unreachable`,
  `gateway-unreachable`, `gateway-cert`, `cancelled`, `timeout` or `other`; the findings use it
  instead of matching message texts.
- **Retry storms**: 10 or more failed logins, each starting at most 30 s after the previous one.

Where the verbose service/agent logs overlap an attempt it gets ordered phase steps; the
event log and the detailed logs are cross-checked and disagreements are shown in the details.

## Freshness badges

Each configuration source carries one badge: **At collection** (snapshot taken when the bundle
was collected), **Last seen in logs** (most recent value found in the rolling logs, possibly
older than the collection), **Historical** (stale file, older than the newest log record by more
than a day). Never read a last-seen or historical value as the current setting.

## Local-time rule

Log times are the local wall-clock time of the client, without any zone conversion. The recent
window and the "last 7 days" are anchored to the **newest log record**, never to the wall clock
of the machine that runs the analyzer, so an old bundle opens on its own latest activity.

## Findings

Codes, levels and help text live in `FLAG_HELP` and `GP_THRESHOLDS` in `gp/checks.py`; this
table mirrors them. The newest wording is always the "Flag reference" of the Findings tab.

| Code | Level | Meaning |
|---|---|---|
| `DRIVER_DISABLED` | info / warning / critical | Newest PANGP driver event is a problem code (for example 22, device disabled). The adapter is normally disabled while the client is disconnected: info when the client was not connected at collection; warning when, in the recent window, logins failed during tunnel creation or adapter setup and a driver problem event exists; critical when the client was connected at collection while the newest driver event is a problem or the adapter is absent. |
| `NOT_CONNECTED_AT_COLLECTION` | info | The tunnel was not up when the logs were collected. A state, not an error. Silent when there is no collection snapshot (no `IpConfig.txt`); `DRIVER_DISABLED` is silent then too. |
| `LAST_ATTEMPT_FAILED` | warning | The newest login or pre-logon attempt failed or was abandoned (cancelled is not reported; restores and reconnects are never considered). |
| `RETRY_STORM` | critical / warning | Many failed logins in quick succession; critical when it ended inside the recent window. |
| `REPEATED_FAILURE` | warning | The same normalised error on at least `repeated_failure_min` logins in the window. |
| `GW_CERT_FAILURE` | warning | Logins failed because the gateway certificate could not be verified. |
| `GW_UNREACHABLE` | warning | Logins failed with the gateway unreachable or unresponsive. |
| `AUTH_FAILURE` | warning | Logins whose `error_category` is `auth` or `saml`; prompts followed by success are not counted. |
| `PORTAL_UNREACHABLE` | warning | Logins that failed with category `portal-unreachable` (invalid portal, no response). |
| `SAML_TIMEOUT` | info / warning | Logins `expired` because the SAML sign-in was not completed in time; warning from `saml_timeout_warn` occurrences. |
| `CLIENT_UPGRADED` | info | The client version changed between service starts inside the bundle (from the configuration data; silent when absent). |
| `RESTORE_GRACE_EXCEEDED` | info | `expired` auto-restores: the downtime exceeded the retry grace period and no retry was attempted (PC slept or offline). |
| `RESTORE_FAILED` | warning | Auto-restores in the recent window where a retry was attempted and failed, with the error breakdown. |
| `LOW_SUCCESS_RATE` | warning | Success rate (`connected` or `internal`) of login and pre-logon attempts in the window below `success_rate_min_pct`; restores and reconnects never count. |
| `STALE_TRB_REPORT` | info | `pan_gp_trb.log` is the report of the last failure and can be much older than the other logs. |
| `LOG_GAP` | info | The event log ends more than `log_gap_s` before the detailed logs. |
| `CONFIG_TRUNCATED` | info | A configuration block was cut by the logger or could not be parsed. |
| `PARTIAL_BUNDLE` | warning | Event log, service log or `regval.txt` missing or empty. |

## Module map (`src/panos_toolbox/gp/`)

| Module | Role |
|---|---|
| `bundle.py` | Safe in-memory reading of the zip or folder, inventory, limits. |
| `logs.py` | Record and line parsing of the event, service and agent logs. |
| `client_config.py` | `build_config`: configuration sections and connection state. |
| `timeline.py` | `build_timeline`: attempts, outcomes, steps, storms, coverage. |
| `checks.py` | `evaluate`: findings; `GP_THRESHOLDS`, `FLAG_HELP`. |
| `analyzer.py` | CLI, data blob, HTML rendering. |
| `report_template.py` | The page: HTML, CSS and JavaScript. |
| `report_help.py` | Per-panel help (`SECTION_HELP`, placeholders `__HB_<id>__` / `__HP_<id>__`). |

## Safety rules of the report

- The page is built with `textContent` and DOM calls only: no `innerHTML`, `eval` or inline
  event handlers; a test checks the template.
- The data blob is JSON in a script element, with `<`, `>`, `&`, U+2028 and U+2029 escaped.
  Placeholders are replaced in a single pass, so log text is never interpreted as a placeholder.
- The bundle is read in memory, never extracted: unsafe member paths and links are skipped,
  and member count, per-member and total expanded sizes are bounded while reading (the size in
  the zip header is never trusted).

## Privacy

The report contains user names, host names, IP addresses and portal and gateway hostnames in
clear text, as found in the logs. The client masks secrets in its own logs and the analyzer
never reads the `<passwd>` element, but treat the report like the bundle: share it only with
people who may see that data.

## Known limitations

- Windows bundles only (GlobalProtect 6.3.x format); macOS and Linux bundles are not supported.
- The format was derived from three real bundles (one with the event log, two service-log-only).
  Some flows (certificate authentication, SSL fallback) are covered by few or no samples (see
  section 12 of [log-formats.md](log-formats.md)); support for them is unverified.
- Without an event log the history starts where the service log starts, and an attempt whose
  portal cycles are far apart (beyond the SAML timeout or the chain gap) is split in two.
- The trigger of an attempt is `unknown` outside the detailed-log window: from the event log
  alone a manual click and an automatic retry look the same.
- Phase steps exist only inside the window covered by the service and agent logs (a few days);
  older attempts have an outcome but no steps.

## Adding a check

1. Write `_my_check(config, timeline, **ctx)` in `gp/checks.py` returning a list of
   `GpFinding` built with `_mk(code, level, text, scope, when, refs, count)`; use only facts
   present in the data. The context passed by `evaluate` is `config`, `timeline`, `attempts`,
   `anchor`, `thr` and `fails` (recent failed logins); accept `**_` for the rest.
2. Add the step to the `steps` list of `evaluate` (a failing check never hides the others).
3. Add the code to `FLAG_HELP` (title and help text). A test checks that every code has help
   and is embedded in the report.
4. A new threshold goes into `GP_THRESHOLDS`; its `--gp-*` option is generated.
5. Add tests with synthetic data in `tests/test_gp_checks.py`, then update the table above.

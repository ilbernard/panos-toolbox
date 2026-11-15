"""Per-section help of the GlobalProtect report.

Every tab and panel of the report has its own short, collapsed help (a "? Help" button that
expands a text at the top of that section). There is no global help page.

``SECTION_HELP`` maps a section id to an HTML template; ``SECTION_TITLES`` maps the same ids to
the titles used for the accessible name of the buttons. The ``{name}`` placeholders of the
templates are filled by :func:`render_section_help` with the parameters of the timeline
(``chain_gap_s``, ``storm_min_failures``, ``storm_max_gap_s``); literal braces are doubled.
The report template holds the placeholders ``__HB_<id>__`` (the button) and ``__HP_<id>__``
(the collapsible text) for each id, inside a hidden store that the page script copies next to
the panel headings.

The help ids of the configuration panels are ``cfg_<section id>`` (section ids of
``client_config``); the flag codes are documented by ``checks.FLAG_HELP``, which the Findings tab
shows in its "Flag reference".

Standard library only.
"""
from __future__ import annotations

import html

from .timeline import CHAIN_GAP_S, STORM_MAX_GAP_S, STORM_MIN_FAILURES

SECTION_TITLES = {
    "summary": "Summary",
    "sum_counters": "Outcome counters",
    "sum_findings": "Findings overview",
    "keysettings": "Key settings",
    "config": "Client configuration",
    "cfg_summary": "Identity and state at collection",
    "cfg_registry": "Registry settings",
    "cfg_status": "Status sent to the UI",
    "cfg_portal_settings": "Portal settings",
    "cfg_gateways": "Gateways",
    "cfg_hip_report": "HIP report",
    "cfg_troubleshooting": "Troubleshooting report",
    "cfg_host_network": "Host and network",
    "cfg_driver": "Virtual adapter driver",
    "timeline": "Connection timeline",
    "tl_chart": "Attempts over time",
    "tl_table": "Attempts table",
    "findings": "Findings",
    "flagref": "Flag reference",
    "coverage": "Source coverage",
    "cov_inventory": "Bundle inventory",
    "cov_ranges": "Time range of the logs",
}

_FRESH = (
    "<p>The badge on every panel says how current the data is: <b>At collection</b> is a "
    "snapshot taken when the bundle was collected; <b>Last seen in logs</b> is the most recent "
    "value found in the rolling logs (it can be older than the collection); <b>Historical</b> "
    "is a stale file, older than the newest log record by more than a day. Never read a "
    "historical or last-seen value as the current setting.</p>"
)

SECTION_HELP = {
    "summary": """
<p>One-page view of the bundle: who and what was collected, the settings that matter most,
how many connection attempts ended in which way in the default period, and the findings.</p>
<ul>
<li><b>Data:</b> everything is derived from the files of the "Collect Logs" bundle; the
Source coverage tab lists which file was used for what.</li>
<li><b>Times</b> are the local wall-clock time of the client, as written in the logs, without
any time zone conversion. "Last 7 days" means the 7 days before the <b>newest log record</b>,
not before today, so an old bundle still opens on its own latest activity.</li>
<li>The <b>analysis status</b> in the page header is <code>complete</code> unless a file was
skipped, truncated or missing; click it for the reasons.</li>
</ul>""",
    "sum_counters": """
<p>Number of attempts that started in the period, by outcome and by kind. The same filter is
available, with more options, in the Connection timeline tab (button below the counters).</p>
<ul>
<li><b>Connected</b>: the tunnel came up. <b>Failed</b>: a terminal error ended the attempt
(for an auto-restore: a reconnection was really attempted and failed). <b>Cancelled</b>: the user
cancelled; most often this is <i>inferred</i> from a user disconnect during the attempt, not read
from an explicit cancel line (the details say which). <b>Abandoned</b>: the attempt stopped at a
credential prompt or while waiting for the user and never completed. <b>Expired</b>
(auto-restores only): the tunnel downtime exceeded the retry grace period, so no reconnection was
attempted (the PC slept or was offline); the log still ends with "failed retry", but it is not a
VPN malfunction and not a failure.</li>
<li>A credential prompt in the middle of an attempt is <b>not</b> a failure: the client first
tries without a password and asks for one when the portal wants it.</li>
<li>"In retry storms" counts the attempts of the period that belong to an automatic retry loop;
they are included in the outcome counters.</li>
</ul>""",
    "sum_findings": """
<p>The findings of the automatic checks, by severity (critical, warning, info). Each links to
the attempts or configuration sections it refers to. The full text and the reference of every
code are in the Findings tab.</p>""",
    "keysettings": """
<p>The settings that most often explain a connection problem, copied from the panels below.
Each row says where the value comes from and how current it is.</p>
""" + _FRESH + """
<p>Settings that could not be found in the bundle are not listed. An empty value is shown as
<code>(empty)</code>: the setting exists and is empty.</p>""",
    "config": """
<p>The configuration and state of the client, one panel per source. Rows are
<i>setting / value / raw key</i>: the raw key is the registry value or XML element the value was
read from, so it can be searched in the Palo Alto documentation or in the file.</p>
""" + _FRESH + """
<ul>
<li>The filter searches the settings, values, raw keys and panel titles of every panel.</li>
<li>Long values (HTML snippets, long lists) are shortened: use <b>expand</b> to see them whole.</li>
<li>Portal settings are what the portal pushed to the client the last time it was reached; a
registry value set by a GPO or by the installer can override them.</li>
</ul>""",
    "cfg_summary": """
<p>Identity of the client and the host, and the state at collection time (connected or not, last
service state, whether the virtual adapter exists). Sources: registry dump, status XML in the
service and agent logs, SystemInfo and IpConfig. Each row names its own source in the note under
the value. The connection state is rebuilt from the evidence listed there: it is an inference
when the bundle has no direct statement.</p>""",
    "cfg_registry": """
<p>GlobalProtect values read from the registry dump (<code>regval.txt</code>), collected at the
same time as the bundle. They include policy values deployed by GPO or MDM and values written by
the installer. Empty values are real: the key exists but holds no data.</p>""",
    "cfg_status": """
<p>The last complete status document that the service sent to the UI (client version, portal,
user, state), and the last "connected" state seen with tunnel protocol, gateway and tunnel
addresses and uptime. It comes from the rolling service and agent logs, so it can predate the
collection: check the timestamp in the panel header.</p>""",
    "cfg_portal_settings": """
<p>Settings delivered by the portal (agent UI and agent configuration: connect method, SSO,
on-demand, tunnel MTU, split tunnel, timeouts, retry behaviour), taken from the last portal
configuration block found in the service log. They describe what the portal configured, not
necessarily what is in effect: see the registry panel for values that override it.</p>""",
    "cfg_gateways": """
<p>The gateway list and the last tunnel configuration received from a gateway (tunnel address,
DNS servers and suffixes, MTU, excluded applications and domains, idle timeout). Last seen in
the service log; it describes the last successful gateway login in the log window.</p>""",
    "cfg_hip_report": """
<p>Snapshot of the last HIP report the client sent (<code>pan_gp_hrpt.xml</code>): host
information, network interfaces and the categories of the checks. It is written when the client
sends a HIP report, usually while connected, so it is often <b>historical</b> compared with the
collection.</p>""",
    "cfg_troubleshooting": """
<p>The report the client writes after a failed connection (<code>pan_gp_trb.log</code>). It is
overwritten at each failure, so it describes the <b>last failed connection</b> only; when it is
older than the logs it is shown as historical. Times inside it can be in UTC (noted in the
rows).</p>""",
    "cfg_host_network": """
<p>Static snapshot of the host at collection: system information, IP configuration, adapters,
routes and whether the PANGP virtual adapter exists. Sources: <code>SystemInfo.txt</code>,
<code>IpConfig.txt</code>, <code>RoutePrint.txt</code>. Useful to see the DNS servers, default
route and interfaces that were active when the problem was captured.</p>""",
    "cfg_driver": """
<p>Entries of the Windows device-install logs (<code>setupapi.dev.log</code>,
<code>setupapi.app.log</code>) that mention the PANGP adapter: installs, enables, failures
with the Windows problem code. These logs are rolling, so only the newest events are present.</p>""",
    "timeline": """
<p>What happened during the connection attempts, from the oldest to the newest record of the
bundle. <b>All</b> attempts of the bundle are in the page; the period filter only decides what is
shown. On opening, the period is the 7 days before the newest log record.</p>
<ul>
<li><b>Kinds.</b> <i>Login</i> is a connection attempt (portal pre-login, authentication,
gateway, tunnel). <i>Auto-restore</i> is an automatic tunnel restore after a network change or
sleep: no portal contact, only the gateway.</li>
<li><b>Cycles.</b> The client first tries to log in without a password; when the portal asks for
credentials the cycle ends at a prompt and a new cycle starts once the user answers. Cycles that
follow each other within {chain_gap_s} s are chained into ONE attempt; "cycles" is how many
were chained. A prompt is therefore not a failure. Chaining never crosses portals: a cycle for
another portal than the previous one starts a new attempt and the earlier one is abandoned.</li>
<li><b>Outcomes.</b> <i>Connected</i>, <i>failed</i>, <i>cancelled</i> (often inferred from a
user disconnect, see the details), <i>abandoned</i> (never completed) and, for auto-restores
only, <i>expired</i>: the downtime exceeded the retry grace period and no reconnection was
attempted, typically because the PC slept or was offline.</li>
<li><b>Retry storms.</b> {storm_min_failures} or more failed logins, each starting at most
{storm_max_gap_s} s after the previous one, are collapsed into one group row that expands.</li>
<li><b>Detail.</b> Phase steps exist only where the detailed logs (service and agent logs, which
cover only the last few days) overlap the attempt; older attempts have the outcome from the
event log but no steps.</li>
<li>Times are local client time, without zone conversion. Durations are measured between the
first and last record of the attempt.</li>
</ul>""",
    "tl_chart": """
<p>Attempts over time for the filtered period. Each mark is one attempt: the row (lane) is its
<b>outcome</b> (connected, failed, cancelled, abandoned, expired) and the colour repeats it; the
<b>shape</b> is its kind (circle = login, diamond = auto-restore). Click a mark to jump to its
row in the table. Hover for a short description. Dense stretches (a retry storm) overlap into a
solid band.</p>""",
    "tl_table": """
<p>One row per attempt (or per retry storm). Click a column heading to sort; click a row to see its
details.</p>
<ul>
<li><b>Trigger</b>: <code>user-click</code> (the user pressed Connect), <code>sso</code>
(single sign-on started it; inferred from timing), <code>auto</code> (the service started it),
<code>restore</code> (auto-restore), <code>unknown</code> (event log only: a click and an
automatic retry look the same).</li>
<li><b>Error</b>: the short normalised text; the logged message and the stage are in the
details. An <i>expired</i> restore shows the grace-period text; the details give the downtime and
whether the PC waited in modern standby. A <i>cancelled</i> attempt says whether the cancel was
explicit or inferred from a user disconnect. Manual gateway switches inside a session are listed
in the details of that session.</li>
<li><b>Details</b> list the ordered phase steps (time, offset from the start, phase, text,
source file) when detailed logs exist for the period, the disconnect reason and session duration
of successful attempts, and any disagreement between the event log and the detailed logs.</li>
<li>Without detailed logs the row says which period the service and agent logs cover.</li>
</ul>""",
    "findings": """
<p>Automatic checks over the configuration and the timeline, grouped by severity. A finding is
a lead, not a verdict: read the text, then open the attempts and sections it links to.
<b>Critical</b> and <b>warning</b> raise the status; <b>info</b> is context. The recent window of
the checks is anchored to the newest log record, like the timeline.</p>""",
    "flagref": """
<p>Meaning of every finding code and the thresholds used in this run (defaults, and any value
changed on the command line with <code>--gp-&lt;name&gt;</code>).</p>""",
    "coverage": """
<p>What was in the bundle and what was used. Use it to judge how far the report can be trusted:
a file that was skipped or truncated, a log that ends before the others, or a missing log
family limits the conclusions.</p>""",
    "cov_inventory": """
<p>Every file of the bundle: its family, size, whether it was read, and the reason when it was
skipped or truncated (unsafe path, link, size limit, duplicate name). "Used for" says which part
of the report the file feeds. Files of families that are not analysed (for example crash dumps)
are listed but not read.</p>""",
    "cov_ranges": """
<p>First and last record and number of records of each log family. The event log
(<code>pan_gp_event</code>) keeps the whole history of the attempts; the service and agent logs
are verbose and rotate quickly, so they cover only the last days: <b>phase steps exist only
inside that detailed-log window</b>. When the event log ends before the detailed logs, the
newest attempts come from the detailed logs alone.</p>""",
}


def _params(params) -> dict:
    values = {
        "chain_gap_s": CHAIN_GAP_S,
        "storm_min_failures": STORM_MIN_FAILURES,
        "storm_max_gap_s": STORM_MAX_GAP_S,
    }
    for key, val in (params or {}).items():
        if key in values:
            values[key] = val
    return {k: html.escape(f"{v:g}" if isinstance(v, float) else str(v)) for k, v in values.items()}


def render_section_help(params=None) -> dict[str, str]:
    """Return ``{placeholder: html}`` for every section (buttons and collapsible texts).

    ``params`` optionally overrides the timeline parameters used in the texts
    (``chain_gap_s``, ``storm_min_failures``, ``storm_max_gap_s``); values are escaped.
    """
    values = _params(params)
    out: dict[str, str] = {}
    for sid, text in SECTION_HELP.items():
        title = html.escape(SECTION_TITLES[sid], quote=True)
        out[f"__HB_{sid}__"] = (
            f'<button type="button" class="helpbtn" aria-expanded="false" '
            f'aria-controls="help-{sid}" aria-label="Help: {title}">? Help</button>')
        out[f"__HP_{sid}__"] = (
            f'<div class="help" id="help-{sid}" hidden>{text.format_map(values)}</div>')
    return out


def render_help() -> str:
    """All help texts in one string (used by tests and documentation checks)."""
    return "\n".join(render_section_help().values())

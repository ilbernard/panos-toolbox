"""Per-section help of the runtime report.

Every tab and panel of the report has its own short, collapsed help (a "? Help" button that
expands a text at the top of that section). There is no global help page.

``SECTION_HELP`` maps a section id to an HTML fragment and ``SECTION_TITLES`` maps the same ids
to the titles used for the accessible name of the buttons. The report template holds the
placeholders ``__HB_<id>__`` (the button) and ``__HP_<id>__`` (the collapsible text) for each id,
inside a hidden store that the page script copies next to the panel headings.

``FLAG_HELP`` documents every finding code emitted by ``analysis.py``: ``code -> (title,
meaning, what to check next)``; ``FLAG_KEYS`` lists the ``RT_THRESHOLDS`` keys behind each code.

Standard library only. Plain ASCII punctuation.
"""
from __future__ import annotations

import html

SECTION_TITLES = {
    "overview": "Overview",
    "ov_inflight": "Inflight monitoring",
    "ov_commands": "Per-command timing",
    "findings": "Findings",
    "flagref": "Flag reference",
    "pow": "POW",
    "pow_groups": "POW groups over time",
    "pow_funcs": "POW top functions",
    "counters": "Counters",
    "ct_table": "Aggregated counters",
    "ct_rates": "Counter rates",
    "ct_samples": "Delta samples",
    "backlog": "Ingress backlogs",
    "bl_chart": "Backlog usage over time",
    "bl_tags": "Special tags",
    "bl_offenders": "Offending sessions",
    "pbp": "Packet buffer",
    "pbp_congestion": "Packet buffer congestion",
    "pbp_latency": "Packet buffer latency",
    "pbp_entries": "Packet buffer protection table",
    "sessions": "Sessions",
    "ss_table": "Session table usage",
    "ss_active": "Active sessions by protocol",
    "ss_rates": "Session rates",
    "resources": "Resources",
    "throughput": "Throughput",
    "tp_total": "Total throughput",
    "tp_ifaces": "Throughput per interface",
    "res_cpu": "Data plane CPU over time",
    "res_heat": "CPU per core heatmap",
    "res_groups": "CPU per group",
    "res_util": "Resource utilization",
    "res_mgmt": "Management plane load",
    "capture": "Capture log",
    "cap_cycles": "Cycle durations",
    "cap_commands": "Commands",
}

SECTION_HELP = {
    "overview": """
<p>What was captured, from which firewall, and how the capture went. The numbers come from
the manifest written by <code>runtime capture</code> and from the samples in the capture
folder; the firewall model and software version come from <code>show system info</code>.</p>
<ul>
<li><b>Times</b> are UTC, as stored in the capture. The workstation time zone is not applied.</li>
<li>A cycle is one slow pass of commands (session info, resource monitor, POW, delta
counters, management load). Backlog and packet buffer commands run on a faster tick.</li>
<li>A capture that was stopped by the user or has no manifest is still analysed; the
counts then show what was actually stored.</li>
</ul>""",
    "ov_inflight": """
<p>Inflight monitoring is a debug setting that is switched on during the capture so that the
ingress backlog and packet buffer tools produce data, and it is always left OFF at the end.
The capture reads the state back after switching it off.</p>
<ul>
<li>A red box means the capture could not confirm that it is OFF. Check the firewall (the
state command is shown in the capture log) and switch it off by hand if needed.</li>
<li>"State before" is what the firewall reported when the capture started.</li>
</ul>""",
    "ov_commands": """
<p>One row per command that did not exist or was refused on this firewall, and the timing of
each command that ran (count, average and maximum duration, failures).</p>
<ul>
<li><b>Unavailable</b> means the firewall answered "Invalid syntax" for that command (platform
or software version). Related tabs show a clear message instead of empty charts.</li>
<li><b>Failed</b> counts samples that ended without the CLI prompt, so the output may be
partial.</li>
</ul>""",
    "findings": """
<p>The automatic checks over the whole capture, sorted by level (critical, warning, info).
Use the buttons to filter by level. Every finding has a code that is explained in the
flag reference below the table.</p>
<ul>
<li>Thresholds are the ones listed in the flag reference; change them with
<code>--threshold KEY=VALUE</code> when running the report.</li>
<li>A finding is a pointer, not a diagnosis: always look at the related tab.</li>
</ul>""",
    "flagref": """
<p>Every finding code the report can raise: what it means, which threshold keys control it
and what to check next. The column "Raised" counts how many times it fired in this
capture.</p>""",
    "pow": """
<p>POW (packet-order-wait style work groups) timing from <code>debug dataplane pow
performance</code>, sampled once per cycle. The tab shows how long each group and function
takes on average in every interval, and the evaluation of the last sample.</p>
<ul>
<li>Per-interval figures are computed from the <b>difference of the ac-* columns</b> (the
accumulated count and total microseconds) between two consecutive samples, so they describe
the interval and not the whole uptime. The first sample has no interval.</li>
<li>An interval with no new calls has no value and leaves a gap in the line.</li>
<li>The evaluation items (banner) are produced by the same rules as the tech support file
report; they are hints, not proof of a fault.</li>
</ul>""",
    "pow_groups": """
<p>Average microseconds per call for the selected group in every interval (difference of
<code>ac-total-us</code> divided by the difference of <code>ac-count</code>). Pick another
group with the selector. Hover a point for the exact value, call count and maximum.</p>
<p><b>Scale.</b> The groups differ by several orders of magnitude (a few microseconds for the
forwarding stages, hundreds of thousands for the management flow), so with every group shown
the default (<i>Auto</i>) is a <b>logarithmic</b> scale: each gridline is ten times the one
below and a ten-fold change looks the same wherever it happens. A single group is drawn
<i>linear</i> by default. The selector forces either. On the log scale an interval with no
calls (average 0 or empty) is a gap, because zero cannot be drawn.</p>""",
    "pow_funcs": """
<p>The functions that used the most total time over the capture (the number is limited by
<code>top_pow_funcs</code>). Columns show the largest and the mean of the per-interval
averages and the total number of calls. Click a column header to sort.</p>""",
    "counters": """
<p>Global counters from <code>show counter global filter delta yes</code>. The firewall
prints the change since the previous request together with the elapsed time and a rate per
second; the report uses that rate.</p>
<ul>
<li><b>The delta baseline is global on the firewall.</b> Any other client that runs the same
command (another admin, a script, a monitoring tool) resets it, so one sample then covers a
shorter window. Such samples are marked as foreign in the samples strip and are <b>left out of
the charts (a gap) and of every statistic</b>: the other client took part of the window, so
the rate of that sample is measured on a short and arbitrary slice.</li>
<li>Counters that never appear in a sample are not listed; a counter that appears late is
listed with its first-seen sample.</li>
</ul>""",
    "ct_table": """
<p>One row per counter seen at least once: severity, category, aspect, number of samples in
which it appeared, the maximum, mean and last rate per second and the sum of the deltas.
Click a header to sort, use the search box for name or description and the severity buttons
to filter.</p>
<ul>
<li>The mean rate divides by the valid delta samples (foreign ones excluded), including those
where the counter did not appear.</li>
<li>A high rate of a <code>drop</code> counter is not always a problem; read the
description and compare with the traffic level.</li>
</ul>""",
    "ct_rates": """
<p>Rate per second of the busiest counters (the number is limited by <code>top_counters</code>)
in every delta sample. A missing counter in a sample is drawn as zero; a foreign sample is a
gap in the line. Hover a point for the value.</p>""",
    "ct_samples": """
<p>One box per delta sample with the elapsed time the firewall reported. A marked box is a
foreign sampler: the elapsed time is clearly shorter than the capture interval, which means
another client read and reset the counters in between. The sample covers only part of the
cycle, so it is excluded from the rate chart and from the counter statistics.</p>""",
    "backlog": """
<p>Ingress backlog usage per data plane, from the ingress backlog command sampled on the
fast tick. It shows how full the atomic and total backlog are and which sessions hold the
largest share.</p>
<ul>
<li>The command needs inflight monitoring, which the capture enables for its duration and
always leaves OFF.</li>
<li>If the firewall does not support the command, this tab says so and has no data.</li>
</ul>""",
    "bl_chart": """
<p>Atomic and total backlog usage in percent per slot and data plane over time. Use the
selector to choose the slot and data plane. Hover a point for the exact values.</p>""",
    "bl_tags": """
<p>Entries in the backlog list that are special tags (for example a forwarding workgroup),
not sessions. The values show the largest share seen. A special tag has no session id, so
<code>show session id</code> does not apply to it.</p>""",
    "bl_offenders": """
<p>Real sessions that held a large share of the backlog. For each one the capture ran
<code>show session id</code> right away; the output is shown as text in the detail box. The
session may be gone by the time you read it, so the saved text is the evidence.</p>""",
    "pbp": """
<p>Packet buffer usage and latency from the packet buffer protection commands. Congestion
shows how much of the buffer is in use, latency how long packets wait in it, and the table
lists the addresses that the protection currently tracks.</p>
<ul>
<li>If the firewall does not support the commands, this tab says so.</li>
<li>Protection "active" means the firewall started to act on the offenders.</li>
</ul>""",
    "pbp_congestion": """
<p>Buffer congestion in percent over time (used divided by total). Sample points where the
protection was active are drawn with a red marker.</p>""",
    "pbp_latency": """
<p>Packet buffer latency in milliseconds: the latest value and the maximum over the
reported buckets, per sample.</p>""",
    "pbp_entries": """
<p>The last packet buffer protection table captured (time shown above the table): address or
session, zone, buffer share, state and drop counters. It is a snapshot, not a history.</p>""",
    "sessions": """
<p>Session table figures from <code>show session info</code>, sampled once per cycle:
allocated sessions against the supported maximum, active sessions by protocol, packet rate,
throughput and connection rate.</p>""",
    "ss_table": """
<p>Allocated sessions and the supported maximum, with the utilization in percent. Warning and
critical levels are <code>session_util_warn</code> and <code>session_util_crit</code>.</p>""",
    "ss_active": """
<p>Active TCP, UDP and ICMP sessions over time. Allocated sessions can be higher than the
active ones because closing sessions are still counted until they age out.</p>""",
    "ss_rates": """
<p>Connections per second (cps), packets per second (pps) and throughput (kbps) as reported
by the firewall at each sample. They are instantaneous values of that moment, not averages
over the cycle.</p>""",
    "resources": """
<p>Dataplane and management resources: CPU per core and per group from <code>show
running resource-monitor</code> and the management plane load from <code>show system
resources</code>, sampled once per cycle.</p>
<ul>
<li>Resource monitor values are 60 second figures kept by the firewall, so one sample
summarises the previous minute.</li>
<li>If the firewall does not support the command, the data plane panels say so.</li>
</ul>""",
    "throughput": """
<p>Traffic through the firewall, computed from the byte counters of <code>show counter
interface all</code>, read at the start of every fast tick (default: every interval/6
seconds, see the Overview tab for the interval actually obtained). A rate is the difference
of two readings divided by the time between them, measured on the local clock at the middle
of each command, so it is an average over that interval.</p>
<ul>
<li>A counter that goes backwards (interface reset or flap) gives a gap, never a negative rate.</li>
<li>If the firewall does not have the command, or the capture was made with
<code>--no-iface-counters</code>, the tab says so.</li>
<li>Counters are not dropped when the tick overruns: a skipped tick only makes the interval
longer; the rate stays correct.</li>
</ul>""",
    "tp_total": """
<p>Sum over the <b>physical ports</b> only (so sub-interfaces, aggregates and tunnels are not
counted twice): received, transmitted and their sum, in Mbit/s. The dashed grey line is
received + transmitted. The red dots are the throughput that the firewall prints in <code>show
session info</code> once per cycle, drawn on the nearest interval as a cross-check; the two
come from different counters (physical port bytes against the data plane's own figure), so
they can differ by the traffic that does not become a session (for example dropped or
management traffic) and by the averaging window.</p>""",
    "tp_ifaces": """
<p>One chart per configured interface, received and transmitted in Mbit/s, busiest first.
For an interface with logical counters (every configured interface, including sub-interfaces,
aggregates and tunnels) those are used; a physical port without configuration is listed only
if it carried traffic during the capture. Use the filter and the sort selector; the checkbox
hides interfaces without any traffic. At most 60 charts are drawn. Logical counters can differ
a little from the physical port counters of the total (they count what the data plane
processed).</p>""",
    "res_heat": """
<p>One row per data plane core and one cell per second, rebuilt from the per-second table
of <code>show running resource-monitor</code>. Each sample holds the last 60 seconds, so
consecutive samples overlap when the interval is shorter than 60 s: the report chains them
by finding the shift at which the overlapping rows match (the local clock is only used as a
starting point) and keeps one value per second. Seconds not covered by any sample stay grey
("no data"), they are never drawn as 0.</p>
<ul>
<li>The colour goes from white (0%) to red (100%); a cell with a dark outline is at or above
<code>cpu_core_warn</code>. When the picture is wider than the screen each pixel column shows
the maximum of the seconds in it.</li>
<li>The <b>peak</b> column is the highest value of each core in the capture.</li>
<li>A core the firewall prints as <code>*</code> (usually core 0) is not drawn.</li>
<li>Row order of the firewall output is newest first (checked on overlapping samples); the
exact second of a row can be off by a second or two.</li>
<li>For captures longer than a few hours each cell is the maximum of several seconds.</li>
</ul>""",
    "res_cpu": """
<p>Per cycle: the busiest core (maximum over the last 60 seconds) and the highest of the core
averages. Thresholds: <code>cpu_core_warn</code> and <code>cpu_core_crit</code>.</p>""",
    "res_groups": """
<p>Left: the busiest group per cycle. Right: CPU percent of every group in the last sample.
Groups are the processing stages of the data plane; a stage near 100% is the likely
bottleneck. Threshold: <code>cpu_group_warn</code>.</p>""",
    "res_util": """
<p>Maximum over the last 60 seconds of the resource pools (session, packet buffer, packet
descriptor, software tags) for the last sample. A pool near 100% runs out of entries.</p>""",
    "res_mgmt": """
<p>Management plane load averages (1, 5 and 15 minutes) per cycle. A value above the number of
management CPU cores means the management plane is saturated; this is separate from the
data plane.</p>""",
    "capture": """
<p>How the capture itself behaved: how long each cycle took and how long every command
took. A slow cycle or a gap between cycles means the samples are less regular than the
interval suggests.</p>""",
    "cap_cycles": """
<p>Total command time per slow cycle in seconds. The warning level is
<code>cycle_slow_share</code> of the interval; a cycle above it can delay the next one.</p>""",
    "cap_commands": """
<p>One row per command: number of samples, failures (no prompt seen), average and maximum
duration in seconds. A slow command on a loaded firewall is itself a sign of load.</p>""",
}

def _f(title: str, meaning: str, check: str) -> tuple[str, str, str]:
    return (title, meaning, check)


FLAG_HELP = {
    "BACKLOG_HIGH": _f(
        "Ingress backlog high",
        "The atomic or total ingress backlog of a data plane reached the warning level in at "
        "least one sample. A full backlog delays packets before they reach the flow stage.",
        "Open the Ingress backlogs tab: look at the time, whether it is atomic or total, and "
        "whether an offender or special tag is listed at the same time."),
    "BACKLOG_OFFENDER": _f(
        "Session dominates the backlog",
        "A real session held a large share of the ingress backlog and was captured with "
        "'show session id'. One heavy flow can starve others on the same worker.",
        "Read the session detail (source, destination, application, rule); check whether it "
        "is a legitimate bulk flow or an attack, and consider a DoS or QoS rule."),
    "BACKLOG_SPECIAL_TAG": _f(
        "Special tag in the backlog",
        "A special tag (a workgroup, not a session) appeared in the backlog list. It is "
        "shown for information: it has no session id.",
        "Do not run 'show session id' on it. Compare with the POW tab and the TAC notes for "
        "the tag name."),
    "CMD_FAILED": _f(
        "Command output incomplete",
        "Some samples of a command ended without the CLI prompt (timeout or dropped "
        "connection), so their output may be partial.",
        "Check the Capture log tab for the command and the durations; rerun with a longer "
        "interval if the firewall is slow."),
    "CMD_NOT_AVAILABLE": _f(
        "Command not available",
        "The firewall answered 'Invalid syntax' for ingress-backlogs, packet-buffer-protection "
        "or resource-monitor. The platform or software version does not provide it.",
        "Nothing to fix; the related tab has no data. Check the software version in the "
        "Overview tab."),
    "COUNTER_DROP_RATE": _f(
        "Drop counter rate",
        "A global counter with severity 'drop' reached the warning or critical rate "
        "(drop_rate_warn, drop_rate_crit, per second).",
        "Open the Counters tab, read the description and the rate chart, and compare with "
        "traffic. Some drop counters are normal on a busy network."),
    "CPS_SPIKE": _f(
        "Connection rate spike",
        "The peak connection rate is at least cps_spike_ratio times the median and above "
        "cps_spike_min. Thresholds: cps_spike_ratio, cps_spike_min.",
        "Open the Sessions tab and match the time with the counters and CPU. A scan or "
        "a misbehaving client often looks like this."),
    "CPU_CORE_HIGH": _f(
        "Data plane core busy",
        "The highest data plane core average reached cpu_core_warn or cpu_core_crit "
        "(percent).",
        "Open the Resources tab and see which group is busy. Compare with the POW tab."),
    "CPU_GROUP_HIGH": _f(
        "Data plane group busy",
        "A processing group used at least cpu_group_warn percent in the 60 second window.",
        "Open the Resources tab; the group name tells which stage is the bottleneck."),
    "CYCLE_SLOW": _f(
        "Slow capture cycle",
        "A cycle took more than cycle_slow_share of the interval, so the next cycle may "
        "start late. Threshold: cycle_slow_share.",
        "Open the Capture log tab and find the slow command. Use a longer interval."),
    "DELTA_FOREIGN_SAMPLER": _f(
        "Another client reset the delta counters",
        "The firewall keeps one global delta baseline. A sample whose elapsed time is shorter "
        "than expected means another client read the counters in between; that sample is "
        "left out of the counter charts and statistics.",
        "Stop other tools or admins that run 'show counter global filter delta yes' during "
        "the capture. The affected samples are excluded from the charts and statistics; "
        "many of them leave gaps in the counter history."),
    "INFLIGHT_LEFT_ON": _f(
        "Inflight monitoring may still be ON",
        "The capture switches inflight monitoring on and must switch it off; it could not "
        "confirm that. A red box also appears in the Overview tab.",
        "Check the state on the firewall and switch it off by hand. Leaving it on has a "
        "performance cost."),
    "PBP_ACTIVE": _f(
        "Packet buffer protection active",
        "Packet buffer protection was active in at least one sample: the firewall considered "
        "the buffer under pressure and acted on offenders.",
        "Open the Packet buffer tab and read the table of tracked addresses and the time "
        "of the first sample."),
    "PBP_CONGESTION": _f(
        "Packet buffer congestion",
        "Buffer usage reached pbp_congestion_warn percent. Threshold: pbp_congestion_warn.",
        "Open the Packet buffer tab; check latency and the backlog at the same time."),
    "PBP_LATENCY_HIGH": _f(
        "Packet buffer latency high",
        "The maximum buffer latency reached pbp_latency_warn_ms or pbp_latency_crit_ms "
        "(milliseconds).",
        "Open the Packet buffer tab and match the time with congestion and CPU."),
    "POW_FINDING": _f(
        "POW evaluation item",
        "An item of the POW evaluation (the same rules as the tech support file report) on "
        "the last sample. Critical items are shown as warning, warnings as info.",
        "Open the POW tab, read the item and the top functions. Treat it as a hint."),
    "SAMPLE_GAP": _f(
        "Gaps in sampling",
        "Cycles were further apart than gap_ratio times the interval, or sampling ticks "
        "were skipped because earlier work took too long. Threshold: gap_ratio.",
        "Check the Capture log tab and the network path to the firewall."),
    "SESSION_UTIL": _f(
        "Session table utilization",
        "Session table utilization reached session_util_warn or session_util_crit "
        "(percent of supported sessions).",
        "Open the Sessions tab; check the timeout settings, the growth rate and "
        "the top talkers."),
}

FLAG_KEYS = {
    "BACKLOG_HIGH": ["backlog_total_warn", "backlog_atomic_warn"],
    "BACKLOG_OFFENDER": [],
    "BACKLOG_SPECIAL_TAG": [],
    "CMD_FAILED": [],
    "CMD_NOT_AVAILABLE": [],
    "COUNTER_DROP_RATE": ["drop_rate_warn", "drop_rate_crit"],
    "CPS_SPIKE": ["cps_spike_ratio", "cps_spike_min"],
    "CPU_CORE_HIGH": ["cpu_core_warn", "cpu_core_crit"],
    "CPU_GROUP_HIGH": ["cpu_group_warn"],
    "CYCLE_SLOW": ["cycle_slow_share"],
    "DELTA_FOREIGN_SAMPLER": [],
    "INFLIGHT_LEFT_ON": [],
    "PBP_ACTIVE": [],
    "PBP_CONGESTION": ["pbp_congestion_warn"],
    "PBP_LATENCY_HIGH": ["pbp_latency_warn_ms", "pbp_latency_crit_ms"],
    "POW_FINDING": ["top_pow_funcs"],
    "SAMPLE_GAP": ["gap_ratio"],
    "SESSION_UTIL": ["session_util_warn", "session_util_crit"],
}


def flag_help_data() -> dict:
    """``code -> [title, meaning, check next, [threshold keys]]`` for the page script."""
    return {c: [*v, list(FLAG_KEYS.get(c, []))] for c, v in FLAG_HELP.items()}


def render_section_help() -> dict[str, str]:
    """Return ``{placeholder: html}`` for every section (buttons and collapsible texts)."""
    out: dict[str, str] = {}
    for sid, text in SECTION_HELP.items():
        title = html.escape(SECTION_TITLES[sid], quote=True)
        out[f"__HB_{sid}__"] = (
            f'<button type="button" class="helpbtn" aria-expanded="false" '
            f'aria-controls="help-{sid}" aria-label="Help: {title}">? Help</button>')
        out[f"__HP_{sid}__"] = f'<div class="help" id="help-{sid}" hidden>{text}</div>'
    return out


def render_help() -> str:
    """All help texts in one string (used by tests)."""
    return "\n".join(render_section_help().values())

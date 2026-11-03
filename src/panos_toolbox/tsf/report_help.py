"""Help tab of the TSF report: how to read the tabs and what each POW flag means.

HELP_HTML is a template. Its {name} placeholders are filled with the live values of
pow_perf.POW_THRESHOLDS by render_help(). Literal braces in the HTML are doubled.

Standard library only.
"""
import html

from .pow_perf import POW_THRESHOLDS

HELP_HTML = """
<h2>1. Overview</h2>
<p>This report is built offline from a Palo Alto Networks Tech Support File (TSF). Each data
source has its own tab. The Help tab is always present. A data tab appears only when its
data is in the file.</p>
<ul>
<li><b>Dataplane Throughput</b> and <b>CPU load by group</b> read the
<code>var/log/pan/dp-monitor.*</code> files.</li>
<li><b>POW performance</b> reads the <code>tmp/cli/*.txt</code> files that contain
<code>debug dataplane pow performance</code> output.</li>
</ul>
<p><b>Time zone.</b> All dp-monitor timestamps are converted to UTC. The original firewall
offsets are listed in the note above the tabs. The POW "Collected at" line is the raw
<code>show clock</code> string from the firewall and is not converted.</p>

<h2>2. Dataplane Throughput</h2>
<h3>Chart</h3>
<ul>
<li><b>Metric</b> selects Throughput (kbps, shown as Mbps or Gbps when large), Packet rate
(pkt/s), New connections (cps), Allocated sessions or Session table utilization (%). Only the
metrics present in the file are listed.</li>
<li><b>Series</b>: one per DP. With two or more DPs an <b>ALL</b> series is added. It is the sum
across DPs, except for session table utilization, where ALL is the maximum across DPs.</li>
<li>The legend checkboxes show or hide a series. Hovering the chart shows the nearest sample.</li>
<li><b>Zoom</b>: drag horizontally across the chart to select a range. Short drags are ignored.
<b>Reset zoom</b> returns to the full period. The selected range also applies to the stats table
and the data table.</li>
</ul>
<h3>Stats table</h3>
<p>For each visible series: samples, min, avg, max and the UTC time of the maximum.</p>
<h3>Data table</h3>
<ul>
<li>Filters: <b>DP</b>, <b>From</b> and <b>To</b> (UTC, minute precision; they follow the zoom)
and <b>Search</b>, which matches the time, DP, source file and throughput in kbps.</li>
<li><b>CPU by group columns</b> adds one column per workgroup. The checkbox appears only when the
file has CPU data.</li>
<li>Click a column header to sort, and click again to reverse. Enter or Space works on a focused
header.</li>
<li>The table shows the first 500 matching rows. <b>Show all</b> displays the rest.</li>
<li><b>Export CSV</b> downloads the rows that match the filters, as UTF-8 with a byte order mark.
The CPU by group columns are always included when the file has them.</li>
</ul>

<h2>3. CPU load by group</h2>
<p>The dp-monitor file has a block titled <i>CPU load sampling by group</i>, which gives the CPU
percentage of each dataplane workgroup for each sample. This tab charts those values per DP.</p>
<ul>
<li><b>DP</b> selects the dataplane. Only DPs with group CPU data are listed.</li>
<li>The series are the workgroups. Use the legend checkboxes, or <b>All</b> (show every workgroup)
and <b>None</b> (hide every workgroup), to change them.</li>
<li>The vertical axis runs from 0 to 100 percent. Zoom, <b>Reset zoom</b> and the stats table work
as in the throughput chart.</li>
</ul>

<h2>4. POW performance</h2>
<h3>What POW/SSO is</h3>
<p>POW/SSO is the dataplane's scheduler and ordering unit: it queues work items and hands them to
the cores. Its counters are reported in two groups:</p>
<ul>
<li><b>Work groups</b> (<code>group</code> rows) are the stage a packet or work item is in, for
example <code>flow_fastpath</code> or <code>flow_slowpath</code>. A short description appears as
a tooltip on the name.</li>
<li><b>Functions</b> (<code>func</code> rows) are the code that runs for a work item, for example
<code>dfa_match</code> or <code>ssl_proxy_proc</code>.</li>
</ul>
<h3>Command and counters</h3>
<p>The firewall prints the tables with <code>debug dataplane pow performance all</code>, and the
per-core tables with <code>debug dataplane pow performance all core A-B</code>. Histograms of the
processing time per call are printed too.</p>
<p>The counters are cumulative since the last reset. dp-monitor resets them every 10 minutes, and
<code>debug dataplane reset pow</code> resets them manually. The plain columns therefore cover the
current window. The <code>ac-*</code> columns (PAN-OS 9.1 and later) accumulate since the dataplane
restarted or the firewall rebooted.</p>
<details open><summary>Column glossary</summary>
<table>
<tr><th>Column</th><th>Meaning</th></tr>
<tr><td>max-us</td><td>Longest single call in the window, in microseconds.</td></tr>
<tr><td>avg-us</td><td>Average time per call in the window.</td></tr>
<tr><td>count</td><td>Number of calls in the window.</td></tr>
<tr><td>total-us</td><td>CPU time in the window, computed as avg-us multiplied by count. The tool
computes it the same way when the firewall does not print it.</td></tr>
<tr><td>share %</td><td>total-us as a percentage of the total-us of the table. Latency counters are
left out and shown as 0.</td></tr>
<tr><td>ac-max-us, ac-avg-us, ac-count, ac-total-us</td><td>The same values accumulated since the
dataplane restart or reboot. Present in 9.1 and later; absent from legacy output.</td></tr>
<tr><td>count / ac-count</td><td>Share of the accumulated calls that fall in the current window. A
high value means the row is busy now compared with its history since boot.</td></tr>
<tr><td>Flags</td><td>Badges from the heuristics in section 5. Hover over a badge for its
detail.</td></tr>
</table>
</details>
<h3>Categories</h3>
<p>Each function is placed in one category based on its name. Category shares use the function
total-us, or the accumulated total-us when the current window is empty. A category other than
<i>other</i> that holds at least {category_dominance}% is listed in the banner.</p>
<details><summary>Category rules</summary>
<table>
<tr><th>Category</th><th>Examples</th><th>Notes</th></tr>
<tr><td>L7</td><td>dfa_match, appid_match, detector_run_p1, ctd_token</td><td>Content and application
inspection: App-ID, Content-ID and threat profiles.</td></tr>
<tr><td>DECRYPT</td><td>ssl_proxy_proc, ecdhe_key_compute, rsa_operation_priv_dec</td><td>SSL/TLS
decryption and public-key operations. Any name starting with rsa_, ecdhe_, ecdsa_ or dhe_ is
included.</td></tr>
<tr><td>TUNNEL</td><td>tunnel_encap, tunnel_esp, vpn_send_to_client</td><td>Tunnel and VPN
processing.</td></tr>
<tr><td>URL</td><td>urlcache_lookup, urlcache_insert</td><td>URL cache operations.</td></tr>
<tr><td>other</td><td>any name not listed above</td><td>Default category.</td></tr>
<tr><td>latency</td><td>pbp_buf_latency</td><td>Names ending in _latency that are not in the
DECRYPT list (rsa_verify_hw_latency is DECRYPT). They measure waits, not CPU time: they stay
visible but are left out of totals, shares and the top-N ranking.</td></tr>
<tr><td>workgroup</td><td>rows of the Workgroups table</td><td>Not a function category.</td></tr>
</table>
</details>
<h3>Views, filters and export</h3>
<ul>
<li><b>View</b> selects Global (all cores combined) or one <b>Core N</b>, when the file has per-core
output. Each view has its own categories and histograms.</li>
<li><b>Search</b> matches the name or the category.</li>
<li><b>only anomalous rows</b> keeps rows with a warning or a critical flag. Info flags do not
colour rows.</li>
<li><b>hide rows without calls</b> (on by default) hides rows with no calls in either window and
no flags.</li>
<li>Click a column header to sort. Red rows are critical and yellow rows are warnings.</li>
<li><b>Export CSV</b> downloads the workgroup and function rows of the selected view that pass the
current filters.</li>
<li><b>Workgroup total-us per core</b> is a heat map: a darker cell means more CPU time. The Total
row sums each core.</li>
</ul>
<h3>Histograms</h3>
<p>Each histogram shows the processing time per call of one function or workgroup, in bins. The
summary line gives the number of calls, p50 and p99 (approximate: the average time of the bin in
which the cumulative count reaches 50% or 99%), and the largest average among the non-empty bins.
The columns are col (bin), avg-ticks, avg-us, count and total-us. Histograms with the most severe
flags are listed first.</p>

<h2>5. Flag reference</h2>
<p>The heuristics in <code>pow_perf.py</code> attach these flags to rows and histograms. The last
column shows the live thresholds used to build this report.</p>
<table>
<tr><th>Code</th><th>Level</th><th>Applies to</th><th>Meaning</th><th>Live thresholds</th></tr>
<tr><td><code>TOP_CPU</code></td><td>warn; crit at the crit share</td><td>workgroups,
functions</td><td>One of the top rows by total-us holds at least the warn share of the table CPU
time.</td><td>top_n = {top_n}; share_warn = {share_warn}%; share_crit = {share_crit}%</td></tr>
<tr><td><code>TOP_CPU_ACC</code></td><td>info</td><td>workgroups, functions</td><td>Same test on
ac-total-us since boot (9.1 and later).</td><td>top_n = {top_n}; share_warn = {share_warn}%</td></tr>
<tr><td><code>MAX_SPIKE</code></td><td>warn; crit at the crit max-us</td><td>workgroups,
functions</td><td>A single call took at least max_spike_abs_us, and max-us is at least
max_spike_ratio times avg-us, over at least min_count calls.</td><td>max_spike_abs_us = {max_spike_abs_us};
max_spike_ratio = {max_spike_ratio}; max_spike_crit_us = {max_spike_crit_us}; min_count =
{min_count}</td></tr>
<tr><td><code>MAX_SPIKE_ACC</code></td><td>info</td><td>workgroups, functions</td><td>Same test on
the ac-* counters since boot (9.1 and later).</td><td>same as MAX_SPIKE</td></tr>
<tr><td><code>AVG_DRIFT</code></td><td>warn; crit at the crit ratio</td><td>workgroups,
functions</td><td>The average time per call in this window is at least drift_ratio times the
since-boot average, with enough calls in both windows. Averages below drift_min_avg_us are
ignored. Needs 9.1 or later.</td><td>drift_ratio = {drift_ratio}; drift_crit_ratio = {drift_crit_ratio};
drift_min_avg_us = {drift_min_avg_us}; min_count = {min_count}</td></tr>
<tr><td><code>HIGH_AVG</code></td><td>warn</td><td>workgroups, functions</td><td>Average time per
call is at least the limit, over at least min_count calls. DECRYPT functions have their own
limit.</td><td>high_avg_us = {high_avg_us}; high_avg_us_decrypt = {high_avg_us_decrypt};
min_count = {min_count}</td></tr>
<tr><td><code>HISTORICAL_ONLY</code></td><td>info</td><td>functions</td><td>No calls in this window,
but ac-max-us since boot is at least max_spike_abs_us (9.1 and later).</td><td>max_spike_abs_us =
{max_spike_abs_us}</td></tr>
<tr><td><code>TAIL</code></td><td>warn; crit at hist_tail_crit_us</td><td>histograms</td><td>A bin
with avg-us at least hist_tail_us holds less than hist_tail_share percent of the calls.</td>
<td>hist_tail_us = {hist_tail_us}; hist_tail_crit_us = {hist_tail_crit_us}; hist_tail_share =
{hist_tail_share}%</td></tr>
<tr><td><code>CORE_IMBALANCE</code></td><td>warn; crit at {core_imbalance_crit}x</td><td>per-core
banner, not a row</td><td>A core's workgroup total-us is at least core_imbalance_ratio times the
median of the active cores. Needs at least min_active_cores active cores.</td><td>core_imbalance_ratio
= {core_imbalance_ratio}; min_active_cores = {min_active_cores}</td></tr>
</table>
<p>The banner above the POW tables summarises the flags. It lists dominant categories, the number
of critical and warning rows, histograms with a TAIL flag, core imbalance and idle cores.</p>
<p class="hint">The thresholds are heuristics defined in <code>pow_perf.POW_THRESHOLDS</code>. In
code, override them with <code>evaluate(parsed, thresholds={{'share_warn': 15.0}})</code>. Unknown
keys raise an error. The command-line tool uses the defaults shown here.</p>

<h2>6. How to read the output</h2>
<p>This follows the approach of the Palo Alto Networks KB article "How to interpret output of
debug dataplane pow performance during troubleshooting high DP CPU".</p>
<ol>
<li><b>Rank by total-us.</b> A function that is both slow per call and frequent uses the most
CPU time. Start with the top rows by total-us, which is count multiplied by avg-us.</li>
<li><b>Compare two captures.</b> Take the same command from a TSF recorded at normal CPU and one
recorded at high CPU, and compare the same rows.</li>
<li><b>Read what changed.</b> A higher avg-us for the same function points to a change in the
traffic pattern or in the work done per call. A higher count points to more traffic reaching that
function.</li>
<li><b>Follow the category.</b> If L7 functions dominate, the traffic is subject to L7
processing: App-ID, Content-ID and threat profiles. Review which policies and profiles apply to
that traffic.</li>
<li><b>DECRYPT dominance</b> means SSL decryption load. The article's case study involves
ssl_proxy_proc and the ecdhe_* and rsa_* functions. Review the decryption policy scope and its
exclusions.</li>
<li><b>TUNNEL</b> points to IPsec or GRE tunnel load. <b>URL</b> points to URL cache
lookups.</li>
</ol>

<h2>7. Limitations</h2>
<ul>
<li>Flags are heuristics that point to what to investigate. They are not verdicts, and a flag
does not prove a cause.</li>
<li>Each file is one snapshot. The current-window counters cover only the time since the last
reset.</li>
<li>Histograms show the distribution of per-call processing time in buckets. They are not totals
over time.</li>
<li>Per-core output covers only the cores listed in the TSF.</li>
<li>A section that the firewall reports as <code>Server error</code> is skipped and listed as a
warning.</li>
</ul>
"""


def render_help(thresholds=None):
    """Returns the Help tab HTML with the live thresholds filled in.

    thresholds: optional overrides with the keys of pow_perf.POW_THRESHOLDS. Unknown keys
    raise ValueError, as in evaluate(). The values are escaped before insertion.
    """
    th = dict(POW_THRESHOLDS)
    unknown = set(thresholds or {}) - set(POW_THRESHOLDS)
    if unknown:
        raise ValueError('unknown POW threshold(s): ' + ', '.join(sorted(unknown)))
    th.update(thresholds or {})
    values = {k: html.escape(str(v)) for k, v in th.items()}
    values['core_imbalance_crit'] = html.escape(str(2 * th['core_imbalance_ratio']))
    return HELP_HTML.format_map(values)

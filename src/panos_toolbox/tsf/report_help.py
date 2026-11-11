"""Per-section help of the TSF report.

Every tab and panel of the report has its own short, collapsed help (a "? Help" button
that expands a text at the top of that section). There is no global help page.

SECTION_HELP maps a section id to an HTML template. Its {name} placeholders are filled
with the live values of pow_perf.POW_THRESHOLDS by render_section_help(). The thresholds of
the Interface Errors tab (interface_errors.IF_THRESHOLDS) are available as {if_<name>} and those of the
Dataplane health tab (dp_health.DP_THRESHOLDS) as {dp_<name>}, those of the Management plane
tab (mp_monitor.MP_THRESHOLDS) as {mp_<name>}. Literal braces
in the HTML are doubled. The report template contains the placeholders __HB_<id>__
(the button) and __HP_<id>__ (the collapsible text) for each id.

Standard library only.
"""
import html

from . import if_glossary
from .dp_health import DP_THRESHOLDS
from .interface_errors import IF_THRESHOLDS
from .mp_monitor import MP_IGNORE_PROCS, MP_THRESHOLDS, MP_WORKER_PREFIXES
from .pow_perf import POW_THRESHOLDS

# Titles are used for the accessible name of the buttons.
SECTION_TITLES = {
    'chart': 'Dataplane throughput', 'table': 'Samples table', 'cpu': 'CPU load by group',
    'pow': 'POW performance', 'pflags': 'Findings and flag reference', 'ptop': 'Top functions',
    'pgroups': 'Workgroups', 'pfuncs': 'Functions', 'pcat': 'Function CPU share by category',
    'phist': 'Histograms', 'pmx': 'Workgroup total-us per core', 'plat': 'Latency counters',
    'ifc': 'Interface errors', 'iflags': 'Interface findings and flag reference',
    'itable': 'Interfaces table', 'ixchk': 'Cross-check with the global counters',
    'coverage': 'Source coverage',
    'dph': 'Dataplane health', 'dphflags': 'Dataplane health findings and flag reference',
    'dphchart': 'Dataplane health chart', 'dphcores': 'CPU peak per core',
    'mp': 'Management plane', 'mpflags': 'Management plane findings and flag reference',
    'mpchart': 'Management plane memory chart', 'mpprocs': 'Management plane processes',
}

SECTION_HELP = {
    'chart': """
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
<p><b>Stats table</b> (under the chart): For each visible series: samples, min, avg, max and the UTC time of the maximum.</p>
<p><b>Display.</b> The report is designed for Full HD (1920x1080) or larger screens. The charts and
tables use the available width and height, and on screens of 2560 px wide or more the POW
tables sit side by side. Below 1900 px wide the page scrolls horizontally.</p>
<p><b>Time zone.</b> All dp-monitor timestamps are converted to UTC. The original firewall
offsets are listed in the note above the tabs. The POW "Collected at" line is the raw
<code>show clock</code> string from the firewall and is not converted.</p>
""",
    'table': """
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
""",
    'cpu': """
<p>The dp-monitor file has a block titled <i>CPU load sampling by group</i>, which gives the CPU
percentage of each dataplane workgroup for each sample. This tab charts those values per DP.</p>
<ul>
<li><b>DP</b> selects the dataplane. Only DPs with group CPU data are listed.</li>
<li>The series are the workgroups. Use the legend checkboxes, or <b>All</b> (show every workgroup)
and <b>None</b> (hide every workgroup), to change them.</li>
<li>The vertical axis runs from 0 to 100 percent. Zoom, <b>Reset zoom</b> and the stats table work
as in the throughput chart.</li>
</ul>
<p>Hover or focus a group name in the legend for its description when it is a known dataplane group.</p>
""",
    'pow': """
<p>Built from the <code>tmp/cli/*.txt</code> files of the TSF that contain <code>debug dataplane pow performance</code> output (recognised by content), or from a plain text file with that output.</p>
<h3>What POW/SSO is</h3>
<p>POW/SSO is the dataplane's scheduler and ordering unit: it queues work items and hands them to
the cores. Its counters are reported in two groups:</p>
<ul>
<li><b>Work groups</b> (<code>group</code> rows) are the stage a packet or work item is in, for
example <code>flow_fastpath</code> or <code>flow_slowpath</code>. Hover or focus the
name for a short description.</li>
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
<h3>Counter glossary and confidence</h3>
<p>Hover or focus any counter or workgroup name, or a column header, for its category and meaning. Each entry carries a confidence code: <b>D</b> documented by Palo Alto, <b>G</b> category documented and meaning inferred from the name, <b>I</b> inferred from the name only, <b>U</b> unknown. The glossary is partly inferred: treat G, I and U entries as hypotheses. Names with U, or not in the glossary at all (shown as <i>Unclassified</i>), are marked in red as "no known meaning" and an active one raises an <code>UNKNOWN</code> flag.</p>
<h3>Limitations</h3>
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
<p>Several dataplanes in one output: only the first one is analysed (a warning lists the rest). Output without the command line (a plain pasted file) is accepted.</p>
""",
    'pflags': """
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
<tr><td><code>UNKNOWN</code></td><td>warn when active in the window, else info</td><td>workgroups,
functions</td><td>The counter has no known meaning (confidence U, or not in the glossary) and is
non-zero. Please report it.</td><td>none</td></tr>
<tr><td><code>LATENCY_HIGH</code></td><td>info</td><td>latency counters</td><td>A latency counter
(not CPU time) has a window average of at least latency_high_us over at least min_count events.</td>
<td>latency_high_us = {latency_high_us}; min_count = {min_count}</td></tr>
<tr><td><code>HIST_SLOW</code></td><td>warn</td><td>function histograms</td><td>Bins with avg-us at
least hist_slow_us hold at least hist_slow_share percent of the histogram time, over at least
hist_slow_min_count calls.</td><td>hist_slow_us = {hist_slow_us}; hist_slow_share =
{hist_slow_share}%; hist_slow_min_count = {hist_slow_min_count}</td></tr>
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
of critical and warning rows, histograms with a TAIL or HIST_SLOW flag, DECRYPT share above
decrypt_share_warn ({decrypt_share_warn}%), counters with no known meaning, core imbalance and idle cores.</p>
<p class="hint">The thresholds are heuristics defined in <code>pow_perf.POW_THRESHOLDS</code>. In
code, override them with <code>evaluate(parsed, thresholds={{'share_warn': 15.0}})</code>. Unknown
keys raise an error. On the command line use the <code>--pow-&lt;name&gt;</code> options
(for example <code>--pow-share-warn 15</code>; see <code>panos-toolbox tsf analyze --help</code>). The values
shown here are the ones used for this report.</p>
<h3>How to read the output</h3>
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
""",
    'ptop': """
<p>The charts rank the functions by <b>total-us</b> (current window, left) and by <b>ac-total-us</b> (accumulated, right; 9.1 and later). A function high in both is a steady cost; high only in the window is a recent change. Bar labels show the time and the share of the CPU-time total. Latency counters are excluded. The number of bars follows the Top selector. Hover or focus a name on the bars for its meaning.</p>
""",
    'pgroups': """
<p>The <b>work groups</b> (<code>group</code> rows) are the stage a packet or work item is in, for
example <code>flow_fastpath</code> or <code>flow_slowpath</code>. Hover or focus the
name for a short description.</p>
<p>Groups are broader than functions: compare them with each other, not with the function ranking. The share column is the part of the sum of all groups (latency counters are not groups).</p>
""",
    'pfuncs': """
<ul>
<li><b>View</b> selects Global (all cores combined) or one <b>Core N</b>, when the file has per-core
output. Each view has its own categories and histograms.</li>
<li><b>Search</b> matches the name or the category.</li>
<li><b>only anomalous rows</b> keeps rows with a warning or a critical flag. Info flags do not
colour rows.</li>
<li><b>hide rows without calls</b> (on by default) hides rows with no calls in either window and
no flags, and collapses all-zero glossary families in the category roll-up. Untick it to show them.</li>
<li>Click a column header to sort. Red rows are critical and yellow rows are warnings.</li>
<li><b>Export CSV</b> downloads the workgroup and function rows of the selected view that pass the
current filters.</li>

</ul>
<p>Hover or focus a function name for its meaning, category and confidence. Names marked in red have no known meaning.</p>
""",
    'pcat': """
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
<tr><td>latency</td><td>pbp_buf_latency, rsa_sign_hw_latency</td><td>Names ending in _latency, and
the glossary family "Latency measures". They measure waits, not CPU time: they are left out of
totals, shares, the top-N ranking and the category roll-ups, and are listed in their own panel.</td></tr>
<tr><td>workgroup</td><td>rows of the Workgroups table</td><td>Not a function category.</td></tr>
</table>
</details>
<h3>Glossary families</h3>
<p>The second table sums the functions by the finer glossary family (decryption, Layer-7 sub-families, session lifecycle, module-internal...). Names missing from the glossary go to <i>Unclassified</i> (or to a family guessed from their prefix), so nothing is dropped. Latency counters and workgroups are left out. Families whose counters are all zero are collapsed until "hide rows without calls" is unticked. The family assignment is partly inferred.</p>
""",
    'phist': """
<p>Each histogram shows the processing time per call of one function or workgroup, in bins. The
summary line gives the number of calls, p50 and p99 (approximate: the average time of the bin in
which the cumulative count reaches 50% or 99%), and the largest average among the non-empty bins.
The columns are col (bin), avg-ticks, avg-us, count and total-us. Histograms with the most severe
flags are listed first.</p>
<p>Open a histogram to see a bar chart of its bins (calls or time per bin, selectable) above the table. Besides TAIL, the <code>HIST_SLOW</code> flag marks functions that spend a large share of their time in slow bins.</p>
""",
    'pmx': """
<p><b>Workgroup total-us per core</b> is a heat map: a darker cell means more CPU time. The Total
row sums each core.</p>
""",
    'plat': """
<p>Counters named <code>*_latency</code> (and the glossary family "Latency measures") measure elapsed time between two events, not CPU time spent. Their totals are huge and would hide real work, so they are left out of the rankings, shares and category roll-ups and listed only here. The <code>LATENCY_HIGH</code> flag marks a window average above the threshold.</p>
""",
    'ifc': """
<p>Built from the interface counters in the CLI output of the TSF (<code>tmp/cli/*.txt</code>, recognised by content), or from a plain text file with that output. Commands used (all optional; a missing one is skipped with a warning):</p>
<ul>
<li><code>show counter interface all</code>: per interface the physical port counters read from the MAC, the hardware counters read from the CPU, and the logical interface counters (flow drops).</li>
<li><code>show interface ethernetX/Y</code>: link state, speed and duplex, zone, address and the detailed physical counters (CRC, fifo overrun, collisions...). Present for some ports only.</li>
<li><code>show interface all</code>: link table of the hardware interfaces and table of the logical interfaces (zone, virtual router, tag, address).</li>
<li><code>show system info</code> and <code>show clock</code>: host, model, PAN-OS version, uptime and capture time.</li>
<li><code>show counter global</code>: global drop counters for the cross-check. <code>show transceiver all</code> and <code>show lacp aggregate-ethernet all</code> are shown when they hold data.</li>
</ul>
<h3>Counters are cumulative since boot</h3>
<p>Every counter counts from the last boot. The <b>uptime</b> in the summary tells how much time the numbers cover. With a short uptime (below short_uptime_s = {if_short_uptime_s} s) the report raises <code>UPTIME_SHORT</code> and the counts are low-significance: drops right after a boot are often transient (routes and ARP not yet learned, sessions lost). Capture again after the firewall has been up for a while, or take two captures and compare them.</p>
<h3>Three layers of counters</h3>
<ul>
<li><b>Physical (MAC)</b>: what the Ethernet port itself saw. Any CRC, fifo overrun, collision, jabber, undersized or oversized count points to the cable, SFP, port or duplex.</li>
<li><b>CPU / hardware</b>: what the dataplane driver counted for the port. Errors here with a clean MAC mean packets were lost inside the firewall.</li>
<li><b>Logical / flow</b>: drops decided by the flow engine for the interface or sub-interface: no route, ARP not found, flow state check, zone protection, zone change...</li>
</ul>
<p>Hover or focus a counter name or a column header for a tooltip with its category, confidence code and meaning (codes: <b>D</b> documented, <b>G</b> well-known behaviour with our own wording, <b>I</b> inferred from the name only, <b>U</b> unknown). The tables below carry the same meanings. Treat G and I entries as hypotheses.</p>
{if_counter_table}
<h3>Limitations</h3>
<ul>
<li>Flags are heuristics that point to what to investigate. They are not verdicts.</li>
<li>The outputs of the commands are captured at slightly different moments; a few packets of difference between the sources are normal.</li>
<li>Several dataplanes in one output: only the first one is analysed and a warning lists the others. A second copy of the same section is ignored.</li>
<li>Counter columns are shown only when at least one interface has a non-zero value for the counter.</li>
</ul>
""",
    'iflags': """
<p>The heuristics in <code>interface_errors.py</code> attach these flags to the interfaces. Levels: <b>crit</b> = high, <b>warn</b> = medium, <b>info</b> = context only. The last column shows the live thresholds used for this report. Thresholds not listed for a code do not apply.</p>
<table>
<tr><th>Code</th><th>Level</th><th>Applies to</th><th>Meaning and suggestion</th><th>Live thresholds</th></tr>
<tr><td><code>UPTIME_SHORT</code></td><td>warn</td><td>whole report</td><td>The uptime is shorter than short_uptime_s, so the cumulative counters cover little time and are low-significance. Capture again later.</td><td>short_uptime_s = {if_short_uptime_s}</td></tr>
<tr><td><code>PHY_ERRORS</code></td><td>crit</td><td>physical ports</td><td>A physical-layer error counter is above the limit: CRC, receive fifo overrun, undersized, oversized, jabber, fragments, collisions (also late and excessive), MAC receive or transmit errors, bad octets. Check cable, SFP, port, duplex and speed on both ends. Oversized frames can also come from an MTU or jumbo mismatch.</td><td>phy_error_min = {if_phy_error_min}</td></tr>
<tr><td><code>PHY_MINOR</code></td><td>info</td><td>physical ports</td><td>Flow control (pause) frames or deferred/multiple transmissions seen. Pause frames mean congestion at one end; deferred/multiple transmissions only occur on half-duplex links.</td><td>none</td></tr>
<tr><td><code>HW_ERRORS</code></td><td>warn</td><td>physical ports</td><td>The hardware (CPU side) counters show receive errors, discards or drops. With a clean MAC the packets were lost inside the firewall (overload, buffers).</td><td>hw_error_min = {if_hw_error_min}</td></tr>
<tr><td><code>DROP_PCT</code></td><td>warn; crit at the crit percentage</td><td>all interfaces</td><td>The logical "packets dropped" is at least drop_pct_warn percent of the packets received, with enough packets and drops that the percentage means something. Look at the specific counters of the interface.</td><td>drop_pct_warn = {if_drop_pct_warn}%; drop_pct_crit = {if_drop_pct_crit}%; min_packets = {if_min_packets}; min_drops = {if_min_drops}</td></tr>
<tr><td><code>NO_ROUTE</code></td><td>warn</td><td>all interfaces</td><td>"no route" drops reach the minimum. The text says how much of the total sits on this interface (concentrated above the share limit) and, for a sub-interface, suggests checking the routes of its virtual router, default route included.</td><td>no_route_min = {if_no_route_min}; concentration_share = {if_concentration_share}%</td></tr>
<tr><td><code>ARP_NOT_FOUND</code></td><td>warn</td><td>all interfaces</td><td>Packets were dropped because ARP could not be resolved. Check that the next-hop hosts exist and answer, the subnet mask and the ARP table.</td><td>arp_min = {if_arp_min}; concentration_share = {if_concentration_share}%</td></tr>
<tr><td><code>L2_RESOLUTION</code></td><td>warn</td><td>all interfaces</td><td>Neighbor not found, neighbor info pending or MAC not found drops reach the minimum (IPv6 neighbor discovery or layer-2 forwarding table).</td><td>l2_min = {if_l2_min}</td></tr>
<tr><td><code>FLOW_STATE_CHECK</code></td><td>info with a short uptime, else warn</td><td>all interfaces</td><td>Packets dropped by the flow state check reach the minimum. Shortly after a boot this is most likely non-SYN TCP of sessions that existed before the reboot. On a long-running firewall look for asymmetric routing, short idle timeouts or a failover.</td><td>flow_state_min = {if_flow_state_min}; short_uptime_s = {if_short_uptime_s}</td></tr>
<tr><td><code>IP_SPOOF</code></td><td>info on a WAN-like zone, else warn</td><td>all interfaces</td><td>Drops by the zone protection option <code>discard-ip-spoof</code>. On an internet-facing zone this is background noise; on an internal zone it points to asymmetric routing, a missing route or real spoofing. A zone counts as WAN-like when its name contains wan, untrust, outside, internet, external, isp or inet.</td><td>none (any count)</td></tr>
<tr><td><code>ATTACK_COUNTERS</code></td><td>warn</td><td>all interfaces</td><td>Land, teardrop, ping-of-death, MAC spoof or ICMP fragment counters are non-zero. Check where the traffic comes from.</td><td>none (any count)</td></tr>
<tr><td><code>FWD_ERRORS</code></td><td>warn</td><td>all interfaces</td><td>Forwarding errors or logical receive errors are non-zero.</td><td>none (any count)</td></tr>
<tr><td><code>ZONE_CHANGE</code></td><td>info on tunnels, warn elsewhere</td><td>all interfaces</td><td>Packets were dropped because the route leads to a zone different from the session's. On a tunnel check proxy-IDs and the routes to the remote networks; elsewhere look for asymmetric routing or overlapping routes.</td><td>zone_change_min = {if_zone_change_min} (non-tunnel interfaces)</td></tr>
<tr><td><code>LINK_HALF_DUPLEX</code></td><td>warn</td><td>physical ports</td><td>The link is up at half duplex, almost always a negotiation problem.</td><td>none</td></tr>
<tr><td><code>LINK_MISMATCH</code></td><td>warn</td><td>physical ports</td><td>Configured speed or duplex (when not auto) differs from the running one. Needs the interface detail output.</td><td>none</td></tr>
<tr><td><code>LINK_SPEED_LOW</code></td><td>warn</td><td>physical ports</td><td>The link negotiated a speed below the best the port supports. Check cable category and length and the peer port. Needs the interface detail output.</td><td>none</td></tr>
<tr><td><code>UP_NO_TRAFFIC</code></td><td>info</td><td>physical ports</td><td>The link is up but no packet was received or sent since boot.</td><td>none</td></tr>
<tr><td><code>DOWN_CONFIGURED</code></td><td>info</td><td>physical ports</td><td>The port is down but has a zone or an address configured. Expected for an unused port; otherwise check cable and peer.</td><td>none</td></tr>
<tr><td><code>XCHECK_MISMATCH</code></td><td>info</td><td>whole report</td><td>The per-interface sum differs from the matching global counter beyond the tolerance (see the cross-check panel).</td><td>xcheck_tolerance_pct = {if_xcheck_tolerance_pct}%; xcheck_abs = {if_xcheck_abs}</td></tr>
</table>
<p>The summary above the table lists, for each flag, the interfaces that carry it. Down ports with nothing configured are listed there as "down / no traffic" without a flag.</p>
<p class="hint">The thresholds are heuristics defined in <code>interface_errors.IF_THRESHOLDS</code>. In code, override them with <code>evaluate_interfaces(parsed, thresholds={{'drop_pct_warn': 2.0}})</code>. Unknown keys raise an error. On the command line use the <code>--if-&lt;name&gt;</code> options (for example <code>--if-drop-pct-warn 2</code>; see <code>panos-toolbox tsf analyze --help</code>). The values shown here are the ones used for this report.</p>
<h3>How to read the output</h3>
<ol>
<li><b>Check the uptime first.</b> A few minutes of uptime make every count unreliable.</li>
<li><b>Physical errors first.</b> A <code>PHY_ERRORS</code> flag on a port with real traffic is the most actionable finding: replace the cable or SFP, then check duplex and speed on both ends.</li>
<li><b>Then the drop percentage.</b> A high <code>DROP_PCT</code> only says there are drops; the counters next to it say why (no route, ARP, flow state, zone change, spoof).</li>
<li><b>Use the cross-check.</b> It tells whether the per-interface counters and the global drop counters tell the same story, and the global counters show the drops that have no interface counter (policy deny, TTL, multicast...).</li>
</ol>
""",
    'itable': """
<ul>
<li>One row per interface: physical ports, aggregate groups, sub-interfaces, tunnel, vlan and loopback. Columns: link, zone, address, packets and bytes since boot, the counter columns in three groups (Physical, CPU / hardware, Logical / flow; the group is marked on the top edge of the header and in the tooltip) and the drop percentage and flags.</li>
<li><b>only interfaces with issues</b> (on by default) keeps rows that have a flag or a non-zero error counter. Untick it to list every interface.</li>
<li><b>Type</b> and <b>Search</b> (name, zone, address, flag code) narrow the list.</li>
<li>Click a column header to sort, and click again to reverse. Enter or Space works on a focused header. Red rows have a crit flag, yellow rows a warn flag.</li>
<li>Counters equal to zero are shown as a dot.</li>
<li><b>Export CSV</b> downloads the rows that match the filters with every counter column, as UTF-8 with a byte order mark.</li>
</ul>
<p><b>Drop %</b> is the logical "packets dropped" divided by the packets received on the same interface. It is left empty when no packet was received.</p>
""",
    'ixchk': """
<p>The per-interface logical counters are added up and compared with the matching <code>show counter global</code> drop counters. If both tell the same story the interface counters can be trusted as the breakdown of the global ones. Values within the larger of xcheck_abs ({if_xcheck_abs}) and xcheck_tolerance_pct ({if_xcheck_tolerance_pct}%) are reported as <b>match</b>; others as <b>differs</b> (info flag <code>XCHECK_MISMATCH</code>); <b>related</b> rows only show values side by side.</p>
<ul>
<li>"no route" seems to add up to <code>flow_fwd_l3_noroute</code> plus <code>flow_policy_nofwd</code>. This was observed on real captures; it is not documented.</li>
<li>The flow state check has no dedicated global counter: <code>flow_tcp_non_syn_drop</code> is one cause among others.</li>
<li>The second table lists the other non-zero drop-related global counters (policy deny, TTL, multicast, broadcast...). They have no interface counter.</li>
</ul>
""",
    'dph': """
<p>Built from the <code>panio</code> sections of the <code>dp-monitor.*</code> files of the TSF (one section about every 10 minutes on the devices seen). Each section has a <i>resource monitor</i>: the dataplane's own view of how full its session table, packet buffer and packet descriptors are, and how busy each core is. The time is the one of the section header, converted to UTC.</p>
<h3>Sources</h3>
<ul>
<li><b>Per second</b> (<i>Resource monitoring sampling data</i>): the last <b>15 seconds</b>, one value per second. The CPU table has one column per core; devices with many cores split it into several blocks, which are merged by core number. The <i>Resource utilization</i> lines give <code>session</code>, <code>packet buffer</code>, <code>packet descriptor</code> and, where present, <code>packet descriptor (on-chip)</code>.</li>
<li><b>Per minute</b> (<i>Resource monitoring statistics</i>): the last <b>15 minutes</b>, with the average and the maximum of each minute for the CPU. The <code>max</code> column of this table gives the "per-minute max" per core; it has its own flag (<code>CORE_PEAK_MINUTE</code>) and is never mixed with the per-second figures. A sample without a per-second CPU table simply has no per-second core value.</li>
<li><b>Session table utilization</b> in the <code>target-dp</code> block of the same section is used for the session utilization only when the per-second resource block is missing (the notes above the summary count such samples).</li>
</ul>
<h3>How a sample is read</h3>
<ul>
<li>The value of a sample is the <b>maximum of its 15 per-second values</b>, so a short spike inside the window is not averaged away. For the packet buffer the chart also shows the average of the 15 values.</li>
<li>A <code>*</code> in a CPU table cell means that the measurement is missing: the cell is ignored (not counted as 0). A value outside 0-100 is discarded. A row whose number of columns differs from the header is discarded. The number of discarded rows and values is shown below the summary.</li>
<li>Each resource block is bound to the <code>target-dp</code> of the same section, by order of appearance. If the numbers of blocks and DPs differ, nothing is bound and a warning is shown. An explicit <code>DP &lt;name&gt;:</code> line before a block would bind it to that DP, but that layout has not been seen on a real device (unverified). DPs are never added or averaged together; each is evaluated alone.</li>
<li>When the same section appears in several rotated files, the first copy (the oldest file) is kept.</li>
</ul>
<h3>Peak versus last</h3>
<p>The firewall's own health checks look at the last sample only. A TSF is a history, so the flags here are based on the <b>peak over the whole period</b>. The text of each flag gives the peak (value and UTC time), the last value and how many samples were at or above the threshold, so that you can tell a spike that is over from a condition that is still there.</p>
<h3>Summary table</h3>
<p>For each DP: the number of samples and the period, then for the session table, the packet buffer, the packet descriptors and the busiest core, once from the per-second table and once from the per-minute max, the last and the peak value (the peak with its UTC time and, for the CPU, the core). Per-minute values have no time of their own: the time shown is that of the section, and the value covers the 15 minutes before it. Rows are coloured by the worst flag of the DP.</p>
""",
    'dphflags': """
<p>The heuristics in <code>dp_health.py</code> attach these flags to each DP. Levels: <b>crit</b> = high, <b>warn</b> = medium. The level comes from the <b>peak</b> over the period (see above). The last column shows the live thresholds used for this report.</p>
<table>
<tr><th>Code</th><th>Level</th><th>Meaning and suggestion</th><th>Live thresholds</th></tr>
<tr><td><code>SESSION_UTIL</code></td><td>warn; crit at the crit limit</td><td>The session table utilization reached the limit. A full session table makes the firewall refuse new sessions. Look at the session count and rate, the session timeouts, and whether the traffic is a scan or an attack (zone protection, DoS protection) before raising anything.</td><td>session_util_warn = {dp_session_util_warn}%; session_util_crit = {dp_session_util_crit}%</td></tr>
<tr><td><code>PKT_BUFFER</code></td><td>warn; crit at the crit limit</td><td>The packet buffer utilization reached the limit. Buffers fill when packets wait longer than the dataplane can process them (overload, a slow function, a burst, a stuck queue), and when they run out new packets are dropped. Compare with the CPU load, the POW tab and the drop counters of the Interface Errors tab.</td><td>pkt_buffer_warn = {dp_pkt_buffer_warn}%; pkt_buffer_crit = {dp_pkt_buffer_crit}%</td></tr>
<tr><td><code>CORE_PEAK</code></td><td>warn</td><td>At least one core reached the per-second CPU limit. The text names the DP and the cores. Samples without a per-second table are not counted (there is no fallback to the per-minute table). One busy core with the others idle points to a single heavy flow (elephant flow) or an unbalanced workload; all cores busy points to a lack of capacity. A single second above the limit is often only a spike: check how many samples were affected. It sees only the 15 seconds of the per-second table in each section (about every 10 minutes), so most of the time is not covered.</td><td>core_peak_warn = {dp_core_peak_warn}% (no crit level)</td></tr>
<tr><td><code>CORE_PEAK_MINUTE</code></td><td>warn</td><td>At least one core reached the limit in the <code>max</code> column of the per-minute CPU table. That table covers the 15 minutes before each section, so together the sections cover practically the whole period, while <code>CORE_PEAK</code> sees only 15 seconds per section. For this reason the two flags are separate and can differ: a short burst between two per-second windows shows up here only. A per-minute row has no time of its own, so the text says "in the 15 minutes before" the section time (UTC). The maximum of a minute is the highest load seen in that minute, so it is more sensitive to short spikes than the per-second values; check the number of samples affected before concluding that a core is saturated.</td><td>core_peak_minute_warn = {dp_core_peak_minute_warn}% (no crit level)</td></tr>
</table>
<p class="hint">The thresholds are heuristics defined in <code>dp_health.DP_THRESHOLDS</code>. In code, override them with <code>evaluate_dp_health(store, thresholds={{'pkt_buffer_warn': 40}})</code>. Unknown keys raise an error. On the command line use the <code>--dp-&lt;name&gt;</code> options (for example <code>--dp-pkt-buffer-warn 40</code>; see <code>panos-toolbox tsf analyze --help</code>). The values shown here are the ones used for this report. The packet descriptors have no flag: they are shown for context.</p>
""",
    'dphchart': """
<ul>
<li><b>DP</b> selects the dataplane. The series are the session table utilization, the packet buffer (average and maximum of the 15 per-second values) and the busiest core, from the per-second table and from the per-minute max. The legend checkboxes show or hide a series.</li>
<li>Each point is one <code>panio</code> section, about 10 minutes apart: between two points nothing is known, so a short peak can fall between samples.</li>
<li>The vertical axis runs from 0 to 100 percent. Zoom (drag across the chart), <b>Reset zoom</b> and the stats table work as in the throughput chart. Hover for the values at the nearest sample.</li>
</ul>
""",
    'dphcores': """
<p>One cell per core of the selected DP, in blocks of 16 cores: the <b>peak</b> of the per-second CPU load over the whole period (the maximum of the 15 values of every sample), and the highest per-minute maximum. The colour goes from white (idle) to red (100%). A bold border marks a cell at or above <code>core_peak_warn</code> ({dp_core_peak_warn}%) in the first row and <code>core_peak_minute_warn</code> ({dp_core_peak_minute_warn}%) in the second. Hover a cell for the UTC time of the peak and the last value.</p>
<p>Cores that show no data at all (always <code>*</code>) are left empty. A core that is always 0 is normally not used by the dataplane (cores reserved for other functions).</p>
""",
    'mp': """
<p>Built from the <code>memory</code> and <code>processes</code> sections of <code>var/log/pan/mp-monitor.log</code> and its rotations (<code>.1</code> to <code>.4</code>) in the TSF. They describe the <b>management plane</b> (the control CPU and its RAM, where <code>configd</code>, <code>mgmtsrvr</code>, <code>logrcvr</code> and the other daemons run), not the dataplane. The time of a sample is the one of its section header, converted to UTC with the offset written in that header: the offset of mp-monitor can differ from the one of dp-monitor, so the two are not assumed to be equal. The other sections of the file (cpu, top_summary, pidstat, filesystem, ...) are not read.</p>
<h3>How it is read</h3>
<ul>
<li><b>Memory</b>: a table with the rows <code>Mem</code> and <code>Swap</code>. The columns are found by their header names. <b>Memory used %</b> = (Total - MemAvailable) / Total x 100 of the <code>Mem</code> row. <code>MemAvailable</code> is the kernel's estimate of the memory that can be given to applications without swapping, so caches that can be dropped are not counted as used. A <code>Mem</code> row without Total or MemAvailable is discarded. The Swap total can be <code>UNKNOWN</code>; the swap series is then empty.</li>
<li><b>Processes</b>: a table with name, PID, CPU %, open file descriptors, virtual memory, <code>Res+Swap</code> (resident plus swapped memory, in kB), state and sometimes <code>Res+Swap-Lazy</code>. The columns are found by their header names. A row with fewer than the mandatory fields, or with a non-numeric value, is discarded and counted. The value <code>Unknown</code> (CPU, virtual or Res+Swap of a process that ended while the sample was taken, state <code>Unk</code>) is not an error: the row is kept and that value is ignored. The <code>Totals</code> row that closes the table is skipped. Names can be truncated by the tool with a trailing <code>+</code> (for example <code>pan_logdb+</code>) and are used as they are. If a name appears several times in one sample (different PIDs) the highest CPU and the sum of Res+Swap are used.</li>
<li>When the same section appears in several rotated files, the first copy (the oldest file) is kept. The number of duplicates ignored and of discarded rows is shown under the title.</li>
<li>The sections are about 3 minutes apart on the devices seen (the memory table covers the last 180 seconds); between two samples nothing is known, so a short peak can fall between them. The info line under the title gives the median interval of the processes samples.</li>
</ul>
<h3>Last versus peak</h3>
<p>The level of the memory flag is based on the <b>last sample</b> (is the box in trouble now?), while <code>MP_MEMORY_PAST_PEAK</code> tells that the memory was above the warning limit earlier in the period and is back to normal. A TSF is taken after the problem is noticed, so both views are useful. Short one-sample CPU spikes are common on the management plane (a <code>grep</code>, a <code>python</code> job, a <code>monitor-dp</code> burst) and are not flagged: see <code>PROC_CPU</code>.</p>
<h3>Summary table</h3>
<p>Number of samples, period, total RAM, memory used in the last sample and at its peak (with UTC time), and the lowest MemAvailable seen. The row is coloured by the worst flag of the tab.</p>
""",
    'mpflags': """
<p>The heuristics in <code>mp_monitor.py</code> attach these flags. Levels: <b>crit</b> = high, <b>warn</b> = medium, <b>info</b> = for your attention only (an info flag does not change the status of the module). The last column shows the live thresholds used for this report.</p>
<table>
<tr><th>Code</th><th>Level</th><th>Meaning and suggestion</th><th>Live thresholds</th></tr>
<tr><td><code>MP_MEMORY</code></td><td>warn; crit at the crit limit</td><td>The memory used % of the <b>last</b> sample is strictly greater than the limit (a value equal to the limit is not flagged). A management plane short of memory starts swapping and may kill processes (out-of-memory killer), which shows as slow commit, GUI or API, or restarted daemons. Check the process table for the biggest and the growing Res+Swap, look in the system log for out-of-memory messages and process restarts, and consider a reboot or a PAN-OS release that fixes a known leak if the growth is steady.</td><td>mem_warn = {mp_mem_warn}%; mem_crit = {mp_mem_crit}% (strictly greater)</td></tr>
<tr><td><code>MP_MEMORY_PAST_PEAK</code></td><td>warn</td><td>The memory used % was above the warning limit at some time in the period but the last sample is back at or below it. The cause may be gone (a commit, a report job, a restart of a daemon) or it may come back: compare the time of the peak with the process table and with what was done on the device at that time. It is never raised together with <code>MP_MEMORY</code>.</td><td>mem_warn = {mp_mem_warn}%</td></tr>
<tr><td><code>PROC_CPU</code></td><td>warn</td><td>A process (one flag per process name) used at least the CPU limit in the minimum number of <b>consecutive</b> samples. The text gives the longest run (length and UTC time range), the peak and the number of runs. A single sample above the limit is not flagged, because short spikes are normal. A run is broken when the process is missing from a sample or when the gap to the previous sample is larger than the gap factor times the median interval between processes samples (so a hole in the log does not join two bursts). The workers (<code>{mp_workers}</code>) and the short-lived commands (<code>{mp_ignored}</code>) are never flagged, but stay in the tables. A process can use more than 100% when it has several threads. A long run of a daemon points to a stuck or overloaded task: check what it does (for example <code>configd</code> during a large commit, <code>logrcvr</code> or <code>mgmtsrvr</code> under heavy logging or API load) and whether it ended.</td><td>proc_cpu_warn = {mp_proc_cpu_warn}% (at or above); proc_cpu_min_samples = {mp_proc_cpu_min_samples}; proc_cpu_gap_factor = {mp_proc_cpu_gap_factor}</td></tr>
<tr><td><code>PROC_ZOMBIE</code></td><td>info</td><td>One or more processes were seen in state <code>Z</code> (zombie: the process ended but its parent has not collected its exit status). A few zombies for a short time are harmless; many of them, or the same one for the whole period, point to a parent that does not reap its children. The text lists the names and in how many samples each was seen, and those in the last sample. Other states (S, R, D, I, Unk) are normal and are not reported.</td><td>none</td></tr>
</table>
<p class="hint">The thresholds are heuristics defined in <code>mp_monitor.MP_THRESHOLDS</code>; the ignored names are <code>MP_WORKER_PREFIXES</code> and <code>MP_IGNORE_PROCS</code>. In code, override the thresholds with <code>evaluate_mp_monitor(store, thresholds={{'mem_warn': 80}})</code>. Unknown keys raise an error. On the command line use the <code>--mp-&lt;name&gt;</code> options (for example <code>--mp-mem-warn 80</code>; see <code>panos-toolbox tsf analyze --help</code>). The values shown here are the ones used for this report.</p>
""",
    'mpchart': """
<ul>
<li>The line is the <b>memory used %</b> of the management plane at each sample; the second line, when present, is the swap used % (omitted if the swap total is unknown). The dashed lines mark the warn and crit limits ({mp_mem_warn}% and {mp_mem_crit}%); a value is flagged when it is strictly above them. The legend checkboxes show or hide a line.</li>
<li>The vertical axis runs from 0 to 100 percent. Zoom (drag across the chart), <b>Reset zoom</b> and the stats table work as in the throughput chart. The stats table lists, for each line, the samples, the minimum, the average, the maximum and its UTC time. Hover for the values at the nearest sample.</li>
<li>A steadily rising line over days points to a leak; saw-tooth patterns that drop at the same time are usually a restart of a daemon or a reboot.</li>
</ul>
""",
    'mpprocs': """
<p>One row per process name. <b>Show</b> selects the rows: the processes with a <code>PROC_CPU</code> flag, the top 10 by peak CPU, by peak <code>Res+Swap</code> or by growth, or all of them. The table can be collapsed. Workers and short-lived commands are listed too and marked "not flagged".</p>
<ul>
<li><b>Peak CPU</b>: the highest value seen and when (UTC). <b>Samples at/above</b>: how many samples reached the CPU limit ({mp_proc_cpu_warn}%), also as isolated spikes.</li>
<li><b>Longest run</b>: the longest series of consecutive samples at or above the limit (see <code>PROC_CPU</code> for what breaks a run), with its UTC time range. <b>Runs</b>: how many runs reached the minimum length ({mp_proc_cpu_min_samples} samples).</li>
<li><b>Peak Res+Swap</b>: the highest resident plus swapped memory (kB converted to MB) and when. <b>Last Res+Swap</b> is the value of the last sample where the process was present. <b>Growth</b> is last minus first Res+Swap of the process; the top-by-growth view lists only positive growth. A process restarted during the period restarts from a low value, which hides or inflates the growth: check the peak and the PID changes before blaming a daemon. No correlation between processes and the memory curve is computed.</li>
<li><b>State Z</b>: in how many samples the process was a zombie.</li>
</ul>
""",
    'coverage': """
<p>Shows what this analysis actually looked at, so that a missing or partial source is never mistaken for a clean one. The badge in the page header summarises it: <b>Analysis: complete</b> or <b>Analysis: partial</b>.</p>
<p>A <b>family</b> is a group of files of the same kind inside the TSF: <code>dp-monitor</code> (the <code>var/log/pan/dp-monitor.*</code> logs, including rotated and compressed copies, which give the throughput and CPU series) and <code>mp-monitor</code> (the <code>var/log/pan/mp-monitor.*</code> logs, which give the management plane memory and processes) and <code>cli</code> (the <code>tmp/cli/*.txt</code> command outputs, which give the POW and interface data). The TSF is read in memory; nothing is extracted to disk.</p>
<h3>States</h3>
<ul>
<li><b>absent</b>: no member of the family exists in the input. The matching tabs are simply missing; this is not an error in the report.</li>
<li><b>unread</b>: members were found but none could be read (for example a total size limit was reached first).</li>
<li><b>0 samples</b>: dp-monitor files were read but no Throughput sample could be extracted (unexpected format, or empty files). It differs from absent: the files exist.</li>
<li><b>truncated</b>: a member is larger than the per-member read limit, so only its <i>tail</i> (the most recent part) was kept and analysed; older data of that file is missing. Compressed members are cut the same way.</li>
<li><b>read error</b>: a member is corrupted or cut short. What could be decoded before the failure is kept.</li>
<li><b>conflict</b>: two dp-monitor samples have the same DP and time but different values, typically overlapping rotated files that disagree. The <i>first</i> one (oldest file in rotation order) is kept and the other is dropped; both files are cited in the warnings and listed in the conflicts table. Identical duplicates are not conflicts and are not reported.</li>
<li><b>skipped</b>: a member was not read. At archive level this is an <i>unsafe path</i> (absolute or containing <code>..</code>), a <i>link</i> (symbolic or hard) or a <i>special file</i> (device, fifo). Such members are never followed or extracted.</li>
</ul>
<h3>Complete and partial</h3>
<p><b>Complete</b>: every member found was read in full and no samples conflicted. <b>Partial</b>: at least one member was truncated or hit a read error, a limit note was recorded (member count or total size) or samples conflicted. Partial does not mean wrong: it means the numbers may not cover the whole capture, so check the table below before drawing conclusions. Skipped unsafe members and absent families do not make the analysis partial by themselves.</p>
<p>The <b>Time range</b> column is computed from the samples of each dp-monitor file (UTC). With a single file instead of an archive or directory there is no inventory, so only a minimal view is shown. The conflicts table lists at most the first 200 conflicts.</p>
""",
}


def render_section_help(thresholds=None, if_thresholds=None, dp_thresholds=None,
                        mp_thresholds=None):
    """Returns {placeholder: html} for every section (buttons and collapsible texts).

    thresholds: optional overrides with the keys of pow_perf.POW_THRESHOLDS. Unknown keys
    raise ValueError, as in evaluate(). if_thresholds: the same for
    interface_errors.IF_THRESHOLDS (available as {if_<name>}). The values are escaped before
    insertion. dp_thresholds: the same for dp_health.DP_THRESHOLDS (available as {dp_<name>}).
    mp_thresholds: the same for mp_monitor.MP_THRESHOLDS (available as {mp_<name>}).
    """
    th = dict(POW_THRESHOLDS)
    unknown = set(thresholds or {}) - set(POW_THRESHOLDS)
    if unknown:
        raise ValueError('unknown POW threshold(s): ' + ', '.join(sorted(unknown)))
    th.update(thresholds or {})
    ith = dict(IF_THRESHOLDS)
    unknown = set(if_thresholds or {}) - set(IF_THRESHOLDS)
    if unknown:
        raise ValueError('unknown interface threshold(s): ' + ', '.join(sorted(unknown)))
    ith.update(if_thresholds or {})
    dth = dict(DP_THRESHOLDS)
    unknown = set(dp_thresholds or {}) - set(DP_THRESHOLDS)
    if unknown:
        raise ValueError('unknown dataplane health threshold(s): ' + ', '.join(sorted(unknown)))
    dth.update(dp_thresholds or {})
    mth = dict(MP_THRESHOLDS)
    unknown = set(mp_thresholds or {}) - set(MP_THRESHOLDS)
    if unknown:
        raise ValueError('unknown management plane threshold(s): ' + ', '.join(sorted(unknown)))
    mth.update(mp_thresholds or {})
    values = {k: html.escape(str(v)) for k, v in th.items()}
    values.update({'mp_' + k: html.escape(f'{v:g}' if isinstance(v, float) else str(v))
                   for k, v in mth.items()})
    values['mp_workers'] = html.escape(', '.join(p + '*' for p in MP_WORKER_PREFIXES))
    values['mp_ignored'] = html.escape(', '.join(MP_IGNORE_PROCS))
    values.update({'dp_' + k: html.escape(f'{v:g}' if isinstance(v, float) else str(v))
                   for k, v in dth.items()})
    values.update({'if_' + k: html.escape(str(v)) for k, v in ith.items()})
    values['if_counter_table'] = if_glossary.help_table_html()
    values['core_imbalance_crit'] = html.escape(str(2 * th['core_imbalance_ratio']))
    out = {}
    for sid, text in SECTION_HELP.items():
        title = html.escape(SECTION_TITLES[sid])
        out['__HB_%s__' % sid] = (
            '<button type="button" class="helpbtn" aria-expanded="false" '
            'aria-controls="help-%s" aria-label="Help: %s">? Help</button>' % (sid, title))
        out['__HP_%s__' % sid] = (
            '<div class="help" id="help-%s" hidden>%s</div>' % (sid, text.format_map(values)))
    return out

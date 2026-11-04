"""Per-section help of the TSF report.

Every tab and panel of the report has its own short, collapsed help (a "? Help" button
that expands a text at the top of that section). There is no global help page.

SECTION_HELP maps a section id to an HTML template. Its {name} placeholders are filled
with the live values of pow_perf.POW_THRESHOLDS by render_section_help(). The thresholds of
the Interface Errors tab (interface_errors.IF_THRESHOLDS) are available as {if_<name>}. Literal braces
in the HTML are doubled. The report template contains the placeholders __HB_<id>__
(the button) and __HP_<id>__ (the collapsible text) for each id.

Standard library only.
"""
import html

from . import if_glossary
from .interface_errors import IF_THRESHOLDS
from .pow_perf import POW_THRESHOLDS

# Titles are used for the accessible name of the buttons.
SECTION_TITLES = {
    'chart': 'Dataplane throughput', 'table': 'Samples table', 'cpu': 'CPU load by group',
    'pow': 'POW performance', 'pflags': 'Findings and flag reference', 'ptop': 'Top functions',
    'pgroups': 'Workgroups', 'pfuncs': 'Functions', 'pcat': 'Function CPU share by category',
    'phist': 'Histograms', 'pmx': 'Workgroup total-us per core', 'plat': 'Latency counters',
    'ifc': 'Interface errors', 'iflags': 'Interface findings and flag reference',
    'itable': 'Interfaces table', 'ixchk': 'Cross-check with the global counters',
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
}


def render_section_help(thresholds=None, if_thresholds=None):
    """Returns {placeholder: html} for every section (buttons and collapsible texts).

    thresholds: optional overrides with the keys of pow_perf.POW_THRESHOLDS. Unknown keys
    raise ValueError, as in evaluate(). if_thresholds: the same for
    interface_errors.IF_THRESHOLDS (available as {if_<name>}). The values are escaped before
    insertion.
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
    values = {k: html.escape(str(v)) for k, v in th.items()}
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

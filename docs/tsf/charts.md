# TSF report charts: reduction and gaps

Applies to the time-series charts of `src/panos_toolbox/tsf/report_template.py`
(`makeChart`): Dataplane throughput (which also carries the dataplane health metrics),
CPU load by group and Management plane. The histogram and bar charts of the POW tab are not time series and
are unchanged.

## Before

- **No downsampling.** Every sample of a series was written to one SVG `polyline`
  (`points=` with one `x,y` pair per sample). A long series therefore produced tens of
  thousands of points per line; the browser rasterised them all and the peaks were only
  visible by accident of overdraw.
- **Dots** (`circle`) were added only when a series had 80 samples or fewer.
- **Gaps were bridged.** The polyline joined any two consecutive samples, however far
  apart (rotated files with a hole in between, a reboot, a TSF taken days later). A
  straight segment crossed the hole as if data existed there.
- **Missing values were dropped, not drawn.** The series builders (`mainSeries`,
  `groupSeries`, `renderDph`, `renderMp`) filtered out every `null`/`undefined` value
  before drawing, so the neighbours of a missing sample were joined by a line. A missing
  value was never drawn as 0, but it was invisible. (No Python builder turns `None` into
  0 for a chart; nothing to fix there.)
- **Zoom** (`setRange`) filters the series by the selected range in the builders and
  re-draws the whole chart; there was no reduction to redo.
- **Hover** looked for the nearest sample among all points; the stats table used all the
  points of the series in the visible range.

## After

- **Reduction by blocks that preserves the extremes** (`reduceMinMax`). When a run of
  samples has more than `CH.REDUCE_FACTOR` (2) points per plot pixel, the visible range is
  split into blocks of `CH.PX_PER_BLOCK` (2) pixels. For each block the lowest and the
  highest sample are kept, plus always the first and the last sample of the run, in time
  order. Peaks stay visible at wide zoom. On zoom the chart is drawn again from the
  samples of the selected range only, so the reduction is redone for that range.
- **Gap breaking** (`splitGaps`). The median distance between consecutive real samples of
  the series is computed. The line is broken (a new path segment starts) when two
  consecutive samples are further apart than `GAP_FACTOR` (3) times the median, clamped
  to `GAP_MIN_MS` (60 s: never broken under it) and `GAP_MAX_MS` (6 h: always broken above
  it). A sample with no neighbour in its run is drawn as a dot.
- **Missing values** are kept in the series as `null` and end the run: the line is
  interrupted, never drawn to 0, never joined across. They are not counted in the stats
  and do not take part in the median or in the vertical scale.
- **Real samples everywhere else.** Hover uses the nearest real (non-missing) sample, and
  the stats tables (samples, min, avg, max, time of maximum) use all the real samples of
  the visible range, not the reduced ones.
- **Tunables** are the constants in the `CH` object at the top of the chart helpers
  (marked `CHART-HELPERS-BEGIN`/`END` in the template). The helpers are pure functions
  (`medianInterval`, `splitGaps`, `reduceMinMax`, `chartRuns`, `realPts`) and are tested
  with node in `tests/test_tsf_charts.py`.
- Help: the `chart`, `cpu` and `mpchart` entries in `report_help.py` describe
  the behaviour.

## Dataplane health metrics in the throughput chart

The utilization chart and the CPU per core table of the Dataplane health tab were merged
into the Dataplane Throughput tab. That tab keeps the Metric selector, the series per DP
(legend checkboxes), the zoomable chart, the stats table and the samples table; the
Dataplane health tab keeps only the per-DP summary and the findings.

**New Metric entries** (listed only when the data has them): Packet buffer & descriptors
(one chart for one DP, one line per kind that has data: Packet buffer (avg), the per-minute
average, Packet buffer (max), Packet descriptor (max), Packet descriptor on-chip (max),
the per-second values; internal metric key `hpkt`, `PKT_KINDS`), Busiest core (per-second), Busiest core (per-minute
max), and CPU per core (per-second / per-minute max / per-minute avg), one series per core
of a DP chosen in a DP selector, with All/None legend buttons. Session table utilization
stays one entry: the per-second `session` value of the resource monitor when the capture
has it, else the target-dp reading. For percentages ALL is the maximum across DPs.

**Timestamp reconstruction.** The section time T is when the command ran. The rows of the
per-minute table are newest first and each is a whole wall-clock minute: row i ends i
minutes before the last minute boundary at or before T (`dp_health.row_time_m`). Verified on
two real TSFs: the rows of two captures 10 minutes apart shift by exactly 10 (old row r ==
new row r+10 for 100% of the values, 46-67% for a shift of 9 or 11), and the last seconds
before T are not in row 0 (a peak of a per-second window appears in row 9 of the capture
10 minutes later, 84 of 84 cases on an 8-core device; a reading "ends at T - i minutes"
fits 87%). The per-second CPU table and the 15 per-second utilization values are assumed
to be newest first too: row i is the second T - i s (`dp_health.row_time_s`). This is
inferred from the per-minute table and cannot be verified from the file.

**Overlapping minutes.** A per-minute table covers 15 minutes and captures are about 10
minutes apart. Each capture carries `k0` (the whole-minute index of its row 0); the minute
of row i is `k0 - i`. `minuteGrid` keeps, for each (core, minute), the value of the most
recent capture (a missing `*` never replaces a real value), so every minute appears once
(the 48-core TSF: 2670 raw rows, 1785 distinct minutes). The per-second windows do not
overlap. The chart breaks the line between captures with the gap rule above.

**Data.** `evaluate_dp_health` adds `detail.by_dp[dp]` to the view: per capture (aligned
with `series.t`) flat row-major arrays of per-second CPU (`cs`), per-minute average
(`cma`) and maximum (`cmm`) over the cores of `cores[dp].ids`, plus `us` (per-second
session / packet buffer / descriptors, 15 values per capture), `um.pb_avg` and `k0`; a
missing value is `null` and a missing table is `null`. The pure helpers (`secondGrid`,
`minuteGrid`, `gridMax`, `mergeMax`, `sessionSeries`, `dphAvail`, between the
`DPH-HELPERS-BEGIN`/`END` markers) are tested with node in `tests/test_tsf_charts.py`.

**CPU per core heatmap** (below the chart, `drawHeat` in `JS_PERCORE`): one SVG per DP in the
DP filter, core on the vertical axis and time on the horizontal axis, with the left and right
margins of the line charts (the throughput chart takes the same right margin while the heatmap
is shown) and the x range of the throughput chart (the zoom range, else its full extent), so
the two line up. The `Source` select picks a grid of `coreGrid`: per-minute max (`mm`, default),
per-minute average (`ma`) or per-second (`s`); only sources with data are listed. The range is
split into buckets of 2 px; `hmBucket` (a pure helper, tested with node) puts in each bucket
the maximum of the cells that overlap it, a cell lasting 60 s or 1 s filling every bucket it
covers, and a bucket with no cell stays empty (never 0). Cells at or above
`core_peak_minute_warn` (per-minute max) or `core_peak_warn` (per-second) get a dark outline.
The right column is the per-core peak in the visible range (`hmPeaks`). Row height is
6-16 px, plot height 160-520 px. Drag selects a range like the line charts; double-click resets.
The previous per-capture rows (per-second, per-minute max and average tables with their
reconstructed UTC times, built on first expansion) are in the collapsed `Raw tables per capture`.

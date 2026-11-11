# TSF report charts: reduction and gaps

Applies to the time-series charts of `src/panos_toolbox/tsf/report_template.py`
(`makeChart`): Dataplane throughput, CPU load by group, Dataplane health and
Management plane. The histogram and bar charts of the POW tab are not time series and
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
- Help: the `chart`, `cpu`, `dphchart` and `mpchart` entries in `report_help.py` describe
  the behaviour.

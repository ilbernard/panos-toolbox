# panos-toolbox

Scripts to manage Palo Alto Networks firewalls (PAN-OS / Panorama) and
Strata Cloud Manager (SCM), exposed through one CLI: `panos-toolbox <area> <tool>`.

| Area        | Purpose                                   | Dependency       |
|-------------|-------------------------------------------|------------------|
| `firewall/` | PAN-OS firewall and Panorama automation   | `pan-os-python` (+ `PySide6` for the console) |
| `scm/`      | Strata Cloud Manager automation           | `pan-scm-sdk`    |
| `tsf/`      | Offline Tech Support File analysis        | none (stdlib)    |

## Quick start (no install)

The TSF analyzer is standard-library only (Python 3.9+) and runs straight from a checkout:

```bash
python scripts/tsf_analyzer.py tsf1.tgz --open     # report in ./output/, opened in the browser
```

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[all,dev]'      # or only '.[console]' / '.[firewall]' / '.[scm]'
cp .env.example .env             # then fill in credentials
```

To use `panos-toolbox` from anywhere without managing a venv, install it with
[pipx](https://pipx.pypa.io): `pipx install '.[all]'`. The `scm` area needs Python 3.10+
(`pan-scm-sdk`); everything else works on 3.9+.

## Tools

| Command | Description |
|---------|-------------|
| `panos-toolbox firewall console [--profiles-file FILE]` | Desktop GUI (Windows/macOS/Linux, needs `.[console]`): log in to Panorama with username/password, list the managed firewalls (filter by any column) and run actions on the selection, all proxied through Panorama. First action: Reboot. Saved connection profiles never contain passwords. See [docs/console/](docs/console/) |
| `panos-toolbox tsf analyze <tsf.tgz ...> [-o DIR] [--open] [--pow-*]` | Interactive HTML report (throughput, pps, cps, sessions, CPU by group) from a TSF's `dp-monitor.*` files, plus a POW performance tab from `debug dataplane pow performance` output in `tmp/cli/*.txt` (workgroups, functions, histograms, per-core view, heuristic anomaly flags); every tab and panel has its own collapsible help and counter names show a glossary tooltip; output goes to `./output/` by default |

Run `panos-toolbox` with no arguments for the full list.

### POW performance tab

The POW tab reads `debug dataplane pow performance all` output found (by content) in `tmp/cli/*.txt`
of a TSF, or in a plain text file given directly (with or without the command line and CLI prompts;
`tests/data/pow_performance_sample.txt` is an example). Pre-9.1 output (`max-us avg-us count` only) is
handled: `total-us` is computed and the accumulated parts are hidden. If several dataplanes are present
only the first is analysed, with a warning. Counters named `*_latency` are not CPU time: they are left
out of rankings, shares and roll-ups and listed in their own panel. All-zero counters and glossary
families are hidden until "hide rows without calls" is unticked.

There is no global help page: each tab and panel has its own collapsed "? Help" text. Hover or focus any
counter name or column header for a tooltip with its category, confidence code and meaning.

**Counter glossary.** `src/panos_toolbox/tsf/pow_glossary.py` holds the meaning of each counter. It is
**partly inferred**; every entry carries a confidence code:

| Code | Meaning |
|------|---------|
| `D` | Documented by a Palo Alto source |
| `G` | Category documented; meaning inferred from the name |
| `I` | Inferred from the name only (hypothesis) |
| `U` | Unknown. Shown as "no known meaning"; an active one raises an `UNKNOWN` flag so it can be reported |

**Thresholds.** The flags are heuristics (`POW_THRESHOLDS` in `pow_perf.py`; the flag reference is in the
help of the Findings panel). Override any of them per run with `--pow-<name>` (underscores become dashes), for
example `--pow-share-warn 15`. Defaults:

| Option | Default |
|--------|---------|
| `--pow-top-n` | 5 |
| `--pow-share-warn` | 10 |
| `--pow-share-crit` | 30 |
| `--pow-max-spike-abs-us` | 10000 |
| `--pow-max-spike-ratio` | 50 |
| `--pow-max-spike-crit-us` | 100000 |
| `--pow-min-count` | 10 |
| `--pow-drift-ratio` | 2 |
| `--pow-drift-crit-ratio` | 5 |
| `--pow-drift-min-avg-us` | 5 |
| `--pow-high-avg-us` | 1000 |
| `--pow-high-avg-us-decrypt` | 10000 |
| `--pow-category-dominance` | 50 |
| `--pow-core-imbalance-ratio` | 2 |
| `--pow-min-active-cores` | 3 |
| `--pow-hist-tail-us` | 10000 |
| `--pow-hist-tail-crit-us` | 100000 |
| `--pow-hist-tail-share` | 1 |
| `--pow-latency-high-us` | 1000 |
| `--pow-decrypt-share-warn` | 15 |
| `--pow-hist-slow-us` | 1000 |
| `--pow-hist-slow-share` | 5 |
| `--pow-hist-slow-min-count` | 10 |

## Layout

```
src/panos_toolbox/
  cli.py          single entry point and tool registry
  common/         config (env/.env credentials), logging
  firewall/       PAN-OS tools + client.py
    console/      Panorama desktop GUI (core/ logic, actions/ plugins, gui/ Qt)
  scm/            SCM tools + client.py
  tsf/            offline TSF tools (analyzer.py, pow_perf.py, pow_glossary.py, report_*.py)
scripts/          zero-install launchers (run from a checkout)
tests/            pytest suite (no real devices)
docs/             contributor docs (docs/console/ for the console tool)
CLAUDE.md         context file for Claude Code sessions
```

See [docs/adding-a-tool.md](docs/adding-a-tool.md) to add a script.

## Development

```bash
pytest
ruff check .
```

## License

AGPL-3.0 — see [LICENSE](LICENSE).

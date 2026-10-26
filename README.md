# panos-toolbox

Scripts to manage Palo Alto Networks firewalls (PAN-OS / Panorama) and
Strata Cloud Manager (SCM), exposed through one CLI: `panos-toolbox <area> <tool>`.

| Area        | Purpose                                   | Dependency       |
|-------------|-------------------------------------------|------------------|
| `firewall/` | PAN-OS firewall and Panorama automation   | `pan-os-python`  |
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
pip install -e '.[all,dev]'      # or only '.[firewall]' / '.[scm]'
cp .env.example .env             # then fill in credentials
```

To use `panos-toolbox` from anywhere without managing a venv, install it with
[pipx](https://pipx.pypa.io): `pipx install '.[all]'`. The `scm` area needs Python 3.10+
(`pan-scm-sdk`); everything else works on 3.9+.

## Tools

| Command | Description |
|---------|-------------|
| `panos-toolbox tsf analyze <tsf.tgz ...> [-o DIR] [--open]` | Interactive HTML report (throughput, pps, cps, sessions, CPU by group) from a TSF's `dp-monitor.*` files; output goes to `./output/` by default |

Run `panos-toolbox` with no arguments for the full list.

## Layout

```
src/panos_toolbox/
  cli.py          single entry point and tool registry
  common/         config (env/.env credentials), logging
  firewall/       PAN-OS tools + client.py
  scm/            SCM tools + client.py
  tsf/            offline TSF tools (analyzer.py)
scripts/          zero-install launchers (run from a checkout)
tests/            pytest suite (no real devices)
docs/             contributor docs
```

See [docs/adding-a-tool.md](docs/adding-a-tool.md) to add a script.

## Development

```bash
pytest
ruff check .
```

## License

AGPL-3.0 — see [LICENSE](LICENSE).

# panos-toolbox

Scripts to manage Palo Alto Networks firewalls (PAN-OS / Panorama) and
Strata Cloud Manager (SCM), exposed through one CLI: `panos-toolbox <area> <tool>`.

| Area        | Purpose                                   | Dependency       |
|-------------|-------------------------------------------|------------------|
| `firewall/` | PAN-OS firewall and Panorama automation   | `pan-os-python`  |
| `scm/`      | Strata Cloud Manager automation           | `pan-scm-sdk`    |
| `tsf/`      | Offline Tech Support File analysis        | none (stdlib)    |

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[all,dev]'      # or only '.[firewall]' / '.[scm]'
cp .env.example .env             # then fill in credentials
```

## Tools

| Command | Description |
|---------|-------------|
| `panos-toolbox tsf analyze <tsf.tgz ...> -o out/` | Interactive HTML report (throughput, pps, cps, sessions, CPU by group) from a TSF's `dp-monitor.*` files |

Run `panos-toolbox` with no arguments for the full list.

## Layout

```
src/panos_toolbox/
  cli.py          single entry point and tool registry
  common/         config (env/.env credentials), logging
  firewall/       PAN-OS tools + client.py
  scm/            SCM tools + client.py
  tsf/            offline TSF tools (analyzer.py)
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

GPL-3.0 — see [LICENSE](LICENSE).

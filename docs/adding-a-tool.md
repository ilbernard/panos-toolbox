# Adding a tool

1. Pick the area: `firewall/` (PAN-OS / Panorama), `scm/` (Strata Cloud Manager)
   or `tsf/` (offline file analysis). Create `src/panos_toolbox/<area>/<tool>.py`.
2. Expose `main(argv=None)` that parses its own arguments with `argparse`
   (use `prog='panos-toolbox <area> <tool>'`) and returns an exit code.
3. Get a connection from `<area>/client.py` and credentials from the
   environment (`common/config.py`); never accept secrets as CLI arguments.
4. Register it in `TOOLS` in `src/panos_toolbox/cli.py`.
5. Add a test under `tests/` (mock the SDK; no test may touch a real device).

Tools run as `panos-toolbox <area> <tool>` or `python -m panos_toolbox.<area>.<tool>`.

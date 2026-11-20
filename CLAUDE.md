# CLAUDE.md

Context for Claude Code sessions in this repository.

## Purpose

`panos-toolbox` is a set of scripts and tools for Palo Alto Networks PAN-OS firewalls,
Panorama and Strata Cloud Manager (SCM). It is written and maintained by Alberto, a
senior network security engineer. Code, docs and GUI text are in **English**, even
though conversations with Alberto are often in Italian. Reply to him in the language he
uses; write everything in the repository in English.

## Layout

See `README.md` ("Layout" section) for the full tree. In short:

- `src/panos_toolbox/cli.py`: single entry point and tool registry (`TOOLS`).
- `src/panos_toolbox/firewall/`: PAN-OS and Panorama tools; `console/` is the Panorama desktop GUI.
- `src/panos_toolbox/scm/`: Strata Cloud Manager tools.
- `src/panos_toolbox/tsf/`: offline Tech Support File analysis (standard library only).
- `src/panos_toolbox/gp/`: offline GlobalProtect client log analysis (standard library only).
- `src/panos_toolbox/common/`: config (environment and `.env`), logging, per-user paths.
  `common/credits.py` is the credits box (git repository and author links) at the top of every
  HTML report (TSF, TSF summary, GlobalProtect, runtime); edit the links there only.
- `tests/`: pytest suite. `scripts/`: zero-install launchers.

## Console tool (Panorama GUI)

Read these before changing anything in `firewall/console/`:

- `docs/console/architecture.md`: layers, data flow, threading, TLS injection.
- `docs/console/adding-an-action.md`: how to add an action, test checklist, destructive-action rules.
- `docs/console/decisions.md`: ADR log (the project memory for design choices).
- `docs/console/roadmap.md`: next steps and open questions.

**Keep these up to date:** update `docs/console/decisions.md` and
`docs/console/roadmap.md` whenever a design decision is made or a roadmap item is done.

## TSF report (`src/panos_toolbox/tsf/`)

- `analyzer.py` collects data and renders; `report_template.py` is the page (HTML, CSS, JS);
  `pow_perf.py` parses and evaluates `debug dataplane pow performance` (`POW_THRESHOLDS`, flags);
  `pow_glossary.py` is the counter glossary (partly inferred, confidence D/G/I/U) behind the tooltips.
- `interface_errors.py` parses and evaluates the interface counters (`show counter interface all`,
  `show interface ...`) for the Interface Errors tab (`IF_THRESHOLDS`, flags, cross-check with the global
  counters); `if_glossary.py` is its counter glossary and reuses the same tooltips.
- No global help page: every tab/panel has its own collapsed help in `report_help.py`
  (`SECTION_HELP`, placeholders `__HB_<id>__`/`__HP_<id>__` in the template). When you add a panel
  or a flag code, add its help and document the code there (a test checks flag codes).
- Counter names and column headers in the report use `glName()` / `glTag()` for the shared tooltip.
- Standard library only; the report is one offline HTML file.

## GlobalProtect log report (`src/panos_toolbox/gp/`)

Docs: `docs/gp/analyzer.md` (usage, report, limitations) and `docs/gp/log-formats.md` (log formats).

- `bundle.py` reads the zip/folder in memory with limits; `logs.py` parses records;
  `client_config.py` builds the configuration sections and state; `timeline.py` builds the attempts;
  `checks.py` holds the findings (`GP_THRESHOLDS`, `FLAG_HELP`); `analyzer.py` is the CLI and renderer;
  `report_template.py` is the page (HTML, CSS, JS).
- No global help page: every tab/panel has its own collapsed help in `report_help.py`
  (`SECTION_HELP`, placeholders `__HB_<id>__`/`__HP_<id>__` in the template).
- Every flag code is documented in `FLAG_HELP` (a test checks it); keep the findings table in
  `docs/gp/analyzer.md` consistent with it.
- Standard library only; the report is one offline HTML file (`textContent` only, no `innerHTML`).
- Tests use synthetic data only and must never contain real customer names, hosts, users or IPs.
  Real sample bundles are untrusted data: never copy values from them into the repository.

## Runtime analyzer (`src/panos_toolbox/runtime/`)

Docs: `docs/runtime/plan.md` (decisions, steps), `docs/runtime/command-notes.md` (command formats),
`docs/runtime/analyzer.md` (usage, report, limitations).

- `capture` (needs paramiko, extra `runtime`): `commands.py` is the allow-list (no free-form command),
  `ssh.py` the shell transport (CLI echo redraw, tolerant prompt), `capture.py` the two-period scheduler
  (full cycle every X s, fast tick every X/6 s, minimum 1 s) and the inflight monitoring handling
  (on at start, always OFF at the end, loud warning if the final `no` is not confirmed), `store.py` the
  capture folder (one raw file per command, delimited samples, gzip), `fake.py` the in-memory transport
  and simulated clock used by the tests.
- `report` (standard library only): `parse_*.py` parse the raw outputs, `analysis.py` builds the data
  blob and the findings (`RT_THRESHOLDS`), `analyzer.py` renders and is the CLI, `report_template.py` is
  the page, `report_help.py` holds the per-section help and `FLAG_HELP` (a test checks every flag code).
- The delta counter baseline is global on the firewall: rates use `Elapsed time since last sampling`
  (padded number, use `\s+`), not the local clock.
- Special backlog tags (id >= 2^31, "NOT valid session id") are never queried with `show session id`.
- The XML API transport is a future item (see the plan).
- Tests use synthetic data only (`tests/runtime_synthetic.py` builds a capture through the real engine
  with `FakeTransport`); real captures are untrusted data and must never be copied into the repository.

## Commands

Install for development (from the repo root):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[console,dev]'
```

Tests (no test may contact a real device or Panorama):

```bash
QT_QPA_PLATFORM=offscreen pytest
```

`tests/conftest.py` sets the Qt offscreen platform and skips `tests/test_console_gui.py`
when PySide6 is not installed. Tests that need pan-os-python use
`pytest.importorskip("panos")`.

Lint:

```bash
ruff check
```

The existing code has 7 ruff findings that are not regressions: 5 in
`src/panos_toolbox/tsf/analyzer.py`, 1 in `src/panos_toolbox/cli.py` (unused `argparse`
import) and 1 in `scripts/tsf_analyzer.py`. Do not fix them as part of unrelated work,
and keep new code free of findings.

Run the CLI: `panos-toolbox` (no arguments lists the tools), or `python -m panos_toolbox.<area>.<tool>`.

## Python compatibility

- Target Python 3.9+ (`requires-python = ">=3.9"`). The `scm` area needs 3.10+ because of `pan-scm-sdk`.
- Put `from __future__ import annotations` at the top of modules that use modern type hints (the console code does this).

## Rules

- **Secrets:** never accept passwords, API keys or tokens as command-line arguments.
  Read them from the environment (`common/config.py`, `.env`) or from the GUI login.
- **Logging:** never log passwords or API keys, including in exception messages.
- **Tests:** never contact a real device. Use fake sessions and sample XML. Mock the SDK.
- **Scope:** change only what the task needs. Do not reformat unrelated code.
- **Documentation language:** English only.

## Adding a CLI tool

See `docs/adding-a-tool.md`. In short:

1. Create `src/panos_toolbox/<area>/<tool>.py` (or a package) with `main(argv=None)`.
2. Parse arguments with `argparse`, using `prog='panos-toolbox <area> <tool>'`.
3. Register the tool in `TOOLS` in `src/panos_toolbox/cli.py`.
4. Add a test under `tests/` that mocks the SDK.

## Adding a console action

See `docs/console/adding-an-action.md`. In short: create
`src/panos_toolbox/firewall/console/actions/<name>.py` with an `Action` subclass decorated
with `@register`. No other registration is needed. Then add tests with a fake session.

## Git workflow

- The default working branch is `develop`. Create feature branches as `feature/<name>`
  from `develop`, and commit there.
- Merge `develop` into `main` **only when Alberto explicitly says so**.
- Never commit directly to `main`. Do not push to `main`.
- Commit and push only when asked.

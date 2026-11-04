# Panorama console: architecture

The console is a desktop GUI (PySide6/Qt, Windows/macOS/Linux) that logs in to a
Panorama, lists the firewalls it manages and runs actions on the selected ones.
Every firewall operation goes through Panorama (`target=<serial>`); the console never
connects to a managed firewall directly.

Entry points:

- `panos-toolbox firewall console [--profiles-file FILE] [-v]`
- `python -m panos_toolbox.firewall.console`

Both call `main()` in `src/panos_toolbox/firewall/console/__init__.py`, which imports
`gui/app.py` lazily so the CLI still starts (with a helpful message) when PySide6 or
pan-os-python is missing.

## Layers

All paths are under `src/panos_toolbox/firewall/console/`.

| Layer | Files | Role | Qt allowed |
|-------|-------|------|------------|
| core | `core/models.py` | `ManagedDevice`, `COLUMNS`, filter `matches()`, natural `sort_key()` | no |
| core | `core/panorama.py` | `ConnectionParams`, `PanoramaSession` (`connect`, `list_devices`, `restart_device`), XML parsers, `PanoramaError`, `Inventory` | no |
| core | `core/tls.py` | `build_ssl_context()` | no |
| core | `core/profiles.py` | `Profile`, `ProfileStore` (saved connections, JSON) | no |
| core | `core/actions.py` | `Action` base class, `Confirmation`, `ActionResult`, `ActionRegistry`, `register`, `run_action` | no |
| actions | `actions/__init__.py` | `discover()`: imports every action module so it registers itself | no |
| actions | `actions/reboot.py` | `RebootAction` (id `reboot`), the first action | no |
| gui | `gui/app.py` | `run()`: login, main window, "switch connection" loop | yes |
| gui | `gui/login.py` | `LoginDialog`: host, credentials, TLS options, saved profiles | yes |
| gui | `gui/main_window.py` | `MainWindow`: filter box, table, menus, toolbar, status bar | yes |
| gui | `gui/table.py` | `DeviceTableModel`, `DeviceFilterProxy` (filter and sort) | yes |
| gui | `gui/dialogs.py` | `ConfirmDialog` (typed confirmation), `ResultsDialog` | yes |
| gui | `gui/workers.py` | `Worker` (`QRunnable`), `Runner` (keeps workers alive) | yes |

Rules that keep the layers honest:

- Nothing under `core/` or `actions/` imports Qt. Check with
  `grep -rn PySide src/panos_toolbox/firewall/console/core src/panos_toolbox/firewall/console/actions`
  (should print nothing).
- Actions know nothing about the GUI. The GUI builds its toolbar, Actions menu and
  right-click menu from `registry.all()`, asks the action for `confirmation()`, then
  calls `run_action()`.
- `core/panorama.py` imports pan-os-python lazily, so the core modules import without it.

## Data flow

```
 LoginDialog (gui/login.py)
    | Worker -> PanoramaSession.connect(params, username, password)
    v
 PanoramaSession (core/panorama.py)        keeps only the API key in memory
    | Worker -> list_devices()
    |            show devices all, show devicegroups, show templates, show template-stack
    v
 Inventory(devices, warnings)
    v
 DeviceTableModel -> DeviceFilterProxy -> QTableView   (filter box, sort)
    |  user selects rows; an action is enabled only if available_for() is None for all
    v
 Action.confirmation(devices) --> ConfirmDialog   (None = no dialog)
    |  Worker -> run_action(action, session, devices, on_progress)
    |              for each device, in order:
    |                available_for() again -> "skipped: ..." or
    |                action.run(session, device) -> message, or exception -> failed
    v
 list[ActionResult] --> ResultsDialog;  status bar says "Refresh to see the current state"
```

Step by step:

1. `app.run()` creates the `ProfileStore`, calls `discover()`, shows `LoginDialog`.
2. `LoginDialog` validates the fields, builds `ConnectionParams`, and starts a `Worker`
   that calls `PanoramaSession.connect`. The password field is cleared right after the
   worker is started. On success the profile is saved (without password) if "Remember"
   is ticked.
3. `MainWindow(session, registry)` shows, then `refresh()` runs `session.list_devices()`
   in a worker. Group or template lookup failures do not fail the load: they are
   collected as `Inventory.warnings` and shown as a tooltip on the firewall count.
4. Selecting rows calls `_update_actions()`, which enables each action only when
   `available_for()` returns `None` for every selected device. The reason is shown as
   a tooltip.
5. Triggering an action shows `confirmation()` if it returns a `Confirmation`. For
   `require_typed`, the OK button stays disabled until the word is typed.
6. `run_action()` runs in a worker and reports progress per device. It never stops
   early: a failure on one device is recorded and the next device still runs.
7. `ResultsDialog` lists one row per device: OK or FAILED, with the message.

## Threading model

- Network calls never run on the GUI thread. `gui/workers.py` runs them in
  `QThreadPool.globalInstance()`.
- `Worker.run()` catches every exception and emits `signals.error(str)`; a successful
  call emits `signals.result(object)`. Progress is emitted through `signals.progress`
  (only for actions, `wants_progress=True`).
- Signals are connected to slots on GUI-thread objects, so Qt delivers them on the GUI
  thread. Widgets and models are only touched from slots.
- `Runner` keeps a reference to each `Worker` until its result or error is delivered
  (the worker has `setAutoDelete(False)`), so a worker is never garbage-collected
  while running.
- While an operation runs, `MainWindow._busy` is set: refresh and actions are disabled.
  Closing the window during an operation asks for confirmation, but does not cancel it.

## Where each concern lives

| Concern | Where |
|---------|-------|
| Talking to Panorama (keygen, op commands, restart) | `core/panorama.py` |
| Certificate verification settings | `core/tls.py`, injected in `core/panorama.py` |
| What a firewall row contains, filtering, sorting | `core/models.py` |
| Saved connections (no secrets) | `core/profiles.py`, file location from `common/paths.py` |
| What an action is, how a run is recorded | `core/actions.py` |
| What the Reboot action does and asks for | `actions/reboot.py` |
| Layout, menus, dialogs, threads | `gui/` |
| Logging setup | `common/log.py` (`get_logger`) |

Profiles file location (from `common/paths.py`, file `console_profiles.json`):

- Windows: `%APPDATA%\panos-toolbox\`
- macOS: `~/Library/Application Support/panos-toolbox/`
- Linux: `$XDG_CONFIG_HOME/panos-toolbox/` or `~/.config/panos-toolbox/`

`--profiles-file` overrides it.

## TLS injection

pan-os-python does not verify the Panorama certificate, and it offers no switch for it.
The console therefore:

1. Builds an `ssl.SSLContext` in `core/tls.py` (`build_ssl_context`): verification is
   on by default, against the system trust store or a PEM `ca_file`. Turning it off is
   an explicit per-connection choice.
2. Performs the API key generation itself with `PanXapi(..., ssl_context=context)`.
3. Creates its own subclasses `TlsPanorama` and `ProxiedFirewall` (built lazily in
   `_tls_classes()`, cached with `functools.cache`). Each overrides `generate_xapi()` to
   set the same `ssl_context` on every API client they create.

The GUI shows "certificate NOT verified" in the status bar, and a warning in red on the
login dialog, whenever verification is off. See `decisions.md` ADR-0001.

## Replacing the GUI toolkit

Only `gui/` is toolkit-specific (about 700 lines, 7 files). To replace PySide6 (for
example with another toolkit or a web front end), keep `core/` and `actions/` unchanged
and provide the same behaviour:

- An entry point that matches `firewall/console/__init__.py`: `main()` calls a `run(profiles_file)`.
- A login step that calls `PanoramaSession.connect(params, username, password)` on a
  background thread and forgets the password afterwards.
- A device view that uses `ManagedDevice.matches()` (filter) and `sort_key()` (sort), and
  shows `COLUMNS` in order.
- For each action in `ActionRegistry.all()`: call `available_for()` to enable it, call
  `confirmation()` to ask, and call `run_action()` on a background thread.
- Show the `ActionResult` list and the `Inventory.warnings`.

No file under `core/` or `actions/` needs to change for this.

## Related

- Adding an action: [adding-an-action.md](adding-an-action.md)
- Design decisions: [decisions.md](decisions.md)
- Next steps: [roadmap.md](roadmap.md)

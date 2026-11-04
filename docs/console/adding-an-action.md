# Adding an action to the Panorama console

An action is one operation run on each firewall selected in the console (for example
Reboot). Adding one takes a single new file: the console discovers it automatically and
shows it in the toolbar, the Actions menu and the right-click menu.

Read [architecture.md](architecture.md) first for the layers and the run flow.

## Steps

1. Create `src/panos_toolbox/firewall/console/actions/<name>.py`. Modules whose name
   starts with `_` are skipped by `discover()`.
2. Subclass `Action` from `..core.actions` and decorate the class with `@register`.
3. Set the metadata:
   - `id`: unique string, used as the registry key (`reboot`). Duplicates raise `ValueError`.
   - `label`: text on the toolbar button and menu item.
   - `description`: shown as the tooltip when the action is disabled, and when it is enabled.
   - `destructive`: `True` for anything that changes or interrupts a device.
   - `order`: lower values appear first in menus (Reboot uses `900`).
4. Implement the three methods:
   - `available_for(device)`: return `None` if the action can run on `device`, otherwise a
     short reason. The toolbar button is disabled if any selected device has a reason.
     `run_action()` checks it again per device and records `skipped: <reason>`.
   - `confirmation(devices)`: return `None` to run without a dialog, or a
     `Confirmation(title, text, require_typed)`.
   - `run(session, device)`: perform the operation on one device and return a short
     message. Raise any exception to mark that device as failed; the text is shown.
5. Add tests (see the checklist below).
6. If the change is a design decision or completes a roadmap item, update
   `docs/console/decisions.md` and `docs/console/roadmap.md`.

No other registration is needed. `actions/__init__.py` imports every module in the package.

## Example (illustrative only)

The file below is an **example for this document**. It is not in the repository, and
you must not create it as-is. It is read-only and needs no network call: it reports the
PAN-OS version that Panorama already listed in the inventory.

`src/panos_toolbox/firewall/console/actions/show_version.py` (example):

```python
"""EXAMPLE ONLY: report the PAN-OS version recorded in the inventory."""
from ..core.actions import Action, register


@register
class ShowVersionAction(Action):
    id = "show-version"
    label = "Show PAN-OS version"
    description = "Report the PAN-OS version of the selected firewalls."
    destructive = False
    order = 200

    def run(self, session, device):
        return f"{device.display_name}: PAN-OS {device.sw_version or 'unknown'}"
```

A version read live from the firewall through Panorama would need a new method on
`PanoramaSession` in `core/panorama.py`, modelled on `restart_device` (use `self._op`
for Panorama commands). That is not written yet; see the open questions in
[roadmap.md](roadmap.md).

Example test (also illustrative), in `tests/test_console_core.py` or a new test file:

```python
from panos_toolbox.firewall.console.actions.show_version import ShowVersionAction
from panos_toolbox.firewall.console.core.actions import run_action
from panos_toolbox.firewall.console.core.models import ManagedDevice


def test_show_version_reports_inventory_version():
    device = ManagedDevice("S1", hostname="fw-a", sw_version="10.2.9")
    results = run_action(ShowVersionAction(), session=None, devices=[device])
    assert results[0].ok
    assert "10.2.9" in results[0].message
```

`session=None` is fine here because this action never touches it. Any action that does
use the session must be tested with a fake session (next section).

## Test checklist

Tests must never contact a real device or Panorama. Use a fake session, never
`PanoramaSession.connect`.

- [ ] Fake session: a small object whose methods record their calls, for example
      `restart_device(serial)` appends the serial to a list. Use `monkeypatch` for anything else.
- [ ] `available_for()` returns a reason for each device that must be refused
      (for example a disconnected device) and `None` for the others.
- [ ] `confirmation()` returns `None` or a `Confirmation`; for destructive actions, check
      that it names every device and sets `require_typed` when more than one is selected.
- [ ] `run()` returns the expected message and calls the session exactly as intended.
- [ ] A session error makes `run_action()` return `ok=False` for that device and still runs the others.
- [ ] `discover()` includes the new `id`, and the id is not a duplicate.
- [ ] GUI tests (if the GUI changed): `QT_QPA_PLATFORM=offscreen pytest`. They need PySide6 installed.

Run: `QT_QPA_PLATFORM=offscreen pytest tests/test_console_core.py tests/test_console_gui.py`

## Rules for destructive actions

Set `destructive = True` for any action that interrupts traffic, changes configuration,
or cannot be undone.

- `confirmation()` is required. Its text must list each firewall by name and serial,
  state the consequence (for example "Traffic through these firewalls will be interrupted."),
  and mention HA failover when an HA active member is selected. Reboot does this.
- Return `require_typed` when more than one firewall is selected. Reboot requires the
  word `REBOOT`. Use a clear word, not a generic "OK".
- `available_for()` must refuse devices the action cannot reach through Panorama
  (Reboot refuses disconnected devices).
- `run()` sends the command once per device. Do not retry automatically: a repeated
  destructive command is worse than a reported failure.
- The result message must say what was actually confirmed. Reboot returns
  "command sent (not yet verified ...)" because the console does not check the outcome.
- Never put secrets in messages, logs or exceptions. The API key and password must not appear.
- Keep the confirmation text in sync with what `run()` does, and test both.

## Where the rest of the logic lives

- Thread handling and progress: the GUI runs `run_action()` in a worker. Do not call
  network code from `available_for()` or `confirmation()`: those run on the GUI thread
  and must be fast and offline.
- Results shown to the user come from the `ActionResult` list. Nothing else is shown.

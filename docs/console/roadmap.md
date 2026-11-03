# Panorama console: roadmap

Status of the console (`panos-toolbox firewall console`). Design reasons for past choices
are in [decisions.md](decisions.md). When an item is done, move it to **Done** and add a
dated line to `decisions.md` if a design choice was made.

## Next

1. **Validate against a live Panorama.** Highest priority. The inventory parsing was
   written from pan-os-python's behaviour and canned XML in tests. Check on a real
   Panorama:
   - the XML fields of `show devices all` (`serial`, `hostname`, `ip-address`, `model`,
     `sw-version`, `connected`, `ha/state`);
   - the output of `show devicegroups`, `show templates` and `show template-stack`
     (group and template membership, stack precedence);
   - the HA state values (the Reboot warning relies on the exact string `active`);
   - the behaviour of the proxied restart (`request restart system`, `target=<serial>`)
     and the exact error messages returned for disconnected or unreachable devices.
2. **After-reboot check.** Poll the device after a reboot until it reconnects to
   Panorama, then show the result. Today the result says only "command sent", and the
   user must refresh by hand.
3. **A second action.** Candidates, not yet decided:
   - an operational command runner (run one `show` command on the selection and show the output);
   - a content or PAN-OS version report (per-device version and content release).
   Choosing one is a design decision: record it in `decisions.md`.

## Later

- Multi-vsys support (one firewall, several virtual systems).
- CSV export of the firewall list.
- API-key login and MFA/SAML login (today: local username and password only).
- A direct-to-firewall option (today every operation goes through Panorama, ADR-0003).
- An inventory cache or persistence beyond saved profiles.
- Packaging as standalone executables (for example with PyInstaller).
- GUI translations (Italian).

## Done

- Login to Panorama with username and password (`gui/login.py`, `core/panorama.py`).
- Firewall list with filter across all columns, and natural sorting (`gui/table.py`, `core/models.py`).
- Saved connection profiles without passwords (`core/profiles.py`).
- TLS certificate verification on by default, with an optional CA file and an explicit
  opt-out per connection (ADR-0001).
- Reboot action through Panorama, with typed confirmation for multiple firewalls (`actions/reboot.py`).

## Open questions

- **API key expiry.** The API key is kept for the session (ADR-0002) and is not renewed.
  What does the console do when Panorama rejects it mid-session, and should it ask the
  user to log in again? Not decided.
- **pan-os-python version.** `pyproject.toml` declares `pan-os-python` without a version pin,
  while the TLS design (ADR-0001) was checked against 1.13.1. Should the dependency be
  pinned, and must the `generate_xapi` hooks be re-checked on every upgrade?
- **HA failover wording.** The Reboot warning names members whose HA state is exactly
  `active`. Is that enough for all HA modes (active-passive, active-active), and what
  does Panorama report for a suspended member?
- **Result semantics.** "Command sent" is shown after `restart()` returns. Is there a
  reliable signal in the response that the reboot was accepted by the firewall?
- **Cancelling an operation.** Closing the window does not cancel a running action
  (`gui/main_window.py`). Should running actions be cancellable, and is it safe to cancel
  a restart already sent?
- **Python version support.** The package declares Python 3.9+, but PySide6 and
  pan-os-python minimum versions for each Python version have not been checked.

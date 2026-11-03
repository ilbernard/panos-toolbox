# Panorama console: decisions

Architecture Decision Records for the console. Newest entries are at the bottom.

## How to add an entry

1. Take the next number (`ADR-NNNN`, four digits, no gaps).
2. Add a heading `## ADR-NNNN: <short title>` at the bottom of the file.
3. Fill in the fields below. Keep each one to a few sentences.
   - **Date**: the day the decision was made (YYYY-MM-DD).
   - **Status**: `Proposed`, `Accepted`, `Superseded by ADR-NNNN`, or `Rejected`.
     Never delete an old entry; supersede it instead.
   - **Context**: the situation and the constraints that forced a choice.
   - **Decision**: what was chosen, in one or two sentences.
   - **Consequences**: what this makes easier, harder, or what must be checked later.
4. If the decision changes the roadmap, update [roadmap.md](roadmap.md) too.

---

## ADR-0001: Verify TLS ourselves instead of using pan-os-python's connection

- **Date**: 2026-10-29
- **Status**: Accepted

**Context.** pan-os-python 1.13.1 never verifies the Panorama TLS certificate. Inside
pan-python, `PanXapi` uses an unverified SSL context when `ssl_context` is `None`.
`PanDevice` has no `ssl_context` option, and `PanDevice._retrieve_api_key` builds its own
`PanXapi`, so the username and password would be sent over an unverified connection.

**Decision.** The console performs the key generation itself with
`PanXapi(ssl_context=...)`. The SSL context is built in `core/tls.py`
(`build_ssl_context`) with verification on by default. A PEM CA bundle can be given
(`ca_file`). Turning verification off is an explicit choice per connection. The
objects that talk to Panorama and firewalls are `TlsPanorama` and `ProxiedFirewall`
(in `core/panorama.py`, `_tls_classes()`). They override `generate_xapi()` to inject the
same context into every API call.

**Consequences.**
- Every connection is verified unless the user opts out. The GUI shows a red warning
  when verification is off.
- The console depends on the internal structure of pan-os-python (`generate_xapi`,
  `PanXapi`). A library upgrade must re-check those hooks.
- Verification failures are reported with a message that suggests a CA file or the opt-out.

## ADR-0002: Keep only the API key; never store the password

- **Date**: 2026-10-29
- **Status**: Accepted

**Context.** Re-login after a timeout would need the password, but storing it, even
encrypted, adds a secret to disk that the console would have to protect.

**Decision.** The password is used once, for key generation in `PanoramaSession.connect`.
Only the API key is kept, in memory, for the life of the session. The login field is
cleared as soon as the login worker starts. Saved profiles (`core/profiles.py`, JSON in
the per-user config directory) contain only `hostname`, `username`, `port`,
`verify_tls` and `ca_file`. A `password` key added by hand is ignored when loading.

**Consequences.**
- No password on disk. The user types it at each start.
- When the API key expires, the session is not renewed automatically (see the open
  questions in [roadmap.md](roadmap.md)).
- Python strings cannot be wiped from memory. Clearing the widget is best effort.

## ADR-0003: Every firewall operation goes through Panorama

- **Date**: 2026-10-29
- **Status**: Accepted

**Context.** Managed firewalls are reached through Panorama. Connecting to each one
directly would need its own address reachability and credentials.

**Decision.** All operations use Panorama with `target=<serial>`. `restart_device()`
adds a `ProxiedFirewall` object to the Panorama object, runs `restart()`, then removes it.
The console never connects directly to a managed firewall.

**Consequences.**
- A single set of credentials and a single reachable address are needed.
- Devices that are disconnected from Panorama cannot be acted on. `RebootAction`
  refuses them.
- A direct-to-firewall option is a possible future feature (see [roadmap.md](roadmap.md)).

## ADR-0004: Separate core from GUI; actions are plugins

- **Date**: 2026-10-29
- **Status**: Accepted

**Context.** The toolkit may change, and new actions are expected regularly.

**Decision.** `core/` has no Qt imports and holds the Panorama session, the device
model, profiles and the action API. `actions/` holds one module per action, registered
with `@register`, and `discover()` imports them all. `gui/` builds the UI from the
registry and only calls the core.

**Consequences.**
- Replacing the GUI means rewriting `gui/` (about 700 lines). `core/` and `actions/`
  stay unchanged.
- Adding an action is one file. It needs no GUI change. See
  [adding-an-action.md](adding-an-action.md).
- Action code is testable without a GUI, using a fake session.

## ADR-0005: Use PySide6 (Qt) rather than Tkinter

- **Date**: 2026-10-29
- **Status**: Accepted

**Context.** The console needs large tables with filtering and sorting, background
threads, and room to grow.

**Decision.** PySide6 is the GUI toolkit. It is an optional dependency
(`panos-toolbox[console]`). Tkinter was considered and rejected for table performance,
threading support and future growth.

**Consequences.**
- Installing the console adds PySide6 (a large dependency). The CLI still starts without it.
- Qt threading rules apply: network calls run in `QThreadPool` workers and report
  through signals (see [architecture.md](architecture.md#threading-model)).

## ADR-0006: Phase-1 scope

- **Date**: 2026-10-29
- **Status**: Accepted

**Context.** The first version has to be useful quickly and safe to run.

**Decision.** Phase 1 supports:

- login with a local Panorama username and password only (no MFA, SAML or API-key login);
- a single virtual system (no multi-vsys handling);
- filtering the firewall list (yes), but no CSV export;
- saved connection profiles only, with no inventory cache or persistence;
- the Reboot action as the first action.

**Consequences.** These limits are listed as "Later" in [roadmap.md](roadmap.md). Anything
outside them must be treated as unsupported until it is built and tested.

## ADR-0007: Inventory sources and degraded group/template lookups

- **Date**: 2026-10-29
- **Status**: Accepted

**Context.** The firewall list needs data from several Panorama commands. A failure in
one of the lookups should not hide the whole list.

**Decision.** `PanoramaSession.list_devices()` runs `show devices all` (serial, hostname,
ip-address, model, sw-version, connected, ha/state). It also runs `show devicegroups`,
`show templates` and `show template-stack`. The "Template / stack" column shows the
template stack when the device belongs to one, otherwise its template(s). A failed
group or template lookup becomes a warning: the list is still shown, and the warning
appears as a tooltip on the firewall count. A failure of `show devices all` is an error.

**Consequences.**
- The parsing was written against pan-os-python's behaviour and canned XML in tests.
  It has **not yet been validated against a live Panorama** (roadmap item 1).
- Warnings can hide missing group or template data, so the status bar message points
  to the tooltip.

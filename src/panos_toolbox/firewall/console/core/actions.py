"""Action plugin API: what the console can do to the selected firewalls.

An action is a class with a ``run`` method, registered with ``@register``. It knows
nothing about the GUI: the front end builds its menus from the registry, asks for
confirmation when ``confirmation()`` returns something, then calls ``run_action``.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Callable

from .models import ManagedDevice


@dataclass(frozen=True)
class Confirmation:
    """What the user must acknowledge before an action runs."""

    title: str
    text: str
    require_typed: str | None = None  # user must type this word to proceed


@dataclass(frozen=True)
class ActionResult:
    serial: str
    name: str
    ok: bool
    message: str


class Action:
    """Base class for console actions. Subclass, set the metadata, implement ``run``."""

    id = ""
    label = ""
    description = ""
    destructive = False
    order = 100  # lower comes first in menus

    def available_for(self, device: ManagedDevice) -> str | None:
        """Return None if the action can run on ``device``, else a short reason why not."""
        return None

    def confirmation(self, devices: Sequence[ManagedDevice]) -> Confirmation | None:
        """Return a Confirmation to require acknowledgement, or None to run immediately."""
        return None

    def run(self, session, device: ManagedDevice) -> str:
        """Perform the action on one device and return a short result message.

        Raise any exception to mark the device as failed; the message is shown to the user.
        """
        raise NotImplementedError


class ActionRegistry:
    def __init__(self):
        self._actions: dict[str, Action] = {}

    def register(self, cls):
        """Class decorator: instantiate and register an Action subclass."""
        action = cls()
        if not action.id:
            raise ValueError(f"{cls.__name__} has no id")
        if action.id in self._actions:
            raise ValueError(f"duplicate action id {action.id!r}")
        self._actions[action.id] = action
        return cls

    def all(self) -> list[Action]:
        return sorted(self._actions.values(), key=lambda a: (a.order, a.label.lower()))

    def get(self, action_id: str) -> Action:
        return self._actions[action_id]


registry = ActionRegistry()
register = registry.register


def run_action(
    action: Action,
    session,
    devices: Sequence[ManagedDevice],
    on_progress: Callable[[int, int, ManagedDevice], None] | None = None,
) -> list[ActionResult]:
    """Run ``action`` on each device in turn; a failure on one never stops the others."""
    results = []
    for index, device in enumerate(devices, start=1):
        if on_progress:
            on_progress(index, len(devices), device)
        reason = action.available_for(device)
        if reason:
            results.append(ActionResult(device.serial, device.display_name, False, f"skipped: {reason}"))
            continue
        try:
            message = action.run(session, device)
        except Exception as exc:  # report per device, keep going  # noqa: BLE001
            results.append(
                ActionResult(device.serial, device.display_name, False, str(exc) or type(exc).__name__)
            )
        else:
            results.append(ActionResult(device.serial, device.display_name, True, message))
    return results

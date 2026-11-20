"""In-memory transport and simulated clock for the tests (no device, no network)."""
from __future__ import annotations

import datetime as dt
from typing import Callable

from . import commands as C
from .transport import Clock, Transport


class SimClock(Clock):
    """A clock that only moves when ``sleep`` or ``advance`` is called."""

    def __init__(self, start: float = 1000.0,
                 epoch: dt.datetime = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)):
        self.now = start
        self._start = start
        self._epoch = epoch

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(0.0, seconds)

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def utcnow(self) -> dt.datetime:
        return self._epoch + dt.timedelta(seconds=self.now - self._start)


class FakeTransport(Transport):
    """Answers allowed commands from a dict of fixed texts or callables.

    ``cost`` is the simulated seconds each command takes (needs a SimClock).
    """

    def __init__(self, responses: dict[str, object] | None = None,
                 clock: SimClock | None = None, cost: float = 0.2):
        self.responses = dict(responses or {})
        self.clock = clock
        self.cost = cost
        self.log: list[tuple[float, str]] = []
        self.closed = False
        self.fail_ok: set = set()  # commands that report "no prompt back"

    def run(self, cmd: str, timeout: float | None = None) -> tuple[str, bool]:
        C.check_allowed(cmd)
        self.log.append((self.clock.now if self.clock else 0.0, cmd))
        if self.clock:
            self.clock.advance(self.cost)
        resp = self.responses.get(cmd, "")
        if callable(resp):
            resp = resp(cmd)
        return str(resp) if resp else "\n", cmd not in self.fail_ok

    def close(self) -> None:
        self.closed = True

    def commands(self) -> list[str]:
        return [c for _, c in self.log]


Responder = Callable[[str], str]

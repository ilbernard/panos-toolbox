"""Transport interface of the runtime analyzer.

A transport runs one allowed CLI command and returns its output. The SSH implementation is in
``ssh.py``; ``fake.py`` holds the in-memory one used by the tests. The XML API is a future
transport (see ``docs/runtime/plan.md``).
"""
from __future__ import annotations

import datetime as dt
import time
from abc import ABC, abstractmethod

from .commands import check_allowed


class TransportError(RuntimeError):
    """Connection or login failure. The message never contains credentials."""


class Transport(ABC):
    @abstractmethod
    def run(self, cmd: str, timeout: float | None = None) -> tuple[str, bool]:
        """Runs an allowed command; returns ``(output, ok)``.

        ``ok`` is False when the prompt did not come back in time (the output may be partial).
        """

    @abstractmethod
    def close(self) -> None:
        """Closes the connection (must never raise)."""

    def check(self, cmd: str) -> None:
        check_allowed(cmd)


class Clock:
    """Wall and monotonic time, replaceable in tests."""

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def utcnow(self) -> dt.datetime:
        return dt.datetime.now(dt.timezone.utc)

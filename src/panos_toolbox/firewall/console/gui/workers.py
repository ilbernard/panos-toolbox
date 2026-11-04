"""Run blocking calls (network) off the GUI thread."""
from __future__ import annotations

from PySide6 import QtCore


class _Signals(QtCore.QObject):
    result = QtCore.Signal(object)
    error = QtCore.Signal(str)
    progress = QtCore.Signal(str)


class Worker(QtCore.QRunnable):
    """Call ``fn(*args)`` in the global thread pool; report via ``signals``.

    ``fn`` may take a ``progress`` keyword (callable accepting a string) when
    ``wants_progress`` is True. Connect signals to methods of a QObject living in the
    GUI thread so delivery is queued onto that thread.
    """

    def __init__(self, fn, *args, wants_progress=False):
        super().__init__()
        self.setAutoDelete(False)  # lifetime is managed by Runner
        self._fn = fn
        self._args = args
        self._wants_progress = wants_progress
        self.signals = _Signals()

    @QtCore.Slot()
    def run(self):
        try:
            if self._wants_progress:
                outcome = self._fn(*self._args, progress=self.signals.progress.emit)
            else:
                outcome = self._fn(*self._args)
        except Exception as exc:  # shown to the user, never silently dropped  # noqa: BLE001
            self.signals.error.emit(str(exc) or type(exc).__name__)
        else:
            self.signals.result.emit(outcome)


class Runner(QtCore.QObject):
    """Starts workers and keeps them referenced until they finish."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._active = set()

    def start(self, worker, on_result, on_error, on_progress=None):
        self._active.add(worker)
        worker.signals.result.connect(on_result)
        worker.signals.error.connect(on_error)
        if on_progress:
            worker.signals.progress.connect(on_progress)
        # Release after delivery of either signal.
        worker.signals.result.connect(lambda _=None, w=worker: self._active.discard(w))
        worker.signals.error.connect(lambda _=None, w=worker: self._active.discard(w))
        QtCore.QThreadPool.globalInstance().start(worker)

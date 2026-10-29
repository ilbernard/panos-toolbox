"""Application bootstrap: login, main window, optional "switch connection" loop."""
from __future__ import annotations

import sys

from PySide6 import QtWidgets

from ..actions import discover
from ..core.profiles import ProfileStore
from .login import LoginDialog
from .main_window import MainWindow


def run(profiles_file=None):
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
    app.setApplicationName("panos-toolbox console")
    app.setQuitOnLastWindowClosed(False)  # we decide when to quit (see the loop below)
    store = ProfileStore(profiles_file)
    registry = discover()

    while True:
        login = LoginDialog(store)
        if login.exec() != QtWidgets.QDialog.Accepted or login.session is None:
            return 0
        window = MainWindow(login.session, registry)
        window.closed.connect(app.quit)
        window.show()
        window.refresh()
        app.exec()
        if not window.switch_requested:
            return 0

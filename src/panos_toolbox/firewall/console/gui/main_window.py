"""Main window: filterable firewall table plus one toolbar button per registered action."""
from __future__ import annotations

from PySide6 import QtCore, QtGui, QtWidgets

from panos_toolbox import __version__

from ..core.actions import run_action
from .dialogs import ConfirmDialog, ResultsDialog
from .table import DeviceFilterProxy, DeviceTableModel
from .workers import Runner, Worker


class MainWindow(QtWidgets.QMainWindow):
    closed = QtCore.Signal()

    def __init__(self, session, registry, parent=None):
        super().__init__(parent)
        self.session = session
        self.registry = registry
        self.switch_requested = False
        self._busy = False
        self._runner = Runner(self)
        self._action_buttons = []  # (Action, QAction)
        self.setWindowTitle(f"Panorama console – {session.hostname}")
        self.resize(1200, 640)

        self._model = DeviceTableModel(self)
        self._proxy = DeviceFilterProxy(self)
        self._proxy.setSourceModel(self._model)

        self._filter = QtWidgets.QLineEdit()
        self._filter.setPlaceholderText("Filter: type words, all must match any column (Ctrl+F)")
        self._filter.setClearButtonEnabled(True)
        self._filter.textChanged.connect(self._on_filter_changed)

        self._table = QtWidgets.QTableView()
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, QtCore.Qt.AscendingOrder)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.selectionModel().selectionChanged.connect(self._update_actions)

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.addWidget(self._filter)
        layout.addWidget(self._table)
        self.setCentralWidget(central)

        self._build_menus_and_toolbar()
        self._build_status_bar()
        self._update_actions()

    # -- construction ------------------------------------------------------------------

    def _build_menus_and_toolbar(self):
        self._refresh_act = QtGui.QAction("Refresh", self)
        self._refresh_act.setShortcut("F5")
        self._refresh_act.setToolTip("Reload the firewall list from Panorama (F5)")
        self._refresh_act.triggered.connect(self.refresh)

        switch_act = QtGui.QAction("Switch connection…", self)
        switch_act.triggered.connect(self._switch_connection)
        quit_act = QtGui.QAction("Quit", self)
        quit_act.setShortcut("Ctrl+Q")
        quit_act.triggered.connect(self.close)
        about_act = QtGui.QAction("About", self)
        about_act.triggered.connect(self._about)
        find_act = QtGui.QAction("Filter", self)
        find_act.setShortcut("Ctrl+F")
        find_act.triggered.connect(self._filter.setFocus)
        self.addAction(find_act)

        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction(self._refresh_act)
        file_menu.addAction(switch_act)
        file_menu.addSeparator()
        file_menu.addAction(quit_act)
        self._actions_menu = self.menuBar().addMenu("&Actions")
        self.menuBar().addMenu("&Help").addAction(about_act)

        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(QtCore.Qt.ToolButtonTextOnly)
        toolbar.addAction(self._refresh_act)
        toolbar.addSeparator()
        for action in self.registry.all():
            qaction = QtGui.QAction(action.label, self)
            qaction.triggered.connect(lambda _checked=False, a=action: self._trigger(a))
            toolbar.addAction(qaction)
            self._actions_menu.addAction(qaction)
            self._action_buttons.append((action, qaction))

    def _build_status_bar(self):
        tls = "certificate verified" if self.session.verify_tls else "certificate NOT verified"
        self._conn_label = QtWidgets.QLabel(
            f"{self.session.username}@{self.session.hostname} · {tls}"
        )
        if not self.session.verify_tls:
            self._conn_label.setStyleSheet("color: #c62828; font-weight: bold;")
        self._count_label = QtWidgets.QLabel("")
        self._progress = QtWidgets.QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setMaximumWidth(120)
        self._progress.setVisible(False)
        status = self.statusBar()
        status.addPermanentWidget(self._progress)
        status.addPermanentWidget(self._count_label)
        status.addPermanentWidget(self._conn_label)

    # -- state -------------------------------------------------------------------------

    def _set_busy(self, busy, message=""):
        self._busy = busy
        self._progress.setVisible(busy)
        self._refresh_act.setEnabled(not busy)
        if message or not busy:
            self.statusBar().showMessage(message)
        self._update_actions()

    def selected_devices(self):
        rows = sorted(index.row() for index in self._table.selectionModel().selectedRows())
        return [self._model.device_at(self._proxy.mapToSource(self._proxy.index(r, 0)).row()) for r in rows]

    def _action_state(self, action, devices):
        """Return (enabled, tooltip) for an action given the current selection."""
        if self._busy:
            return False, "An operation is in progress"
        if not devices:
            return False, f"{action.description} Select one or more firewalls."
        reasons = []
        for device in devices:
            reason = action.available_for(device)
            if reason:
                reasons.append(f"{device.display_name}: {reason}")
        if reasons:
            return False, "Not available for the selection:\n" + "\n".join(reasons)
        return True, action.description

    @QtCore.Slot()
    def _update_actions(self, *_):
        devices = self.selected_devices()
        for action, qaction in self._action_buttons:
            enabled, tip = self._action_state(action, devices)
            qaction.setEnabled(enabled)
            qaction.setToolTip(tip)
            qaction.setStatusTip(tip)

    @QtCore.Slot(str)
    def _on_filter_changed(self, text):
        self._proxy.set_query(text)
        self._update_counts()

    def _update_counts(self):
        total = self._model.rowCount()
        shown = self._proxy.rowCount()
        connected = sum(1 for r in range(total) if self._model.device_at(r).connected)
        text = f"{total} firewalls ({connected} connected)"
        if shown != total:
            text += f" · {shown} shown"
        self._count_label.setText(text)

    # -- refresh -----------------------------------------------------------------------

    @QtCore.Slot()
    def refresh(self):
        if self._busy:
            return
        self._set_busy(True, f"Loading firewalls from {self.session.hostname}…")
        self._runner.start(Worker(self.session.list_devices), self._on_inventory, self._on_error)

    @QtCore.Slot(object)
    def _on_inventory(self, inventory):
        self._model.set_devices(inventory.devices)
        self._table.resizeColumnsToContents()
        self._update_counts()
        if inventory.warnings:
            self._count_label.setToolTip("\n".join(inventory.warnings))
            message = "Loaded, but device group / template info is incomplete (see tooltip on the count)."
        else:
            self._count_label.setToolTip("")
            message = "Loaded."
        self._set_busy(False, message)

    @QtCore.Slot(str)
    def _on_error(self, message):
        self._set_busy(False, "Failed.")
        QtWidgets.QMessageBox.critical(self, "Error", message)

    # -- actions -----------------------------------------------------------------------

    def _show_context_menu(self, position):
        devices = self.selected_devices()
        if not devices:
            return
        menu = QtWidgets.QMenu(self)
        for _action, qaction in self._action_buttons:
            menu.addAction(qaction)
        menu.exec(self._table.viewport().mapToGlobal(position))

    def _trigger(self, action):
        devices = self.selected_devices()
        enabled, _ = self._action_state(action, devices)
        if not enabled:
            return
        confirmation = action.confirmation(devices)
        if confirmation is not None:
            dialog = ConfirmDialog(confirmation, action.label, self)
            if dialog.exec() != QtWidgets.QDialog.Accepted:
                return
        self._current_action = action

        def job(progress):
            def on_progress(index, total, device):
                progress(f"{action.label}: {device.display_name} ({index}/{total})")

            return run_action(action, self.session, devices, on_progress)

        self._set_busy(True, f"{action.label}…")
        worker = Worker(job, wants_progress=True)
        self._runner.start(worker, self._on_action_done, self._on_error, self._on_progress)

    @QtCore.Slot(str)
    def _on_progress(self, message):
        self.statusBar().showMessage(message)

    @QtCore.Slot(object)
    def _on_action_done(self, results):
        failed = sum(1 for r in results if not r.ok)
        label = self._current_action.label
        self._set_busy(False, f"{label} finished: {len(results) - failed} ok, {failed} failed. Refresh to see the current state.")
        ResultsDialog(f"{label} results", results, self).exec()

    # -- window ------------------------------------------------------------------------

    def _switch_connection(self):
        self.switch_requested = True
        self.close()

    def _about(self):
        QtWidgets.QMessageBox.about(
            self,
            "About",
            f"panos-toolbox {__version__}\nPanorama console\n\nConnected to {self.session.hostname}",
        )

    def closeEvent(self, event):
        if self._busy:
            answer = QtWidgets.QMessageBox.question(
                self,
                "Operation in progress",
                "An operation is still running and will not be cancelled by closing the window.\n"
                "Close anyway?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )
            if answer != QtWidgets.QMessageBox.Yes:
                self.switch_requested = False
                event.ignore()
                return
        event.accept()
        self.closed.emit()

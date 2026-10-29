"""Confirmation and result dialogs for actions."""
from __future__ import annotations

from PySide6 import QtCore, QtWidgets


class ConfirmDialog(QtWidgets.QDialog):
    """Shows what is about to happen. Cancel is the default; an optional word must be typed."""

    def __init__(self, confirmation, action_label, parent=None):
        super().__init__(parent)
        self.setWindowTitle(confirmation.title)
        self.setModal(True)
        self.resize(520, 360)
        layout = QtWidgets.QVBoxLayout(self)

        body = QtWidgets.QPlainTextEdit(confirmation.text)
        body.setReadOnly(True)
        layout.addWidget(body)

        self._required = confirmation.require_typed
        self._typed = None
        if self._required:
            layout.addWidget(QtWidgets.QLabel(f"Type {self._required} to confirm:"))
            self._typed = QtWidgets.QLineEdit()
            self._typed.textChanged.connect(self._update_ok)
            layout.addWidget(self._typed)

        buttons = QtWidgets.QDialogButtonBox()
        self._ok = buttons.addButton(action_label, QtWidgets.QDialogButtonBox.AcceptRole)
        cancel = buttons.addButton(QtWidgets.QDialogButtonBox.Cancel)
        cancel.setDefault(True)
        self._ok.setAutoDefault(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._update_ok()

    def _update_ok(self):
        self._ok.setEnabled(self._typed is None or self._typed.text().strip() == self._required)


class ResultsDialog(QtWidgets.QDialog):
    def __init__(self, title, results, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(640, 320)
        layout = QtWidgets.QVBoxLayout(self)

        failed = sum(1 for r in results if not r.ok)
        summary = "All done." if not failed else f"{failed} of {len(results)} failed."
        layout.addWidget(QtWidgets.QLabel(summary))

        table = QtWidgets.QTableWidget(len(results), 3)
        table.setHorizontalHeaderLabels(["Firewall", "Result", "Message"])
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        for row, result in enumerate(results):
            table.setItem(row, 0, QtWidgets.QTableWidgetItem(f"{result.name} ({result.serial})"))
            table.setItem(row, 1, QtWidgets.QTableWidgetItem("OK" if result.ok else "FAILED"))
            table.setItem(row, 2, QtWidgets.QTableWidgetItem(result.message))
        table.resizeColumnsToContents()
        layout.addWidget(table)

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.button(QtWidgets.QDialogButtonBox.Close).clicked.connect(self.accept)
        layout.addWidget(buttons)
        self.setAttribute(QtCore.Qt.WA_DeleteOnClose, False)

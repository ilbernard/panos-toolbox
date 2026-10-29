"""Qt table model and filter/sort proxy over the device list."""
from __future__ import annotations

from PySide6 import QtCore, QtGui

from ..core.models import COLUMNS

_CONNECTION_COLUMN = [key for key, _ in COLUMNS].index("connection")


class DeviceTableModel(QtCore.QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._devices = []

    def set_devices(self, devices):
        self.beginResetModel()
        self._devices = list(devices)
        self.endResetModel()

    def device_at(self, row):
        return self._devices[row]

    def rowCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self._devices)

    def columnCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(COLUMNS)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return None
        device = self._devices[index.row()]
        key = COLUMNS[index.column()][0]
        if role == QtCore.Qt.DisplayRole:
            return device.value(key)
        if role == QtCore.Qt.ForegroundRole and index.column() == _CONNECTION_COLUMN:
            # The text always says connected/disconnected; colour is only a hint.
            return QtGui.QBrush(QtGui.QColor("#2e7d32" if device.connected else "#c62828"))
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            return COLUMNS[section][1]
        return None


class DeviceFilterProxy(QtCore.QSortFilterProxyModel):
    """Filters rows with ``ManagedDevice.matches`` and sorts with ``ManagedDevice.sort_key``."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._query = ""

    def set_query(self, text):
        self.beginFilterChange()
        self._query = text
        self.endFilterChange()

    def filterAcceptsRow(self, source_row, source_parent):
        return self.sourceModel().device_at(source_row).matches(self._query)

    def lessThan(self, left, right):
        key = COLUMNS[left.column()][0]
        model = self.sourceModel()
        return model.device_at(left.row()).sort_key(key) < model.device_at(right.row()).sort_key(key)

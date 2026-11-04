"""Headless smoke tests for the console GUI (Qt offscreen platform, fake Panorama session)."""
import time

import pytest
from PySide6 import QtCore, QtWidgets

from panos_toolbox.firewall.console.actions import discover
from panos_toolbox.firewall.console.core.models import ManagedDevice
from panos_toolbox.firewall.console.core.panorama import Inventory, PanoramaError
from panos_toolbox.firewall.console.core.profiles import ProfileStore
from panos_toolbox.firewall.console.gui import dialogs, main_window
from panos_toolbox.firewall.console.gui.login import LoginDialog
from panos_toolbox.firewall.console.gui.main_window import MainWindow

DEVICES = [
    ManagedDevice("S1", "fw-b", "10.0.0.11", "PA-440", "10.2.9", True, "active", "DG1", "Stack1"),
    ManagedDevice("S2", "fw-a", "10.0.0.9", "PA-3220", "10.1.14", True, "passive", "DG1", ""),
    ManagedDevice("S3", "fw-c", "10.0.1.1", "PA-440", "10.2.9", False, "", "DG2", ""),
]


@pytest.fixture(scope="module")
def qapp():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def wait_until(condition, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        QtWidgets.QApplication.processEvents()
        if condition():
            return True
        time.sleep(0.01)
    return False


class FakeSession:
    hostname = "pano.example.com"
    username = "admin"
    verify_tls = True

    def __init__(self):
        self.restarted = []

    def list_devices(self):
        return Inventory(list(DEVICES), ["show templates failed: denied"])

    def restart_device(self, serial):
        self.restarted.append(serial)


def make_window(qapp):
    window = MainWindow(FakeSession(), discover())
    window.refresh()
    assert wait_until(lambda: window._model.rowCount() == 3)
    assert wait_until(lambda: not window._busy)
    return window


def select(window, serials):
    window._table.clearSelection()
    sel = window._table.selectionModel()
    for row in range(window._proxy.rowCount()):
        index = window._proxy.index(row, 0)
        source = window._proxy.mapToSource(index).row()
        if window._model.device_at(source).serial in serials:
            sel.select(index, QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows)


def reboot_action(window):
    return next(q for a, q in window._action_buttons if a.id == "reboot")


def test_table_filter_and_natural_ip_sort(qapp):
    window = make_window(qapp)
    assert window._count_label.text().startswith("3 firewalls (2 connected)")
    assert "denied" in window._count_label.toolTip()  # lookup warning surfaced, not swallowed

    window._table.sortByColumn(1, QtCore.Qt.AscendingOrder)  # IP address column
    ips = [window._proxy.index(r, 1).data() for r in range(3)]
    assert ips == ["10.0.0.9", "10.0.0.11", "10.0.1.1"]

    window._filter.setText("pa-440 dg1")
    assert window._proxy.rowCount() == 1 and window._proxy.index(0, 0).data() == "fw-b"
    window._filter.setText("")
    assert window._proxy.rowCount() == 3


def test_reboot_enabled_only_for_connected_selection(qapp):
    window = make_window(qapp)
    reboot = reboot_action(window)
    assert not reboot.isEnabled()  # nothing selected

    select(window, {"S1"})
    assert reboot.isEnabled()

    select(window, {"S1", "S3"})  # S3 is disconnected
    assert not reboot.isEnabled()
    assert "fw-c" in reboot.toolTip() and "not connected" in reboot.toolTip()


def test_reboot_flow_confirms_then_sends(qapp, monkeypatch):
    window = make_window(qapp)
    shown = {}

    def fake_confirm_exec(self):
        shown["text"] = self.findChild(QtWidgets.QPlainTextEdit).toPlainText()
        shown["typed"] = self._typed is not None
        return QtWidgets.QDialog.Accepted

    results = {}
    monkeypatch.setattr(dialogs.ConfirmDialog, "exec", fake_confirm_exec)
    monkeypatch.setattr(main_window.ResultsDialog, "exec", lambda self: results.setdefault("n", 1))

    select(window, {"S1", "S2"})
    window._trigger(discover().get("reboot"))
    assert wait_until(lambda: "n" in results)
    assert sorted(window.session.restarted) == ["S1", "S2"]
    assert shown["typed"] is True  # two firewalls: the confirmation word is required
    assert "fw-a" in shown["text"] and "fw-b" in shown["text"] and "failover" in shown["text"]


def test_reboot_declined_sends_nothing(qapp, monkeypatch):
    window = make_window(qapp)
    monkeypatch.setattr(dialogs.ConfirmDialog, "exec", lambda self: QtWidgets.QDialog.Rejected)
    select(window, {"S1"})
    window._trigger(discover().get("reboot"))
    QtWidgets.QApplication.processEvents()
    assert window.session.restarted == []


def test_confirm_dialog_requires_typed_word(qapp):
    from panos_toolbox.firewall.console.core.actions import Confirmation

    dialog = dialogs.ConfirmDialog(Confirmation("t", "body", require_typed="REBOOT"), "Reboot")
    assert not dialog._ok.isEnabled()
    dialog._typed.setText("reboot")
    assert not dialog._ok.isEnabled()  # exact match only
    dialog._typed.setText("REBOOT")
    assert dialog._ok.isEnabled()


def test_login_success_saves_profile_without_password(qapp, tmp_path):
    seen = {}

    def fake_connect(params, username, password):
        seen.update(params=params, username=username, password=password)
        return FakeSession()

    store = ProfileStore(tmp_path / "p.json")
    dialog = LoginDialog(store, connect_fn=fake_connect)
    dialog._host.setText("pano.example.com")
    dialog._user.setText("admin")
    dialog._password.setText("s3cret")
    dialog._verify.setChecked(False)
    dialog._start_connect()
    assert dialog._password.text() == ""  # cleared as soon as it is handed over
    assert wait_until(lambda: dialog.session is not None)
    assert seen["password"] == "s3cret" and seen["params"].verify_tls is False
    saved = (tmp_path / "p.json").read_text()
    assert "pano.example.com" in saved and "s3cret" not in saved


def test_login_failure_shows_error_and_stays_open(qapp, tmp_path):
    def failing_connect(params, username, password):
        raise PanoramaError("Invalid credentials.")

    dialog = LoginDialog(ProfileStore(tmp_path / "p.json"), connect_fn=failing_connect)
    dialog._host.setText("h")
    dialog._user.setText("u")
    dialog._password.setText("bad")
    dialog._start_connect()
    assert wait_until(lambda: "Invalid credentials" in dialog._status.text())
    assert dialog.session is None and dialog._connect_btn.isEnabled()
    assert not (tmp_path / "p.json").exists()


def test_login_requires_all_fields(qapp, tmp_path):
    dialog = LoginDialog(ProfileStore(tmp_path / "p.json"), connect_fn=lambda *a: None)
    dialog._start_connect()
    assert "required" in dialog._status.text()

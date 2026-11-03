"""Login dialog: Panorama address, credentials, TLS options, saved profiles."""
from __future__ import annotations

from PySide6 import QtCore, QtWidgets

from ..core.panorama import ConnectionParams, PanoramaSession
from ..core.profiles import Profile
from .workers import Runner, Worker

_NEW = "New connection…"


class LoginDialog(QtWidgets.QDialog):
    """Connects to Panorama; on success ``self.session`` holds the PanoramaSession."""

    def __init__(self, store, parent=None, connect_fn=PanoramaSession.connect):
        super().__init__(parent)
        self.setWindowTitle("Connect to Panorama")
        self.setModal(True)
        self.session = None
        self._store = store
        self._connect_fn = connect_fn
        self._runner = Runner(self)
        self._profiles = []

        self._profile_box = QtWidgets.QComboBox()
        self._delete_btn = QtWidgets.QPushButton("Delete")
        self._host = QtWidgets.QLineEdit()
        self._host.setPlaceholderText("panorama.example.com")
        self._port = QtWidgets.QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(443)
        self._user = QtWidgets.QLineEdit()
        self._password = QtWidgets.QLineEdit()
        self._password.setEchoMode(QtWidgets.QLineEdit.Password)
        self._verify = QtWidgets.QCheckBox("Verify the Panorama certificate")
        self._verify.setChecked(True)
        self._ca_file = QtWidgets.QLineEdit()
        self._ca_file.setPlaceholderText("Optional CA bundle (PEM); empty = system trust store")
        self._browse = QtWidgets.QPushButton("Browse…")
        self._remember = QtWidgets.QCheckBox("Remember this connection (the password is never saved)")
        self._remember.setChecked(True)
        self._status = QtWidgets.QLabel()
        self._status.setWordWrap(True)
        self._connect_btn = QtWidgets.QPushButton("Connect")
        self._connect_btn.setDefault(True)
        cancel_btn = QtWidgets.QPushButton("Cancel")

        profile_row = QtWidgets.QHBoxLayout()
        profile_row.addWidget(self._profile_box, 1)
        profile_row.addWidget(self._delete_btn)
        ca_row = QtWidgets.QHBoxLayout()
        ca_row.addWidget(self._ca_file, 1)
        ca_row.addWidget(self._browse)

        form = QtWidgets.QFormLayout()
        form.addRow("Saved connection", profile_row)
        form.addRow("Panorama host", self._host)
        form.addRow("Port", self._port)
        form.addRow("Username", self._user)
        form.addRow("Password", self._password)
        form.addRow("", self._verify)
        form.addRow("CA certificate", ca_row)
        form.addRow("", self._remember)

        buttons = QtWidgets.QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(cancel_btn)
        buttons.addWidget(self._connect_btn)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self._status)
        layout.addLayout(buttons)
        self.setMinimumWidth(480)

        self._profile_box.currentIndexChanged.connect(self._on_profile_selected)
        self._delete_btn.clicked.connect(self._delete_profile)
        self._browse.clicked.connect(self._browse_ca)
        self._verify.toggled.connect(self._on_verify_toggled)
        self._connect_btn.clicked.connect(self._start_connect)
        cancel_btn.clicked.connect(self.reject)

        self._reload_profiles()
        self._on_verify_toggled(self._verify.isChecked())

    # -- profiles ----------------------------------------------------------------------

    def _reload_profiles(self, select=None):
        self._profiles = self._store.load()
        self._profile_box.blockSignals(True)
        self._profile_box.clear()
        self._profile_box.addItem(_NEW)
        for profile in self._profiles:
            self._profile_box.addItem(profile.name)
        index = 0
        if select:
            index = max(0, self._profile_box.findText(select))
        elif self._profiles:
            index = 1
        self._profile_box.setCurrentIndex(index)
        self._profile_box.blockSignals(False)
        self._on_profile_selected(index)

    def _on_profile_selected(self, index):
        self._delete_btn.setEnabled(index > 0)
        if index <= 0:
            return
        profile = self._profiles[index - 1]
        self._host.setText(profile.hostname)
        self._port.setValue(profile.port)
        self._user.setText(profile.username)
        self._verify.setChecked(profile.verify_tls)
        self._ca_file.setText(profile.ca_file)
        self._password.clear()
        self._password.setFocus()

    def _delete_profile(self):
        index = self._profile_box.currentIndex()
        if index > 0:
            self._store.delete(self._profiles[index - 1].name)
            self._reload_profiles()

    def _browse_ca(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "CA certificate", "", "PEM files (*.pem *.crt *.cer);;All files (*)"
        )
        if path:
            self._ca_file.setText(path)

    def _on_verify_toggled(self, checked):
        self._ca_file.setEnabled(checked)
        self._browse.setEnabled(checked)
        if not checked:
            self._set_status(
                "Certificate verification is OFF: the connection can be intercepted.", error=True
            )
        elif self._status.text().startswith("Certificate verification is OFF"):
            self._set_status("")

    # -- connecting --------------------------------------------------------------------

    def _set_status(self, text, error=False):
        self._status.setStyleSheet("color: #c62828;" if error else "")
        self._status.setText(text)

    def _set_busy(self, busy):
        for widget in (
            self._profile_box, self._delete_btn, self._host, self._port, self._user,
            self._password, self._verify, self._ca_file, self._browse, self._remember,
            self._connect_btn,
        ):
            widget.setEnabled(not busy)
        if not busy:
            self._on_verify_toggled(self._verify.isChecked())
            self._delete_btn.setEnabled(self._profile_box.currentIndex() > 0)

    def current_profile(self):
        return Profile(
            hostname=self._host.text().strip(),
            username=self._user.text().strip(),
            port=self._port.value(),
            verify_tls=self._verify.isChecked(),
            ca_file=self._ca_file.text().strip() if self._verify.isChecked() else "",
        )

    @QtCore.Slot()
    def _start_connect(self):
        profile = self.current_profile()
        password = self._password.text()
        if not profile.hostname or not profile.username or not password:
            self._set_status("Host, username and password are required.", error=True)
            return
        params = ConnectionParams(
            hostname=profile.hostname,
            port=profile.port,
            verify_tls=profile.verify_tls,
            ca_file=profile.ca_file,
        )
        self._pending_profile = profile
        self._set_busy(True)
        self._set_status(f"Connecting to {profile.hostname}…")
        worker = Worker(self._connect_fn, params, profile.username, password)
        self._runner.start(worker, self._on_connected, self._on_failed)
        self._password.clear()  # not kept in the widget once handed to the worker

    @QtCore.Slot(object)
    def _on_connected(self, session):
        self.session = session
        if self._remember.isChecked():
            try:
                self._store.upsert(self._pending_profile)
            except OSError as exc:  # a failed save must not block the login
                self._set_status(f"Connected, but the profile could not be saved: {exc}")
        self.accept()

    @QtCore.Slot(str)
    def _on_failed(self, message):
        self._set_busy(False)
        self._set_status(message, error=True)
        self._password.setFocus()

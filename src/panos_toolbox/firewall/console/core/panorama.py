"""Panorama session: login with username/password, list managed firewalls, proxy commands.

All firewall operations go through Panorama (``target=<serial>``); the console
never opens a connection to a managed firewall directly.

The password is used once to obtain an API key and is not kept; only the API key
lives in memory for the lifetime of the session.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from functools import cache

from .models import ManagedDevice
from .tls import build_ssl_context

log = logging.getLogger(__name__)


class PanoramaError(Exception):
    """A failure talking to Panorama, with a message fit to show to the user."""

    def __init__(self, message, tls_error=False):
        super().__init__(message)
        self.tls_error = tls_error


@dataclass(frozen=True)
class ConnectionParams:
    hostname: str
    port: int = 443
    verify_tls: bool = True
    ca_file: str = ""
    timeout: int = 60  # seconds per API call


@dataclass
class Inventory:
    devices: list[ManagedDevice]
    warnings: list[str] = field(default_factory=list)


# --- XML parsing (pure functions, unit-tested with sample responses) ---------------------


def _yes(value):
    return (value or "").strip().lower() == "yes"


def _text(entry, path):
    return (entry.findtext(path) or "").strip()


def parse_devices(response):
    """Parse the response of ``show devices all`` into devices (no group/template yet)."""
    devices = []
    for entry in response.findall("result/devices/entry"):
        serial = _text(entry, "serial") or entry.get("name", "").strip()
        if not serial:
            continue
        devices.append(
            ManagedDevice(
                serial=serial,
                hostname=_text(entry, "hostname"),
                ip_address=_text(entry, "ip-address"),
                model=_text(entry, "model"),
                sw_version=_text(entry, "sw-version"),
                connected=_yes(entry.findtext("connected")),
                ha_state=_text(entry, "ha/state"),
            )
        )
    return devices


def parse_membership(response):
    """Map serial -> sorted names from ``show devicegroups`` / ``show templates`` / stacks.

    Works for any ``result/<container>/entry[@name]/devices/entry[@name=serial]`` layout.
    """
    members: dict[str, list[str]] = {}
    for container in response.findall("result/*/entry"):
        name = container.get("name", "").strip()
        for dev in container.findall("devices/entry"):
            serial = dev.get("name", "").strip()
            if name and serial:
                members.setdefault(serial, []).append(name)
    return {serial: sorted(set(names)) for serial, names in members.items()}


def merge_inventory(devices, device_groups, templates, stacks):
    merged = []
    for dev in devices:
        names = stacks.get(dev.serial) or templates.get(dev.serial) or []
        merged.append(
            ManagedDevice(
                serial=dev.serial,
                hostname=dev.hostname,
                ip_address=dev.ip_address,
                model=dev.model,
                sw_version=dev.sw_version,
                connected=dev.connected,
                ha_state=dev.ha_state,
                device_group=", ".join(device_groups.get(dev.serial, [])),
                template=", ".join(names),
            )
        )
    return merged


# --- pan-os-python glue ------------------------------------------------------------------


@cache
def _tls_classes():
    """Panorama/Firewall subclasses that apply our SSL context to every API call."""
    from panos.firewall import Firewall
    from panos.panorama import Panorama

    class TlsPanorama(Panorama):
        ssl_context = None

        def generate_xapi(self):
            xapi = super().generate_xapi()
            xapi.ssl_context = self.ssl_context
            return xapi

    class ProxiedFirewall(Firewall):
        """A firewall reached through its Panorama (``target=<serial>``)."""

        def generate_xapi(self):
            xapi = super().generate_xapi()
            xapi.ssl_context = self.panorama().ssl_context
            return xapi

    return TlsPanorama, ProxiedFirewall


def _explain(exc, params):
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text or "CertificateError" in text:
        return (
            f"Certificate of {params.hostname} could not be verified. Provide the CA "
            "certificate, or disable certificate verification for this connection."
        ), True
    return text or exc.__class__.__name__, False


class PanoramaSession:
    """An authenticated Panorama connection. Build it with :meth:`connect`."""

    def __init__(self, panorama, params, username):
        self._panorama = panorama
        self.params = params
        self.username = username

    @property
    def hostname(self):
        return self.params.hostname

    @property
    def verify_tls(self):
        return self.params.verify_tls

    @classmethod
    def connect(cls, params, username, password):
        """Log in and return a session. Raises :class:`PanoramaError`."""
        try:
            from pan.xapi import PanXapi, PanXapiError
        except ImportError as exc:
            raise PanoramaError(
                "pan-os-python is not installed (pip install 'panos-toolbox[console]')"
            ) from exc

        context = build_ssl_context(params.verify_tls, params.ca_file or None)
        try:
            xapi = PanXapi(
                api_username=username,
                api_password=password,
                hostname=params.hostname,
                port=params.port,
                timeout=params.timeout,
                ssl_context=context,
            )
            xapi.keygen()
            api_key = xapi.api_key
        except PanXapiError as exc:
            message, tls = _explain(exc, params)
            raise PanoramaError(message, tls_error=tls) from exc
        finally:
            xapi = None  # drop the object holding the password

        tls_panorama, _ = _tls_classes()
        panorama = tls_panorama(
            params.hostname, api_key=api_key, port=params.port, timeout=params.timeout
        )
        panorama.ssl_context = context
        log.info("connected to Panorama %s as %s", params.hostname, username)
        return cls(panorama, params, username)

    def _op(self, command):
        try:
            return self._panorama.op(command)
        except Exception as exc:  # third-party boundary: surface a readable message
            message, tls = _explain(exc, self.params)
            raise PanoramaError(f"'{command}' failed: {message}", tls_error=tls) from exc

    def _membership(self, command, warnings):
        try:
            return parse_membership(self._op(command))
        except PanoramaError as exc:
            log.warning("%s", exc)
            warnings.append(str(exc))
            return {}

    def list_devices(self):
        """Return the managed firewalls. Group/template lookups degrade to warnings."""
        devices = parse_devices(self._op("show devices all"))
        warnings: list[str] = []
        device_groups = self._membership("show devicegroups", warnings)
        templates = self._membership("show templates", warnings)
        stacks = self._membership("show template-stack", warnings)
        return Inventory(merge_inventory(devices, device_groups, templates, stacks), warnings)

    def restart_device(self, serial):
        """Send ``request restart system`` to a firewall through Panorama."""
        _, proxied_firewall = _tls_classes()
        firewall = proxied_firewall(serial=serial)
        # pan-os-python defaults to 1200 s, which would freeze a batch on one unreachable device.
        firewall.timeout = self.params.timeout
        self._panorama.add(firewall)
        try:
            firewall.restart()
        except Exception as exc:
            message, tls = _explain(exc, self.params)
            raise PanoramaError(f"restart of {serial} failed: {message}", tls_error=tls) from exc
        finally:
            self._panorama.remove(firewall)


def parse_xml(text):
    """Convenience for tests and tooling: parse an XML string."""
    return ET.fromstring(text)

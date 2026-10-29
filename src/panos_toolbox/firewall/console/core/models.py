"""Data model for firewalls managed by Panorama."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# (attribute/key, column header) in display order.
COLUMNS = (
    ("hostname", "Hostname"),
    ("ip_address", "IP address"),
    ("serial", "Serial"),
    ("model", "Model"),
    ("sw_version", "PAN-OS"),
    ("connection", "Connection"),
    ("ha_state", "HA state"),
    ("device_group", "Device group"),
    ("template", "Template / stack"),
)

_VERSION_TOKEN = re.compile(r"\d+|[A-Za-z]+")


def _version_key(text):
    return tuple((0, int(t)) if t.isdigit() else (1, t.lower()) for t in _VERSION_TOKEN.findall(text))


def _ip_key(text):
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return (99, 0, text)
    return (ip.version, int(ip), "")


@dataclass(frozen=True)
class ManagedDevice:
    """One firewall as reported by Panorama."""

    serial: str
    hostname: str = ""
    ip_address: str = ""
    model: str = ""
    sw_version: str = ""
    connected: bool = False
    ha_state: str = ""
    device_group: str = ""
    template: str = ""  # template stack if assigned to one, otherwise template(s)

    @property
    def display_name(self):
        return self.hostname or self.serial

    @property
    def connection(self):
        return "connected" if self.connected else "disconnected"

    def value(self, key):
        """Text shown for a column key (see COLUMNS)."""
        return str(getattr(self, key, "") or "")

    def matches(self, query):
        """True if every whitespace-separated word of ``query`` appears in any column."""
        words = query.lower().split()
        if not words:
            return True
        haystack = " ".join(self.value(key) for key, _ in COLUMNS).lower()
        return all(word in haystack for word in words)

    def sort_key(self, key):
        """Comparable value for sorting a column (IPs and versions sort naturally)."""
        text = self.value(key)
        if key == "ip_address":
            return _ip_key(text)
        if key == "sw_version":
            return _version_key(text)
        return text.lower()

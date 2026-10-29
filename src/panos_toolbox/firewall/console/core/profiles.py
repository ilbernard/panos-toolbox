"""Saved connection profiles. A profile never contains a password or API key."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from panos_toolbox.common.paths import user_config_dir

log = logging.getLogger(__name__)

PROFILES_FILENAME = "console_profiles.json"
_FORMAT_VERSION = 1


@dataclass
class Profile:
    hostname: str
    username: str = ""
    port: int = 443
    verify_tls: bool = True
    ca_file: str = ""

    @property
    def name(self):
        return f"{self.username}@{self.hostname}" if self.username else self.hostname

    def to_dict(self):
        return {
            "hostname": self.hostname,
            "username": self.username,
            "port": self.port,
            "verify_tls": self.verify_tls,
            "ca_file": self.ca_file,
        }

    @classmethod
    def from_dict(cls, data):
        """Build from stored data; unknown keys (e.g. a hand-added password) are ignored."""
        hostname = str(data.get("hostname", "")).strip()
        if not hostname:
            raise ValueError("profile without hostname")
        port = int(data.get("port", 443))
        if not 1 <= port <= 65535:
            raise ValueError(f"invalid port {port}")
        return cls(
            hostname=hostname,
            username=str(data.get("username", "")).strip(),
            port=port,
            verify_tls=bool(data.get("verify_tls", True)),
            ca_file=str(data.get("ca_file", "")).strip(),
        )


class ProfileStore:
    """JSON file with the saved profiles, one per ``user@host``."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else user_config_dir() / PROFILES_FILENAME

    def load(self) -> list[Profile]:
        if not self.path.is_file():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            entries = raw["profiles"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            backup = self.path.with_suffix(".json.bak")
            log.warning("unreadable profiles file %s (%s); moving it to %s", self.path, exc, backup)
            try:
                os.replace(self.path, backup)
            except OSError:
                pass
            return []
        profiles = []
        for entry in entries:
            try:
                profiles.append(Profile.from_dict(entry))
            except (ValueError, TypeError, AttributeError) as exc:
                log.warning("skipping invalid profile entry: %s", exc)
        return profiles

    def save(self, profiles: list[Profile]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": _FORMAT_VERSION, "profiles": [p.to_dict() for p in profiles]}
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)

    def upsert(self, profile: Profile) -> None:
        profiles = [p for p in self.load() if p.name != profile.name]
        profiles.append(profile)
        profiles.sort(key=lambda p: p.name.lower())
        self.save(profiles)

    def delete(self, name: str) -> None:
        self.save([p for p in self.load() if p.name != name])

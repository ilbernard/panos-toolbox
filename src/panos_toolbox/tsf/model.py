"""Data containers shared by the TSF reader and the analyzer (standard library only)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FamilyInventory:
    """What was found for one source family (e.g. "dp-monitor", "cli")."""
    family: str
    found: list[str] = field(default_factory=list)       # member names seen
    read: list[str] = field(default_factory=list)        # members whose content was read
    truncated: list[str] = field(default_factory=list)   # read, but only partially
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (name, reason)
    errors: dict[str, str] = field(default_factory=dict)  # member -> read error message
    # List-only families (archive.LIST_ONLY_PREFIX): regular files whose NAME and size were
    # recorded without opening them, and directories seen. Such members are in `found` but
    # never in `read`.
    listed: list[str] = field(default_factory=list)
    sizes: dict[str, int] = field(default_factory=dict)  # listed member -> size in bytes
    dirs: list[str] = field(default_factory=list)


@dataclass
class Inventory:
    """Inventory of an archive or directory, filled while it is read."""
    families: dict[str, FamilyInventory] = field(default_factory=dict)
    # Members rejected before reaching any family: (name, reason). Reasons:
    # "unsafe path", "link", "special file".
    skipped: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)       # e.g. a limit was hit
    members_seen: int = 0
    bytes_read: int = 0                                  # expanded bytes kept in memory

    def family(self, name: str) -> FamilyInventory:
        fam = self.families.get(name)
        if fam is None:
            fam = self.families[name] = FamilyInventory(name)
        return fam

    def skipped_count(self, reason: str | None = None) -> int:
        return sum(1 for _n, r in self.skipped if reason is None or r == reason)


@dataclass
class Collected:
    """Result of analyzer.collect(): same meaning as the former 5-tuple, plus inventory."""
    samples: list[dict[str, Any]]
    offsets: set
    n_files: int
    pow_data: dict[str, Any] | None
    ifc_data: dict[str, Any] | None
    inventory: Inventory = field(default_factory=Inventory)
    # Conflicting duplicate samples (dp, t, kept_src, dropped_src), first one kept.
    conflicts: list = field(default_factory=list)
    status: str = 'complete'                             # findings.analysis_status()
    # dp_health.new_store() filled by the panio resource-monitor parser, or None.
    dp_health: dict[str, Any] | None = None
    # mp_monitor.new_store() filled by the mp-monitor memory/processes parser, or None.
    mp_data: dict[str, Any] | None = None
    # system_health.new_store() filled from the CLI dump and the core file names, or None.
    sys_data: dict[str, Any] | None = None

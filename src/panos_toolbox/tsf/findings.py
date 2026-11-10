"""Findings model of the TSF report (standard library only).

A Finding is one observation (code, level, text) with an optional scope (what it is
about) and references to the source file/line it comes from. This module also derives
the status of a report module and of the whole analysis from findings and inventory.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .model import Inventory

# Finding levels, from least to most severe.
INFO = 'info'
WARNING = 'warning'
CRITICAL = 'critical'
LEVELS = (INFO, WARNING, CRITICAL)

# Module status: the worst level among the findings, or no data at all.
OK = 'ok'
NO_DATA = 'no_data'

# Analysis status: partial when input was cut short or samples conflict.
COMPLETE = 'complete'
PARTIAL = 'partial'

# Level names used by the flags of pow_perf.py / interface_errors.py.
FLAG_LEVELS = {'info': INFO, 'warn': WARNING, 'crit': CRITICAL}


@dataclass
class SourceRef:
    file: str
    line: int | None = None


@dataclass
class Finding:
    code: str
    level: str
    text: str
    scope: str = ''
    refs: list[SourceRef] = field(default_factory=list)


def module_status(findings: Iterable[Finding], has_data: bool) -> str:
    """'no_data' without data; else 'critical', 'warning' or 'ok'.

    Info findings never raise the status.
    """
    if not has_data:
        return NO_DATA
    worst = OK
    for f in findings:
        if f.level == CRITICAL:
            return CRITICAL
        if f.level == WARNING:
            worst = WARNING
    return worst


def analysis_status(inventory: Inventory, n_conflicts: int) -> str:
    """'partial' when any member was truncated, a limit note exists or samples conflict."""
    if n_conflicts > 0 or inventory.notes:
        return PARTIAL
    if any(fam.truncated for fam in inventory.families.values()):
        return PARTIAL
    return COMPLETE


def from_flags(flags: Iterable[dict[str, Any]], *, scope: str = '',
               refs: Iterable[SourceRef] | None = None, code_key: str = 'code',
               level_key: str = 'level', text_key: str = 'text') -> list[Finding]:
    """Converts flag dicts ({'code', 'level', 'text'}) into Findings, read-only.

    pow_perf.py and interface_errors.py use the levels 'info', 'warn' and 'crit', mapped
    to 'info', 'warning' and 'critical'. The flags are not modified. `scope` and `refs`
    (copied for each finding) come from the caller, since a flag does not carry them.
    A flag with an unknown level raises ValueError.
    """
    out = []
    for fl in flags:
        raw = fl[level_key]
        if raw in FLAG_LEVELS:
            level = FLAG_LEVELS[raw]
        elif raw in LEVELS:
            level = raw
        else:
            raise ValueError(f'unknown flag level: {raw!r}')
        out.append(Finding(fl[code_key], level, fl[text_key], scope,
                           [SourceRef(r.file, r.line) for r in refs or ()]))
    return out

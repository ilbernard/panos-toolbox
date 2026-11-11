"""Source coverage view of the TSF report (standard library only).

Turns the inventory, the samples and the conflicts of a Collected into a JSON-serializable
dict: for each source family what was found, read, truncated or skipped, which time range
the dp-monitor and mp-monitor files cover and which samples conflicted. It answers "what did this
analysis actually look at?", so that a missing or partial source is never mistaken for
a clean one.
"""
from __future__ import annotations

import os
from typing import Any

from . import mp_monitor
from .model import Collected

# Families the analyzer knows about; listed even when no member was found ("absent").
KNOWN_FAMILIES = ('dp-monitor', 'mp-monitor', 'cli')
MAX_CONFLICTS = 200

# Family states, in the order they are reported.
ABSENT = 'absent'            # no member of the family at all
UNREAD = 'unread'            # members found, none could be read
ZERO_SAMPLES = 'zero_samples'  # dp-/mp-monitor members read, no sample extracted
TRUNCATED = 'truncated'      # at least one member read only in part (tail kept)
ERROR = 'error'              # at least one member hit a read error
CONFLICT = 'conflict'        # dp-monitor samples with the same DP and time but other values
OK = 'ok'


def _time_ranges(samples) -> dict[str, dict[str, int]]:
    """Per source file (base name): sample count, first and last timestamp (ms UTC)."""
    out: dict[str, dict[str, int]] = {}
    for s in samples:
        if s.get('dp') == 'ALL':          # synthetic aggregate rows
            continue
        r = out.setdefault(s['src'], {'n': 0, 'first': s['t'], 'last': s['t']})
        r['n'] += 1
        r['first'] = min(r['first'], s['t'])
        r['last'] = max(r['last'], s['t'])
    return out


def _family_row(name: str, fam, ranges, conflicts, mp_ranges=None) -> dict[str, Any]:
    found = list(fam.found) if fam else []
    read = set(fam.read) if fam else set()
    trunc = set(fam.truncated) if fam else set()
    errors = dict(fam.errors) if fam else {}
    skipped = dict(fam.skipped) if fam else {}
    is_dp = name == 'dp-monitor'
    is_mp = name == 'mp-monitor'
    if is_mp:
        ranges = mp_ranges or {}
    members = []
    for m in found:
        base = os.path.basename(m)
        if m in errors:
            state, detail = 'error', errors[m]
        elif m in skipped:
            state, detail = 'skipped:' + skipped[m], skipped[m]
        elif m in trunc:
            state, detail = 'truncated', ''
        elif m in read:
            state, detail = 'read', ''
        else:                     # found but never reached (a total limit stopped reading)
            state, detail = 'skipped:not read', 'not read'
        row: dict[str, Any] = {'name': m, 'state': state, 'detail': detail,
                               'samples': None, 'first': None, 'last': None}
        if (is_dp or is_mp) and m in read:
            r = ranges.get(base)
            row['samples'] = r['n'] if r else 0
            if r:
                row['first'], row['last'] = r['first'], r['last']
        members.append(row)
    n_conf = len(conflicts) if is_dp else 0
    n_read = len(read)
    n_error = len(errors)
    n_trunc = len([m for m in found if m in trunc and m not in errors])
    row_first = row_last = None
    n_samples = None
    if is_dp or is_mp:
        got = [m for m in members if m['samples']]
        n_samples = sum(m['samples'] or 0 for m in members)
        if got:
            row_first = min(m['first'] for m in got)
            row_last = max(m['last'] for m in got)
    states = []
    if not found:
        states.append(ABSENT)
    else:
        if n_read == 0:
            states.append(UNREAD)
        if (is_dp or is_mp) and n_read > 0 and n_samples == 0:
            states.append(ZERO_SAMPLES)
        if n_trunc:
            states.append(TRUNCATED)
        if n_error:
            states.append(ERROR)
        if n_conf:
            states.append(CONFLICT)
        if not states:
            states.append(OK)
    return {'family': name, 'states': states, 'found': len(found), 'read': n_read,
            'truncated': n_trunc, 'errors': n_error, 'skipped': len(skipped),
            'samples': n_samples, 'first': row_first, 'last': row_last,
            'conflicts': n_conf, 'members': members}


def build_coverage(collected: Collected) -> dict[str, Any]:
    """Source coverage view of a Collected (JSON-serializable).

    Keys: status ('complete'/'partial'), archive (False for a single-file input, where
    only a minimal view is possible), families (one row per family, known ones first, see
    _family_row), skipped (archive-level members rejected: [{'name', 'reason'}]), notes
    (limit notes), conflicts ({'total', 'shown', 'items': [{'dp', 't', 'kept', 'dropped'}]},
    capped at MAX_CONFLICTS) and summary (list of short reasons the analysis is partial).
    """
    inv = collected.inventory
    conflicts = collected.conflicts
    ranges = _time_ranges(collected.samples)
    mp_ranges = mp_monitor.source_ranges(collected.mp_data)
    is_archive = bool(inv.families or inv.skipped or inv.members_seen)
    names = list(KNOWN_FAMILIES) + sorted(n for n in inv.families if n not in KNOWN_FAMILIES)
    families = []
    if is_archive:
        families = [_family_row(n, inv.families.get(n), ranges, conflicts, mp_ranges) for n in names]
    skipped = [{'name': n, 'reason': r} for n, r in inv.skipped]
    items = [{'dp': dp, 't': t, 'kept': kept, 'dropped': dropped}
             for dp, t, kept, dropped in conflicts[:MAX_CONFLICTS]]
    reasons = []
    n_trunc = sum(f['truncated'] + f['errors'] for f in families)
    if n_trunc:
        reasons.append(f'{n_trunc} member(s) read only in part')
    if conflicts:
        reasons.append(f'{len(conflicts)} conflicting duplicate sample(s)')
    if inv.notes:
        reasons.append('; '.join(inv.notes))
    notes = list(inv.notes)
    if not is_archive:
        notes.append('Single-file input: source coverage is only meaningful for archives '
                     'and directories.')
    return {'status': collected.status, 'archive': is_archive, 'families': families,
            'skipped': skipped, 'notes': notes,
            'conflicts': {'total': len(conflicts), 'shown': len(items), 'items': items},
            'summary': reasons}

"""Verified correlations of the System health tab (step 7, standard library only).

One check so far, ``crash_link`` in the group ``Correlations``: it links the software components
that are NOT running (rows of ``show system software status`` whose State is not ``running``)
to the kernel crash events of ``var/log/messages`` (segfault, general protection, oom-kill) by
NORMALISED PROCESS NAME. It is a pure function of the System health view (the ``software`` view
and ``logs.kernel``): nothing is parsed here and no other flag is changed.

Normalisation of a name (:func:`normalize_name`):

* lowercase, surrounding blanks removed;
* a ``(ppid:N)`` or ``(ppid:*)`` suffix is removed;
* a trailing ``+`` (truncation marker of the software status) is removed and remembered;
* nothing else is touched. In particular a worker index is part of the name: ``pan_task_0`` and
  ``pan_task_1`` (or ``all_task_N``) are different processes.

Matching (:func:`names_match`), software name ``s`` against kernel comm ``c``:

* equal after normalisation: match;
* the kernel truncates the command name to 15 characters (Linux ``TASK_COMM_LEN`` is 16 with the
  NUL), so a comm of exactly 15 characters matches a software name that starts with it;
* a software name that carried the ``+`` marker is truncated too: it matches a comm that starts
  with it.
Everything else is no match (no fuzzy matching, no substring matching).

Status per non-running component:

* ``confirmed``: exactly one distinct crash process matches (all its types are listed);
* ``ambiguous``: more than one distinct crash process matches (typically a 15-character comm
  and a prefix shared by several names); all candidates are listed;
* ``no_match``: the kernel log was read and no crash process matches;
* ``not_evaluable``: there is no kernel log in the TSF, or the software status is missing or
  empty.

``CRASH_LINK`` (info) is raised for each confirmed or ambiguous component. It is context: it
never changes the level of another flag. The check is ``ok`` when it has data (also when all
processes are running: nothing to correlate) and ``no_data`` when it is not evaluable.
"""
from __future__ import annotations

import re
from typing import Any

from .findings import from_flags, module_status

FLAG_CODES = ('CRASH_LINK',)
CODE_CHECK = {'CRASH_LINK': 'crash_link'}
GROUP_CORRELATIONS = 'Correlations'
COMM_LEN = 15                  # Linux task command name, without the NUL
MAX_LINK_FLAGS = 30            # CRASH_LINK findings; the rest is summarised in one finding
STATUSES = ('confirmed', 'ambiguous', 'no_match', 'not_evaluable')
PPID_RE = re.compile(r'\(ppid:[^)]*\)\s*$')


def normalize_name(name) -> tuple:
    """Returns (normalised name, truncated) for a process name; see the module docstring."""
    s = PPID_RE.sub('', (name or '').strip().lower()).strip()
    truncated = s.endswith('+')
    if truncated:
        s = s[:-1]
    return s, truncated


def names_match(sw_name, comm) -> bool:
    """True when the software status name `sw_name` and the kernel comm `comm` are the same
    process under the rules of the module docstring."""
    s, trunc = normalize_name(sw_name)
    c, _ = normalize_name(comm)
    if not s or not c:
        return False
    if s == c:
        return True
    if len(c) == COMM_LEN and s.startswith(c):
        return True
    return trunc and c.startswith(s)


def _flag(subject, code, level, text):
    return {'code': code, 'level': level, 'text': text, 'subject': subject,
            'check': CODE_CHECK[code]}


def _crash_groups(events):
    """Kernel events grouped by normalised process: {name: [event, ...]}."""
    groups: dict[str, list] = {}
    for e in events:
        name, _ = normalize_name(e['process'])
        if name and name != '(unknown)':
            groups.setdefault(name, []).append(e)
    return groups


def _match_text(matches):
    return '; '.join(f'{m["process"]} {m["type"]} x{m["count"]}' for m in matches)


def evaluate_correlations(sys_view) -> dict[str, Any]:
    """Builds the correlation view from a System health view (after log events were applied).

    Keys: 'present' (software status with rows), 'kernel_present', 'n_bad', 'counts'
    ({status: n}), 'items' ([{process, type, slot, role, title, state, status, matches
    [{process, type, count, files}], text}]), 'check' (a check dict like system_health's, group
    ``Correlations``, id ``crash_link``) and 'findings' (CRASH_LINK, info). The view is not
    modified.
    """
    sw = sys_view.get('software') or {}
    kernel = ((sys_view.get('logs') or {}).get('kernel')) or {}
    sw_present = bool(sw.get('present') and sw.get('total'))
    k_present = bool(kernel.get('present'))
    groups = _crash_groups(kernel.get('events') or []) if k_present else {}
    items: list[dict[str, Any]] = []
    for b in sw.get('blocks') or []:
        for r in b['bad']:
            matched = sorted(n for n in groups if names_match(r['name'], n))
            if not sw_present or not k_present:
                status = 'not_evaluable'
            elif not matched:
                status = 'no_match'
            else:
                status = 'confirmed' if len(matched) == 1 else 'ambiguous'
            matches = [{'process': e['process'], 'type': e['type'], 'count': e['count'],
                        'files': list(e['files'])} for n in matched for e in groups[n]]
            items.append({'process': r['name'], 'type': r['type'], 'slot': b['slot'],
                          'role': b['role'], 'title': b['title'], 'state': r['state'],
                          'status': status, 'matches': matches})
    counts = {s: sum(1 for i in items if i['status'] == s) for s in STATUSES}
    flags = []
    linked = [i for i in items if i['status'] in ('confirmed', 'ambiguous')]
    for i in linked[:MAX_LINK_FLAGS]:
        if i['status'] == 'confirmed':
            text = (f'{i["process"]} ({i["title"]}) is {i["state"]} and the kernel log shows '
                    f'{_match_text(i["matches"])} for the same process name: the crash is a '
                    f'likely reason it is not running.')
        else:
            text = (f'{i["process"]} ({i["title"]}) is {i["state"]} and more than one crashed '
                    f'process name matches it ({_match_text(i["matches"])}): the link is '
                    f'ambiguous.')
        flags.append(_flag(i['process'], 'CRASH_LINK', 'info', text + ' (informational)'))
    if len(linked) > MAX_LINK_FLAGS:
        flags.append(_flag('other processes', 'CRASH_LINK', 'info', (
            f'{len(linked) - MAX_LINK_FLAGS} more not-running process(es) linked to kernel '
            f'crashes: ' + ', '.join(i['process'] for i in linked[MAX_LINK_FLAGS:][:10]) + '.')))

    if not sw_present:
        has, value, note = False, '', 'No software status in the CLI dump.'
    elif not items:
        has, value, note = True, 'all processes running', 'all processes running - nothing to correlate'
    elif not k_present:
        has, value, note = False, '', (f'{len(items)} process(es) not running, but there is no '
                                       f'kernel log (var/log/messages) in the input.')
    else:
        has, note = True, ''
        value = f'{len(items)} not running: ' + ', '.join(
            f'{counts[s]} {s.replace("_", " ")}' for s in STATUSES if counts[s])
    status = module_status(from_flags(flags), has)
    check = {'id': 'crash_link', 'group': GROUP_CORRELATIONS,
             'title': 'Not-running processes vs kernel crashes',
             'source': 'show system software status; var/log/messages', 'status': status,
             'value': value, 'note': note, 'n_flags': len(flags)}
    return {'present': sw_present, 'kernel_present': k_present, 'n_bad': len(items),
            'counts': counts, 'items': items, 'check': check, 'findings': flags}


def apply_to_system_view(sys_view):
    """Appends the Correlations check and findings to a System health view (in place) and
    returns it. Call it after the log events were applied. The overall status is not touched
    (the check only carries info findings)."""
    cv = evaluate_correlations(sys_view)
    sys_view['checks'].append(cv['check'])
    sys_view['findings'].extend(cv['findings'])
    sys_view['correlations'] = {k: cv[k] for k in
                                ('present', 'kernel_present', 'n_bad', 'counts', 'items')}
    return sys_view

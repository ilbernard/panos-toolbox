"""System health of the TSF report (standard library only).

Reads four sources of the TSF and turns them into per-check statuses, flags and the tables
behind them:

* ``show system software status`` (CLI dump): the state of every software group and process.
* ``debug dataplane show cfg-memstat statistics`` (CLI dump): configuration memory allocators.
* ``show running global-ippool`` and ``show running ippool`` (CLI dump): NAT DIP/DIPP pools.
* The NAMES of the archive members under ``opt/dpfs/var/cores/`` and ``var/cores/`` (core
  files). Their content is never read: the archive layer only lists name and size.

CLI dump. ``tmp/cli/techsupport_*.txt`` is a sequence of sections. A section starts with a line
``> <command>`` (a prompt such as ``admin@fw(active)> <command>`` is accepted too) and ends at
the next such line. :func:`iter_cli_sections` splits a dump this way (there was no shared helper:
pow_perf and interface_errors each split on their own); later steps of the System health tab
reuse it. The first occurrence of a command wins; a repeat in another file is ignored with a
warning.

Formats (verified on a PA-5410 / PAN-OS 11.1 and a PA-850 / PAN-OS 10.2 TSF):

* ``show system software status``: one or more blocks ``Slot N, Role X``, a dashed line, a
  header ``Type Name State Info`` and rows ``Group|Process <name> <state> [(pid: N)]``. All
  rows seen were ``running``.
* ``cfg-memstat``: ``VSYS Config Allocator Usage : 40960KB (13% of 299904KB)`` and
  ``POLICY CACHE USAGE : 3456KB ( 2% of 157280KB)`` (spacing varies). The percentage is
  recomputed from used and total (the printed one is truncated to an integer); the printed
  value is used only when the total is 0. The policy cache is printed twice, after a
  ``POLICY CACHE (ACTIVE)`` and after a ``POLICY CACHE (PASSIVE)`` header (each with its size);
  both usage lines are kept (role ``active`` / ``passive``) and evaluated as separate subjects.
  A usage line without such header has no role. UNVERIFIED: on multi-DP devices the command may print
  one block per DP. A block is closed by a repeated allocator line or by a ``DP dpN:``-like
  header; blocks are kept separate and labelled with the DP name (or ``block N``).
* ``show running global-ippool`` ends with ``Usable NAT DIP/DIPP shared memory size: N``,
  ``Used NAT DIP/DIPP shared memory size: N(x%)``, ``Dynamic IP NAT Pool: N(x%)`` and
  ``Dynamic IP/Port NAT Pool: N(x%)``. The pool table above them is not used.
* ``show running ippool``: per ``VSYS n has m NAT rules, DIP and DIPP rules:`` a table
  ``Rule Type Used Available Mem Size Ratio [Persistent Min Max]``. Rule names can contain
  spaces, so a row is parsed with a regex anchored on the Type value and the numbers after it.
  Used % = Used / (Used + Available) x 100.

Flags (same dict structure as the other modules, so findings.from_flags works; the extra keys
``subject`` and ``check`` are ignored by it):

* ``PROC_NOT_RUNNING`` (crit, one per ``Slot N, Role X`` block): Group or Process rows whose
  State is not ``running``.
* ``CFG_MEMORY`` (warn at ``cfg_mem_warn``, crit at ``cfg_mem_crit``, AT OR ABOVE; one per
  allocator, so the config allocator and the policy cache are separate subjects).
* ``NAT_POOL`` (warn at ``nat_pool_warn``, at or above): the shared memory, each DIP/DIPP pool
  line, and the rules. Up to ``MAX_RULE_FLAGS`` rules get a flag each; more are aggregated in
  one flag that lists the top ones.
* ``CORE_FILES`` (crit): regular files under the cores directories. A directory alone is not a
  core. No core directory (``absent``) and an empty one (``empty``) are both ok.

A check is ``no_data`` when its command is missing from the dump, or is there without any
usable row (an empty section is never reported as ok). Cores are ``no_data`` only when the input
is not an archive (no member list).

Tune SYS_THRESHOLDS in code with ``evaluate_system_health(store, thresholds={...})`` or on the
command line with the ``--sys-<name>`` options. Unknown keys raise ValueError.
"""
from __future__ import annotations

import re
from typing import Any

from .findings import CRITICAL, OK, WARNING, from_flags, module_status

# Every number used by evaluate_system_health(). Percentages are 0-100, limits AT OR ABOVE.
SYS_THRESHOLDS = {
    'cfg_mem_warn': 50,     # config allocator / policy cache used % (warn)
    'cfg_mem_crit': 90,     # config allocator / policy cache used % (crit)
    'nat_pool_warn': 50,    # NAT shared memory / pool / rule used % (warn, no crit)
}

FLAG_CODES = ('PROC_NOT_RUNNING', 'CFG_MEMORY', 'NAT_POOL', 'CORE_FILES')
# Flag code -> id of the check it belongs to.
CODE_CHECK = {'PROC_NOT_RUNNING': 'software', 'CFG_MEMORY': 'cfg_mem', 'NAT_POOL': 'nat',
              'CORE_FILES': 'cores'}

MAX_RULE_FLAGS = 3          # more offending NAT rules than this are aggregated in one flag
TOP_RULES = 10              # rules listed in the aggregated flag and in the report summary
MAX_LISTED = 30             # names listed in a flag text before "and N more"
MAX_RULES_VIEW = 2000       # NAT rules kept in the view (the worst ones)
GROUP_CLI = 'CLI snapshot'

CMD_SOFTWARE = 'show system software status'
CMD_CFGMEM = 'debug dataplane show cfg-memstat statistics'
CMD_GLOBAL_POOL = 'show running global-ippool'
CMD_RULES = 'show running ippool'
COMMANDS = {CMD_SOFTWARE: 'software', CMD_CFGMEM: 'cfg_mem', CMD_GLOBAL_POOL: 'global_pool',
            CMD_RULES: 'rules'}
CORES_SOURCE = 'opt/dpfs/var/cores/, var/cores/ (archive member names)'

# CLI prompt, e.g. 'admin@PA-560(active)> show system software status'.
PROMPT_RE = re.compile(r'^\S+@\S+?(?:\([^)]*\))?[>#]\s*(.*)$')
SLOT_RE = re.compile(r'^Slot\s+(\d+),\s*Role\s+(\S+)')
SW_ROW_RE = re.compile(r'^(Group|Process)\s+(\S+)\s+(\S+)(?:\s+(.*?))?\s*$')
_PCT = r'(\d+(?:\.\d+)?)'
CFG_ALLOC_RE = re.compile(
    r'^VSYS Config Allocator Usage\s*:\s*(\d+)\s*KB\s*\(\s*' + _PCT + r'\s*%\s+of\s+(\d+)\s*KB\)')
CFG_POLICY_RE = re.compile(
    r'^POLICY CACHE USAGE\s*:\s*(\d+)\s*KB\s*\(\s*' + _PCT + r'\s*%\s+of\s+(\d+)\s*KB\)')
CFG_CACHE_RE = re.compile(r'^POLICY CACHE \((ACTIVE|PASSIVE)\)\s*:\s*(\d+)\s*KB')
CFG_DP_RE = re.compile(r'^(?:(?:DP|target-dp)\s*:?\s*|(?=(?:s\d+\.)?dp\d+\s*:))'
                       r'\*?\.?((?:s\d+\.)?[\w-]+)\s*:?\s*$', re.IGNORECASE)
POOL_USABLE_RE = re.compile(r'^Usable NAT DIP/DIPP shared memory size:\s*(\d+)')
POOL_USED_RE = re.compile(
    r'^Used NAT DIP/DIPP shared memory size:\s*(\d+)\s*\(\s*' + _PCT + r'\s*%\s*\)')
POOL_LINE_RE = re.compile(
    r'^(Dynamic IP/Port|Dynamic IP) NAT Pool:\s*(\d+)\s*\(\s*' + _PCT + r'\s*%\s*\)')
VSYS_RE = re.compile(r'^VSYS\s+(\S+)\s+has\s+(\d+)\s+NAT rules')
RULE_RE = re.compile(
    r'^(?P<rule>.+?)\s+(?P<type>Dynamic IP/Port|Dynamic IP|Static IP)\s+'
    r'(?P<used>\d+)\s+(?P<avail>\d+)\s+(?P<mem>\d+)\s+(?P<ratio>\d+)(?:\s+(?P<rest>.*?))?\s*$')
CORES_RE = re.compile(r'^(?:opt/dpfs/)?var/cores(?:/(.*))?$')

COUNTERS = ('sections', 'duplicates', 'bad_rows')


def new_store() -> dict[str, Any]:
    """Accumulator for parse_system_health() / add_core_members()."""
    return {
        'sections': {},                         # key -> source file of the first occurrence
        'software': {'blocks': []},
        'cfg': {'blocks': []},
        'nat': {'shared': None, 'pools': [], 'rules': [], 'vsys': []},
        'cores': {'listed': False, 'files': [], 'dirs': []},
        'counters': dict.fromkeys(COUNTERS, 0),
    }


def has_data(store) -> bool:
    """True when at least one CLI section was seen or a core file / directory was listed."""
    if not store:
        return False
    c = store['cores']
    return bool(store['sections'] or c['files'] or c['dirs'])


def iter_cli_sections(lines):
    """Yields ``(command, body_lines)`` for every section of a CLI dump.

    A section starts with ``> <command>`` or with a prompt line and ends at the next one. The
    command has its whitespace collapsed. Lines before the first command are dropped.
    """
    cmd, body = None, []
    for raw in lines:
        line = raw.rstrip('\r\n')
        m = PROMPT_RE.match(line)
        if m or line.startswith('> '):
            if cmd is not None:
                yield cmd, body
            cmd = ' '.join((m.group(1) if m else line[2:]).split())
            body = []
        elif cmd is not None:
            body.append(line)
    if cmd is not None:
        yield cmd, body


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def _parse_software(body, store):
    blocks = store['software']['blocks']
    cur = None
    for line in body:
        text = line.strip()
        m = SLOT_RE.match(text)
        if m:
            cur = {'slot': m.group(1), 'role': m.group(2), 'rows': []}
            blocks.append(cur)
            continue
        m = SW_ROW_RE.match(text)
        if m and m.group(3) != 'Info':
            if cur is None:
                cur = {'slot': None, 'role': None, 'rows': []}
                blocks.append(cur)
            cur['rows'].append({'type': m.group(1), 'name': m.group(2), 'state': m.group(3),
                                'info': m.group(4) or ''})


def _parse_cfgmem(body, store):
    blocks = store['cfg']['blocks']
    cur = None
    label = None
    role = size = None          # role and size of the policy cache whose usage line comes next

    def new_block():
        nonlocal cur
        cur = {'label': label, 'config': None, 'policies': []}
        blocks.append(cur)

    for line in body:
        text = line.strip()
        m = CFG_ALLOC_RE.match(text)
        if m:
            if cur is None or cur['config'] is not None:
                new_block()
            cur['config'] = _alloc(m)
            role = size = None
            continue
        m = CFG_POLICY_RE.match(text)
        if m:
            if cur is None or any(p['role'] == role for p in cur['policies']):
                new_block()
            cur['policies'].append(dict(_alloc(m), role=role, size_kb=size))
            role = size = None
            continue
        m = CFG_CACHE_RE.match(text)
        if m:
            role, size = m.group(1).lower(), int(m.group(2))
            continue
        m = CFG_DP_RE.match(text)
        if m:
            label = m.group(1)
            cur = None


def _alloc(m):
    used, printed, total = int(m.group(1)), float(m.group(2)), int(m.group(3))
    pct = round(used / total * 100, 2) if total else printed
    return {'used_kb': used, 'total_kb': total, 'pct': pct, 'printed_pct': printed}


def _parse_global_pool(body, store):
    nat = store['nat']
    usable = None
    for line in body:
        text = line.strip()
        m = POOL_USABLE_RE.match(text)
        if m:
            usable = int(m.group(1))
            continue
        m = POOL_USED_RE.match(text)
        if m:
            used, printed = int(m.group(1)), float(m.group(2))
            pct = round(used / usable * 100, 2) if usable else printed
            nat['shared'] = {'usable': usable, 'used': used, 'pct': pct, 'printed_pct': printed}
            continue
        m = POOL_LINE_RE.match(text)
        if m:
            nat['pools'].append({'name': m.group(1), 'count': int(m.group(2)),
                                 'pct': float(m.group(3))})


def _parse_rules(body, store):
    nat = store['nat']
    vsys = None
    for line in body:
        text = line.strip()
        m = VSYS_RE.match(text)
        if m:
            vsys = m.group(1)
            nat['vsys'].append({'vsys': vsys, 'declared': int(m.group(2)), 'n': 0})
            continue
        m = RULE_RE.match(text)
        if not m:
            continue
        used, avail = int(m.group('used')), int(m.group('avail'))
        rest = (m.group('rest') or '').split()
        persistent = rest[0] if rest and rest[0] in ('yes', 'no') else None
        nums = [int(t) for t in rest[1:] if t.isdigit()]
        total = used + avail
        nat['rules'].append({
            'vsys': vsys, 'rule': m.group('rule'), 'type': m.group('type'), 'used': used,
            'avail': avail, 'mem': int(m.group('mem')), 'ratio': int(m.group('ratio')),
            'persistent': persistent, 'min': nums[0] if len(nums) > 0 else None,
            'max': nums[1] if len(nums) > 1 else None,
            'pct': round(used / total * 100, 2) if total else None})
        if nat['vsys']:
            nat['vsys'][-1]['n'] += 1


def parse_system_health(cli_text_or_lines, src, store, warnings) -> int:
    """Adds the sections of a CLI dump that this module knows to `store`.

    `cli_text_or_lines` is the text of the file or an iterable of lines; `src` is the file name
    used in messages. Returns the number of known sections taken (0 for a file without any).
    The first occurrence of a command wins; a repeat is counted and ignored (with one warning
    per command when it comes from another file).
    """
    lines = cli_text_or_lines.splitlines() if isinstance(cli_text_or_lines, str) \
        else cli_text_or_lines
    cnt = store['counters']
    taken = 0
    for cmd, body in iter_cli_sections(lines):
        key = COMMANDS.get(cmd)
        if key is None:
            continue
        first = store['sections'].get(key)
        if first is not None:
            cnt['duplicates'] += 1
            if first != src:
                warnings.append(f'{src}: "{cmd}" already read from {first}, this copy ignored')
            continue
        store['sections'][key] = src
        cnt['sections'] += 1
        taken += 1
        if key == 'software':
            _parse_software(body, store)
        elif key == 'cfg_mem':
            _parse_cfgmem(body, store)
        elif key == 'global_pool':
            _parse_global_pool(body, store)
        else:
            _parse_rules(body, store)
    return taken


def core_path_kind(logical: str):
    """For an archive path (``.gz`` dropped, a trailing ``/`` for a directory): 'dir', 'file'
    when it is under a cores directory, else None. Used by the analyzer's family selector."""
    m = CORES_RE.match(logical.rstrip('/'))
    if not m:
        return None
    if logical.endswith('/'):
        return 'dir'
    return 'file' if m.group(1) else None


def add_core_members(store, names_sizes, dirs=()) -> None:
    """Records the core directories and files listed from an archive (names and sizes only).

    `names_sizes` is an iterable of ``(name, size)`` for regular files under the cores
    directories (size may be None); `dirs` the directory entries seen. Calling it, even with
    nothing, marks the member list as known (an archive was read): the cores check is then ok
    ("absent" or "empty") instead of no_data.
    """
    c = store['cores']
    c['listed'] = True
    c['files'].extend((n, s) for n, s in names_sizes)
    c['dirs'].extend(dirs)


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def _flag(subject, code, level, text):
    return {'code': code, 'level': level, 'text': text, 'subject': subject,
            'check': CODE_CHECK[code]}


def _more(items, shown):
    return f' and {len(items) - shown} more' if len(items) > shown else ''


def _size(n) -> str:
    if n is None:
        return 'unknown size'
    for unit in ('bytes', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:,} bytes' if unit == 'bytes' else f'{n:,.1f} {unit}'
        n /= 1024
    return ''


def _software_view(store, flags):
    blocks = store['software']['blocks']
    out_blocks = []
    for b in blocks:
        bad = [r for r in b['rows'] if r['state'] != 'running']
        slot = 'Slot ' + b['slot'] + ', Role ' + b['role'] if b['slot'] is not None \
            else 'Software status'
        out_blocks.append({'slot': b['slot'], 'role': b['role'], 'title': slot,
                           'total': len(b['rows']), 'running': len(b['rows']) - len(bad),
                           'bad': bad})
        if bad:
            shown = bad[:MAX_LISTED]
            listing = ', '.join(f'{r["name"]} ({r["type"]}, {r["state"]})' for r in shown)
            flags.append(_flag(slot, 'PROC_NOT_RUNNING', 'crit', (
                f'{slot}: {len(bad)} of {len(b["rows"])} software component(s) not running: '
                f'{listing}{_more(bad, len(shown))}.')))
    total = sum(b['total'] for b in out_blocks)
    return {'present': 'software' in store['sections'], 'blocks': out_blocks, 'total': total,
            'running': sum(b['running'] for b in out_blocks),
            'bad': sum(len(b['bad']) for b in out_blocks)}


def _cfg_view(store, th, flags):
    blocks = store['cfg']['blocks']
    multi = len(blocks) > 1
    out_blocks = []
    for i, b in enumerate(blocks, 1):
        label = b['label'] or (f'block {i}' if multi else '')
        out_blocks.append({'label': label, 'config': b['config'], 'policies': b['policies']})
        for subject, alloc in [('config allocator', b['config'])] + [
                ('policy cache' + (f' ({p["role"]})' if p['role'] else ''), p)
                for p in b['policies']]:
            if alloc is None or alloc['pct'] < th['cfg_mem_warn']:
                continue
            crit = alloc['pct'] >= th['cfg_mem_crit']
            limit = th['cfg_mem_crit'] if crit else th['cfg_mem_warn']
            where = f' ({label})' if label else ''
            subj = subject + (f' {label}' if label else '')
            flags.append(_flag(subj, 'CFG_MEMORY', 'crit' if crit else 'warn', (
                f'Configuration memory, {subject}{where}: {alloc["pct"]:g}% used '
                f'({alloc["used_kb"]:,} KB of {alloc["total_kb"]:,} KB), at or above '
                f'{limit:g}% (warn {th["cfg_mem_warn"]:g}%, crit {th["cfg_mem_crit"]:g}%).')))
    return {'present': 'cfg_mem' in store['sections'], 'blocks': out_blocks}


def _rule_text(r):
    return (f'{r["rule"]} (VSYS {r["vsys"]}, {r["type"]}): {r["used"]:,} used of '
            f'{r["used"] + r["avail"]:,} (used + available), {r["pct"]:g}%')


def _nat_view(store, th, flags):
    nat = store['nat']
    warn = th['nat_pool_warn']
    sh = nat['shared']
    if sh is not None and sh['pct'] >= warn:
        flags.append(_flag('shared memory', 'NAT_POOL', 'warn', (
            f'NAT DIP/DIPP shared memory: {sh["pct"]:g}% used ({sh["used"]:,} of {sh["usable"]:,}'
            f' usable), at or above {warn:g}%.' if sh['usable'] else
            f'NAT DIP/DIPP shared memory: {sh["pct"]:g}% used, at or above {warn:g}%.')))
    for p in nat['pools']:
        if p['pct'] >= warn:
            flags.append(_flag(p['name'] + ' pool', 'NAT_POOL', 'warn', (
                f'{p["name"]} NAT pool: {p["pct"]:g}% of the shared memory ({p["count"]:,}), '
                f'at or above {warn:g}%.')))
    rules = sorted(nat['rules'], key=lambda r: (-(r['pct'] if r['pct'] is not None else -1),
                                                -r['used'], r['vsys'] or '', r['rule']))
    over = [r for r in rules if r['pct'] is not None and r['pct'] >= warn]
    if 0 < len(over) <= MAX_RULE_FLAGS:
        for r in over:
            flags.append(_flag(f'rule {r["vsys"]}/{r["rule"]}', 'NAT_POOL', 'warn', (
                f'NAT rule {_rule_text(r)}, at or above {warn:g}%.')))
    elif over:
        top = over[:TOP_RULES]
        flags.append(_flag('rules', 'NAT_POOL', 'warn', (
            f'{len(over)} NAT rule(s) at or above {warn:g}% used (Used / (Used + Available)); '
            f'top {len(top)}: ' + '; '.join(_rule_text(r) for r in top) + '.')))
    return {
        'present_global': 'global_pool' in store['sections'],
        'present_rules': 'rules' in store['sections'],
        'shared': sh, 'pools': nat['pools'], 'vsys': nat['vsys'],
        'rules': rules[:MAX_RULES_VIEW], 'n_rules': len(rules), 'n_over': len(over),
        'top': rules[:TOP_RULES]}


def _cores_view(store, flags):
    c = store['cores']
    files = sorted(c['files'], key=lambda x: x[0])
    dirs = sorted(set(c['dirs']))
    if files:
        state = 'files'
        shown = files[:MAX_LISTED]
        listing = ', '.join(f'{n} ({_size(s)})' for n, s in shown)
        flags.append(_flag('cores', 'CORE_FILES', 'crit', (
            f'{len(files)} core file(s) in the archive: {listing}{_more(files, len(shown))}.')))
    elif dirs:
        state = 'empty'
    elif c['listed']:
        state = 'absent'
    else:
        state = 'unknown'
    return {'listed': c['listed'], 'state': state, 'dirs': dirs,
            'files': [{'name': n, 'size': s} for n, s in files]}


def _status_for(check_id, flags, has):
    fl = [f for f in flags if f['check'] == check_id]
    return module_status(from_flags(fl), has), len(fl)


def evaluate_system_health(store, thresholds=None) -> dict[str, Any]:
    """Builds the JSON-serialisable view of a parse_system_health() store.

    Keys: 'thresholds'; 'status' (worst of the checks: ok / warning / critical, or no_data when
    none has data); 'checks' (list of {id, group, title, source, status, value, note, n_flags};
    status is one of ok / warning / critical / no_data; `group` lets later steps append checks
    of other kinds to the same list); 'findings' (flag dicts {code, level, text, subject,
    check}); 'software' (present, total, running, bad, blocks: [{slot, role, title, total,
    running, bad: [{type, name, state, info}]}]); 'cfg' (present, blocks: [{label, config,
    policies}] with config = {used_kb, total_kb, pct, printed_pct} or None and policies = list
    of {role (active / passive / None), size_kb, used_kb, total_kb, pct, printed_pct});
    'nat' (present_global, present_rules, shared {usable, used, pct, printed_pct} or
    None, pools [{name, count, pct}], vsys [{vsys, declared, n}], rules (worst first, at most
    MAX_RULES_VIEW) with n_rules and n_over, top = the first TOP_RULES); 'cores' (listed, state
    absent / empty / files / unknown, dirs, files [{name, size}]); 'sources' (command -> file);
    'warnings'. The store is not modified.
    """
    th = dict(SYS_THRESHOLDS)
    unknown = set(thresholds or {}) - set(SYS_THRESHOLDS)
    if unknown:
        raise ValueError('unknown system health threshold(s): ' + ', '.join(sorted(unknown)))
    th.update(thresholds or {})
    store = store or new_store()
    flags: list[dict[str, Any]] = []
    sw = _software_view(store, flags)
    cfg = _cfg_view(store, th, flags)
    nat = _nat_view(store, th, flags)
    cores = _cores_view(store, flags)

    checks = []

    def add(cid, title, source, has, value, note):
        status, n = _status_for(cid, flags, has)
        checks.append({'id': cid, 'group': GROUP_CLI if cid != 'cores' else 'Archive members',
                       'title': title, 'source': source, 'status': status, 'value': value,
                       'note': note, 'n_flags': n})

    # Software status.
    if not sw['present']:
        has, value, note = False, '', 'Command not found in the CLI dump.'
    elif not sw['total']:
        has, value, note = False, '', 'The section has no Group or Process rows.'
    else:
        has, note = True, ''
        value = (f'all {sw["total"]} running' if not sw['bad']
                 else f'{sw["bad"]} not running of {sw["total"]}')
        if len(sw['blocks']) > 1:
            note = f'{len(sw["blocks"])} slot/role blocks.'
    add('software', 'Software processes', CMD_SOFTWARE, has, value, note)

    # Configuration memory.
    allocs = [a for b in cfg['blocks'] for a in [b['config'], *b['policies']] if a]
    if not cfg['present']:
        has, value, note = False, '', 'Command not found in the CLI dump.'
    elif not allocs:
        has, value, note = False, '', 'The section has no allocator usage lines.'
    else:
        has, note = True, ('Several blocks (one per DP?), kept separate; unverified.'
                           if len(cfg['blocks']) > 1 else '')
        parts = []
        cm = [b['config']['pct'] for b in cfg['blocks'] if b['config']]
        pm = [p['pct'] for b in cfg['blocks'] for p in b['policies']]
        if cm:
            parts.append(f'config {max(cm):g}%')
        if pm:
            parts.append(f'policy cache {max(pm):g}%')
        value = ', '.join(parts) + (' (highest)' if len(cfg['blocks']) > 1 else '')
    add('cfg_mem', 'Configuration memory', CMD_CFGMEM, has, value, note)

    # NAT pools.
    have_nat = nat['shared'] is not None or nat['pools'] or nat['vsys'] or nat['n_rules']
    present = nat['present_global'] or nat['present_rules']
    if not present:
        has, value, note = False, '', 'Commands not found in the CLI dump.'
    elif not have_nat:
        has, value, note = False, '', 'The sections have no pool or rule lines.'
    else:
        has, notes = True, []
        parts = []
        if nat['shared'] is not None:
            parts.append(f'shared memory {nat["shared"]["pct"]:g}%')
        else:
            notes.append('no shared memory summary')
        if nat['n_rules']:
            parts.append(f'busiest rule {nat["rules"][0]["pct"]:g}%'
                         if nat['rules'][0]['pct'] is not None else f'{nat["n_rules"]} rule(s)')
        elif nat['present_rules']:
            parts.append('no DIP/DIPP rules')
        if not nat['present_global']:
            notes.append(f'"{CMD_GLOBAL_POOL}" not found')
        if not nat['present_rules']:
            notes.append(f'"{CMD_RULES}" not found')
        value, note = ', '.join(parts), '; '.join(notes)
    add('nat', 'NAT pools', f'{CMD_GLOBAL_POOL}; {CMD_RULES}', has, value, note)

    # Core files.
    st = cores['state']
    if st == 'files':
        has, value, note = True, f'{len(cores["files"])} core file(s)', ''
    elif st == 'empty':
        has, value, note = True, '0 files', 'core directory present, empty'
    elif st == 'absent':
        has, value, note = True, '0 files', 'no core directory in the archive'
    else:
        has, value, note = False, '', 'Input is not an archive: no member list.'
    add('cores', 'Core files', CORES_SOURCE, has, value, note)

    order = {OK: 0, WARNING: 1, CRITICAL: 2}
    statuses = [c['status'] for c in checks if c['status'] in order]
    status = max(statuses, key=lambda s: order[s]) if statuses else 'no_data'
    sources = dict(store['sections'])
    return {'thresholds': th, 'status': status, 'checks': checks, 'findings': flags,
            'software': sw, 'cfg': cfg, 'nat': nat, 'cores': cores, 'sources': sources,
            'warnings': []}

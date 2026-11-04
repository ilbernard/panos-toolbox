"""Parser and heuristics for the interface error/drop counters of a TSF.

Input: the CLI output stored by the TSF (``tmp/cli/*.txt``) or a plain text file, with
these commands (all optional, missing ones are skipped):

* ``show counter interface all``: per interface the physical port counters read from the
  MAC, the hardware counters read from the CPU, and a later "Logical interface counters"
  part (drops, no route, ARP not found, zone protection...).
* ``show interface ethernetX/Y`` (any interface name): link state, zone, IP and the
  detailed physical counters (CRC, fifo overrun, collisions...).
* ``show interface all``: link table of the hardware interfaces and table of the logical
  interfaces (vsys, zone, forwarding, tag, address).
* ``show system info`` and ``show clock``: hostname, model, version, uptime. All counters
  are cumulative since boot, so a short uptime makes them low-significance.
* ``show counter global``: global drop counters, cross-checked with the per-interface sums.
* ``show transceiver all`` and ``show lacp aggregate-ethernet all``: shown when present.

The heuristics are hints for the investigation, not verdicts. Tune IF_THRESHOLDS to the
environment. Flag levels: crit (high), warn (medium), info.

Standard library only. No HTML in this module.
"""
import copy
import re

from . import if_glossary

# Every number used by evaluate_interfaces(). Override any of them with
# evaluate_interfaces(parsed, thresholds={'key': value}); unknown keys raise ValueError.
IF_THRESHOLDS = {
    # Counters are cumulative since boot: a shorter uptime makes them low-significance.
    'short_uptime_s': 3600,
    # Drop percentage test (logical "packets dropped" / received packets).
    'min_packets': 1000,            # received packets needed before the % is judged
    'min_drops': 10,                # and at least this many drops
    'drop_pct_warn': 1.0,           # percent (warn)
    'drop_pct_crit': 10.0,          # percent (crit)
    # Routing / resolution drops per interface.
    'no_route_min': 100,
    'arp_min': 50,
    'l2_min': 10,                   # neighbor not found, neighbor info pending, mac not found
    'concentration_share': 50.0,    # percent of all interfaces' count that is called "concentrated"
    'flow_state_min': 100,          # drops by flow state check
    'zone_change_min': 10,          # routed to different zone (non-tunnel interfaces)
    # Physical / hardware error counters flag when the count is above this value.
    'phy_error_min': 0,
    'hw_error_min': 0,
    # Cross-check with the global counters: values within the larger of the two tolerances match.
    'xcheck_tolerance_pct': 20.0,
    'xcheck_abs': 20,
}

# Zone names that look like an internet-facing zone (lower case substrings).
WAN_ZONE_HINTS = ('wan', 'untrust', 'outside', 'internet', 'external', 'isp', 'inet')

PHY_ERROR_KEYS = (
    'receive fifo overrun', 'packets with bad crc', 'undersized packets', 'oversized packets',
    'mac receive error', 'bad_octets_rcv', 'collisions', 'excessive_collisions',
    'fragments_pkts', 'jabber_pkts', 'late_collisions', 'mac_transmit_err')
PHY_MINOR_KEYS = ('flow control transmitted', 'flow control received', 'sent_deferred',
                  'sent_multiple')
HW_ERROR_KEYS = ('receive incoming errors', 'receive discarded', 'receive errors',
                 'packets dropped')
ATTACK_KEYS = ('land attacks', 'ping-of-death attacks', 'teardrop attacks', 'mac spoof attacks',
               'ICMP fragment')
L2_KEYS = ('neighbor not found', 'neighbor info pending', 'mac not found')

# Cross-check: (label, interface counter, global counters summed, kind). kind 'sum' expects
# the two sides to match; 'related' only shows the values.
XCHECKS = (
    ('ARP not found', 'arp not found', ('flow_fwd_l3_noarp',), 'sum',
     'Per-interface "arp not found" should equal the global no-ARP drops.'),
    ('No route', 'no route', ('flow_fwd_l3_noroute', 'flow_policy_nofwd'), 'sum',
     ('Observed: the per-interface "no route" adds up to flow_fwd_l3_noroute plus '
      'flow_policy_nofwd (no destination zone from forwarding). Not documented.')),
    ('Routed to different zone', 'packets routed to different zone', ('flow_fwd_zonechange',),
     'sum', 'Per-interface count should equal the global zone-change drops.'),
    ('IP spoof', 'ip spoof attacks', ('flow_dos_pf_ipspoof',), 'sum',
     "Per-interface count should equal the zone protection 'discard-ip-spoof' drops."),
    ('Dropped by flow state check', 'packets dropped by flow state check',
     ('flow_tcp_non_syn_drop',), 'related',
     ('Related only: non-SYN TCP without a session is one cause of flow state check drops, '
      'not the only one.')),
)

_PROMPT_RE = re.compile(r'^\S+@\S+?(?:\([^)]*\))?[>#]\s*(.*)$')
_CLOCK_RE = re.compile(r'^[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \S+ \d{4}$')
_DP_RE = re.compile(r'^(?:(?:DP|target-dp)(?::\s*|\s+)|(?=(?:s\d+\.)?dp\d+\s*:))'
                    r'(\*?\.?(?:s\d+\.)?[\w-]+)\s*:?\s*$', re.IGNORECASE)
_KV_RE = re.compile(r'^(\S.*?)\s{2,}(-?\d+)\s*$')
_IFACE_HDR_RE = re.compile(r'^Interface:\s*(\S+)\s*$')
_NAME_HDR_RE = re.compile(r'^Name:\s*(\S+?),\s*ID:\s*(\d+)')
_BLOCK_RE = re.compile(r'^(Detailed physical|Physical) port counters read from MAC:?$|'
                       r'^(Hardware|Logical) interface counters read from CPU:?$')
_SECTION_RE = re.compile(r'^(Hardware|Logical) interface counters:\s*$')
_LINK_RE = re.compile(r'^(Runtime|Configured) link speed/duplex/state:\s*(\S*)/(\S*)/(\S*)')
_UPTIME_RE = re.compile(r'(?:(\d+)\s+days?,\s*)?(\d+):(\d{2}):(\d{2})')
_STATE_RE = re.compile(r'^([A-Za-z]+)')
_GLOBAL_ROW_RE = re.compile(r'^(\S+)\s+(\d+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(.*)$')

_COUNTER_BLOCKS = {'Physical': 'mac', 'Detailed physical': 'detail', 'Hardware': 'cpu',
                   'Logical': 'logical'}


def _classify_command(cmd):
    """Returns (kind, arg) for the commands this module reads, else (None, None)."""
    cmd = ' '.join(cmd.split())
    if cmd == 'show clock':
        return 'clock', None
    if cmd == 'show system info':
        return 'sysinfo', None
    if cmd == 'show counter global':
        return 'global', None
    if cmd == 'show counter interface all':
        return 'counters', None
    if cmd == 'show interface all':
        return 'ifall', None
    if cmd in ('show transceiver all',):
        return 'transceiver', None
    if cmd == 'show lacp aggregate-ethernet all':
        return 'lacp', None
    m = re.match(r'^show interface (\S+)$', cmd)
    if m and m.group(1) not in ('all', 'management'):
        return 'detail', m.group(1)
    return None, None


def _new_parsed():
    return {'warnings': [], 'system': {}, 'collected_at': None, 'counters': {}, 'detail': {},
            'hw_table': {}, 'logical_table': {}, 'global': {}, 'transceivers': None,
            'lacp': []}


def _slice_columns(header, line):
    """Splits a fixed-width table row at the column offsets of its header line."""
    cols = [(m.group(0), m.start()) for m in re.finditer(r'\S+', header)]
    out = {}
    for i, (name, start) in enumerate(cols):
        end = cols[i + 1][1] if i + 1 < len(cols) else len(line)
        out[name] = line[start:end].strip()
    return out


def _parse_link(text):
    """'1000/full/up', 'ukn/ukn/down((autoneg))', '[n/a]/[n/a]/up' -> (speed, duplex, state)."""
    parts = text.split('/')
    if len(parts) < 3:
        return None
    state = _STATE_RE.match(parts[2])
    return parts[0], parts[1], state.group(1).lower() if state else parts[2]


def parse_interfaces(lines, src=None):
    """Parses the lines of a CLI text file (or of a single command output).

    Returns a dict with the keys: warnings, system (show system info key/values),
    collected_at (show clock), counters ({iface: {'mac', 'cpu', 'logical': {name: int}}}
    from show counter interface all), detail ({iface: {...}} from show interface <name>),
    hw_table / logical_table ({name: {...}} from show interface all), global
    ({name: {'value', 'severity', 'description'}}), transceivers (None or
    {'header': [...], 'rows': [[...]]}) and lacp (raw lines).
    """
    prefix = f'{src}: ' if src else ''
    out = _new_parsed()
    warnings = out['warnings']
    kind = arg = None
    skip = False                # duplicate section / second dataplane: ignore until next command
    clock_pending = False
    first_dp = None
    iface = None                # current interface of a counters / detail section
    block = None                # 'mac' | 'detail' | 'cpu' | 'logical'
    target = None               # dict that receives the counters of the current block
    detail = None               # detail record of the current `show interface <name>`
    table_kind = header = None  # show interface all: 'hw' | 'agg' | 'logical'
    seen_dup = set()

    def start_target():
        nonlocal target
        target = None
        if iface is None or block is None:
            return
        rec = out['counters'].setdefault(iface, {}) if kind == 'counters' else detail
        if block in rec:
            seen_dup.add((kind, iface, block))
            return
        rec[block] = {}
        target = rec[block]

    for raw in lines:
        line = raw.rstrip()
        prompt = _PROMPT_RE.match(line)
        if line.startswith('> ') or prompt:
            cmd = (prompt.group(1) if prompt else line[2:]).strip()
            kind, arg = _classify_command(cmd)
            skip = False
            iface = block = target = detail = table_kind = header = None
            clock_pending = kind == 'clock'
            if kind == 'sysinfo' and out['system']:
                kind = None                     # keep the first complete show system info
            elif kind == 'global' and out['global']:
                kind = None
            elif kind == 'counters' and out['counters']:
                warnings.append(prefix + 'second "show counter interface all" ignored')
                kind = None
            elif kind == 'ifall' and (out['hw_table'] or out['logical_table']):
                kind = None
            elif kind == 'detail':
                if arg in out['detail']:
                    kind = None
                else:
                    detail = out['detail'][arg] = {'name': arg}
            elif (kind == 'transceiver' and out['transceivers'] is not None) \
                    or (kind == 'lacp' and out['lacp']):
                kind = None
            continue
        if kind is None:
            continue
        stripped = line.strip()

        if kind == 'clock':
            if clock_pending and stripped:
                clock_pending = False
                if _CLOCK_RE.match(stripped):
                    out['collected_at'] = stripped
            continue

        if kind == 'sysinfo':
            m = re.match(r'^([\w.-]+):\s*(.*)$', stripped)
            if m:
                out['system'].setdefault(m.group(1), m.group(2).strip())
            continue

        if kind == 'lacp':
            if stripped and len(out['lacp']) < 300:
                out['lacp'].append(line)
            continue

        if kind == 'transceiver':
            if stripped.startswith('-') or not stripped:
                continue
            words = stripped.split()
            if out['transceivers'] is None and 'Port' in words:
                out['transceivers'] = {'header': re.split(r'\s{2,}', stripped), 'rows': []}
            elif out['transceivers'] is not None and len(words) >= 2 \
                    and len(out['transceivers']['rows']) < 500:
                out['transceivers']['rows'].append(words)
            continue

        if kind in ('global', 'counters'):
            m = _DP_RE.match(stripped)
            if m and not stripped.lower().startswith('interface'):
                dp = m.group(1).lstrip('*.')
                if first_dp is None:
                    first_dp = dp
                elif dp != first_dp:
                    if (kind, 'dp') not in seen_dup:
                        seen_dup.add((kind, 'dp'))
                        warnings.append(f'{prefix}several dataplanes in the output: only {first_dp} '
                                        f'is analysed, {dp} and later ones are ignored')
                    skip = True
                else:
                    skip = False
                continue
            if skip:
                continue

        if kind == 'global':
            m = _GLOBAL_ROW_RE.match(stripped)
            if m and m.group(1) != 'name':
                out['global'].setdefault(m.group(1), {
                    'value': int(m.group(2)), 'severity': m.group(4), 'description': m.group(7).strip()})
            continue

        if kind == 'ifall':
            low = stripped.lower()
            if low.startswith(('total', 'aggregation')):
                table_kind = header = None
                continue
            if low.startswith('name ') and ' id' in low:
                header = line
                if 'speed/duplex/state' in low:
                    table_kind = 'hw'
                elif 'vsys' in low and 'zone' in low:
                    table_kind = 'logical'
                else:
                    table_kind = 'agg'
                continue
            if not stripped or stripped.startswith('-') or table_kind is None:
                continue
            tokens = stripped.split()
            if table_kind == 'logical':
                cells = _slice_columns(header, line)
                if cells.get('name') != tokens[0]:
                    cells = {'name': tokens[0], 'id': tokens[1] if len(tokens) > 1 else '',
                             'zone': '', 'address': tokens[-1]}
                out['logical_table'].setdefault(tokens[0], cells)
            else:
                rec = {'name': tokens[0], 'id': tokens[1] if len(tokens) > 1 else ''}
                for tok in tokens[2:]:
                    link = _parse_link(tok)
                    if link:
                        rec['speed'], rec['duplex'], rec['state'] = link
                        break
                rec['mac'] = next((t for t in tokens if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', t)), '')
                out['hw_table'].setdefault(tokens[0], rec)
            continue

        # counters / detail sections: headings and key/value rows
        if _SECTION_RE.match(stripped):
            iface = block = target = None
            continue
        m = _IFACE_HDR_RE.match(stripped)
        if m and kind == 'counters':
            iface, block, target = m.group(1), None, None
            continue
        if kind == 'detail':
            m = _NAME_HDR_RE.match(stripped)
            if m:
                iface, block, target = m.group(1), None, None
                detail.setdefault('id', m.group(2))
                continue
            _parse_detail_line(detail, stripped)
        m = _BLOCK_RE.match(stripped)
        if m:
            word = m.group(1) or m.group(2)
            block = _COUNTER_BLOCKS[word]
            start_target()
            continue
        if target is not None:
            m = _KV_RE.match(stripped)
            if m:
                target[m.group(1)] = int(m.group(2))
    return out


def _parse_detail_line(detail, text):
    m = _LINK_RE.match(text)
    if m:
        which = m.group(1).lower()
        state = _STATE_RE.match(m.group(4))
        detail[which] = {'speed': m.group(2), 'duplex': m.group(3),
                         'state': (state.group(1) if state else m.group(4)).lower()}
        return
    for key, rx in (('port_type', r'^Port Type:?\s*(.*)$'), ('capability', r'^Capability\s*:\s*(.*)$'),
                    ('mode', r'^Operation mode:\s*(\S+)'), ('vr', r'^Virtual router\s+(\S+)'),
                    ('mtu', r'^Interface MTU\s+(\d+)'), ('ip', r'^Interface IP address:\s*(.*)$')):
        m = re.match(rx, text)
        if m:
            detail.setdefault(key, m.group(1).strip())
            return
    m = re.match(r'^Zone:\s*(.*?),\s*virtual system:\s*(\S+)', text)
    if m:
        detail.setdefault('zone', m.group(1).strip())
        detail.setdefault('vsys', m.group(2))


def has_data(parsed):
    """True when the parsed output holds interface counters, details or interface tables."""
    return bool(parsed['counters'] or parsed['detail'] or parsed['hw_table']
                or parsed['logical_table'])


def merge_parsed(parts):
    """Merges the parse_interfaces() results of several files: first non-empty value wins."""
    out = _new_parsed()
    for p in parts:
        out['warnings'].extend(p['warnings'])
        for key in ('system', 'counters', 'detail', 'hw_table', 'logical_table', 'global'):
            if not out[key]:
                out[key] = p[key]
        for key in ('collected_at', 'transceivers'):
            if out[key] is None:
                out[key] = p[key]
        if not out['lacp']:
            out['lacp'] = p['lacp']
    return out


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def _natural(name):
    return [int(t) if t.isdigit() else t for t in re.split(r'(\d+)', name)]


def interface_kind(name):
    """Returns (kind, parent) for an interface name."""
    base, dot, _sub = name.partition('.')
    if re.fullmatch(r'ae\d+', base):
        kind = 'aggregate'
    elif base.startswith('ethernet'):
        kind = 'physical'
    elif base == 'tunnel' or base == 'vlan' or base == 'loopback':
        kind = base
    elif base.startswith(('tunnel', 'vlan', 'loopback')):
        kind = re.match(r'[a-z]+', base).group(0)
    else:
        kind = 'other'
    if dot:
        return ('sub-interface' if kind in ('physical', 'aggregate') else kind), base
    return kind, None


def parse_uptime(text):
    """'0 days, 0:18:51' -> seconds, or None."""
    m = _UPTIME_RE.search(text or '')
    if not m:
        return None
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return ((d * 24 + h) * 60 + mi) * 60 + s


def _fmt_uptime(sec):
    if sec is None:
        return 'unknown'
    d, rest = divmod(sec, 86400)
    h, rest = divmod(rest, 3600)
    mi, s = divmod(rest, 60)
    return (f'{d}d ' if d else '') + f'{h}h {mi:02d}m {s:02d}s'


def _flag(row, code, level, text):
    row['flags'].append({'code': code, 'level': level, 'text': text})


def _nz(counters, keys):
    return {k: counters[k] for k in keys if counters.get(k, 0)}


def _fmt_counts(counts):
    return ', '.join(f'{k} {v:,}' for k, v in counts.items())


def _max_speed_mbps(capability):
    best = 0
    for m in re.finditer(r'(\d+)(Mb|Gb)/s', capability or ''):
        best = max(best, int(m.group(1)) * (1000 if m.group(2) == 'Gb' else 1))
    return best


def _speed_mbps(text):
    m = re.fullmatch(r'(\d+)', text or '')
    return int(m.group(1)) if m else None


def _build_row(name, parsed, order):
    counters = parsed['counters'].get(name, {})
    det = parsed['detail'].get(name, {})
    hw = parsed['hw_table'].get(name, {})
    lg = parsed['logical_table'].get(name, {})
    kind, parent = interface_kind(name)
    mac = counters.get('mac') or det.get('mac') or {}
    phys_detail = det.get('detail') or {}
    cpu = counters.get('cpu') or det.get('cpu') or {}
    logical = counters.get('logical') or det.get('logical') or {}
    runtime = det.get('runtime') or {}
    speed = runtime.get('speed') or hw.get('speed') or ''
    duplex = runtime.get('duplex') or hw.get('duplex') or ''
    state = (runtime.get('state') or hw.get('state') or '').lower()
    if speed in ('ukn', 'unknown', '[n/a]'):
        speed = ''
    if duplex in ('ukn', 'unknown', '[n/a]'):
        duplex = ''
    ip = det.get('ip') or lg.get('address') or ''
    if ip.upper() == 'N/A':
        ip = ''
    vr = det.get('vr') or ''
    fwd = lg.get('forwarding', '')
    if not vr and fwd.startswith('vr:'):
        vr = fwd[3:]
    zone = det.get('zone') or lg.get('zone') or ''
    if zone.upper() == 'N/A':
        zone = ''
    # Traffic totals: logical counters first, then hardware, then the MAC counters.
    if 'packets received' in logical:
        src = logical
    elif 'packets received' in cpu:
        src = cpu
    else:
        src = None
    if src is not None:
        rx_pkts, tx_pkts = src.get('packets received', 0), src.get('packets transmitted', 0)
        rx_bytes, tx_bytes = src.get('bytes received', 0), src.get('bytes transmitted', 0)
    elif mac:
        rx_pkts = sum(mac.get(k, 0) for k in ('rx-broadcast', 'rx-multicast', 'rx-unicast'))
        tx_pkts = sum(mac.get(k, 0) for k in ('tx-broadcast', 'tx-multicast', 'tx-unicast'))
        rx_bytes, tx_bytes = mac.get('rx-bytes', 0), mac.get('tx-bytes', 0)
    else:
        rx_pkts = tx_pkts = rx_bytes = tx_bytes = None

    def errors(group, counts):
        cols = set(if_glossary.GROUP_COUNTERS[group])
        extra = {k for k in counts if k not in if_glossary.GLOSSARY and
                 not re.match(r'^(rx |tx |bytes |packets (received|transmitted))', k)}
        return {k: v for k, v in counts.items() if v and (k in cols or k in extra)}

    # The detailed physical counters (show interface <name>) also carry the MAC ones.
    phys = errors('phys', {**phys_detail})
    row = {
        'name': name, 'kind': kind, 'parent': parent, 'order': order, 'state': state or 'n/a',
        'speed': speed, 'duplex': duplex, 'zone': zone, 'ip': ip, 'vr': vr,
        'tag': lg.get('tag', ''), 'port_type': det.get('port_type', ''),
        'rx_pkts': rx_pkts, 'tx_pkts': tx_pkts, 'rx_bytes': rx_bytes, 'tx_bytes': tx_bytes,
        'phys': phys, 'cpu': errors('cpu', cpu), 'logical': errors('logical', logical),
        'has_phys_data': bool(phys_detail), 'drop_pct': None, 'flags': [],
        '_det': det, '_mac': mac,
    }
    if state == 'down':
        has_traffic = any(mac.get(k, 0) for k in mac) or bool(rx_pkts) or bool(tx_pkts)
        row['note'] = 'down' if has_traffic else 'down / no traffic'
    else:
        row['note'] = ''
    return row


def _link_text(row):
    st = row['state']
    if st == 'n/a':
        return '-'
    if row['note'] == 'down / no traffic':
        return 'down / no traffic'
    bits = [st]
    if row['speed']:
        bits.append(row['speed'] + (f"/{row['duplex']}" if row['duplex'] else ''))
    return ' '.join(bits)


def _evaluate_row(row, th, uptime_s, totals):
    short = uptime_s is not None and uptime_s < th['short_uptime_s']
    low = (f' Counts cover only the first {_fmt_uptime(uptime_s)} after boot, so this may be '
           f'transient.') if short else ''
    kind, state = row['kind'], row['state']
    phys, cpu, lg = row['phys'], row['cpu'], row['logical']
    det = row['_det']
    zone, ip = row['zone'], row['ip']

    bad = {k: v for k, v in _nz(phys, PHY_ERROR_KEYS).items() if v > th['phy_error_min']}
    if bad:
        _flag(row, 'PHY_ERRORS', 'crit',
              f'Physical-layer errors: {_fmt_counts(bad)}. Check cable, SFP/transceiver and '
              f'port, the duplex/speed settings on both ends and the peer device.')
    minor = _nz(phys, PHY_MINOR_KEYS)
    if minor:
        _flag(row, 'PHY_MINOR', 'info',
              f'Flow control or deferred/multiple transmissions seen: {_fmt_counts(minor)}. '
              f'Pause frames mean the peer or the firewall is congested; deferred/multiple '
              f'transmissions only happen on half-duplex links.')
    hw = {k: v for k, v in _nz(cpu, HW_ERROR_KEYS).items() if v > th['hw_error_min']}
    if hw:
        _flag(row, 'HW_ERRORS', 'warn',
              f'Hardware (CPU side) receive errors or drops: {_fmt_counts(hw)}. Compare with the '
              f'MAC counters; if those are clean the packets were lost inside the firewall '
              f'(overload, buffers).')

    drops = lg.get('packets dropped', 0)
    rx = row['rx_pkts'] or 0
    if drops and rx:
        row['drop_pct'] = round(100.0 * drops / rx, 3)
        if rx >= th['min_packets'] and drops >= th['min_drops'] \
                and row['drop_pct'] >= th['drop_pct_warn']:
            level = 'crit' if row['drop_pct'] >= th['drop_pct_crit'] else 'warn'
            _flag(row, 'DROP_PCT', level,
                  f"{drops:,} packets dropped out of {rx:,} received ({row['drop_pct']:.2f}%). "
                  f'Look at the specific counters of this interface and at `show counter global '
                  f'filter delta yes severity drop`.' + low)

    nr = lg.get('no route', 0)
    if nr >= th['no_route_min']:
        share = 100.0 * nr / totals['no route'] if totals['no route'] else 0.0
        conc = (f' Concentrated here: {share:.0f}% of the no-route count of all interfaces.'
                if share >= th['concentration_share'] else f' ({share:.0f}% of all interfaces).')
        where = (f' This is a sub-interface: check the default and specific routes of virtual '
                 f"router '{row['vr'] or 'unknown'}' for the networks reached through it."
                 if kind == 'sub-interface' else
                 f" Check the routing table of virtual router '{row['vr'] or 'unknown'}'.")
        _flag(row, 'NO_ROUTE', 'warn',
              f'{nr:,} packets dropped for no route.{conc}{where}' + low)
    arp = lg.get('arp not found', 0)
    if arp >= th['arp_min']:
        share = 100.0 * arp / totals['arp not found'] if totals['arp not found'] else 0.0
        conc = (f' Concentrated here: {share:.0f}% of the ARP failures of all interfaces.'
                if share >= th['concentration_share'] else f' ({share:.0f}% of all interfaces).')
        _flag(row, 'ARP_NOT_FOUND', 'warn',
              f'{arp:,} packets dropped because ARP could not be resolved.{conc} Check that '
              f'the next-hop hosts exist and answer ARP, the subnet mask, and `show arp`.' + low)
    l2 = {k: v for k, v in _nz(lg, L2_KEYS).items() if v >= th['l2_min']}
    if l2:
        _flag(row, 'L2_RESOLUTION', 'warn',
              f'Neighbor / MAC resolution failures: {_fmt_counts(l2)}. Check IPv6 neighbor '
              f'discovery or the layer-2 forwarding table of the attached segment.' + low)
    fs = lg.get('packets dropped by flow state check', 0)
    if fs >= th['flow_state_min']:
        if short:
            _flag(row, 'FLOW_STATE_CHECK', 'info',
                  f'{fs:,} packets dropped by the flow state check shortly after boot '
                  f'({_fmt_uptime(uptime_s)}): most likely non-SYN TCP packets of sessions that '
                  f'existed before the reboot. Re-check after the firewall has been up longer.')
        else:
            _flag(row, 'FLOW_STATE_CHECK', 'warn',
                  f'{fs:,} packets dropped by the flow state check (packets without a session '
                  f'that cannot start one). Look for asymmetric routing, idle timeouts shorter '
                  f'than the applications need, or a failover.')
    sp = lg.get('ip spoof attacks', 0)
    if sp:
        wan = any(h in zone.lower() for h in WAN_ZONE_HINTS)
        if wan:
            _flag(row, 'IP_SPOOF', 'info',
                  f"{sp:,} packets dropped by the zone protection option 'discard-ip-spoof' on "
                  f"internet-facing zone '{zone}'. Expected background noise on a WAN; a "
                  f'sustained rise is worth checking.')
        else:
            _flag(row, 'IP_SPOOF', 'warn',
                  f"{sp:,} packets dropped by the zone protection option 'discard-ip-spoof'"
                  + (f" on zone '{zone}'" if zone else '') + ': internal hosts sending packets '
                  'with a source address that the routing table does not expect on this '
                  'interface (asymmetric routing, missing route, or spoofing).')
    att = _nz(lg, ATTACK_KEYS)
    if att:
        _flag(row, 'ATTACK_COUNTERS', 'warn',
              f'Zone protection / packet-based attack counters: {_fmt_counts(att)}. Check the '
              f'source of the traffic.')
    fe = _nz(lg, ('forwarding errors', 'receive errors'))
    if fe:
        _flag(row, 'FWD_ERRORS', 'warn',
              f'Forwarding or receive errors on the logical interface: {_fmt_counts(fe)}.')
    zc = lg.get('packets routed to different zone', 0)
    if zc:
        if kind == 'tunnel':
            _flag(row, 'ZONE_CHANGE', 'info',
                  f'{zc:,} packets routed to a different zone on a tunnel: return traffic '
                  f'or routes that point to another zone than the tunnel zone. Check proxy-IDs, '
                  f'routes to the remote networks and the tunnel zone.')
        elif zc >= th['zone_change_min']:
            _flag(row, 'ZONE_CHANGE', 'warn',
                  f'{zc:,} packets dropped because the route leads to a different zone than the '
                  f"session's. Check for asymmetric routing and overlapping routes.")

    # Link state of physical ports.
    if kind in ('physical', 'aggregate'):
        runtime = det.get('runtime') or {}
        if state == 'up' and row['duplex'] == 'half':
            _flag(row, 'LINK_HALF_DUPLEX', 'warn',
                  'The link runs half duplex. Half duplex is almost always a negotiation '
                  'problem: set both ends to auto or to the same fixed values.')
        configured = det.get('configured') or {}
        cfg_speed, cfg_duplex = configured.get('speed', ''), configured.get('duplex', '')
        mism = []
        if state == 'up' and runtime:
            if cfg_speed and cfg_speed != 'auto' and runtime.get('speed') != cfg_speed:
                mism.append(f"speed configured {cfg_speed}, running {runtime.get('speed')}")
            if cfg_duplex and cfg_duplex != 'auto' and runtime.get('duplex') != cfg_duplex:
                mism.append(f"duplex configured {cfg_duplex}, running {runtime.get('duplex')}")
        if mism:
            _flag(row, 'LINK_MISMATCH', 'warn',
                  'Configured and running link settings differ (' + '; '.join(mism) + '). '
                  'Align the settings on both ends.')
        top = _max_speed_mbps(det.get('capability'))
        run = _speed_mbps(row['speed'])
        if state == 'up' and top and run and run < top:
            _flag(row, 'LINK_SPEED_LOW', 'warn',
                  f'The link negotiated {run} Mb/s but the port supports {top} Mb/s. Check the '
                  f'cable (category and length), the peer port and its advertised speeds.')
        mac = row['_mac']
        if state == 'up' and kind == 'physical' and not (row['rx_pkts'] or row['tx_pkts']) \
                and (mac or row['rx_pkts'] is not None):
            _flag(row, 'UP_NO_TRAFFIC', 'info',
                  'The link is up but no packet was received or sent since boot. Check that the '
                  'peer is configured and that the interface is assigned to a zone.' +
                  (f' Uptime is only {_fmt_uptime(uptime_s)}.' if short else ''))
        if state == 'down' and (zone or ip):
            _flag(row, 'DOWN_CONFIGURED', 'info',
                  'The port is down but it has ' + ' and '.join(
                      x for x in ((f"zone '{zone}'" if zone else ''),
                                  (f'address {ip}' if ip else '')) if x) +
                  '. Expected if the port is unused; otherwise check cable and peer.')


def _crosscheck(rows, parsed, th):
    glob = parsed['global']
    out = []
    if not glob:
        return out
    for label, counter, gnames, kind, note in XCHECKS:
        isum = sum(r['logical'].get(counter, 0) for r in rows)
        gvals = {g: glob.get(g, {}).get('value') for g in gnames}
        gsum = sum(v or 0 for v in gvals.values())
        if not isum and not gsum:
            continue
        diff = isum - gsum
        if kind == 'related':
            status = 'related'
        elif abs(diff) <= max(th['xcheck_abs'], th['xcheck_tolerance_pct'] / 100.0 * max(isum, gsum)):
            status = 'match'
        else:
            status = 'differs'
        out.append({'label': label, 'counter': counter, 'interface_sum': isum,
                    'globals': [{'name': g, 'value': gvals[g]} for g in gnames],
                    'global_sum': gsum, 'diff': diff, 'status': status, 'note': note,
                    'missing': [g for g, v in gvals.items() if v is None]})
    return out


def _context_counters(parsed):
    rows = []
    for name in if_glossary.GLOBAL_DROP_COUNTERS:
        g = parsed['global'].get(name)
        if g and g['value']:
            rows.append({'name': name, 'value': g['value'], 'description': g['description']})
    return rows


def _banner(rows, system, xcheck, th):
    items = []
    up = system['uptime_s']
    if up is not None and up < th['short_uptime_s']:
        items.append({'level': 'warn', 'code': 'UPTIME_SHORT',
                      'text': f"Uptime is only {_fmt_uptime(up)}. All counters are cumulative "
                              f"since boot, so the numbers below are low-significance (drops "
                              f"right after a boot are often transient: routes and ARP not yet "
                              f"learned, sessions lost). Capture again after the firewall has "
                              f"been up for at least {_fmt_uptime(th['short_uptime_s'])}."})
    order = {'crit': 2, 'warn': 1, 'info': 0}
    by_code = {}
    for r in rows:
        for f in r['flags']:
            by_code.setdefault(f['code'], []).append((r['name'], f['level']))
    for code, hits in sorted(by_code.items(), key=lambda kv: (-max(order[l] for _n, l in kv[1]),
                                                              kv[0])):
        names = [n for n, _l in hits]
        level = max((l for _n, l in hits), key=order.get)
        shown = ', '.join(names[:8]) + (f' (+{len(names) - 8} more)' if len(names) > 8 else '')
        items.append({'level': level, 'code': code, 'flag': code,
                      'text': f'{code}: {len(names)} interface(s): {shown}'})
    bad = [x['label'] for x in xcheck if x['status'] == 'differs']
    if bad:
        items.append({'level': 'info', 'code': 'XCHECK_MISMATCH',
                      'text': 'XCHECK_MISMATCH: the per-interface sums differ from the global '
                              'counters for: ' + ', '.join(bad) + '. The two outputs may have '
                              'been captured at different moments.'})
    return items


def evaluate_interfaces(parsed, thresholds=None):
    """Adds flags, drop percentages, a cross-check and a banner to a parse_interfaces() result.

    Returns a new JSON-serialisable dict: 'thresholds', 'system' (hostname, model, version,
    uptime, capture time), 'banner', 'rows' (one per interface, with the non-zero error
    counters grouped in 'phys', 'cpu' and 'logical' and a list of 'flags'), 'groups' (the
    report column groups with the counters present), 'crosscheck', 'context', 'down_ports',
    'transceivers', 'lacp' and 'warnings'. The input is not modified.
    """
    th = dict(IF_THRESHOLDS)
    unknown = set(thresholds or {}) - set(IF_THRESHOLDS)
    if unknown:
        raise ValueError('unknown interface threshold(s): ' + ', '.join(sorted(unknown)))
    th.update(thresholds or {})
    parsed = copy.deepcopy(parsed)
    warnings = list(parsed['warnings'])
    sysinfo = parsed['system']
    uptime_s = parse_uptime(sysinfo.get('uptime'))
    system = {'hostname': sysinfo.get('hostname', ''), 'model': sysinfo.get('model', ''),
              'sw_version': sysinfo.get('sw-version', ''), 'uptime': sysinfo.get('uptime', ''),
              'uptime_s': uptime_s, 'uptime_text': _fmt_uptime(uptime_s),
              'collected_at': parsed['collected_at'] or sysinfo.get('time', '')}
    if not sysinfo:
        warnings.append('show system info not found: uptime unknown, the counters cannot be '
                        'put in context')
    if not parsed['counters'] and not parsed['detail']:
        warnings.append('show counter interface all (and show interface <name>) not found: '
                        'only the interface tables are shown')
    if not parsed['hw_table'] and not parsed['logical_table']:
        warnings.append('show interface all not found: link state, zone and address are '
                        'missing for interfaces without a detail output')
    if not parsed['global']:
        warnings.append('show counter global not found: no cross-check with the global counters')

    names = set(parsed['counters']) | set(parsed['detail']) | set(parsed['hw_table']) \
        | set(parsed['logical_table'])
    ordered = sorted(names, key=_natural)
    rows = [_build_row(n, parsed, i) for i, n in enumerate(ordered)]
    totals = {k: sum(r['logical'].get(k, 0) for r in rows) for k in ('no route', 'arp not found')}
    for r in rows:
        _evaluate_row(r, th, uptime_s, totals)
    for r in rows:
        r['link_txt'] = _link_text(r)
        r.pop('_det')
        r.pop('_mac')
        r['issue'] = bool(r['flags'] or r['phys'] or r['cpu'] or r['logical'])
    xcheck = _crosscheck(rows, parsed, th)

    groups = []
    for gid, label in if_glossary.GROUP_LABELS.items():
        present = {k for r in rows for k in r[gid]}
        known = [k for k in if_glossary.GROUP_COUNTERS[gid] if k in present]
        extra = sorted(present - set(known))
        cols = [{'k': k, 'gl': if_glossary.gl_key(gid, k)} for k in known + extra]
        groups.append({'id': gid, 'label': label, 'cols': cols})
    down = [r['name'] for r in rows if r['note'] == 'down / no traffic' and r['kind'] == 'physical']
    return {
        'thresholds': th, 'system': system, 'banner': _banner(rows, system, xcheck, th),
        'rows': rows, 'groups': groups, 'crosscheck': xcheck,
        'context': _context_counters(parsed), 'down_ports': down,
        'transceivers': parsed['transceivers'], 'lacp': parsed['lacp'], 'warnings': warnings,
        'summary': {'interfaces': len(rows), 'with_issues': sum(1 for r in rows if r['issue'])},
    }


def glossary_keys(view):
    """Tooltip keys used by an evaluated view (counter columns, cross-check, context)."""
    keys = {c['gl'] for g in view['groups'] for c in g['cols']}
    keys.update(g['name'] for x in view['crosscheck'] for g in x['globals'])
    keys.update(c['name'] for c in view['context'])
    keys.update(x['counter'] for x in view['crosscheck'])
    return keys

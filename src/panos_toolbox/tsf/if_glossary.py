"""Glossary of the interface counters shown in the "Interface Errors" tab.

Covers the counters printed by ``show counter interface all`` and ``show interface
<name>`` (physical port counters read from the MAC, hardware counters read from the CPU,
logical interface counters) and the global counters used by the cross-check.

It reuses the tooltip mechanism of the POW glossary (same JSON shape, same confidence
codes) so that ``glName()`` / ``glTag()`` in the report work unchanged:

D = documented by Palo Alto (for the global counters, the description printed by the
    firewall itself),
G = well-known behaviour (standard Ethernet statistics, Palo Alto flow behaviour), the
    exact wording is ours,
I = inferred from the name only (hypothesis),
U = unknown (names missing from this glossary).

Standard library only. No HTML except in help_table_html().
"""
import html
import re

# Report column groups, in display order: id -> label.
GROUP_LABELS = {
    'phys': 'Physical (MAC)',
    'cpu': 'CPU / hardware',
    'logical': 'Logical / flow',
}

CAT_MAC = 'Physical port (MAC)'
CAT_CPU = 'Hardware (read from CPU)'
CAT_LOG = 'Logical interface (flow)'
CAT_TRAFFIC = 'Traffic'
CAT_GLOBAL = 'Global counter'

# Names printed by the firewall -> (group, category, confidence, meaning).
# GLOSSARY keys are the tooltip keys; the hardware (CPU) counters are prefixed with
# "cpu: " because several of them share their CLI name with a logical counter.
GLOSSARY = {}
# Ordered counter names per report group (the CLI names, without the "cpu: " prefix).
GROUP_COUNTERS = {'phys': [], 'cpu': [], 'logical': []}


def _add(group, cat, conf, name, meaning, column=True):
    key = 'cpu: ' + name if group == 'cpu' else name
    GLOSSARY[key] = {'kind': 'counter', 'category': cat, 'conf': conf, 'meaning': meaning,
                     'group': group, 'column': column}
    if column:
        GROUP_COUNTERS[group].append(name)


# ---------------------------------------------------------------- physical (MAC)
for _n, _m in (
        ('rx-broadcast', 'Broadcast frames received on the port.'),
        ('rx-multicast', 'Multicast frames received on the port.'),
        ('rx-unicast', 'Unicast frames received on the port.'),
        ('rx-bytes', 'Bytes received on the port.'),
        ('tx-broadcast', 'Broadcast frames transmitted on the port.'),
        ('tx-multicast', 'Multicast frames transmitted on the port.'),
        ('tx-unicast', 'Unicast frames transmitted on the port.'),
        ('tx-bytes', 'Bytes transmitted on the port.')):
    _add('phys', CAT_TRAFFIC, 'G', _n, _m, column=False)

_P = CAT_MAC
_add('phys', _P, 'G', 'receive fifo overrun',
     'The MAC receive FIFO overflowed because the port delivered frames faster than they '
     'were drained; the excess frames were lost. Points to an overloaded or bursty port.')
_add('phys', _P, 'G', 'packets with bad crc',
     'Frames received with a failed frame check sequence (CRC). Typical causes: faulty '
     'cable, SFP or port, duplex mismatch, electrical interference, a faulty peer.')
_add('phys', _P, 'G', 'undersized packets',
     'Frames shorter than 64 bytes that carry a valid CRC (runts). Usually a faulty '
     'peer or a media converter.')
_add('phys', _P, 'G', 'oversized packets',
     'Frames longer than the maximum accepted size. Check that the MTU / jumbo-frame '
     'settings agree on both ends of the link.')
_add('phys', _P, 'I', 'mac receive error',
     'Frames the MAC reported as received with an error that is not classified by the '
     'other counters. The exact trigger is not documented.')
_add('phys', _P, 'I', 'bad_octets_rcv',
     'Probably the number of bytes in received frames that had errors (bad CRC, '
     'undersized, oversized, fragments). Inferred from the name.')
_add('phys', _P, 'G', 'collisions',
     'Collisions seen on the link. Only expected on half-duplex links; on a full-duplex '
     'link they point to a duplex mismatch.')
_add('phys', _P, 'G', 'excessive_collisions',
     'Frames dropped after too many successive collisions (half-duplex only).')
_add('phys', _P, 'G', 'fragments_pkts',
     'Frames shorter than 64 bytes with a bad CRC (fragments). Usually the result of '
     'collisions or cabling faults.')
_add('phys', _P, 'G', 'jabber_pkts',
     'Frames longer than the maximum size with a bad CRC. Points to a faulty transmitter, '
     'NIC or cable on the peer.')
_add('phys', _P, 'G', 'late_collisions',
     'Collisions detected after the first 64 bytes of a frame were sent. A classic '
     'sign of a duplex mismatch or an over-long cable.')
_add('phys', _P, 'I', 'mac_transmit_err',
     'Frames the MAC failed to transmit because of an internal error. Inferred from the '
     'name.')
_add('phys', _P, 'I', 'sent_deferred',
     'Frames whose transmission was delayed because the medium was busy (half-duplex '
     'behaviour). Inferred from the name.')
_add('phys', _P, 'I', 'sent_multiple',
     'Frames sent successfully after more than one collision (half-duplex behaviour). '
     'Inferred from the name.')
_add('phys', _P, 'G', 'flow control transmitted',
     '802.3x pause frames sent by the firewall to the peer, asking it to slow down.')
_add('phys', _P, 'G', 'flow control received',
     '802.3x pause frames received from the peer, asking the firewall to slow down its '
     'transmit side.')
for _n in ('rx packets 64 bytes', 'rx packets 65 to 127 bytes', 'rx packets 128 to 255 bytes',
           'rx packets 256 to 511 bytes', 'rx packets 512 to 1023 bytes',
           'rx packets 1024+ bytes'):
    _add('phys', CAT_TRAFFIC, 'G', _n, 'Received-frame size histogram bucket.', column=False)

# ---------------------------------------------------------------- hardware (CPU)
_H = CAT_CPU
for _n, _m in (('bytes received', 'Bytes received, as counted by the dataplane driver.'),
               ('bytes transmitted', 'Bytes transmitted, as counted by the dataplane driver.'),
               ('packets received', 'Packets received, as counted by the dataplane driver.'),
               ('packets transmitted',
                'Packets transmitted, as counted by the dataplane driver.')):
    _add('cpu', CAT_TRAFFIC, 'G', _n, _m, column=False)
_add('cpu', _H, 'I', 'receive incoming errors',
     'Receive errors reported by the hardware for packets entering the dataplane '
     '(hypothesis, inferred from the name).')
_add('cpu', _H, 'I', 'receive discarded',
     'Packets discarded by the driver on receive, for example for lack of buffers '
     '(hypothesis, inferred from the name).')
_add('cpu', _H, 'I', 'receive errors',
     'Packets received with an error, as counted by the dataplane driver (hypothesis, '
     'inferred from the name).')
_add('cpu', _H, 'I', 'packets dropped',
     'Packets dropped by the driver at interface level, before flow processing '
     '(hypothesis, inferred from the name). Not the same counter as the logical '
     '"packets dropped".')

# ---------------------------------------------------------------- logical (flow)
_L = CAT_LOG
for _n, _m in (('bytes received', 'Bytes received on the logical interface.'),
               ('bytes transmitted', 'Bytes transmitted on the logical interface.'),
               ('packets received', 'Packets received on the logical interface.'),
               ('packets transmitted', 'Packets transmitted on the logical interface.')):
    GLOSSARY.setdefault(_n, {'kind': 'counter', 'category': CAT_TRAFFIC, 'conf': 'G',
                             'meaning': _m, 'group': 'logical', 'column': False})
_add('logical', _L, 'I', 'receive errors',
     'Packets received on the logical interface with an error (hypothesis, inferred from '
     'the name).')
_add('logical', _L, 'G', 'packets dropped',
     'All packets dropped by the dataplane on this logical interface, for any reason '
     '(no route, ARP, policy, flow state, zone protection...). Read it together with the '
     'specific counters next to it.')
_add('logical', _L, 'G', 'packets dropped by flow state check',
     'Packets that matched no session and were not allowed to create one because of the '
     'flow/TCP state, for example non-SYN TCP packets without a session. Typical right '
     'after a reboot or failover, or with asymmetric routing.')
_add('logical', _L, 'I', 'forwarding errors',
     'Errors in the forwarding stage of the dataplane (hypothesis, inferred from the '
     'name).')
_add('logical', _L, 'G', 'no route',
     'Packets dropped because the virtual router has no route to the destination. The '
     'interface is the one the packet arrived on. It seems to add up to the global counters '
     'flow_fwd_l3_noroute and flow_policy_nofwd (observed, not documented).')
_add('logical', _L, 'G', 'arp not found',
     'Packets that matched a route but were dropped because no ARP entry for the next '
     'hop or destination could be resolved. Matches the global counter flow_fwd_l3_noarp.')
_add('logical', _L, 'I', 'neighbor not found',
     'IPv6 counterpart of "arp not found": no neighbor entry for the next hop '
     '(hypothesis, inferred from the name).')
_add('logical', _L, 'I', 'neighbor info pending',
     'Packets waiting for an IPv6 neighbor resolution that had not finished '
     '(hypothesis, inferred from the name).')
_add('logical', _L, 'I', 'mac not found',
     'The destination MAC address was not found in the layer-2 forwarding table '
     '(hypothesis, inferred from the name).')
_add('logical', _L, 'G', 'packets routed to different zone',
     'Packets whose route lookup leads to an egress zone different from the one of the '
     'session. They are dropped; the sum over the interfaces matches the global counter '
     'flow_fwd_zonechange.')
_add('logical', _L, 'G', 'land attacks',
     'LAND packets (source equal to destination) caught by the zone protection profile.')
_add('logical', _L, 'G', 'ping-of-death attacks',
     'Oversized or malformed ICMP echo packets caught by the zone protection profile.')
_add('logical', _L, 'G', 'teardrop attacks',
     'Overlapping IP fragments caught by the zone protection profile.')
_add('logical', _L, 'G', 'ip spoof attacks',
     "Packets dropped by the zone protection option 'discard-ip-spoof' (source address "
     'not reachable through the ingress interface according to the routing table). '
     'Matches the global counter flow_dos_pf_ipspoof.')
_add('logical', _L, 'G', 'mac spoof attacks',
     'Packets dropped because the source MAC address is not allowed on the interface '
     '(zone protection / reconnaissance setting).')
_add('logical', _L, 'G', 'ICMP fragment',
     'Fragmented ICMP packets caught by the zone protection profile.')
_add('logical', _L, 'I', 'layer2 encapsulated packets',
     'Packets encapsulated in a layer-2 header on this interface (hypothesis, inferred '
     'from the name).', column=False)
_add('logical', _L, 'I', 'layer2 decapsulated packets',
     'Packets decapsulated from a layer-2 header on this interface (hypothesis, '
     'inferred from the name).', column=False)
for _n in ('tcp cps', 'udp cps', 'sctp cps', 'other cps'):
    _add('logical', _L, 'I', _n,
         'New connections per second on this interface for this protocol class '
         '(hypothesis, inferred from the name).', column=False)

# ---------------------------------------------------------------- global counters
# Meaning = the description printed by `show counter global` itself (confidence D).
GLOBAL_DROP_COUNTERS = {
    'flow_fwd_l3_noroute': 'Packets dropped: no route.',
    'flow_fwd_l3_noarp': 'Packets dropped: no ARP.',
    'flow_policy_nofwd': 'Session setup: no destination zone from forwarding.',
    'flow_policy_deny': 'Session setup: denied by policy.',
    'flow_tcp_non_syn_drop': 'Packets dropped: non-SYN TCP without session match.',
    'flow_dos_pf_ipspoof': "Packets dropped: Zone protection option 'discard-ip-spoof'.",
    'flow_fwd_zonechange': 'Packets dropped: forwarded to different zone.',
    'flow_fwd_l3_mcast_drop': 'Packets dropped: no route for IP multicast.',
    'flow_fwd_l3_bcast_drop': 'Packets dropped: unhandled IP broadcast.',
    'flow_fwd_l3_ttl_zero': 'Packets dropped: IP TTL reaches zero.',
    'flow_fwd_drop_noxmit': 'Packet dropped at forwarding: noxmit.',
    'flow_ipv6_disabled': 'Packets dropped: IPv6 disabled on interface.',
    'flow_host_service_deny': 'Device management session denied.',
}
for _n, _m in GLOBAL_DROP_COUNTERS.items():
    GLOSSARY[_n] = {'kind': 'counter', 'category': CAT_GLOBAL, 'conf': 'D',
                    'meaning': _m + ' (description printed by `show counter global`.)',
                    'group': 'global', 'column': False}

# ---------------------------------------------------------------- column headers
EXTRA_FIELDS = {
    'if:interface': 'Interface name as printed by the firewall: physical ports, aggregate '
                    'groups (ae), sub-interfaces (.N), tunnel, vlan and loopback. (D)',
    'if:type': 'Interface type derived from the name: physical, aggregate (ae), sub-interface, '
               'tunnel, vlan or loopback. (D)',
    'if:link': 'Runtime link state, speed and duplex from `show interface`. Ports that are down '
               'and carry no traffic are shown as "down / no traffic". Logical interfaces '
               'have no link of their own. (D)',
    'if:zone': 'Security zone of the interface, from `show interface all` or the interface '
               'detail. (D)',
    'if:ip': 'IP address configured on the interface. (D)',
    'if:rx_pkts': 'Packets received (logical interface counters when present, else hardware '
                  'counters, else the MAC counters). Counted since boot. (D)',
    'if:tx_pkts': 'Packets transmitted, from the same source as the received packets. (D)',
    'if:rx_bytes': 'Bytes received, from the same source as the received packets. (D)',
    'if:tx_bytes': 'Bytes transmitted, from the same source as the received packets. (D)',
    'if:drop_pct': 'Logical "packets dropped" as a percentage of the received packets. Only '
                   'computed when enough packets were received (min_packets). (I)',
    'if:flags': 'Badges raised by the interface heuristics (see the flag reference in the '
                'help). Hover a badge for the detail. (D)',
    'if:vr': 'Virtual router the interface belongs to. (D)',
}


def field_entries():
    """Column descriptions as {key: {'m': text, 'f': confidence}} for the report tooltips."""
    out = {}
    for k, text in EXTRA_FIELDS.items():
        m = re.search(r'\s*\(([DGIU])\)\.?\s*$', text)
        out[k] = {'m': text[:m.start()] if m else text, 'f': m.group(1) if m else 'D'}
    return out


def gl_key(group, name):
    """Tooltip key of a counter of the given report group ('phys', 'cpu', 'logical')."""
    return 'cpu: ' + name if group == 'cpu' else name


def lookup(key):
    """Glossary entry for a tooltip key; never raises."""
    if key in GLOSSARY:
        return GLOSSARY[key]
    return {'kind': 'counter', 'category': 'Unclassified', 'conf': 'U', 'group': None,
            'column': True, 'meaning': 'Not in the glossary. No meaning known.'}


def glossary_subset(keys):
    """Entries of the given tooltip keys, ready for the report JSON (same shape as pow)."""
    out = {}
    for k in sorted(set(keys)):
        g = lookup(k)
        out[k] = {'c': g['category'], 'f': g['conf'], 'm': g['meaning'], 'k': 'counter',
                  'u': 1 if k in GLOSSARY else 0}
    return out


def help_table_html():
    """HTML tables with the meaning of every counter, for the help of the tab."""
    parts = []
    sections = (('Physical port counters (read from the MAC)', 'phys'),
                ('Hardware interface counters (read from the CPU)', 'cpu'),
                ('Logical interface counters (flow)', 'logical'))
    for title, group in sections:
        rows = ''.join(
            f"<tr><td><code>{html.escape(key)}</code></td><td>{html.escape(g['conf'])}</td>"
            f"<td>{html.escape(g['meaning'])}</td></tr>"
            for key, g in GLOSSARY.items() if g['group'] == group and g['column'])
        parts.append(f'<details><summary>{html.escape(title)}</summary><table><tr>'
                     f'<th>Counter</th><th>Conf.</th><th>Meaning</th></tr>{rows}'
                     f'</table></details>')
    rows = ''.join(f'<tr><td><code>{html.escape(k)}</code></td><td>{html.escape(v)}</td></tr>'
                   for k, v in GLOBAL_DROP_COUNTERS.items())
    parts.append(f'<details><summary>Global counters used by the cross-check</summary><table>'
                 f'<tr><th>Counter</th><th>Description printed by the firewall</th></tr>{rows}'
                 f'</table></details>')
    return ''.join(parts)

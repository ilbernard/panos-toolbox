"""Per-interface byte counters from ``show counter interface all`` (standard library only).

The parsing of the command is the one of the TSF interface report
(:func:`panos_toolbox.tsf.interface_errors.parse_interfaces`); this module only picks, for each
interface, the byte counters used for the throughput charts.

Result of :func:`parse_iface_counters`: ``{name: record}`` with

``rx`` / ``tx``     cumulative bytes received / transmitted, from the first source available among
                    the logical interface counters, the hardware counters read from the CPU and
                    the MAC counters (the same order as the TSF report)
``src``             which one it was: ``logical``, ``cpu`` or ``mac``
``logical``         True when the interface has a "Logical interface counters" block, that is it
                    is configured (physical ports that are not configured only have hardware
                    counters)
``hw``              True for a physical port (it has CPU or MAC counters)
``hw_rx`` / ``hw_tx``  bytes of the physical port (CPU counters, else MAC); used for the total so
                    that sub-interfaces, aggregates and tunnels are not counted twice

An empty dict means "no usable counters" (error text, unknown format). Never raises.
"""
from __future__ import annotations

from ..tsf import interface_errors

_HEADER = "> show counter interface all"


def _pair(block, rx_key, tx_key):
    if not block or rx_key not in block or tx_key not in block:
        return None
    return block[rx_key], block[tx_key]


def parse_iface_counters(text: str) -> dict:
    try:
        lines = [_HEADER] + str(text).replace("\r", "").split("\n")
        counters = interface_errors.parse_interfaces(lines).get("counters", {})
    except Exception:  # noqa: BLE001 - a broken sample must not stop the report
        return {}
    out = {}
    for name, rec in counters.items():
        logical, cpu, mac = rec.get("logical"), rec.get("cpu"), rec.get("mac")
        lg = _pair(logical, "bytes received", "bytes transmitted")
        hw = _pair(cpu, "bytes received", "bytes transmitted") \
            or _pair(mac, "rx-bytes", "tx-bytes")
        chosen, src = (lg, "logical") if lg else ((hw, "cpu" if _pair(cpu, "bytes received", "bytes transmitted") else "mac") if hw else (None, None))
        if chosen is None:
            continue
        out[name] = {"rx": chosen[0], "tx": chosen[1], "src": src,
                     "logical": logical is not None and bool(logical),
                     "hw": bool(cpu or mac), "hw_rx": hw[0] if hw else None,
                     "hw_tx": hw[1] if hw else None}
    return out

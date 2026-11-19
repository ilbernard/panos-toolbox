"""Turns a capture folder into the data blob of the runtime report (standard library only).

``analyze(folder, thresholds=None)`` returns a JSON-serialisable dict:

``meta``       capture parameters, sample counts, time range, firewall model and version
``session``    ``series``: one point per full cycle (allocated, supported, util_pct, tcp, udp, icmp,
               pps, kbps, cps)
``load``       management plane load averages per cycle
``delta``      ``samples`` (elapsed time, foreign sampler flag), ``counters`` (aggregated per
               counter) and ``top`` (rate series of the busiest counters)
``pow``        per-interval figures from differences of the ``ac-*`` columns: ``intervals``,
               ``groups`` and ``funcs`` (``avg_us``, ``count``, ``max_us`` series), plus the
               evaluation banner of the last sample
``backlog``    ``available``, ``series`` (atomic/total per slot and DP), ``special_tags``,
               ``offenders`` (with the ``show session id`` output)
``pbp``        ``available``, congestion ``series``, ``latency`` series, last table ``entries``
``resmon``     ``available``, per-cycle CPU/utilization summary, last per-group CPU
``findings``   list of ``{code, level, title, detail, t}``; ``level`` is critical/warning/info
``capture``    per-command timing statistics and the duration of every cycle
``thresholds`` the thresholds used

Times are UTC ISO strings. Counter rates come from the firewall's own ``rate`` column (the
delta baseline is global on the firewall, see docs/runtime/command-notes.md).
"""
from __future__ import annotations

import datetime as dt
import re
import statistics
from datetime import datetime, timezone
from pathlib import Path

from ..tsf import pow_perf
from . import commands as C
from .parse_backlog import is_unavailable, parse_backlog
from .parse_counters import parse_delta
from .parse_pbp import parse_pbp, parse_pbp_latency
from .parse_resmon import parse_resmon, summarize_resmon
from .parse_session import parse_mgmt_load, parse_session_info
from .store import CaptureReader

RT_THRESHOLDS = {
    "session_util_warn": 70.0,
    "session_util_crit": 90.0,
    "cps_spike_ratio": 3.0,
    "cps_spike_min": 500,
    "cpu_core_warn": 80,
    "cpu_core_crit": 95,
    "cpu_group_warn": 80,
    "backlog_total_warn": 90.0,
    "backlog_atomic_warn": 70.0,
    "pbp_congestion_warn": 50.0,
    "pbp_latency_warn_ms": 1000,
    "pbp_latency_crit_ms": 3000,
    "drop_rate_warn": 100,
    "drop_rate_crit": 1000,
    "cycle_slow_share": 0.5,
    "gap_ratio": 1.5,
    "top_counters": 10,
    "top_pow_funcs": 12,
    "max_pbp_entries": 50,
}

LEVEL_ORDER = {"critical": 0, "warning": 1, "info": 2}
_MODEL_RE = re.compile(r"^\s*model:\s*(.+?)\s*$", re.MULTILINE)
_SW_RE = re.compile(r"^\s*sw-version:\s*(.+?)\s*$", re.MULTILINE)
_FAMILY_RE = re.compile(r"^\s*family:\s*(.+?)\s*$", re.MULTILINE)
_HOST_RE = re.compile(r"^\s*hostname:\s*(.+?)\s*$", re.MULTILINE)


def _finding(code, level, title, detail="", t=""):
    return {"code": code, "level": level, "title": title, "detail": detail, "t": t}


def _nums(values):
    return [v for v in values if v is not None]


def _median(values):
    values = _nums(values)
    return statistics.median(values) if values else None


# ------------------------------------------------------------------------------ builders

def _session_series(samples):
    series = []
    for s in samples:
        p = parse_session_info(s.text)
        if not p.get("ok"):
            continue
        series.append({"t": s.t, "allocated": p["allocated"], "supported": p["supported"],
                       "util_pct": p["utilization_pct"], "tcp": p["active_tcp"],
                       "udp": p["active_udp"], "icmp": p["active_icmp"], "pps": p["pps"],
                       "kbps": p["kbps"], "cps": p["cps"]})
    return series


def _load_series(samples):
    out = []
    for s in samples:
        p = parse_mgmt_load(s.text)
        if p.get("ok"):
            out.append({"t": s.t, "load1": p["load1"], "load5": p["load5"],
                        "load15": p["load15"]})
    return out


def _delta(samples, th):
    out_samples, agg = [], {}
    for s in samples:
        p = parse_delta(s.text)
        out_samples.append({"t": s.t, "elapsed": p["elapsed_s"],
                            "foreign": s.attrs.get("foreign_sampler") == "1",
                            "n_counters": len(p["counters"]),
                            "total_declared": p["total_declared"]})
        for name, c in p["counters"].items():
            a = agg.setdefault(name, {"name": name, "severity": c["severity"],
                                      "category": c["category"], "aspect": c["aspect"],
                                      "description": c["description"], "samples": 0,
                                      "sum_value": 0, "rates": {}, "first_seen": len(out_samples)})
            a["samples"] += 1
            a["sum_value"] += c["value"]
            a["rates"][len(out_samples) - 1] = c["rate"]
    n = len(out_samples)
    counters = []
    for a in agg.values():
        rates = a.pop("rates")
        a["max_rate"] = max(rates.values())
        a["mean_rate"] = round(sum(rates.values()) / n, 2) if n else 0
        a["last_rate"] = rates.get(n - 1, 0)
        a["_rates"] = rates
        counters.append(a)
    counters.sort(key=lambda c: (-c["max_rate"], c["name"]))
    top = {"t": [x["t"] for x in out_samples], "series": {}}
    for c in counters[: th["top_counters"]]:
        top["series"][c["name"]] = [c["_rates"].get(i, 0) for i in range(n)]
    for c in counters:
        del c["_rates"]
    return {"samples": out_samples, "counters": counters, "top": top}


def _pow_rows(sample):
    try:
        lines = ["> " + C.POW] + sample.text.split("\n")
        return pow_perf.parse_pow(lines)
    except Exception:  # noqa: BLE001 - a broken sample must not stop the report
        return None


def _pow(samples, th):
    parsed = [(s, _pow_rows(s)) for s in samples]
    parsed = [(s, p) for s, p in parsed if p and pow_perf.has_data(p)]
    out = {"intervals": [], "groups": {}, "funcs": {}, "banner": []}
    if not parsed:
        return out
    prev = None
    totals_f = {}
    for s, p in parsed:
        view = p["global"]
        groups = {r["name"]: r for r in view["groups"]}
        funcs = {r["name"]: r for r in view["funcs"]}
        if prev is not None:
            out["intervals"].append(s.t)
            idx = len(out["intervals"]) - 1
            for kind, cur, old in (("groups", groups, prev[0]), ("funcs", funcs, prev[1])):
                dest = out[kind]
                for name, row in cur.items():
                    o = old.get(name)
                    d = {"avg_us": None, "count": 0, "max_us": row.get("max_us")}
                    if o is not None:
                        dc = row["ac_count"] - o["ac_count"]
                        dt_ = row["ac_total_us"] - o["ac_total_us"]
                        if dc > 0 and dt_ >= 0:
                            d = {"avg_us": round(dt_ / dc, 2), "count": dc,
                                 "max_us": row.get("max_us")}
                            if kind == "funcs":
                                totals_f[name] = totals_f.get(name, 0) + dt_
                    ser = dest.setdefault(name, {"avg_us": [], "count": [], "max_us": []})
                    while len(ser["avg_us"]) < idx:  # pad late-appearing rows
                        for k in ser:
                            ser[k].append(None)
                    ser["avg_us"].append(d["avg_us"])
                    ser["count"].append(d["count"])
                    ser["max_us"].append(d["max_us"])
        prev = (groups, funcs)
    keep = sorted(totals_f, key=lambda n: -totals_f[n])[: th["top_pow_funcs"]]
    out["funcs"] = {n: out["funcs"][n] for n in keep if n in out["funcs"]}
    try:
        out["banner"] = pow_perf.evaluate(parsed[-1][1]).get("banner", [])
    except Exception:  # noqa: BLE001
        out["banner"] = []
    return out


def _backlog(samples, id_samples, manifest):
    avail = manifest.get("available", {}).get("ingress_backlogs", True)
    if samples and is_unavailable(samples[0].text):
        avail = False
    out = {"available": bool(samples) and avail, "series": [], "special_tags": [],
           "offenders": []}
    if not out["available"]:
        return out
    details = {s.attrs.get("id"): s.text for s in id_samples}
    tags, seen = {}, {}
    for s in samples:
        for sec in parse_backlog(s.text):
            real = [r for r in sec["top"] if not r["special"]]
            spec = [r for r in sec["top"] if r["special"]]
            out["series"].append({"t": s.t, "slot": sec["slot"], "dp": sec["dp"],
                                  "atomic": sec["atomic"], "total": sec["total"],
                                  "real": len(real), "special": len(spec)})
            for r in spec:
                key = str(r["grp_id"])
                a = tags.setdefault(key, {"name": key, "pct_max": 0, "count_max": 0,
                                          "samples": 0})
                a["samples"] += 1
                a["pct_max"] = max(a["pct_max"], r["pct"] or 0)
                a["count_max"] = max(a["count_max"], r["count"] or 0)
            for r in real:
                key = str(r["sess_id"])
                if key not in seen:
                    seen[key] = {"id": key, "first_seen": s.t, "pct": r["pct"],
                                 "grp_id": r["grp_id"], "count": r["count"],
                                 "slot": sec["slot"], "dp": sec["dp"],
                                 "detail": details.get(key, "")}
                else:
                    seen[key]["pct"] = max(seen[key]["pct"] or 0, r["pct"] or 0)
    out["special_tags"] = sorted(tags.values(), key=lambda a: -a["pct_max"])
    out["offenders"] = list(seen.values())
    return out


def _pbp(samples, lat_samples, manifest, th):
    avail = manifest.get("available", {}).get("pbp", True)
    if samples and is_unavailable(samples[0].text):
        avail = False
    out = {"available": bool(samples) and avail, "series": [], "latency": [], "entries": [],
           "basis": None}
    if not out["available"]:
        return out
    for s in samples:
        p = parse_pbp(s.text)
        if not p["ok"]:
            continue
        out["basis"] = p["basis"] or out["basis"]
        out["series"].append({"t": s.t, "congestion_pct": p["congestion_pct"],
                              "active": p["active"], "used": p["congestion_used"],
                              "total": p["congestion_total"]})
        if p["entries"]:
            out["entries"] = p["entries"][: th["max_pbp_entries"]]
            out["entries_t"] = s.t
    for s in lat_samples:
        p = parse_pbp_latency(s.text)
        if p["ok"]:
            out["latency"].append({"t": s.t, "latest_ms": p["latest_ms"],
                                   "max_ms": max(p["max_ms"]) if p["max_ms"] else None})
    return out


def _resmon(samples, manifest):
    avail = manifest.get("available", {}).get("resource_monitor", True)
    if samples and is_unavailable(samples[0].text):
        avail = False
    out = {"available": bool(samples) and avail, "series": [], "last_groups": {},
           "last_util": {}}
    if not out["available"]:
        return out
    for s in samples:
        p = parse_resmon(s.text)
        if not p["ok"]:
            continue
        m = summarize_resmon(p)
        cmax, cavg = m["core_max_60s"], m["core_avg_60s"]
        out["series"].append({
            "t": s.t, "group_max_pct": m["group_max_pct"], "group_max_name": m["group_max_name"],
            "core_max": max(cmax.values()) if cmax else None,
            "core_avg": round(max(cavg.values()), 1) if cavg else None,
            "util_max": m["util_max_60s"]})
        out["last_groups"] = p["groups"]
        out["last_util"] = m["util_max_60s"]
    return out


# ------------------------------------------------------------------------------ capture log

def _capture_log(reader, manifest):
    stats, cycles, ticks = {}, {}, {}
    for slug in reader.slugs():
        for s in reader.samples(slug):
            a = stats.setdefault(slug, {"slug": slug, "n": 0, "failed": 0, "dur_sum": 0.0,
                                        "dur_max": 0.0})
            a["n"] += 1
            a["failed"] += 0 if s.ok else 1
            a["dur_sum"] += s.dur
            a["dur_max"] = max(a["dur_max"], s.dur)
            n = s.attrs.get("cycle")
            tick = s.attrs.get("tick", "")
            if n is None and re.fullmatch(r"c\d+", tick):
                n = tick[1:]
            if n is not None:
                cycles.setdefault(int(n), {"n": int(n), "t": s.t, "total_s": 0.0})
                cycles[int(n)]["total_s"] += s.dur
            elif tick:
                ticks[tick] = ticks.get(tick, 0.0) + s.dur
    commands = []
    for a in stats.values():
        commands.append({"slug": a["slug"], "n": a["n"], "failed": a["failed"],
                         "dur_avg": round(a["dur_sum"] / a["n"], 3),
                         "dur_max": round(a["dur_max"], 3)})
    return {"commands": commands,
            "cycles": [dict(c, total_s=round(c["total_s"], 3))
                       for c in sorted(cycles.values(), key=lambda c: c["n"])],
            "fast_tick_max_s": round(max(ticks.values()), 3) if ticks else None}


# ------------------------------------------------------------------------------ findings

def _findings(blob, th, reader):
    f = []
    meta = blob["meta"]
    for w in meta["warnings"]:
        f.append(_finding("INFLIGHT_LEFT_ON", "critical", "Inflight monitoring may still be ON",
                          w))
    util = [x for x in blob["session"]["series"] if x["util_pct"] is not None]
    if util:
        peak = max(util, key=lambda x: x["util_pct"])
        if peak["util_pct"] >= th["session_util_crit"]:
            f.append(_finding("SESSION_UTIL", "critical",
                              f"Session table at {peak['util_pct']}%", "", peak["t"]))
        elif peak["util_pct"] >= th["session_util_warn"]:
            f.append(_finding("SESSION_UTIL", "warning",
                              f"Session table at {peak['util_pct']}%", "", peak["t"]))
    cps = [x["cps"] for x in blob["session"]["series"] if x["cps"] is not None]
    med = _median(cps)
    if cps and med is not None and max(cps) >= th["cps_spike_min"] and \
            max(cps) >= th["cps_spike_ratio"] * max(med, 1):
        f.append(_finding("CPS_SPIKE", "warning",
                          f"Connection rate peak {max(cps)} cps (median {med:g})"))
    rm = blob["resmon"]
    for x in rm["series"]:
        if x["core_avg"] is not None and x["core_avg"] >= th["cpu_core_crit"]:
            f.append(_finding("CPU_CORE_HIGH", "critical",
                              f"Data plane core average at {x['core_avg']}%", "", x["t"]))
            break
        if x["core_avg"] is not None and x["core_avg"] >= th["cpu_core_warn"]:
            f.append(_finding("CPU_CORE_HIGH", "warning",
                              f"Data plane core average at {x['core_avg']}%", "", x["t"]))
            break
    for x in rm["series"]:
        if x["group_max_pct"] is not None and x["group_max_pct"] >= th["cpu_group_warn"]:
            f.append(_finding("CPU_GROUP_HIGH", "warning",
                              f"Group {x['group_max_name']} at {x['group_max_pct']}%", "",
                              x["t"]))
            break
    bl = blob["backlog"]
    if bl["offenders"]:
        for o in bl["offenders"]:
            f.append(_finding("BACKLOG_OFFENDER", "critical",
                              f"Session {o['id']} holds {o['pct']}% of the ingress backlog",
                              "show session id output is in the Ingress backlogs tab.",
                              o["first_seen"]))
    for a in bl["special_tags"]:
        f.append(_finding("BACKLOG_SPECIAL_TAG", "info",
                          f"Special tag {a['name']} up to {a['pct_max']:g}% of the backlog",
                          "A workgroup, not a session."))
    high = [x for x in bl["series"] if x["total"] is not None and x["atomic"] is not None and
            (x["total"] >= th["backlog_total_warn"] or x["atomic"] >= th["backlog_atomic_warn"])]
    if high:
        peak = max(high, key=lambda x: x["total"] or 0)
        f.append(_finding("BACKLOG_HIGH", "warning",
                          f"Ingress backlog at atomic {peak['atomic']:g}% / total "
                          f"{peak['total']:g}% ({len(high)} samples)", "", peak["t"]))
    pb = blob["pbp"]
    act = [x for x in pb["series"] if x["active"]]
    if act:
        f.append(_finding("PBP_ACTIVE", "critical", "Packet buffer protection was active",
                          f"{len(act)} samples", act[0]["t"]))
    cong = [x for x in pb["series"] if (x["congestion_pct"] or 0) >= th["pbp_congestion_warn"]]
    if cong:
        peak = max(cong, key=lambda x: x["congestion_pct"])
        f.append(_finding("PBP_CONGESTION", "warning",
                          f"Packet buffer congestion up to {peak['congestion_pct']}%", "",
                          peak["t"]))
    lat = [x for x in pb["latency"] if x["max_ms"] is not None]
    if lat:
        peak = max(lat, key=lambda x: x["max_ms"])
        if peak["max_ms"] >= th["pbp_latency_crit_ms"]:
            f.append(_finding("PBP_LATENCY_HIGH", "critical",
                              f"Packet buffer latency up to {peak['max_ms']} ms", "", peak["t"]))
        elif peak["max_ms"] >= th["pbp_latency_warn_ms"]:
            f.append(_finding("PBP_LATENCY_HIGH", "warning",
                              f"Packet buffer latency up to {peak['max_ms']} ms", "", peak["t"]))
    for c in blob["delta"]["counters"]:
        if c["severity"] == "drop" and c["max_rate"] >= th["drop_rate_warn"]:
            level = "critical" if c["max_rate"] >= th["drop_rate_crit"] else "warning"
            f.append(_finding("COUNTER_DROP_RATE", level,
                              f"Drop counter {c['name']} up to {c['max_rate']}/s",
                              c["description"]))
    for item in blob["pow"]["banner"]:
        level = {"crit": "warning", "warn": "info"}.get(item.get("level"), "info")
        f.append(_finding("POW_FINDING", level, str(item.get("text", ""))[:300]))
    foreign = sum(1 for x in blob["delta"]["samples"] if x["foreign"])
    if foreign:
        f.append(_finding("DELTA_FOREIGN_SAMPLER", "warning",
                          f"Another client reset the delta counters {foreign} time(s)",
                          "Rates use the elapsed time printed by the firewall, but part of the "
                          "window was consumed by the other client."))
    interval = meta.get("interval_s") or 0
    times = [s.t for s in reader.samples("session_info")]
    if interval and len(times) > 1:
        def ts(v):
            return datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=timezone.utc).timestamp()

        try:
            gaps = [ts(b) - ts(a) for a, b in zip(times, times[1:])]
        except ValueError:
            gaps = []
        big = [g for g in gaps if g > th["gap_ratio"] * interval]
        if big:
            f.append(_finding("SAMPLE_GAP", "warning",
                              f"{len(big)} gap(s) between cycles longer than "
                              f"{th['gap_ratio']:g}x the interval (max {max(big):.0f} s)"))
    if meta.get("skipped_ticks"):
        f.append(_finding("SAMPLE_GAP", "warning",
                          f"{meta['skipped_ticks']} sampling tick(s) skipped because the "
                          "previous work overran its period"))
    slow = [c for c in blob["capture"]["cycles"]
            if interval and c["total_s"] > th["cycle_slow_share"] * interval]
    if slow:
        f.append(_finding("CYCLE_SLOW", "warning",
                          f"{len(slow)} cycle(s) took more than "
                          f"{int(th['cycle_slow_share'] * 100)}% of the interval",
                          f"Longest {max(c['total_s'] for c in slow):.1f} s"))
    for c in blob["capture"]["commands"]:
        if c["failed"]:
            f.append(_finding("CMD_FAILED", "warning",
                              f"{c['slug']}: {c['failed']} of {c['n']} samples without a prompt",
                              "The output of those samples may be partial."))
    for key, label in (("ingress_backlogs", "ingress-backlogs"), ("pbp", "packet-buffer-protection"),
                       ("resource_monitor", "resource-monitor")):
        if not blob[{"ingress_backlogs": "backlog", "pbp": "pbp",
                     "resource_monitor": "resmon"}[key]]["available"]:
            f.append(_finding("CMD_NOT_AVAILABLE", "info", f"{label} is not available here",
                              "The firewall answered 'Invalid syntax' (platform or version)."))
    f.sort(key=lambda x: (LEVEL_ORDER[x["level"]], x["code"], x["t"]))
    return f


# ------------------------------------------------------------------------------ entry point

def analyze(folder, thresholds=None) -> dict:
    th = dict(RT_THRESHOLDS)
    th.update(thresholds or {})
    folder = Path(folder)
    reader = CaptureReader(folder)
    manifest = reader.manifest
    sysinfo = (reader.samples("system_info") or [None])[0]
    fw = {}
    if sysinfo:
        for key, rx in (("hostname", _HOST_RE), ("model", _MODEL_RE), ("sw_version", _SW_RE),
                         ("family", _FAMILY_RE)):
            m = rx.search(sysinfo.text)
            if m:
                fw[key] = m.group(1)
    counts = {slug: len(reader.samples(slug)) for slug in reader.slugs()}
    all_t = [s.t for slug in reader.slugs() for s in reader.samples(slug)]
    inflight_note = manifest.get("inflight_monitoring", "unknown")
    blob = {
        "meta": {
            "folder": folder.name,
            "tool": manifest.get("tool", ""),
            "started_utc": manifest.get("started_utc"),
            "finished_utc": manifest.get("finished_utc"),
            "interval_s": manifest.get("interval_s"),
            "backlog_interval_s": manifest.get("backlog_interval_s"),
            "duration_s": manifest.get("duration_s"),
            "cycles": manifest.get("cycles", len(reader.samples("session_info"))),
            "fast_ticks": manifest.get("fast_ticks", 0),
            "skipped_ticks": manifest.get("skipped_ticks", 0),
            "stopped_by_user": manifest.get("stopped_by_user", False),
            "available": manifest.get("available", {}),
            "inflight": {"note": inflight_note,
                         "before": manifest.get("inflight_state_before", "unknown")},
            "warnings": list(manifest.get("warnings", [])),
            "sample_counts": counts,
            "first_t": min(all_t) if all_t else None,
            "last_t": max(all_t) if all_t else None,
            "firewall": fw,
            "has_manifest": bool(manifest),
            "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        },
        "session": {"series": _session_series(reader.samples("session_info"))},
        "load": _load_series(reader.samples("mgmt_load")),
        "delta": _delta(reader.samples("delta"), th),
        "pow": _pow(reader.samples("pow"), th),
        "backlog": _backlog(reader.samples("ingress_backlogs"),
                            reader.samples("session_id"), manifest),
        "pbp": _pbp(reader.samples("pbp"), reader.samples("pbp_latency"), manifest, th),
        "resmon": _resmon(reader.samples("resource_monitor"), manifest),
        "capture": _capture_log(reader, manifest),
        "thresholds": th,
    }
    blob["findings"] = _findings(blob, th, reader)
    return blob

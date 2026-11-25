"""``panos-toolbox runtime capture``: samples a firewall over SSH and stores the raw outputs.

Every ``--interval`` seconds a full cycle runs (POW, global counter delta, session info,
resource monitor, management plane load); every ``--backlog-interval`` seconds (default
interval/6, minimum 1 s) a fast tick runs (ingress-backlogs, packet-buffer-protection and its
latency, then, as the least important, the interface counters for the throughput charts; those
are skipped when the tick is already a full period late). For every real session reported by ingress-backlogs the tool also runs
``show session id <id>``. Inflight monitoring is switched on at the start and always left OFF at
the end, with a loud warning when the final ``no`` cannot be confirmed.

The password is asked with getpass (or an SSH key file is used); no secret is accepted on the
command line, printed or written to disk. The capture folder contains the firewall's real
hostnames, IPs and serials: keep it out of the repository.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import getpass
import platform
import re
import signal
import sys
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import commands as C
from .parse_backlog import is_unavailable, offending_ids, parse_backlog
from .parse_sessions_all import parse_sessions_page
from .store import CaptureWriter
from .transport import Clock, Transport, TransportError

ELAPSED_RE = re.compile(r"Elapsed time since last sampling:\s*([\d.]+)\s+seconds")
SET_FAILED_RE = re.compile(r"invalid syntax|unknown command|not permitted|denied|error", re.IGNORECASE)
_ON_RE = re.compile(r"\b(yes|on|enabled|true)\b", re.IGNORECASE)
_OFF_RE = re.compile(r"\b(no|off|disabled|false)\b", re.IGNORECASE)

MIN_BACKLOG_INTERVAL = 1.0
SESSIONS_EMPTY_STOP = 3  # consecutive pages without sessions that end the dump


def inflight_state(text: str) -> str:
    """'on', 'off' or 'unknown' from ``show session inflight_monitoring status``.

    The wording is not verified yet: anything ambiguous, or an error, is 'unknown'.
    """
    if is_unavailable(text):
        return "unknown"
    on, off = bool(_ON_RE.search(text)), bool(_OFF_RE.search(text))
    return "on" if on and not off else "off" if off and not on else "unknown"


def next_index(t0: float, period: float, idx: int, covered_until: float, now: float):
    """Index of the next tick after tick ``idx`` was served at ``now``, and ticks skipped.

    Ticks covered by the work just done (due <= covered_until) are not repeated; ticks more
    than one full period late are skipped and counted.
    """
    idx += 1
    while t0 + idx * period <= covered_until + 1e-6:
        idx += 1
    skipped = 0
    while t0 + idx * period < now - period:
        idx += 1
        skipped += 1
    return idx, skipped


@dataclass
class CaptureConfig:
    interval: float = 30.0
    backlog_interval: float | None = None
    duration: float = 120.0  # 0 = until Ctrl+C
    max_cycles: int = 0  # 0 = no limit
    pow_all: bool = False
    inflight: bool = True
    max_offenders: int = 10
    iface_counters: bool = True  # "show counter interface all" in every fast tick
    dump_sessions: bool = False  # one paged "show session all start-at N" dump at the end
    sessions_max_pages: int = 500  # about 500K sessions; a larger table is cut and flagged
    sessions_pause: float = 0.2  # seconds between pages, to spare the management plane

    def __post_init__(self):
        if self.interval < 1:
            raise ValueError("--interval must be at least 1 second")
        if self.sessions_max_pages < 1:
            raise ValueError("--sessions-max-pages must be at least 1")
        if self.sessions_pause < 0:
            raise ValueError("--sessions-pause cannot be negative")
        if self.backlog_interval is None:
            self.backlog_interval = self.interval / 6
        self.backlog_interval = max(MIN_BACKLOG_INTERVAL, self.backlog_interval)


class Capture:
    def __init__(self, transport: Transport, writer: CaptureWriter, cfg: CaptureConfig,
                 clock: Clock | None = None,
                 reconnect: Callable[[], Transport] | None = None,
                 out: Callable[[str], None] = print):
        self.t = transport
        self.w = writer
        self.cfg = cfg
        self.clock = clock or Clock()
        self.reconnect = reconnect
        self.say = out
        self.cycles = 0
        self.fast_ticks = 0
        self.skipped = 0
        self.iface_skipped = 0
        self.foreign = 0
        self.last_delta: float | None = None
        self.available = {"ingress_backlogs": True, "pbp": True, "pbp_latency": True,
                          "resource_monitor": True, "iface_counters": True}
        self.seen_ids: set = set()
        self.warnings: list = []
        self.stopped_by_user = False
        self.sessions_dump: dict = {"requested": cfg.dump_sessions}
        self.inflight = {"wanted": cfg.inflight, "needs_off": False, "off_done": False,
                         "prior": "not read", "note": "not requested"}
        self.started = self.clock.utcnow()

    # ------------------------------------------------------------------ primitives

    def _stamp(self) -> str:
        return self.clock.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def run(self, cmd: str, transport: Transport | None = None,
            attrs_fn: Callable[[str], dict[str, str]] | None = None, **attrs):
        """Runs one allowed command and stores the sample; returns ``(text, ok)``."""
        C.check_allowed(cmd)
        stamp = self._stamp()
        t0 = self.clock.monotonic()
        text, ok = (transport or self.t).run(cmd)
        dur = self.clock.monotonic() - t0
        if attrs_fn:
            attrs = {**attrs, **attrs_fn(text)}
        self.w.add(C.slug_for(cmd), stamp, dur, ok, text, **attrs)
        return text, ok

    # ------------------------------------------------------------------ inflight monitoring

    def _set_inflight(self, cmd: str, transport: Transport | None = None) -> bool:
        text, ok = self.run(cmd, transport)
        return ok and not SET_FAILED_RE.search(text)

    def inflight_on(self) -> None:
        inf = self.inflight
        text, _ = self.run(C.INFLIGHT_STATE)
        inf["prior"] = inflight_state(text)
        if not inf["wanted"]:
            return
        if inf["prior"] == "on":
            self.say("  Inflight monitoring was already ON: it will be set to OFF at the end.")
        self.say("Enabling inflight monitoring ...")
        text, ok = self.run(C.INFLIGHT_ON)
        if ok and not SET_FAILED_RE.search(text):
            inf.update(needs_off=True, note="enabled")
        elif not ok:  # no prompt back: state unknown, assume enabled
            inf.update(needs_off=True, note="enable unconfirmed (no prompt)")
        else:
            inf["note"] = "enable FAILED (command rejected)"
            inf["needs_off"] = inf["prior"] == "on"  # it still must end OFF
            self.say("  WARNING: the firewall rejected the inflight monitoring command.")

    def inflight_off(self) -> None:
        inf = self.inflight
        if not inf["needs_off"] or inf["off_done"]:
            return
        self.say("Disabling inflight monitoring ...")
        for attempt in (1, 2):
            try:
                tr = self.t
                if attempt == 2:
                    if not self.reconnect:
                        break
                    tr = self.reconnect()
                if self._set_inflight(C.INFLIGHT_OFF, tr):
                    after = inflight_state(self.run(C.INFLIGHT_STATE, tr)[0])
                    if after == "on":
                        self.say("  the firewall still reports inflight monitoring ON")
                        continue
                    was = "was ON before the capture; " if inf["prior"] == "on" else ""
                    tail = "" if after == "off" else "; state not verifiable"
                    inf.update(off_done=True,
                               note=f"ended OFF ({was}enabled, then disabled{tail})")
                    return
            except (TransportError, ValueError, OSError) as exc:
                self.say(f"  attempt {attempt} failed: {type(exc).__name__}")
        self.warnings.append(
            f"inflight monitoring may still be ENABLED: run '{C.INFLIGHT_OFF}' manually")

    # ------------------------------------------------------------------ sampling

    def preamble(self) -> None:
        self.say("Preamble ...")
        for cmd in (C.SYSTEM_INFO, C.CLOCK, C.PBP_ZONES, C.BACKLOG_THRESHOLD,
                    C.BACKLOG_DURATION, C.BACKLOG_TRIGGER):
            self.run(cmd)

    def _delta_attrs(self, mono_started: float) -> Callable[[str], dict[str, str]]:
        def fn(text: str) -> dict[str, str]:
            m = ELAPSED_RE.search(text)
            if not m:
                return {}
            elapsed = float(m.group(1))
            attrs = {"elapsed": f"{elapsed:.3f}"}
            if self.last_delta is not None:
                gap = mono_started - self.last_delta
                attrs["local_gap"] = f"{gap:.3f}"
                if abs(elapsed - gap) > max(2.0, 0.15 * gap):
                    self.foreign += 1
                    attrs["foreign_sampler"] = "1"
                    self.say(f"      delta: firewall says {elapsed:.1f}s, our gap is {gap:.1f}s: "
                             "someone else ran the same command in between")
            self.last_delta = mono_started
            return attrs
        return fn

    def _optional(self, key: str, cmd: str, **attrs) -> str | None:
        if not self.available[key]:
            return None
        text, _ = self.run(cmd, **attrs)
        if is_unavailable(text):
            self.available[key] = False
            self.say(f"      {cmd!r} is not available on this firewall: not sampled any more")
            return None
        return text

    def fast_tick(self, label: str, due: float | None = None) -> None:
        self.fast_ticks += 1
        text = self._optional("ingress_backlogs", C.BACKLOG, tick=label)
        if text is not None:
            sections = parse_backlog(text)
            for sec in sections:
                real = [r for r in sec["top"] if not r["special"]]
                spec = [r for r in sec["top"] if r["special"]]
                self.say(f"      slot {sec['slot']} {sec['dp']}: atomic={sec['atomic']}% "
                         f"total={sec['total']}% sessions={len(real)} special_tags={len(spec)}")
            new = [i for i in offending_ids(sections) if i not in self.seen_ids]
            for sid in new[: self.cfg.max_offenders]:
                self.seen_ids.add(sid)
                self.run(f"show session id {sid}", id=sid, tick=label)
        self._optional("pbp", C.PBP, tick=label)
        self._optional("pbp_latency", C.PBP_LAT, tick=label)
        # Last and first to go: throughput matters less than the overload indicators.
        if self.cfg.iface_counters:
            if due is not None and self.clock.monotonic() > due + self.cfg.backlog_interval:
                self.iface_skipped += 1
            else:
                self._optional("iface_counters", C.IFACE_COUNTERS, tick=label)

    def cycle(self, n: int) -> None:
        self.run(C.MGMT_LOAD, cycle=n)
        self.run(C.SESSION_INFO, cycle=n)
        self._optional("resource_monitor", C.RESMON, cycle=n)
        self.run(C.POW, cycle=n)
        if self.cfg.pow_all:
            self.run(C.POW_ALL, cycle=n)
        started = self.clock.monotonic()
        self.run(C.DELTA, attrs_fn=self._delta_attrs(started), cycle=n)
        self.fast_tick(f"c{n}")  # covers the coincident fast tick

    def dump_sessions(self) -> None:
        """Pages through the whole session table (``show session all start-at N``, 1K a page).

        Stops at the end of the table (empty pages), at ``sessions_max_pages`` (truncated, with a
        warning), on an error answer or on Ctrl+C. Session ids already seen are counted as
        duplicates (a live table moves while it is read, so this is not an atomic snapshot).
        """
        cfg = self.cfg
        info = self.sessions_dump
        info.update(pages=0, sessions=0, duplicates=0, truncated=False, reason="")
        seen: set = set()
        empty = 0
        start = 1
        self.say("Dumping the session table (show session all start-at N) ...")
        try:
            while True:
                if info["pages"] >= cfg.sessions_max_pages:
                    info.update(truncated=True, reason=f"page limit {cfg.sessions_max_pages}")
                    break
                if start > C.SESSIONS_ALL_MAX_START:
                    info["reason"] = "end of the start-at range"
                    break
                text, ok = self.run(C.sessions_all_cmd(start), start=start)
                info["pages"] += 1
                if not ok or is_unavailable(text):
                    info.update(truncated=True, reason="command failed or not available")
                    self.warnings.append(
                        f"session dump stopped at start-at {start}: command failed or not available")
                    break
                rows = parse_sessions_page(text)
                new = [r for r in rows if r["id"] not in seen]
                seen.update(r["id"] for r in rows)
                info["duplicates"] += len(rows) - len(new)
                info["sessions"] = len(seen)
                empty = 0 if rows else empty + 1
                if info["pages"] % 50 == 0:
                    self.say(f"      {info['pages']} pages, {info['sessions']} sessions so far")
                if empty >= SESSIONS_EMPTY_STOP:
                    info["reason"] = "end of the table"
                    break
                start += C.SESSIONS_ALL_PAGE
                if cfg.sessions_pause:
                    self.clock.sleep(cfg.sessions_pause)
        except KeyboardInterrupt:
            self.stopped_by_user = True
            info.update(truncated=True, reason="stopped by the user")
            self.say("\nSession dump interrupted by the user.")
        if info["truncated"] and info["reason"].startswith("page limit"):
            self.warnings.append(
                f"session dump truncated at {info['pages']} pages ({info['sessions']} sessions): "
                "raise --sessions-max-pages to read the whole table")
        self.say(f"  session dump: {info['pages']} pages, {info['sessions']} sessions"
                 + (" (TRUNCATED)" if info["truncated"] else ""))

    def loop(self) -> None:
        clock, cfg = self.clock, self.cfg
        x, b = cfg.interval, cfg.backlog_interval
        t0 = clock.monotonic()
        end = t0 + cfg.duration if cfg.duration > 0 else float("inf")
        k = j = 0
        while True:
            due_m, due_b = t0 + k * x, t0 + j * b
            nxt = min(due_m, due_b)
            if nxt >= end:
                break
            wait = nxt - clock.monotonic()
            if wait > 0:
                clock.sleep(wait)
            if due_m <= due_b:
                self.cycles += 1
                self.cycle(self.cycles)
                now = clock.monotonic()
                k, s1 = next_index(t0, x, k, due_m, now)
                j, s2 = next_index(t0, b, j - 1, due_m, now)
                self.skipped += s1 + s2
                if cfg.max_cycles and self.cycles >= cfg.max_cycles:
                    break
            else:
                self.fast_tick(f"t{j}", due_b)
                now = clock.monotonic()
                j, s2 = next_index(t0, b, j, due_b, now)
                self.skipped += s2

    # ------------------------------------------------------------------ run

    def manifest(self) -> dict:
        inf = self.inflight
        return {
            "tool": "panos-toolbox runtime capture",
            "started_utc": self.started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished_utc": self.clock.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python": platform.python_version(),
            "interval_s": self.cfg.interval,
            "backlog_interval_s": self.cfg.backlog_interval,
            "duration_s": self.cfg.duration,
            "pow_all": self.cfg.pow_all,
            "cycles": self.cycles,
            "fast_ticks": self.fast_ticks,
            "skipped_ticks": self.skipped,
            "iface_counters_skipped": self.iface_skipped,
            "delta_foreign_sampler_events": self.foreign,
            "available": dict(self.available),
            "stopped_by_user": self.stopped_by_user,
            "inflight_monitoring": inf["note"],
            "inflight_state_before": inf["prior"],
            "sessions_dump": dict(self.sessions_dump),
            "warnings": list(self.warnings),
        }

    def execute(self) -> dict:
        """Preamble, inflight on, sampling loop, inflight off, optional session dump; returns the manifest."""
        try:
            self.preamble()
            self.inflight_on()
            self.say("Sampling (Ctrl+C stops it) ...")
            try:
                self.loop()
            except KeyboardInterrupt:
                self.stopped_by_user = True
                self.say("\nStopped by the user.")
            with _shielded():  # sampling is over: put inflight monitoring back to OFF first,
                self.inflight_off()  # so a slow or interrupted session dump cannot leave it ON
            if self.cfg.dump_sessions:
                self.dump_sessions()
            self.run(C.CLOCK)
        except KeyboardInterrupt:  # Ctrl+C during setup: still clean up and keep what we have
            self.stopped_by_user = True
            self.say("\nStopped by the user.")
        finally:
            with _shielded():  # a second Ctrl+C must not skip the inflight monitoring "no"
                self.inflight_off()
                self.w.write_manifest(self.manifest())
        return self.manifest()


@contextlib.contextmanager
def _shielded():
    """Ignores Ctrl+C while the firewall is being put back in its normal state."""
    old = None
    with contextlib.suppress(ValueError):  # not the main thread: nothing to shield
        old = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        yield
    finally:
        if old is not None:
            signal.signal(signal.SIGINT, old)


# ---------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="panos-toolbox runtime capture",
        description="Sample a PAN-OS firewall over SSH and store the raw outputs "
                    "(then run 'panos-toolbox runtime report' on the folder).")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--key-file", help="SSH private key (the password is asked otherwise)")
    ap.add_argument("--accept-new-hostkey", action="store_true",
                    help="trust an unknown SSH host key (default: reject)")
    ap.add_argument("--interval", type=float, default=30.0,
                    help="seconds between full cycles (default 30)")
    ap.add_argument("--backlog-interval", type=float, default=None,
                    help="seconds between fast ticks (default interval/6, minimum 1)")
    ap.add_argument("--duration", type=float, default=120.0,
                    help="total seconds to sample (default 120; 0 = until Ctrl+C)")
    ap.add_argument("--max-cycles", type=int, default=0, help="stop after N full cycles")
    ap.add_argument("--pow-all", action="store_true",
                    help="also run 'debug dataplane pow performance all' (histograms)")
    ap.add_argument("--no-inflight-monitoring", action="store_true",
                    help="do not run 'set session inflight_monitoring yes/no'")
    ap.add_argument("--max-offenders", type=int, default=10,
                    help="show session id queries per fast tick (default 10)")
    ap.add_argument("--no-iface-counters", action="store_true",
                    help="do not run 'show counter interface all' in the fast ticks "
                         "(no throughput charts, shorter ticks)")
    ap.add_argument("--dump-sessions", action="store_true",
                    help="at the end of the capture, dump every active session with a paged "
                         "'show session all start-at N' (1K sessions per command; heavy on big "
                         "tables, see --sessions-max-pages)")
    ap.add_argument("--sessions-max-pages", type=int, default=500,
                    help="page limit of the session dump (default 500, about 500K sessions; "
                         "a table cut by the limit is flagged)")
    ap.add_argument("--sessions-pause", type=float, default=0.2,
                    help="seconds to wait between pages of the session dump (default 0.2)")
    ap.add_argument("--no-compress", action="store_true", help="write plain text raw files")
    ap.add_argument("--outdir", default=".", help="where the capture folder is created")
    ap.add_argument("--no-report", action="store_true",
                    help="do not build the HTML report when the capture ends")
    ap.add_argument("--open", action="store_true", help="open the report in the browser")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = CaptureConfig(interval=args.interval, backlog_interval=args.backlog_interval,
                            duration=args.duration, max_cycles=args.max_cycles,
                            pow_all=args.pow_all, inflight=not args.no_inflight_monitoring,
                            max_offenders=args.max_offenders,
                            iface_counters=not args.no_iface_counters,
                            dump_sessions=args.dump_sessions,
                            sessions_max_pages=args.sessions_max_pages,
                            sessions_pause=args.sessions_pause)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    from . import ssh

    cache: dict[str, str] = {}

    def ask(prompt: str) -> str:
        if prompt not in cache:  # kept in memory only, never printed or saved
            cache[prompt] = getpass.getpass(prompt)
        return cache[prompt]

    def open_session() -> Transport:
        return ssh.connect(args.host, args.port, args.user, args.key_file, ask,
                           args.accept_new_hostkey)

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_host = re.sub(r"[^A-Za-z0-9.-]", "_", args.host)
    folder = Path(args.outdir) / f"runtime_{safe_host}_{stamp}"
    transport = None
    writer = None
    try:
        print("Opening SSH session ...")
        transport = open_session()
        writer = CaptureWriter(folder, compress=not args.no_compress)
        print(f"Capture folder: {folder}")
        cap = Capture(transport, writer, cfg, reconnect=open_session)
        result = cap.execute()
    except KeyboardInterrupt:  # before the sampling started: nothing to report
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except TransportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if writer is not None:  # connection lost mid-capture: report what was collected
            writer.close()
            writer = None
            _finish_report(folder, args)
        return 1
    finally:
        if transport:
            transport.close()
        if writer:
            writer.close()
    if result["warnings"]:
        print("\n" + "!" * 70)
        for w in result["warnings"]:
            print(f"WARNING: {w} (host: {args.host})")
        print("!" * 70)
    print(f"\nDone: {result['cycles']} cycles, {result['fast_ticks']} fast ticks, "
          f"{result['delta_foreign_sampler_events']} foreign-sampler events, "
          f"{result['skipped_ticks']} skipped ticks.")
    return _finish_report(folder, args)


def _finish_report(folder: Path, args) -> int:
    """Builds the HTML report from the capture just written (also after Ctrl+C)."""
    if args.no_report:
        print(f"Report: panos-toolbox runtime report {folder}")
        return 0
    from .analyzer import build_report

    try:
        blob, target = build_report(folder)
    except Exception as exc:  # noqa: BLE001  # the raw capture is safe on disk whatever happens here
        print(f"ERROR building the report: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"The capture is kept; retry with: panos-toolbox runtime report {folder}")
        return 1
    sev = {lv: sum(1 for f in blob["findings"] if f["level"] == lv)
           for lv in ("critical", "warning", "info")}
    print(f"Report: {target}  (findings: {sev['critical']} critical, "
          f"{sev['warning']} warning, {sev['info']} info)")
    if args.open:
        webbrowser.open(target.resolve().as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())

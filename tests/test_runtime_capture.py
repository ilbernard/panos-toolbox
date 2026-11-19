import json

import pytest

from panos_toolbox.runtime import commands as C
from panos_toolbox.runtime.capture import (
    Capture,
    CaptureConfig,
    inflight_state,
    next_index,
)
from panos_toolbox.runtime.fake import FakeTransport, SimClock
from panos_toolbox.runtime.store import CaptureReader, CaptureWriter

BACKLOG_OK = "-- SLOT: s1, DP: dp0 --\nUSAGE - ATOMIC: 1.0% TOTAL: 2.0%\n"
BACKLOG_OFFENDER = (
    "-- SLOT: s1, DP: dp0 --\nUSAGE - ATOMIC: 80.0% TOTAL: 86.0%\n\nTOP SESSIONS:\n"
    "SESS-ID PCT GRP-ID COUNT\n235208 80% 1 874\n\nSESSION DETAILS\n")
BACKLOG_SPECIAL = (
    "-- SLOT: s1, DP: dp0 --\nUSAGE - ATOMIC: 50.0% TOTAL: 90.0%\n\nTOP SESSIONS:\n"
    "SESS-ID PCT GRP-ID COUNT Special Notes\n"
    "2149580803 23% pktlog_forwarding 242 Special TAG values, NOT valid session id\n")
INVALID = "Invalid syntax."


class Fw:
    """A tiny firewall model: delta baseline, inflight state, optional commands."""

    def __init__(self, clock, backlog=BACKLOG_OK, pbp="ok", resmon="ok", state_cmd=True,
                 stuck_on=False, foreign_at=None, prior="no"):
        self.clock, self.backlog, self.pbp, self.resmon = clock, backlog, pbp, resmon
        self.state = prior
        self.stuck_on = stuck_on
        self.state_cmd = state_cmd
        self.last_delta = clock.now
        self.ndelta = 0
        self.foreign_at = foreign_at

    def responses(self):
        r = {
            C.SESSION_INFO: "Number of sessions supported: 100\n",
            C.POW: "pow\n",
            C.MGMT_LOAD: "top - load average: 1.0, 1.0, 1.0\n",
            C.RESMON: INVALID if self.resmon == "invalid" else "resmon\n",
            C.PBP: INVALID if self.pbp == "invalid" else "pbp\n",
            C.PBP_LAT: INVALID if self.pbp == "invalid" else "lat\n",
            C.BACKLOG: INVALID if self.backlog == INVALID else self.backlog,
            C.DELTA: self.delta,
            C.INFLIGHT_STATE: self.inflight_state,
            C.INFLIGHT_ON: self.set_on,
            C.INFLIGHT_OFF: self.set_off,
        }
        return r

    def delta(self, cmd):
        self.ndelta += 1
        if self.foreign_at == self.ndelta:
            self.last_delta = self.clock.now - 7
        out = f"Elapsed time since last sampling: {self.clock.now - self.last_delta:6.3f} seconds\n"
        self.last_delta = self.clock.now
        return out

    def inflight_state(self, cmd):
        return f"Inflight monitoring: {self.state}" if self.state_cmd else INVALID

    def set_on(self, cmd):
        self.state = "yes"
        return "\n"

    def set_off(self, cmd):
        if not self.stuck_on:
            self.state = "no"
        return "\n"


def build(tmp_path, cfg=None, **fw_kw):
    clock = SimClock()
    fw = Fw(clock, **fw_kw)
    tr = FakeTransport(fw.responses(), clock)
    w = CaptureWriter(tmp_path / "cap")
    cap = Capture(tr, w, cfg or CaptureConfig(interval=30, duration=65), clock=clock,
                  reconnect=lambda: tr, out=lambda s: None)
    return cap, tr, fw, w


def count(tr, cmd):
    return tr.commands().count(cmd)


def test_scheduler_two_periods(tmp_path):
    cap, tr, _, _ = build(tmp_path)
    m = cap.execute()
    assert m["cycles"] == 3 and m["fast_ticks"] == 13 and m["backlog_interval_s"] == 5.0
    assert count(tr, C.RESMON) == 3  # once per full cycle (X)
    assert count(tr, C.BACKLOG) == count(tr, C.PBP) == count(tr, C.PBP_LAT) == 13  # every X/6
    cycle_times = [round(t - 1000) for t, c in tr.log if c == C.SESSION_INFO]
    assert cycle_times == [2, 32, 62] or len(cycle_times) == 3
    assert m["skipped_ticks"] == 0


def test_backlog_interval_has_a_minimum_of_one_second(tmp_path):
    cfg = CaptureConfig(interval=3, duration=10)
    assert cfg.backlog_interval == 1.0
    with pytest.raises(ValueError):
        CaptureConfig(interval=0.5)
    cap, _, _, _ = build(tmp_path, cfg)
    m = cap.execute()
    assert m["backlog_interval_s"] == 1.0
    assert 1 <= m["fast_ticks"] <= 12  # about one per second for 10 s, never faster


def test_foreign_delta_sampler_is_flagged(tmp_path):
    cap, _, _, w = build(tmp_path, foreign_at=2)
    m = cap.execute()
    w.close()
    assert m["delta_foreign_sampler_events"] == 1
    flagged = [s for s in CaptureReader(tmp_path / "cap").samples("delta")
               if s.attrs.get("foreign_sampler") == "1"]
    assert len(flagged) == 1 and float(flagged[0].attrs["elapsed"]) < 20


def test_padded_elapsed_number_is_read(tmp_path):
    cap, tr, _, w = build(tmp_path)
    tr.responses[C.DELTA] = lambda cmd: "Elapsed time since last sampling:  5.64  seconds\n"
    cap.execute()
    w.close()
    assert CaptureReader(tmp_path / "cap").samples("delta")[0].attrs["elapsed"] == "5.640"


def test_unavailable_commands_probed_once(tmp_path):
    cap, tr, _, _ = build(tmp_path, backlog=INVALID, pbp="invalid", resmon="invalid")
    m = cap.execute()
    assert m["available"] == {"ingress_backlogs": False, "pbp": False, "pbp_latency": False,
                              "resource_monitor": False}
    assert count(tr, C.BACKLOG) == 1 and count(tr, C.PBP) == 1 and count(tr, C.RESMON) == 1
    assert m["cycles"] == 3


def test_offender_queried_once_and_special_tag_never(tmp_path):
    cap, tr, _, _ = build(tmp_path, backlog=BACKLOG_OFFENDER)
    cap.execute()
    assert [c for c in tr.commands() if c.startswith("show session id")] == [
        "show session id 235208"]
    cap, tr, _, _ = build(tmp_path / "b", backlog=BACKLOG_SPECIAL)
    cap.execute()
    assert not [c for c in tr.commands() if c.startswith("show session id")]


def test_overrun_skips_ticks(tmp_path):
    cap, _, _, _ = build(tmp_path, CaptureConfig(interval=30, duration=130))
    orig = cap.cycle

    def slow(n):
        orig(n)
        cap.clock.advance(70)

    cap.cycle = slow
    m = cap.execute()
    assert m["skipped_ticks"] > 0


def test_next_index_covers_coincident_tick_and_counts_skips():
    idx, skipped = next_index(0.0, 5.0, 5, 30.0, 31.0)  # tick 6 (t=30) already served
    assert idx == 7 and skipped == 0
    idx, skipped = next_index(0.0, 5.0, 0, 5.0, 100.0)
    assert skipped > 0


def test_inflight_on_then_always_off(tmp_path):
    cap, tr, fw, _ = build(tmp_path)
    m = cap.execute()
    cmds = tr.commands()
    assert cmds.index(C.INFLIGHT_ON) < cmds.index(C.INFLIGHT_OFF)
    assert fw.state == "no" and m["inflight_monitoring"].startswith("ended OFF")
    assert m["inflight_state_before"] == "off" and not m["warnings"]


def test_inflight_already_on_is_turned_off_and_noted(tmp_path):
    cap, tr, _, _ = build(tmp_path, prior="yes")
    m = cap.execute()
    assert C.INFLIGHT_ON in tr.commands() and C.INFLIGHT_OFF in tr.commands()
    assert m["inflight_state_before"] == "on" and "was ON before" in m["inflight_monitoring"]


def test_inflight_state_unreadable_still_toggles(tmp_path):
    cap, _, fw, _ = build(tmp_path, state_cmd=False)
    m = cap.execute()
    assert fw.state == "no" and "state not verifiable" in m["inflight_monitoring"]


def test_inflight_stuck_on_gives_a_warning(tmp_path):
    cap, _, _, _ = build(tmp_path, stuck_on=True)
    m = cap.execute()
    assert any("manually" in w for w in m["warnings"])


def test_no_inflight_flag_leaves_configuration_alone(tmp_path):
    cap, tr, _, _ = build(tmp_path, CaptureConfig(interval=30, duration=40, inflight=False))
    cap.execute()
    assert C.INFLIGHT_ON not in tr.commands() and C.INFLIGHT_OFF not in tr.commands()


def test_ctrl_c_stops_and_disables_inflight(tmp_path):
    cap, _, fw, _ = build(tmp_path, CaptureConfig(interval=30, duration=0))
    orig = cap.cycle

    def interrupt(n):
        orig(n)
        if n == 2:
            raise KeyboardInterrupt

    cap.cycle = interrupt
    m = cap.execute()
    assert m["stopped_by_user"] and m["cycles"] == 2 and fw.state == "no"


def test_max_cycles_and_manifest_has_no_host_or_user(tmp_path):
    cap, _, _, _ = build(tmp_path, CaptureConfig(interval=30, duration=0, max_cycles=2))
    m = cap.execute()
    assert m["cycles"] == 2
    keys = set(json.loads((tmp_path / "cap" / "manifest.json").read_text()))
    assert not keys & {"host", "hostname", "user", "username", "password", "banner", "prompt"}


def test_session_samples_stored_per_command(tmp_path):
    cap, _, _, w = build(tmp_path)
    cap.execute()
    w.close()
    r = CaptureReader(tmp_path / "cap")
    assert {"pow", "delta", "session_info", "resource_monitor", "ingress_backlogs", "pbp",
            "pbp_latency", "mgmt_load", "system_info", "clock"} <= set(r.slugs())
    assert len(r.samples("pow")) == 3


@pytest.mark.parametrize("text,expected", [
    ("Inflight monitoring: yes", "on"), ("inflight monitoring is enabled", "on"),
    ("Inflight monitoring: no", "off"), ("disabled", "off"),
    ("Invalid syntax.", "unknown"), ("something odd", "unknown"), ("on off", "unknown"),
])
def test_inflight_state_parsing(text, expected):
    assert inflight_state(text) == expected


def test_capture_main_builds_report_and_survives_ctrl_c(tmp_path, monkeypatch):
    import sys

    from panos_toolbox.runtime import capture as cap
    from panos_toolbox.runtime.fake import FakeTransport, SimClock

    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
    from runtime_synthetic import SYSTEM_INFO  # noqa: F401

    clock = SimClock()
    fake = FakeTransport({}, clock)
    monkeypatch.setattr("panos_toolbox.runtime.ssh.connect", lambda *a, **k: fake)

    def boom(self):
        raise KeyboardInterrupt

    monkeypatch.setattr(cap.Capture, "loop", boom)
    rc = cap.main(["--host", "h", "--user", "u", "--outdir", str(tmp_path)])
    assert rc in (0, 1)
    folders = [p for p in tmp_path.iterdir() if p.is_dir()]
    assert len(folders) == 1 and (folders[0] / "manifest.json").exists()
    assert "stopped_by_user" in (folders[0] / "manifest.json").read_text()

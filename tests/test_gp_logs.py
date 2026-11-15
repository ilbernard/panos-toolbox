"""Tests for gp/logs.py: service/agent log records and event-log lines (synthetic data only)."""
from __future__ import annotations

from datetime import datetime

from panos_toolbox.gp.logs import (
    ParseStats,
    iter_event_log,
    iter_records,
    parse_event_log,
    parse_records,
)

P = "(P100-T200)"


def rec_line(level="Debug", code=1234, stamp="11/12/26 20:38:12:533", msg="hello"):
    pad = level.ljust(5)
    return f"{P}{pad}({code:>4}): {stamp} {msg}"


def test_normal_record():
    text = rec_line("Info", 564, msg="msgtype = portal") + "\r\n"
    recs, st = parse_records(text, "PanGPS.log")
    assert len(recs) == 1
    r = recs[0]
    assert (r.pid, r.tid, r.level, r.code) == (100, 200, "Info", 564)
    assert r.ts == datetime(2026, 11, 12, 20, 38, 12, 533000)  # noqa: DTZ001
    assert r.msg == "msgtype = portal" and r.src == "PanGPS.log"
    assert r.extra == () and r.body == ""
    assert st.records == 1 and st.unparseable == 0 and st.first == st.last == r.ts


def test_level_padding_and_wide_code():
    text = "\n".join([rec_line("Dump", 5), rec_line("Info", 14802), rec_line("Error", 7), rec_line("Debug", 99)])
    recs, st = parse_records(text, "x")
    assert [r.level for r in recs] == ["Dump", "Info", "Error", "Debug"]
    assert [r.code for r in recs] == [5, 14802, 7, 99]
    assert st.levels == {"Dump": 1, "Info": 1, "Error": 1, "Debug": 1}


def test_glued_record():
    text = rec_line(msg="first no newline") + rec_line("Dump", 9, msg="second") + "\r\n"
    recs = list(iter_records(text, "x"))
    assert [r.msg for r in recs] == ["first no newline", "second"]
    assert recs[1].level == "Dump"


def test_continuation_lines():
    text = (rec_line(msg="prelogin result is ") + "\r\n<response>\r\n\t<status>ok</status>\r\n</response>\r\n"
            + rec_line(msg="next") + "\r\n")
    recs = list(iter_records(text, "x"))
    assert len(recs) == 2
    assert recs[0].msg == "prelogin result is"
    assert recs[0].extra == ["<response>", "\t<status>ok</status>", "</response>"]
    assert recs[0].body == "<response>\n\t<status>ok</status>\n</response>"
    assert recs[1].extra == ()


def test_lone_cr_and_double_cr():
    text = (rec_line(msg="a") + "\r\r\n" + "Windows IP Configuration\r\r\n\r\n"
            + "x\ry\r\n" + rec_line(msg="b") + "\r\n")
    recs = list(iter_records(text, "x"))
    assert [r.msg for r in recs] == ["a", "b"]
    assert recs[0].extra == ["Windows IP Configuration", "", "xy"]


def test_cr_only_terminator():
    text = rec_line(msg="a") + "\r" + rec_line(msg="b") + "\r"
    assert [r.msg for r in iter_records(text, "x")] == ["a", "b"]


def test_invalid_date_counted_not_raised():
    text = "\n".join([rec_line(stamp="13/45/26 20:38:12:533", msg="bad") + "\nlost continuation",
                      rec_line(msg="good")])
    recs, st = parse_records(text, "x")
    assert [r.msg for r in recs] == ["good"]
    assert st.unparseable == 1 and st.records == 2
    assert recs[0].extra == ()               # the continuation of the bad record is not attached to "good"


def test_out_of_order_timestamps_kept_in_file_order():
    text = "\n".join([rec_line(stamp="11/12/26 14:06:22:052", msg="a"),
                      rec_line(stamp="11/12/26 14:06:22:051", msg="b")])
    recs = list(iter_records(text, "x"))
    assert [r.msg for r in recs] == ["a", "b"]
    assert recs[1].ts < recs[0].ts


def test_orphan_continuation_at_top():
    text = "tail of a previous record\n" + rec_line(msg="a") + "\n"
    recs, st = parse_records(text, "x")
    assert len(recs) == 1 and st.orphan_lines == 1


def test_skip_dump_levels_and_keep_codes():
    text = "\n".join([rec_line("Dump", 1, msg="noise") + "\nxml line",
                      rec_line("Dump", 8450, msg="chunk") + "\n<a>",
                      rec_line("Debug", 2, msg="flow")])
    recs, st = parse_records(text, "x", skip_levels={"Dump"})
    assert [r.msg for r in recs] == ["flow"]
    assert st.skipped == 2 and st.records == 3 and st.levels["Dump"] == 2
    recs, st = parse_records(text, "x", skip_levels={"Dump"}, keep_codes={8450})
    assert [r.msg for r in recs] == ["chunk", "flow"]
    assert recs[0].extra == ["<a>"]
    assert st.skipped == 1


def test_iter_records_is_lazy():
    gen = iter_records(rec_line(msg="a") + "\n" + rec_line(msg="b"), "x")
    assert next(gen).msg == "a"


def test_empty_and_garbage_text():
    assert list(iter_records("", "x")) == []
    recs, st = parse_records("no records here\nat all\n", "x")
    assert recs == [] and st.orphan_lines == 2


def test_event_log_info_error_and_nonmatching():
    text = ("08/17/2025 04:08:55:333 [Info ]: Started the Portal pre-login \r\n"
            "08/17/2025 04:08:56:001 [Error]: Failed to find adapter\r\n"
            "\r\n"
            "random text\r\n"
            "08/17/2025 04:08:57:010 [Info ]: Connected\r\n")
    st = ParseStats()
    lines = list(iter_event_log(text, "pan_gp_event.log", st))
    assert [(e.level, e.msg) for e in lines] == [
        ("Info", "Started the Portal pre-login"), ("Error", "Failed to find adapter"), ("Info", "Connected")]
    assert lines[0].ts == datetime(2025, 8, 17, 4, 8, 55, 333000)  # noqa: DTZ001
    assert lines[0].src == "pan_gp_event.log"
    assert st.orphan_lines == 2 and st.records == 3
    assert st.first == lines[0].ts and st.last == lines[-1].ts


def test_event_log_final_newline_not_counted_and_wrapper():
    out, bad = parse_event_log("01/02/2026 10:00:00:000 [Info ]: x\n", "f")
    assert len(out) == 1 and bad == 0
    out, bad = parse_event_log("01/02/2026 10:00:00:000 [Info ]: x\n\n", "f")
    assert len(out) == 1 and bad == 1


def test_event_log_invalid_date():
    out, bad = parse_event_log("13/45/2026 10:00:00:000 [Info ]: x\n02/03/2026 10:00:00:000 [Error]: y", "f")
    assert [e.msg for e in out] == ["y"] and bad == 1


def test_keep_msgs_ignores_the_source_number():
    # The same message logged under different source numbers (client builds) is kept either way.
    text = "\n".join([
        rec_line("Dump", 8450, msg="ResponseToClient.txt_output: <a>"),
        rec_line("Dump", 9999, msg="") + "\nResponseToClient.txt_output: <b>",
        rec_line("Dump", 8450, msg="other noise"),
        rec_line("Debug", 2, msg="flow")])
    recs, st = parse_records(text, "x", skip_levels={"Dump"}, keep_msgs=("ResponseToClient.txt_output: ",))
    assert [r.code for r in recs] == [8450, 9999, 2]
    assert st.skipped == 1 and st.levels["Dump"] == 3


def test_warn_level_glued_backward_and_long_continuation():
    lines = [rec_line("Warn", 5, "11/12/26 20:38:12:533", "Service start pending..."),
             rec_line("Info ", 6, "11/12/26 20:38:12:600", "a") + rec_line("Debug", 7, "11/12/26 20:38:12:590", "glued"),
             rec_line("Error", 8, "11/12/26 20:38:12:700", "xml") + "\n" + "\n".join(f"<l{i}/>" for i in range(650))]
    recs, st = parse_records("\r\n".join(lines) + "\r\n", "x")
    assert [r.level for r in recs] == ["Warn", "Info", "Debug", "Error"]
    assert st.levels == {"Warn": 1, "Info": 1, "Debug": 1, "Error": 1}
    assert st.glued == 1 and st.backward == 1 and st.unparseable == 0
    assert len(recs[-1].extra) == 650 and st.max_lines == 651
    assert recs[1].msg == "a" and recs[2].msg == "glued"


def test_stats_cover_skipped_records_too():
    text = "\n".join([rec_line("Dump", 1, "11/12/26 20:00:00:000", "n"),
                      rec_line("Debug", 2, "11/12/26 21:00:00:000", "x"),
                      rec_line("Dump", 1, "11/12/26 22:00:00:000", "n")])
    _, st = parse_records(text, "x", skip_levels={"Dump"})
    assert st.first == st.last == datetime(2026, 11, 12, 21, 0)  # noqa: DTZ001
    assert st.first_any == datetime(2026, 11, 12, 20, 0)  # noqa: DTZ001
    assert st.last_any == datetime(2026, 11, 12, 22, 0)  # noqa: DTZ001

from __future__ import annotations

from panos_toolbox.runtime.parse_backlog import (
    is_special_tag,
    is_unavailable,
    offending_ids,
    parse_backlog,
    special_tags,
)

SPECIAL = """Mon Jan  5 10:00:01 2026

-- SLOT: s1, DP: dp0 --
USAGE - ATOMIC: 12.5% TOTAL: 50.25%

TOP SESSIONS:
SESS-ID         PCT     GRP-ID          COUNT           Special Notes
2149000001      23%     some_workgroup  42              Special TAG values, NOT valid session id
"""

REAL = """Mon Jan  5 10:05:00 2026

-- SLOT: s1, DP: dp1 --
USAGE - ATOMIC: 80.0% TOTAL: 90.5%

TOP SESSIONS:
SESS-ID         PCT     GRP-ID          COUNT           Special Notes
1234  80%  1  874

SESSION DETAILS:
1234  6  trust  10.0.0.1  1234  10.0.0.2  443  ethernet1/1  ethernet1/2  FLOW  ssl
"""

NO_SESSIONS = """-- SLOT: s1, DP: dp0 --
USAGE - ATOMIC: 0.0% TOTAL: 1.5%
"""

OLD_FORMAT = """-- SLOT: s2, DP: dp2 --
USAGE - ATOMIC: 5.0% TOTAL: 6.0%
TOP SESSIONS:
SESS-ID  PCT  GRP-ID  COUNT
777  10%  3  20
"""


def test_special_tag():
    secs = parse_backlog(SPECIAL)
    assert len(secs) == 1
    s = secs[0]
    assert (s["slot"], s["dp"]) == ("s1", "dp0")
    assert s["fw_time"] == "Mon Jan  5 10:00:01 2026"
    assert (s["atomic"], s["total"]) == (12.5, 50.25)
    row = s["top"][0]
    assert row["sess_id"] == "2149000001"
    assert row["pct"] == 23.0 and row["count"] == 42
    assert row["grp_id"] == "some_workgroup"
    assert row["special"] is True
    assert offending_ids(secs) == []
    tags = special_tags(secs)
    assert tags[0]["slot"] == "s1" and tags[0]["dp"] == "dp0"


def test_real_session_with_details():
    secs = parse_backlog(REAL)
    s = secs[0]
    assert s["top"][0]["special"] is False
    assert s["top"][0]["notes"] == ""
    d = s["details"][0]
    assert d["sess_id"] == "1234" and d["zone"] == "trust" and d["app"] == "ssl"
    assert d["dport"] == "443"
    assert offending_ids(secs) == ["1234"]
    assert special_tags(secs) == []


def test_no_sessions():
    secs = parse_backlog(NO_SESSIONS)
    assert len(secs) == 1
    assert secs[0]["top"] == [] and secs[0]["details"] == []
    assert secs[0]["total"] == 1.5
    assert secs[0]["fw_time"] is None


def test_multi_slot_and_old_format():
    secs = parse_backlog(SPECIAL + "\n" + OLD_FORMAT + "\n" + REAL)
    assert [(s["slot"], s["dp"]) for s in secs] == [("s1", "dp0"), ("s2", "dp2"), ("s1", "dp1")]
    assert secs[1]["top"][0]["notes"] == ""
    assert offending_ids(secs) == ["777", "1234"]
    assert len(special_tags(secs)) == 1


def test_invalid_syntax():
    out = "Invalid syntax.\n"
    assert is_unavailable(out)
    assert is_unavailable("  ^\nUnknown command: foo unexpected here")
    assert parse_backlog(out) == []
    assert not is_unavailable(SPECIAL)


def test_empty_and_garbage():
    assert parse_backlog("") == []
    assert parse_backlog("garbage\n\x00\xff random") == []
    assert parse_backlog(None) == []  # type: ignore[arg-type]
    assert not is_unavailable("")


def test_is_special_tag():
    assert is_special_tag(5, "Special TAG values, NOT valid session id")
    assert is_special_tag(2**31, "")
    assert not is_special_tag(2**31 - 1, "")
    assert not is_special_tag(10, "")

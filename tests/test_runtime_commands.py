import pytest

from panos_toolbox.runtime import commands as C


def test_allow_list_and_session_id():
    for cmd in (C.POW, C.DELTA, C.INFLIGHT_ON, C.INFLIGHT_OFF, "show session id 12345"):
        C.check_allowed(cmd)
    for bad in ("show session id 12345; x", "show session id", "show session id 1234567890123",
                "configure", "show session all", ""):
        with pytest.raises(ValueError):
            C.check_allowed(bad)


def test_slugs_unique_and_complete():
    # every command has its own file, except the two inflight set commands that share one log
    assert len(set(C.SLUGS.values())) == len(C.SLUGS) - 1
    assert C.slug_for("show session id 7") == "session_id"
    assert C.slug_for(C.INFLIGHT_STATE) == "state_inflight"


def test_inflight_state_needs_the_status_keyword():
    # found with the inline help: without "status" the firewall answers "Invalid syntax"
    assert C.INFLIGHT_STATE.endswith(" status") and C.BACKLOG_TRIGGER.endswith(" status")

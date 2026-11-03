"""Tests for the GUI-independent console core. No real device is ever contacted."""
import json
import ssl
import xml.etree.ElementTree as ET

import pytest

from panos_toolbox.firewall.console.actions import discover
from panos_toolbox.firewall.console.actions.reboot import CONFIRM_WORD
from panos_toolbox.firewall.console.core import panorama as pano
from panos_toolbox.firewall.console.core.actions import Action, ActionRegistry, run_action
from panos_toolbox.firewall.console.core.models import ManagedDevice
from panos_toolbox.firewall.console.core.profiles import Profile, ProfileStore
from panos_toolbox.firewall.console.core.tls import build_ssl_context

DEVICES_XML = """
<response status="success"><result><devices>
  <entry name="001122334455">
    <serial>001122334455</serial><connected>yes</connected>
    <hostname>fw-milano-1</hostname><ip-address>10.0.0.11</ip-address>
    <model>PA-3220</model><sw-version>10.2.9-h1</sw-version>
    <ha><state>active</state></ha>
  </entry>
  <entry name="001122334466">
    <serial>001122334466</serial><connected>no</connected>
    <hostname>fw-roma-1</hostname><ip-address>10.0.0.9</ip-address>
    <model>PA-440</model><sw-version>10.1.14</sw-version>
  </entry>
  <entry name="001122334477"><connected>yes</connected></entry>
</devices></result></response>
"""

GROUPS_XML = """
<response><result><devicegroups>
  <entry name="DG-Nord"><devices>
    <entry name="001122334455"/><entry name="001122334466"/>
  </devices></entry>
  <entry name="DG-Empty"/>
</devicegroups></result></response>
"""

TEMPLATES_XML = """
<response><result><templates>
  <entry name="T-Base"><devices><entry name="001122334455"/></devices></entry>
</templates></result></response>
"""

STACKS_XML = """
<response><result><template-stack>
  <entry name="Stack-Nord"><devices><entry name="001122334455"/></devices></entry>
</template-stack></result></response>
"""


class FakePanorama:
    """Stands in for panos.panorama.Panorama: answers op() from canned XML."""

    def __init__(self, answers):
        self.answers = answers
        self.added = []
        self.removed = []

    def op(self, command):
        answer = self.answers[command]
        if isinstance(answer, Exception):
            raise answer
        return ET.fromstring(answer)

    def add(self, child):
        self.added.append(child)

    def remove(self, child):
        self.removed.append(child)


def make_session(answers):
    params = pano.ConnectionParams("panorama.example.com")
    return pano.PanoramaSession(FakePanorama(answers), params, "admin")


# --- parsing / inventory ---------------------------------------------------------------


def test_parse_devices():
    devices = pano.parse_devices(ET.fromstring(DEVICES_XML))
    assert [d.serial for d in devices] == ["001122334455", "001122334466", "001122334477"]
    first = devices[0]
    assert (first.hostname, first.ip_address, first.model) == ("fw-milano-1", "10.0.0.11", "PA-3220")
    assert first.sw_version == "10.2.9-h1" and first.connected and first.ha_state == "active"
    assert devices[1].connected is False and devices[1].ha_state == ""
    assert devices[2].display_name == "001122334477"  # no hostname: falls back to serial


def test_list_devices_merges_groups_and_prefers_stack():
    session = make_session(
        {
            "show devices all": DEVICES_XML,
            "show devicegroups": GROUPS_XML,
            "show templates": TEMPLATES_XML,
            "show template-stack": STACKS_XML,
        }
    )
    inventory = session.list_devices()
    by_serial = {d.serial: d for d in inventory.devices}
    assert by_serial["001122334455"].device_group == "DG-Nord"
    assert by_serial["001122334455"].template == "Stack-Nord"  # stack wins over template
    assert by_serial["001122334466"].device_group == "DG-Nord"
    assert by_serial["001122334466"].template == ""
    assert inventory.warnings == []


def test_group_lookup_failure_becomes_warning_not_error():
    session = make_session(
        {
            "show devices all": DEVICES_XML,
            "show devicegroups": GROUPS_XML,
            "show templates": RuntimeError("command not permitted"),
            "show template-stack": STACKS_XML,
        }
    )
    inventory = session.list_devices()
    assert len(inventory.devices) == 3
    assert len(inventory.warnings) == 1 and "show templates" in inventory.warnings[0]
    assert inventory.devices[0].template == "Stack-Nord"


def test_device_listing_failure_raises_panorama_error():
    session = make_session({"show devices all": RuntimeError("boom")})
    with pytest.raises(pano.PanoramaError, match="show devices all"):
        session.list_devices()


def test_certificate_errors_are_flagged():
    session = make_session({"show devices all": RuntimeError("[SSL: CERTIFICATE_VERIFY_FAILED]")})
    with pytest.raises(pano.PanoramaError) as info:
        session.list_devices()
    assert info.value.tls_error is True


# --- model -------------------------------------------------------------------------------


def test_filter_matches_all_words_in_any_column():
    dev = ManagedDevice("0011", hostname="fw-milano-1", model="PA-3220", device_group="DG-Nord")
    assert dev.matches("")
    assert dev.matches("milano pa-3220")
    assert dev.matches("DG-NORD")
    assert not dev.matches("milano roma")


def test_sort_keys_are_natural():
    a = ManagedDevice("1", ip_address="10.0.0.9", sw_version="10.1.14")
    b = ManagedDevice("2", ip_address="10.0.0.11", sw_version="10.2.9-h1")
    assert a.sort_key("ip_address") < b.sort_key("ip_address")
    assert a.sort_key("sw_version") < b.sort_key("sw_version")


# --- TLS ---------------------------------------------------------------------------------


def test_tls_verification_is_on_by_default():
    ctx = build_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_tls_can_be_disabled_explicitly():
    ctx = build_ssl_context(verify=False)
    assert ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname


# --- profiles ----------------------------------------------------------------------------


def test_profiles_roundtrip_without_password(tmp_path):
    store = ProfileStore(tmp_path / "p.json")
    store.upsert(Profile("pano.example.com", username="admin", verify_tls=False))
    store.upsert(Profile("pano.example.com", username="admin", port=8443))  # same name: replaced
    profiles = store.load()
    assert [(p.name, p.port, p.verify_tls) for p in profiles] == [("admin@pano.example.com", 8443, True)]
    stored = (tmp_path / "p.json").read_text()
    assert "password" not in stored.lower() and "api_key" not in stored.lower()


def test_profile_loader_ignores_extra_secret_fields(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"profiles": [{"hostname": "h", "password": "x"}]}))
    store = ProfileStore(path)
    assert store.load() == [Profile("h")]
    store.upsert(Profile("h2"))
    assert "password" not in path.read_text()


def test_corrupt_profiles_file_is_set_aside(tmp_path):
    path = tmp_path / "p.json"
    path.write_text("{not json")
    assert ProfileStore(path).load() == []
    assert (tmp_path / "p.json.bak").exists()


def test_invalid_profile_entries_are_skipped(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"profiles": [{"hostname": ""}, {"hostname": "ok", "port": 99999}, {"hostname": "good"}]}))
    assert [p.hostname for p in ProfileStore(path).load()] == ["good"]


# --- actions -----------------------------------------------------------------------------


class _Boom(Action):
    id = "boom"
    label = "Boom"

    def run(self, session, device):
        if device.serial == "bad":
            raise RuntimeError("nope")
        return "done"


def test_registry_rejects_duplicates_and_orders():
    reg = ActionRegistry()

    class A(Action):
        id, label, order = "a", "A", 2

    class B(Action):
        id, label, order = "b", "B", 1

    reg.register(A)
    reg.register(B)
    assert [a.id for a in reg.all()] == ["b", "a"]
    with pytest.raises(ValueError):
        reg.register(A)


def test_run_action_continues_after_failure():
    devices = [ManagedDevice("good"), ManagedDevice("bad"), ManagedDevice("good2")]
    results = run_action(_Boom(), None, devices)
    assert [r.ok for r in results] == [True, False, True]
    assert results[1].message == "nope"


def test_discover_registers_reboot():
    registry = discover()
    assert "reboot" in [a.id for a in registry.all()]


def test_reboot_skips_disconnected_and_confirms():
    reboot = discover().get("reboot")
    online = ManagedDevice("1", hostname="a", connected=True, ha_state="active")
    offline = ManagedDevice("2", hostname="b", connected=False)
    assert reboot.available_for(online) is None
    assert "not connected" in reboot.available_for(offline)

    single = reboot.confirmation([online])
    assert single.require_typed is None and "failover" in single.text
    several = reboot.confirmation([online, ManagedDevice("3", connected=True)])
    assert several.require_typed == CONFIRM_WORD


def test_reboot_sends_through_session():
    sent = []

    class Session:
        def restart_device(self, serial):
            sent.append(serial)

    reboot = discover().get("reboot")
    results = run_action(reboot, Session(), [ManagedDevice("1", connected=True), ManagedDevice("2")])
    assert sent == ["1"]  # the disconnected one is skipped, never sent
    assert [r.ok for r in results] == [True, False]


def test_restart_device_proxies_via_panorama_and_cleans_up(monkeypatch):
    pytest.importorskip("panos")
    session = make_session({})
    calls = []
    _, proxied = pano._tls_classes()
    monkeypatch.setattr(proxied, "restart", lambda self: calls.append(self.serial))
    session.restart_device("001122334455")
    fake = session._panorama
    assert calls == ["001122334455"]
    assert fake.added == fake.removed and len(fake.added) == 1


def test_connect_verifies_tls_and_does_not_keep_password(monkeypatch):
    pytest.importorskip("panos")
    import pan.xapi

    seen = {}

    class FakeXapi:
        def __init__(self, **kwargs):
            seen.update(kwargs)
            self.api_key = "KEY"

        def keygen(self):
            pass

    monkeypatch.setattr(pan.xapi, "PanXapi", FakeXapi)
    params = pano.ConnectionParams("pano.example.com")
    session = pano.PanoramaSession.connect(params, "admin", "s3cret")
    ctx = seen["ssl_context"]
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert seen["api_password"] == "s3cret"
    assert "s3cret" not in repr(vars(session)) and "s3cret" not in repr(vars(session._panorama))
    assert session._panorama.ssl_context is ctx
    # every xapi the library builds from now on must carry the same context
    assert session._panorama.xapi.ssl_context is ctx


def test_connect_login_failure_is_reported(monkeypatch):
    pytest.importorskip("panos")
    import pan.xapi

    class FakeXapi:
        def __init__(self, **kwargs):
            pass

        def keygen(self):
            raise pan.xapi.PanXapiError("Invalid credentials.")

    monkeypatch.setattr(pan.xapi, "PanXapi", FakeXapi)
    with pytest.raises(pano.PanoramaError, match="Invalid credentials"):
        pano.PanoramaSession.connect(pano.ConnectionParams("h"), "admin", "bad")


class _FakeHttpResponse:
    def __init__(self, body):
        self._body = body.encode()

    def info(self):
        return {}

    def read(self):
        return self._body

    def getheader(self, name, default=None):
        return "application/xml" if name.lower() == "content-type" else default


def test_requests_on_the_wire_are_verified_targeted_and_bounded(monkeypatch):
    """Drive the real pan-os-python stack against a fake HTTP layer (no network)."""
    pytest.importorskip("panos")
    import urllib.parse

    import pan.xapi

    sent = []

    def fake_urlopen(url, context=None, timeout=None):
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url.full_url).query))
        query.update(urllib.parse.parse_qsl(url.data.decode() if url.data else ""))
        sent.append((query, context, timeout))
        if query["type"] == "keygen":
            return _FakeHttpResponse("<response status='success'><result><key>K</key></result></response>")
        return _FakeHttpResponse("<response status='success'><msg>Command succeeded with no output</msg></response>")

    monkeypatch.setattr(pan.xapi, "urlopen", fake_urlopen)
    params = pano.ConnectionParams("pano.example.com", timeout=42)
    session = pano.PanoramaSession.connect(params, "admin", "pw")
    session.restart_device("0011AABB")

    keygen, restart = sent
    assert keygen[0]["user"] == "admin"
    assert restart[0]["target"] == "0011AABB"  # proxied through Panorama, never direct
    assert restart[0]["cmd"] == "<request><restart><system></system></restart></request>"
    assert "password" not in restart[0]  # only the API key travels after login
    for _, context, timeout in sent:
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        assert timeout == 42

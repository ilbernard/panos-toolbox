import pytest

from panos_toolbox.runtime import commands as C
from panos_toolbox.runtime.ssh import Shell, extract_output, login_shell
from panos_toolbox.runtime.transport import TransportError

PROMPT = b"admin@fw-test(active)> "


class FakeChan:
    """Mimics a PAN-OS shell channel: echo redraw at every word, output, prompt."""

    def __init__(self, first=PROMPT, outputs=None, needs_enter=False):
        self.q = [] if needs_enter else [b"banner\r\n" + first]
        self.first = first
        self.outputs = outputs or {}
        self.sent = []

    def recv_ready(self):
        return bool(self.q)

    def recv(self, n):
        return self.q.pop(0)

    def send(self, s):
        self.sent.append(s)
        cmd = s.strip()
        if not cmd:
            self.q.append(b"\r\n" + self.first)
            return
        words = cmd.split()
        echo = "".join(f"\r{PROMPT.decode()}{' '.join(words[:i])}" for i in range(1, len(words) + 1))
        body = self.outputs.get(cmd, "")
        self.q.append((echo + "\r\n" + body.replace("\n", "\r\n") + "\r\n").encode())
        self.q.append(PROMPT)


def test_run_drops_redrawn_echo_and_prompt():
    chan = FakeChan(outputs={C.SESSION_INFO: "line a\nline b"})
    sh, _ = login_shell(chan)
    text, ok = sh.run(C.SESSION_INFO)
    assert ok and text == "line a\nline b\n"


def test_login_newline_fallback_for_banner_waiting_for_a_key():
    chan = FakeChan(needs_enter=True)
    sh, _ = login_shell(chan, first_wait=0.2)
    assert "\n" in chan.sent
    assert isinstance(sh, Shell)


def test_login_failure_reports_text_without_secrets():
    class Mute(FakeChan):
        def send(self, s):
            self.sent.append(s)

    chan = Mute(needs_enter=True)
    chan.q.append(b"Password expires in 3 days\r\nSomething unexpected: ")
    with pytest.raises(TransportError) as err:
        login_shell(chan, first_wait=0.2)
    assert "Something unexpected" in str(err.value)


def test_disallowed_command_is_never_sent():
    chan = FakeChan()
    sh, _ = login_shell(chan)
    before = list(chan.sent)
    with pytest.raises(ValueError):
        sh.run("show system info; set deviceconfig")
    with pytest.raises(ValueError):
        sh.run("show session id abc")
    assert chan.sent == before


def test_extract_output_without_prompt():
    assert extract_output("x\nout1\nout2", "x", prompt_back=False) == "out1\nout2\n"

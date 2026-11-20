"""SSH transport: interactive CLI shell over paramiko (optional extra ``runtime``).

PAN-OS CLI details handled here: the CLI redraws ``prompt + partial command`` at every word, so
the echo can span several lines (everything up to the LAST line ending with the command is
dropped); the prompt is detected with a tolerant regular expression, with a newline fallback for
banners that wait for a key.
"""
from __future__ import annotations

import contextlib
import re
import time
from typing import Callable

from .commands import SETUP_CLI, check_allowed
from .transport import Transport, TransportError

PROMPT_RE = re.compile(r"[^\s@]+@[^\s>#]+[>#]\s*$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]")


def clean(buf: str) -> str:
    return ANSI_RE.sub("", buf).replace("\r\n", "\n").replace("\r", "\n")


def extract_output(text: str, cmd: str, prompt_back: bool) -> str:
    """Strips the echo (up to the last line ending with ``cmd``) and the trailing prompt."""
    lines = text.split("\n")
    echo = [i for i, line in enumerate(lines) if line.rstrip().endswith(cmd)]
    if echo:
        lines = lines[echo[-1] + 1:]
    if prompt_back and lines:
        lines = lines[:-1]
    return "\n".join(lines).strip("\n") + "\n"


class Shell:
    """Command runner over an object with ``recv_ready``, ``recv`` and ``send`` (a paramiko channel)."""

    def __init__(self, chan, timeout: float = 120.0, sleep: Callable[[float], None] = time.sleep,
                 mono: Callable[[], float] = time.monotonic):
        self.chan = chan
        self.timeout = timeout
        self._sleep = sleep
        self._mono = mono

    def _read_until_prompt(self, timeout: float) -> tuple[str, bool]:
        buf, text = "", ""
        deadline = self._mono() + timeout
        while self._mono() < deadline:
            if self.chan.recv_ready():
                buf += self.chan.recv(65535).decode("utf-8", "replace")
                text = clean(buf)
                if PROMPT_RE.search(text.split("\n")[-1]):
                    return text, True
            else:
                self._sleep(0.05)
        return text, False

    def wait_prompt(self, timeout: float = 30.0) -> tuple[str, bool]:
        return self._read_until_prompt(timeout)

    def run(self, cmd: str, timeout: float | None = None) -> tuple[str, bool]:
        check_allowed(cmd)
        while self.chan.recv_ready():  # drop leftovers
            self.chan.recv(65535)
        self.chan.send(cmd + "\n")
        text, ok = self._read_until_prompt(timeout or self.timeout)
        return extract_output(text, cmd, ok), ok


class SshTransport(Transport):
    def __init__(self, client, shell: Shell, banner: str = ""):
        self._client = client
        self.shell = shell
        self.banner = banner

    def run(self, cmd: str, timeout: float | None = None) -> tuple[str, bool]:
        return self.shell.run(cmd, timeout)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._client.close()


def login_shell(chan, timeout: float = 120.0, first_wait: float = 15.0) -> tuple[Shell, str]:
    """Waits for the first prompt (newline fallback), then disables the pager."""
    sh = Shell(chan, timeout)
    banner, ok = sh.wait_prompt(first_wait)
    if not ok:
        chan.send("\n")  # a banner waiting for a key, or a prompt printed before we read
        more, ok = sh.wait_prompt(first_wait)
        banner += more
    if not ok:
        raise TransportError(
            f"CLI prompt not detected after login. Last text received: {banner[-600:]!r}")
    for cmd in SETUP_CLI:
        sh.run(cmd, 20)
    return sh, banner


def connect(host: str, port: int, user: str, key_file: str | None,
            password_cb: Callable[[str], str], accept_new_hostkey: bool,
            timeout: float = 120.0) -> SshTransport:
    """Opens an SSH session; ``password_cb(prompt)`` returns the password or key passphrase."""
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise TransportError("paramiko is required: pip install 'panos-toolbox[runtime]'") from exc

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy() if accept_new_hostkey else paramiko.RejectPolicy())
    kw = {"hostname": host, "port": port, "username": user, "timeout": 20, "banner_timeout": 30,
              "auth_timeout": 30}
    try:
        if key_file:
            kw.update(key_filename=key_file, look_for_keys=False, allow_agent=False)
            try:
                client.connect(**kw)
            except paramiko.PasswordRequiredException:
                kw["passphrase"] = password_cb(f"Passphrase for key {key_file}: ")
                client.connect(**kw)
        else:
            kw.update(password=password_cb(f"Password for {user}@{host}: "),
                      look_for_keys=False, allow_agent=False)
            client.connect(**kw)
        chan = client.invoke_shell(width=500, height=2000)
        shell, banner = login_shell(chan, timeout)
    except TransportError:
        client.close()
        raise
    except Exception as exc:
        client.close()
        raise TransportError(f"SSH connection failed: {type(exc).__name__}") from exc
    return SshTransport(client, shell, banner)

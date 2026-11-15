"""Read a GlobalProtect log bundle: zip file, tar archive or folder.

Accepted inputs: a "Collect Logs" ``.zip``, a tar archive (``.tgz``, ``.tar.gz``, ``.tar``,
``.tar.bz2``, ``.tar.xz``: anything ``tarfile`` reads, detected by content and not by the
extension) or a folder. Standard library only. Nothing is extracted to disk: members are read
in memory, on demand, with limits that are enforced while reading (the size declared in the
archive header is never trusted).

Safety rules (the same for zip, tar and folders)
- A member with an absolute path (also ``C:`` drives and backslashes) or a ``..`` component
  is skipped ("unsafe path"). The check runs on the raw name.
- Links are skipped ("link"), devices and fifos too ("special file"). In directory mode
  symlinks are not followed. Directories are ignored.
- Members are looked up by base name: the files may sit in a sub-folder of the archive or
  folder. When a base name occurs more than once the choice is deterministic: a safe member
  beats an unsafe one, then the shallowest path, then the smallest path in text order. The
  others are ignored and the choice is recorded in ``Bundle.warnings`` and
  ``Bundle.duplicates`` ("duplicate name").

Limits (module constants; read at call time so tests can monkeypatch them)
- MAX_MEMBERS: archive entries examined (files only); the rest of the archive is not indexed
  (warning). For a tar archive indexing also stops when the declared sizes add up to
  MAX_TOTAL_BYTES (warning), so a crafted archive cannot keep the indexer busy.
- MAX_MEMBER_BYTES: expanded bytes kept per member. A larger member keeps its HEAD, cut at
  the last complete line, and is marked "truncated" (a bounded read is what makes it safe
  against zip bombs; the tail is not scanned).
- MAX_TOTAL_BYTES: expanded bytes kept for the whole bundle; when it is reached the member
  being read is truncated and the following ones are skipped ("total size limit reached").
"""
from __future__ import annotations

import os
import re
import stat
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

MAX_MEMBERS = 5000
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024

_CHUNK = 1024 * 1024

# Member status values.
FOUND = "found"          # in the bundle, not read (yet)
READ = "read"
EMPTY = "empty"          # zero bytes
SKIPPED = "skipped"      # refused; see Member.reason
TRUNCATED = "truncated"  # read, but only the first part is kept; see Member.reason

# (pattern on the lower-case base name, family)
_FAMILIES = [
    (re.compile(r"^pangps(\.\d+)?\.log(\.old)?$"), "service_log"),
    (re.compile(r"^pangpa(\.\d+)?\.log(\.old)?$"), "agent_log"),
    (re.compile(r"^pan_gp_event(\.\d+)?\.log(\.old)?$"), "event_log"),
    (re.compile(r"^logonui(\.\d+)?\.log(\.old)?$"), "logonui_log"),
    (re.compile(r"^pangphipmp(\.\d+)?\.log(\.old)?$"), "hip_mp_log"),
    (re.compile(r"^pangphip(\.\d+)?\.log(\.old)?$"), "hip_log"),
    (re.compile(r"^panproxyagent(\.\d+)?\.log(\.old)?$"), "proxy_log"),
    (re.compile(r"^debug_drv(\.\d+)?\.log(\.old)?$"), "driver_log"),
    (re.compile(r"^setupapi\.(dev|app)\.log$"), "setupapi_log"),
    (re.compile(r"^pangpmsi(\.\d+)?\.log(\.old)?$"), "msi_log"),
    (re.compile(r"^pan_gp_trb\.log$"), "troubleshooting"),
    (re.compile(r"^pan_gp_hrpt\.xml$"), "hip_report"),
    (re.compile(r"^regval\.txt$"), "registry_dump"),
    (re.compile(r"^systeminfo\.txt$"), "system_info"),
    (re.compile(r"^(ipconfig|routeprint|netstat|nicdetails|nicconfig|tcpipbind|processinfo|"
                r"serviceinfo|driverinfo)\.txt$"), "system_dump"),
    (re.compile(r"\.dmp$"), "crash_dump"),
]
OTHER = "other"

# <stem>[.N].log[.old]  (the number comes before the extension in the real bundles)
_ROT_RE = re.compile(r"^(?P<stem>.+?)(?:\.(?P<n>\d+))?\.log(?P<old>\.old)?$", re.IGNORECASE)


class BundleError(Exception):
    """The path is not a readable GlobalProtect log bundle."""


@dataclass
class Member:
    name: str                # base name, as shown to the user
    size: int                # size declared by the zip header / the file system
    status: str = FOUND      # found | read | empty | skipped | truncated
    reason: str = ""         # why skipped / truncated
    family: str = OTHER      # see _FAMILIES; "other" for unknown files
    used_for: str = ""
    path: str = ""           # raw name in the zip, or file system path


@dataclass
class Bundle:
    path: Path
    members: dict[str, Member] = field(default_factory=dict)   # key: lower-case base name
    warnings: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)        # "kept X, ignored Y" per clash
    kind: str = ""                                             # "zip" | "tar" | "folder"
    _zip: zipfile.ZipFile | None = None
    _tar: tarfile.TarFile | None = None
    _handles: dict = field(default_factory=dict)               # member key -> tar member info
    _rank: dict = field(default_factory=dict)                  # member key -> duplicate rank
    _examined: int = 0
    _total: int = 0

    # ------------------------------------------------------------------ open
    @classmethod
    def open(cls, path) -> Bundle:
        path = Path(path)
        bundle = cls(path=path)
        if path.is_dir():
            bundle.kind = "folder"
            bundle._index_dir()
        elif path.is_file() and zipfile.is_zipfile(path):
            bundle.kind = "zip"
            try:
                bundle._zip = zipfile.ZipFile(path)
                bundle._index_zip()
            except (zipfile.BadZipFile, OSError) as exc:
                bundle.close()
                raise BundleError(f"{path}: cannot read the zip file ({exc})") from exc
        elif path.is_file() and _is_tar(path):
            bundle.kind = "tar"
            try:
                bundle._tar = tarfile.open(path, "r:*")  # noqa: SIM115 - closed by close()
                bundle._index_tar()
            except (tarfile.TarError, OSError, EOFError, zlib.error, ValueError) as exc:
                bundle.close()
                raise BundleError(f"{path}: cannot read the tar archive ({exc})") from exc
        else:
            raise BundleError(f"{path}: not a zip file, a tar archive or a folder")
        if not bundle.members:
            bundle.close()
            raise BundleError(f"{path}: no readable file found")
        return bundle

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None
        if self._tar is not None:
            self._tar.close()
            self._tar = None

    # ------------------------------------------------------------ inventory
    def _add(self, raw: str, size: int, skip_reason: str = "", locator: str = "",
             handle=None) -> bool:
        """Register one member; ``raw`` is the name inside the archive or the relative path.

        Returns False when the member limit is reached (the caller stops indexing).
        """
        if self._examined >= MAX_MEMBERS:
            note = f"too many members, only the first {MAX_MEMBERS} are indexed"
            if note not in self.warnings:
                self.warnings.append(note)
            return False
        self._examined += 1
        norm = raw.replace("\\", "/")
        base = norm.rsplit("/", 1)[-1]
        if not base:
            return True
        key = base.lower()
        # Duplicate choice: safe before unsafe, then shallowest, then smallest raw name.
        rank = (1 if skip_reason else 0, norm.count("/"), norm)
        old = self.members.get(key)
        if old is not None:
            if rank >= self._rank[key]:
                self._record_duplicate(old.path, raw, ignored=raw)
                return True
            self._record_duplicate(raw, old.path, ignored=old.path)
        member = Member(name=base, size=size, family=classify(base), path=locator or raw)
        if skip_reason:
            member.status, member.reason = SKIPPED, skip_reason
            self.warnings.append(f"{raw}: skipped ({skip_reason})")
        elif size == 0:
            member.status = EMPTY
        self.members[key] = member
        self._rank[key] = rank
        if handle is not None:
            self._handles[key] = handle
        else:
            self._handles.pop(key, None)
        return True

    def _record_duplicate(self, kept: str, other: str, ignored: str) -> None:
        self.duplicates.append(f"kept {kept}, ignored {other}")
        self.warnings.append(f"{ignored}: skipped (duplicate name, kept {kept})")

    def _index_zip(self) -> None:
        assert self._zip is not None
        for info in self._zip.infolist():
            if info.is_dir():
                continue
            reason = unsafe_reason(info.filename)
            if not reason and info.create_system == 3:    # Unix: the mode is in external_attr
                kind = stat.S_IFMT(info.external_attr >> 16)    # 0 when the type bits are unset
                if kind == stat.S_IFLNK:
                    reason = "link"
                elif kind and kind != stat.S_IFREG:
                    reason = "special file"
            if not self._add(info.filename, info.file_size, reason):
                break

    def _index_tar(self) -> None:
        assert self._tar is not None
        declared = 0
        while True:
            try:
                info = self._tar.next()
            except (tarfile.TarError, OSError, EOFError, zlib.error, ValueError) as exc:
                if not self.members:
                    raise
                self.warnings.append(f"archive damaged or cut after {self._examined} "
                                     f"member(s), the rest is not indexed ({exc})")
                break
            if info is None:
                break
            if info.isdir():
                continue
            reason = unsafe_reason(info.name)
            if not reason:
                if info.issym() or info.islnk():
                    reason = "link"
                elif not info.isreg():
                    reason = "special file"
            if not self._add(info.name, max(info.size, 0), reason, handle=info):
                break
            declared += max(info.size, 0)
            if declared > MAX_TOTAL_BYTES:
                self.warnings.append("declared sizes exceed the total size limit: the rest of "
                                     "the archive is not indexed")
                break

    def _index_dir(self) -> None:
        root = self.path
        for dirpath, dirs, files in os.walk(root, followlinks=False):
            dirs.sort()
            for fname in sorted(files):
                full = Path(dirpath) / fname
                rel = full.relative_to(root).as_posix()
                try:
                    st = full.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    ok = self._add(rel, 0, "link", str(full))
                elif not stat.S_ISREG(st.st_mode):
                    ok = self._add(rel, 0, "special file", str(full))
                else:
                    ok = self._add(rel, st.st_size, "", str(full))
                if not ok:
                    return

    def inventory(self) -> list[Member]:
        """All members, sorted by name (status reflects what has been read so far)."""
        return [self.members[k] for k in sorted(self.members)]

    # ------------------------------------------------------------------ read
    def has(self, name: str) -> bool:
        m = self.members.get(name.lower())
        return bool(m and m.status != SKIPPED)

    def _skip(self, member: Member, reason: str) -> None:
        member.status, member.reason = SKIPPED, reason
        self.warnings.append(f"{member.name}: skipped ({reason})")

    def read_bytes(self, name: str, used_for: str = "") -> bytes | None:
        """Content of a member, or None when it is missing, skipped or unreadable.

        Never raises for bad data: limits and read errors are recorded on the member.
        """
        member = self.members.get(name.lower())
        if member is None or member.status == SKIPPED:
            return None
        if used_for:
            member.used_for = used_for
        if member.status == EMPTY:
            return b""
        remaining = MAX_TOTAL_BYTES - self._total
        if remaining <= 0:
            self._skip(member, "total size limit reached")
            return None
        cap = min(MAX_MEMBER_BYTES, remaining)
        try:
            data = self._read_limited(member, cap + 1)
        except (OSError, zipfile.BadZipFile, tarfile.TarError, RuntimeError, EOFError,
                NotImplementedError, zlib.error, ValueError) as exc:
            self._skip(member, f"read error: {exc}")
            return None
        if len(data) > cap:
            limit_hit = "total size limit reached" if cap < MAX_MEMBER_BYTES else "larger than the per-file limit"
            data = data[:cap]
            cut = data.rfind(b"\n")
            if cut >= 0:
                data = data[:cut + 1]
            member.status = TRUNCATED
            member.reason = f"{limit_hit}: only the first {len(data)} bytes are used"
            self.warnings.append(f"{member.name}: truncated ({limit_hit})")
        else:
            member.status = READ if data else EMPTY
        self._total += len(data)
        return data

    def _read_limited(self, member: Member, limit: int) -> bytes:
        """Read at most ``limit`` bytes in chunks (never trusts the declared size)."""
        if self._zip is not None:
            with self._zip.open(member.path) as zfh:
                return _read_chunks(zfh, limit)
        if self._tar is not None:
            info = self._handles.get(member.name.lower())
            tfh = self._tar.extractfile(info) if info is not None else None
            if tfh is None:
                raise OSError("member cannot be read")
            with tfh:
                return _read_chunks(tfh, limit)
        with open(member.path, "rb") as fh:
            return _read_chunks(fh, limit)

    def read_text(self, name: str, used_for: str = "") -> str | None:
        data = self.read_bytes(name, used_for)
        return None if data is None else decode_text(data)

    # -------------------------------------------------------------- rotation
    def rotation(self, stem: str) -> list[str]:
        """Member names of a rotated log, oldest first (see ``sort_rotations``).

        ``stem`` is e.g. ``PanGPS`` or ``pan_gp_event``; skipped members are left out.
        """
        names = []
        for member in self.members.values():
            parts = _rotation_parts(member.name)
            if parts and parts[0] == stem.lower() and member.status != SKIPPED:
                names.append(member.name)
        return sort_rotations(names)


# ---------------------------------------------------------------------- helpers
def _read_chunks(fh, limit: int) -> bytes:
    chunks: list[bytes] = []
    got = 0
    while got < limit:
        chunk = fh.read(min(_CHUNK, limit - got))
        if not chunk:
            break
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _is_tar(path: Path) -> bool:
    try:
        return tarfile.is_tarfile(path)
    except (OSError, tarfile.TarError, EOFError, zlib.error, ValueError):
        return False


def unsafe_reason(raw_name: str) -> str:
    """"unsafe path" for absolute names, drive letters, NUL and ``..`` components; else ''."""
    norm = raw_name.replace("\\", "/")
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm) or "\x00" in norm:
        return "unsafe path"
    if ".." in norm.split("/"):
        return "unsafe path"
    return ""


def classify(name: str) -> str:
    """Family of a file by its base name (``other`` when unknown)."""
    low = name.lower()
    for pattern, family in _FAMILIES:
        if pattern.search(low):
            return family
    return OTHER


def _rotation_parts(name: str):
    """(stem, rank, number) of a rotated log name, or None when it is not a ``.log`` name.

    rank 0 = numbered (higher number is older), 1 = ``.old``, 2 = current file.
    """
    m = _ROT_RE.match(name)
    if not m:
        return None
    if m.group("n") is not None:
        return m.group("stem").lower(), 0, int(m.group("n"))
    if m.group("old"):
        return m.group("stem").lower(), 1, 0
    return m.group("stem").lower(), 2, 0


def rotation_key(name: str):
    """Sort key: oldest first within a stem; ``.10`` comes before ``.9`` (numeric, not text)."""
    parts = _rotation_parts(name)
    if parts is None:
        return (name.lower(), 3, 0, name)
    stem, rank, num = parts
    return (stem, rank, -num, name)


def sort_rotations(names: list[str]) -> list[str]:
    """Order file names oldest first: ``X.8.log .. X.1.log, X.log.old, X.log``.

    Different stems stay grouped (sorted by stem).
    """
    return sorted(names, key=rotation_key)


def decode_text(data: bytes) -> str:
    """Decode log bytes without ever raising and WITHOUT translating newlines.

    UTF-8 (a BOM is dropped), UTF-16 when a BOM says so, UTF-16LE when the BOM was damaged
    (the Windows Installer log of some bundles starts with two U+FFFD sequences instead of
    ``FF FE``) or is missing but every other byte is NUL, otherwise latin-1.
    """
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return data.decode("utf-16", errors="replace")
    if data[:6] == b"\xef\xbf\xbd\xef\xbf\xbd" and len(data) > 7 and data[7:8] == b"\x00":
        return data[6:].decode("utf-16-le", errors="replace")      # damaged BOM
    if _looks_utf16le(data):
        return data.decode("utf-16-le", errors="replace")
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _looks_utf16le(data: bytes) -> bool:
    """True for ASCII text stored as UTF-16LE without a BOM (NUL in most odd positions)."""
    sample = data[:400]
    if len(sample) < 8:
        return False
    odd, even = sample[1::2], sample[0::2]
    return odd.count(0) >= 0.9 * len(odd) and even.count(0) <= 0.1 * len(even)

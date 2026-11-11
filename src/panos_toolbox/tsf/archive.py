"""Safe, in-memory reader for TSF archives and directory trees (standard library only).

Members are iterated in one pass and returned as ``(name, bytes)`` held in memory;
nothing is ever extracted to disk.

Safety rules
- A member with an absolute path or a ``..`` component is skipped ("unsafe path"). The check
  runs on the raw name, BEFORE normalization.
- Symlinks and hard links are skipped ("link"); devices and fifos are skipped ("special file").
  In directory mode symlinks are not followed.
- A literal leading ``./`` (and empty or ``.`` components) is dropped from the normalized name.

Limits (module-level, tunable; read at call time so tests can monkeypatch them)
- MAX_MEMBERS: members examined in one archive/tree; reading stops after that (recorded in
  ``Inventory.notes``).
- MAX_MEMBER_BYTES: bytes kept per member. A larger member keeps its TAIL (the last
  MAX_MEMBER_BYTES bytes, minus the first partial line) and is marked truncated: logs
  are most useful at their recent end.
- MAX_TOTAL_BYTES: expanded bytes kept for the whole archive; once reached, no further
  member is read (recorded in ``Inventory.notes``).
- LIST_ONLY_PREFIX: a selector may return ``'list:<family>'`` for a member whose content must
  NEVER be read (e.g. core files, which can be huge). Its name and size are recorded
  (``FamilyInventory.listed`` / ``sizes``) and a Member with empty ``data`` and
  ``list_only=True`` is yielded; the member limits above do not apply because nothing is read.
  For every directory entry the selector is also called with the logical path plus a trailing
  ``/``; only a list-only answer is used (``FamilyInventory.dirs``, ``Member.is_dir=True``),
  so an empty directory can be told from an absent one.
- MAX_GZ_SCAN_BYTES: how much a ``.gz`` member may expand while it is scanned. Up to
  that bound the tail is kept exactly like for plain files (memory stays bounded by
  MAX_MEMBER_BYTES); past it the scan stops and the tail of what was scanned is kept,
  marked truncated (decompression-bomb guard).
"""
from __future__ import annotations

import os
import re
import stat
import tarfile
import zlib
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .model import Inventory

MAX_MEMBERS = 200_000
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_GZ_SCAN_BYTES = 4 * 1024 * 1024 * 1024

_CHUNK = 1024 * 1024

REASON_UNSAFE = 'unsafe path'
REASON_LINK = 'link'
REASON_SPECIAL = 'special file'
LIST_ONLY_PREFIX = 'list:'

# Selector: logical relative path (".gz" dropped) -> family name, or None to ignore.
Selector = Callable[[str], 'str | None']


@dataclass
class Member:
    name: str                 # normalized real member path (keeps ".gz")
    logical: str              # name used for family matching (".gz" dropped)
    family: str
    data: bytes
    truncated: bool = False   # only part of the member is in `data`
    error: str | None = None   # read error; `data` holds what was read
    size: int | None = None    # size on disk / in the archive (list-only members)
    list_only: bool = False    # name and size only, content never read
    is_dir: bool = False       # list-only directory entry


def split_safe(raw_name: str) -> str | None:
    """Normalized relative path, or None when the raw name is unsafe or empty.

    Unsafe: absolute, or containing a ``..`` component. Checked before normalizing.
    """
    if raw_name.startswith('/'):
        return None
    parts = raw_name.split('/')
    if '..' in parts:
        return None
    norm = '/'.join(p for p in parts if p not in ('', '.'))
    return norm or None


def logical_name(name: str) -> str:
    return name.removesuffix('.gz')


# --------------------------------------------------------------------------
# Rotation ordering
# --------------------------------------------------------------------------
_ROT_NUM_RE = re.compile(r'^(.*)\.(\d+)$')


def rotation_key(name: str):
    """Sort key placing rotated logs oldest -> current.

    Order within one stem: highest ``.N`` first, then ``.old``, then the current file.
    ``.gz`` is ignored. Ties are broken by the full name.
    """
    logical = logical_name(name)
    m = _ROT_NUM_RE.match(logical)
    if m:
        stem, rank, num = m.group(1), 0, -int(m.group(2))
    elif logical.endswith('.old'):
        stem, rank, num = logical[:-4], 1, 0
    else:
        stem, rank, num = logical, 2, 0
    return (stem, rank, num, name)


def sort_rotations(names: list[str]) -> list[str]:
    """Deterministic oldest -> current order for the names of one family."""
    return sorted(names, key=rotation_key)


# --------------------------------------------------------------------------
# Reading helpers
# --------------------------------------------------------------------------
def _drop_partial_line(data: bytes) -> bytes:
    """Drops everything up to and including the first newline.

    Callers pass one byte more than they keep, so a cut that falls exactly on a line
    boundary drops only that extra newline and no complete line is lost.
    """
    i = data.find(b'\n')
    return b'' if i < 0 else data[i + 1:]


def _read_plain(fobj, size: int):
    """Returns (data, truncated). Keeps the tail when larger than MAX_MEMBER_BYTES."""
    cap = MAX_MEMBER_BYTES
    if size <= cap:
        return fobj.read(), False
    fobj.seek(size - cap - 1)
    return _drop_partial_line(fobj.read()), True


def _gz_chunks(fobj):
    """Yields decompressed chunks (each <= _CHUNK bytes) of a possibly multi-member gzip.

    Uses zlib directly so that data decoded before a corruption/truncation is still
    delivered; raises zlib.error / EOFError at the failure point.
    """
    d = zlib.decompressobj(zlib.MAX_WBITS | 16)
    while True:
        raw = fobj.read(_CHUNK)
        if not raw:
            if not d.eof:
                raise EOFError('compressed file ended before the end-of-stream marker')
            return
        while raw:
            if d.eof:                       # next gzip member
                d = zlib.decompressobj(zlib.MAX_WBITS | 16)
            while raw:
                out = d.decompress(raw, _CHUNK)
                raw = d.unconsumed_tail
                if out:
                    yield out
                if d.eof:
                    raw = d.unused_data + raw
                    break
            else:
                break


def _read_gz(fobj):
    """Returns (data, truncated, error): decompressed tail, bounded in memory."""
    cap = MAX_MEMBER_BYTES
    scan_cap = MAX_GZ_SCAN_BYTES
    chunks = deque()
    kept = scanned = 0
    truncated = False
    error = None
    try:
        for chunk in _gz_chunks(fobj):
            scanned += len(chunk)
            chunks.append(chunk)
            kept += len(chunk)
            while kept - len(chunks[0]) > cap:
                kept -= len(chunks.popleft())
            if scanned >= scan_cap:
                truncated = True
                break
    except (OSError, EOFError, zlib.error) as exc:
        error = f'{type(exc).__name__}: {exc}'
    data = b''.join(chunks)
    if scanned > cap:
        data = data[-(cap + 1):]
        # Something was dropped from the front: cut at a line boundary.
        truncated = True
        data = _drop_partial_line(data)
    return data, truncated, error


class _Reader:
    """Shared bookkeeping for the tar and directory iterators."""

    def __init__(self, select: Selector, inventory: Inventory):
        self.select = select
        self.inv = inventory

    def skip(self, name: str, reason: str) -> None:
        self.inv.skipped.append((name, reason))

    def begin(self) -> bool:
        """False (and a note) when the member limit has been reached."""
        if self.inv.members_seen >= MAX_MEMBERS:
            self.inv.notes.append(f'member limit reached ({MAX_MEMBERS}), '
                                  f'remaining members not read')
            return False
        self.inv.members_seen += 1
        return True

    def total_ok(self) -> bool:
        if self.inv.bytes_read >= MAX_TOTAL_BYTES:
            self.inv.notes.append(f'total size limit reached ({MAX_TOTAL_BYTES} bytes), '
                                  f'remaining members not read')
            return False
        return True

    def list_only(self, name: str, logical: str, tag: str, size: int, is_dir: bool = False):
        """Records a list-only member (no content read) and returns its Member."""
        family = tag[len(LIST_ONLY_PREFIX):]
        fam = self.inv.family(family)
        if is_dir:
            fam.dirs.append(name)
        else:
            fam.found.append(name)
            fam.listed.append(name)
            fam.sizes[name] = size
        return Member(name, logical, family, b'', size=size, list_only=True, is_dir=is_dir)

    def dir_member(self, raw_name: str):
        """Member for a directory entry when the selector lists directories, else None."""
        name = split_safe(raw_name)
        if name is None:
            return None
        logical = logical_name(name)
        tag = self.select(logical + '/')
        if isinstance(tag, str) and tag.startswith(LIST_ONLY_PREFIX):
            return self.list_only(name, logical, tag, 0, True)
        return None

    def make(self, name: str, logical: str, family: str, fobj, size: int):
        """Reads one selected member; returns a Member."""
        truncated, error = False, None
        try:
            if name.endswith('.gz'):
                data, truncated, error = _read_gz(fobj)
            else:
                data, truncated = _read_plain(fobj, size)
        except (OSError, EOFError, tarfile.TarError) as exc:
            data, error = b'', f'{type(exc).__name__}: {exc}'
        fam = self.inv.family(family)
        fam.read.append(name)
        if truncated or error:
            fam.truncated.append(name)
        if error:
            fam.errors[name] = error
        self.inv.bytes_read += len(data)
        return Member(name, logical, family, data, truncated, error)


def iter_tar(path: str, select: Selector, inventory: Inventory) -> Iterator[Member]:
    rd = _Reader(select, inventory)
    with tarfile.open(path, 'r:*') as tf:
        for m in tf:
            if not rd.begin():
                return
            if m.isdir():
                dm = rd.dir_member(m.name)
                if dm is not None:
                    yield dm
                continue
            name = split_safe(m.name)
            if name is None:
                rd.skip(m.name, REASON_UNSAFE)
                continue
            if m.issym() or m.islnk():
                rd.skip(name, REASON_LINK)
                continue
            if not m.isfile():
                rd.skip(name, REASON_SPECIAL)
                continue
            logical = logical_name(name)
            family = select(logical)
            if family is None:
                continue
            if family.startswith(LIST_ONLY_PREFIX):
                yield rd.list_only(name, logical, family, m.size)
                continue
            inventory.family(family).found.append(name)
            if not rd.total_ok():
                return
            fobj = tf.extractfile(m)
            if fobj is None:
                inventory.family(family).skipped.append((name, 'unreadable'))
                continue
            yield rd.make(name, logical, family, fobj, m.size)


def iter_dir(path: str, select: Selector, inventory: Inventory) -> Iterator[Member]:
    rd = _Reader(select, inventory)
    for root, dirs, files in os.walk(path, followlinks=False):
        dirs.sort()
        # Symlinked directories are listed in `dirs` but never entered.
        for d in list(dirs):
            full = os.path.join(root, d)
            if os.path.islink(full):
                dirs.remove(d)
                if not rd.begin():
                    return
                rd.skip(os.path.relpath(full, path).replace(os.sep, '/'), REASON_LINK)
                continue
            dm = rd.dir_member(os.path.relpath(full, path).replace(os.sep, '/'))
            if dm is not None:
                yield dm
        for f in sorted(files):
            if not rd.begin():
                return
            full = os.path.join(root, f)
            name = split_safe(os.path.relpath(full, path).replace(os.sep, '/'))
            if name is None:
                rd.skip(full, REASON_UNSAFE)
                continue
            if os.path.islink(full):
                rd.skip(name, REASON_LINK)
                continue
            try:
                st = os.lstat(full)
            except OSError:
                rd.skip(name, 'unreadable')
                continue
            if not stat.S_ISREG(st.st_mode):
                rd.skip(name, REASON_SPECIAL)
                continue
            logical = logical_name(name)
            family = select(logical)
            if family is None:
                continue
            if family.startswith(LIST_ONLY_PREFIX):
                yield rd.list_only(name, logical, family, st.st_size)
                continue
            inventory.family(family).found.append(name)
            if not rd.total_ok():
                return
            try:
                with open(full, 'rb') as fh:
                    yield rd.make(name, logical, family, fh, st.st_size)
            except OSError as exc:
                inventory.family(family).skipped.append((name, f'open error: {exc}'))


def iter_members(path: str, select: Selector, inventory: Inventory) -> Iterator[Member]:
    """Yields the selected members of a directory or tar archive (in-memory content).

    `select(logical_relpath)` returns a family name for members to read, else None.
    `inventory` is filled while iterating.
    """
    if os.path.isdir(path):
        return iter_dir(path, select, inventory)
    return iter_tar(path, select, inventory)

"""Capture folder: one raw file per command, samples delimited, gzip by default.

Layout::

    runtime_<host>_<UTC>/
      manifest.json
      raw/<slug>.txt.gz        (or .txt with compress=False)

Each raw file is a sequence of samples::

    #### SAMPLE n=<int> t=<UTC ISO> dur=<seconds> ok=<0|1> [key=value ...]
    <raw output>
    #### END

Files are flushed after every sample (gzip with a sync flush), so a capture killed halfway is
still readable; the reader tolerates a truncated gzip stream. Output lines that start with
``####`` are escaped with a leading space and restored when reading.
"""
from __future__ import annotations

import contextlib
import gzip
import json
import re
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

HEADER_RE = re.compile(r"^#### SAMPLE (.*)$")
END_LINE = "#### END"


@dataclass
class Sample:
    n: int
    t: str
    dur: float
    ok: bool
    text: str
    attrs: dict[str, str] = field(default_factory=dict)


def _clean_value(value) -> str:
    return re.sub(r"\s+", "_", str(value)) or "-"


class CaptureWriter:
    def __init__(self, root: Path, compress: bool = True):
        self.root = Path(root)
        self.raw = self.root / "raw"
        self.raw.mkdir(parents=True, exist_ok=True)
        self.compress = compress
        self._files: dict[str, object] = {}
        self._count: dict[str, int] = {}

    def _file(self, slug: str):
        fh = self._files.get(slug)
        if fh is None:
            if self.compress:
                fh = gzip.open(  # noqa: SIM115 - handles stay open for the whole capture
                    self.raw / f"{slug}.txt.gz", "wt", encoding="utf-8")
            else:
                fh = open(  # noqa: SIM115
                    self.raw / f"{slug}.txt", "w", encoding="utf-8")
            self._files[slug] = fh
        return fh

    def count(self, slug: str) -> int:
        return self._count.get(slug, 0)

    def add(self, slug: str, t: str, dur: float, ok: bool, text: str, **attrs) -> int:
        """Appends one sample and flushes; returns its sequence number within the slug."""
        n = self._count.get(slug, 0) + 1
        self._count[slug] = n
        head = f"n={n} t={t} dur={dur:.3f} ok={1 if ok else 0}"
        for key, value in attrs.items():
            head += f" {key}={_clean_value(value)}"
        body = "\n".join((" " + ln) if ln.startswith("####") else ln
                         for ln in text.rstrip("\n").split("\n"))
        fh = self._file(slug)
        fh.write(f"#### SAMPLE {head}\n{body}\n{END_LINE}\n")
        fh.flush()
        return n

    def write_manifest(self, data: dict) -> None:
        tmp = self.root / "manifest.json.tmp"
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.root / "manifest.json")

    def close(self) -> None:
        for fh in self._files.values():
            with contextlib.suppress(Exception):
                fh.close()
        self._files.clear()


def _parse_head(rest: str) -> dict:
    out = {}
    for part in rest.split():
        key, _, value = part.partition("=")
        out[key] = value
    return out


def _read_lines(path: Path) -> Iterator[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield line.rstrip("\n")
    except (EOFError, zlib.error, OSError):
        return  # truncated stream: keep what was read


def read_samples(path: Path) -> list[Sample]:
    """All complete samples of a raw file (an unfinished last sample is dropped)."""
    samples: list[Sample] = []
    head, body = None, []
    for line in _read_lines(Path(path)):
        m = HEADER_RE.match(line)
        if m and head is None:
            head, body = _parse_head(m.group(1)), []
        elif line == END_LINE and head is not None:
            attrs = {k: v for k, v in head.items() if k not in ("n", "t", "dur", "ok")}
            try:
                dur = float(head.get("dur", "0"))
            except ValueError:
                dur = 0.0
            text = "\n".join(ln[1:] if ln.startswith(" ####") else ln for ln in body) + "\n"
            samples.append(Sample(int(head.get("n", "0") or 0), head.get("t", ""), dur,
                                  head.get("ok") == "1", text, attrs))
            head = None
        elif head is not None:
            body.append(line)
    return samples


class CaptureReader:
    """Reads a capture folder written by :class:`CaptureWriter`."""

    def __init__(self, root: Path):
        self.root = Path(root)
        raw = self.root / "raw"
        if not raw.is_dir():
            raise ValueError(f"not a capture folder (no raw/ directory): {self.root}")
        self._files = {}
        for p in sorted(raw.iterdir()):
            if p.name.endswith(".txt.gz"):
                self._files[p.name[:-7]] = p
            elif p.name.endswith(".txt"):
                self._files[p.name[:-4]] = p
        mf = self.root / "manifest.json"
        try:
            self.manifest = json.loads(mf.read_text(encoding="utf-8")) if mf.is_file() else {}
        except (ValueError, OSError):
            self.manifest = {}

    def slugs(self) -> list[str]:
        return sorted(self._files)

    def samples(self, slug: str) -> list[Sample]:
        path = self._files.get(slug)
        return read_samples(path) if path else []

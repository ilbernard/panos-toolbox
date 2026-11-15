"""Record parsers for the GlobalProtect client logs (standard library only).

Two formats are handled:

* event log (``pan_gp_event.log``): ``MM/DD/YYYY HH:MM:SS:mmm [Info ]: message``
* service and agent logs (``PanGPS.log``, ``PanGPA.log``, ...):
  ``(P<pid>-T<tid>)<Level> ?(<src>): MM/DD/YY HH:MM:SS:mmm <message>``. A record can
  continue on the following lines (XML dumps), and a record can start in the middle of a
  physical line when the previous one lost its line terminator ("glued" records).

Timestamps are the client's local time, naive (no UTC offset in the logs). They are not
strictly monotonic: records are yielded in file order and never sorted here.

Memory and time: ``iter_records`` is a generator; ~99% of the records of a service log are
level ``Dump``, so callers that do not need them can pass ``skip_levels={"Dump"}``: such
records are only counted (no datetime, no object). ``keep_msgs`` re-admits skipped-level
records whose message starts with one of the given texts, e.g. the Dump records that carry the
status XML.

The ``<src>`` number in the prefix (``code``) is the source line of the logging call in the
client build: it changes between client versions, even inside one bundle. Nothing in this
package may depend on a fixed value. ``keep_codes`` is kept for callers that know better, but
match on message text instead.

Levels seen: ``Dump``, ``Debug``, ``Info``, ``Warn``, ``Error`` (the level may be followed by
a space before the parenthesis: ``Info (1043)``). Real bundles have hundreds of glued records
per file, timestamps that step backwards by a few milliseconds (thread interleaving, or a
second process, e.g. the installer, writing into the same file) and XML continuations of
about 650 lines.
"""
from __future__ import annotations

import re
from collections.abc import Collection, Iterator
from dataclasses import dataclass, field
from datetime import datetime

_EVENT_RE = re.compile(
    r"^(\d\d)/(\d\d)/(\d{4}) (\d\d):(\d\d):(\d\d):(\d{3}) \[(\w+)\s*\]: ?(.*)$"
)
_SVC_RE = re.compile(
    r"\(P(\d+)-T(\d+)\)([A-Za-z]+) *\( *(\d+)\): "
    r"(\d\d)/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d):(\d{3}) ?"
)

_NO_EXTRA: tuple = ()


@dataclass
class EventLine:
    ts: datetime
    level: str      # "Info" or "Error" (padding stripped)
    msg: str
    src: str        # file name


class Record:
    """One service/agent log record."""

    __slots__ = ("code", "extra", "level", "msg", "pid", "src", "tid", "ts")

    def __init__(self, ts: datetime, pid: int, tid: int, level: str, code: int, msg: str,
                 src: str, extra=_NO_EXTRA):
        self.ts = ts
        self.pid = pid
        self.tid = tid
        self.level = level      # stripped: "Dump", "Debug", "Info", "Error"
        self.code = code        # the number in parentheses (source line of the logging call)
        self.msg = msg          # first line of the message
        self.src = src          # file name
        self.extra = extra      # continuation lines (list), empty tuple when there are none

    @property
    def body(self) -> str:
        return "\n".join(self.extra)

    def __repr__(self) -> str:
        return f"Record({self.ts:%Y-%m-%d %H:%M:%S.%f} P{self.pid}-T{self.tid} {self.level}({self.code}) {self.msg[:40]!r})"


@dataclass
class ParseStats:
    """Counters filled while a log is parsed (pass an instance to the parsers)."""

    records: int = 0        # prefixes found, including skipped and unparseable ones
    skipped: int = 0        # not built because of ``skip_levels``
    unparseable: int = 0    # prefix found but the date is invalid (record and its lines dropped)
    orphan_lines: int = 0   # non-empty lines before the first record (continuation without start)
    levels: dict[str, int] = field(default_factory=dict)   # records per level, all of them
    first: datetime | None = None   # first / last timestamp of the records that were built
    last: datetime | None = None
    glued: int = 0          # records whose prefix does not start a line (all records counted)
    backward: int = 0       # records stamped earlier than the previous record (file order)
    max_lines: int = 0      # longest record (continuation lines + 1), built records only
    first_any: datetime | None = None   # first / last timestamp of ALL records, skipped ones
    last_any: datetime | None = None    # included (valid dates only; set when the parse ends)


def _clean(text: str) -> str:
    """Drop carriage returns: ``\\r\\n``, ``\\r\\r\\n`` and lone ``\\r`` (they sit inside XML dumps).

    A file whose only line terminator is CR is split on it instead.
    """
    if "\r" not in text:
        return text
    if "\n" not in text:
        return text.replace("\r", "\n")
    return text.replace("\r", "")


def iter_records(text: str, src: str, skip_levels: Collection[str] = (),
                 keep_codes: Collection[int] = (),
                 stats: ParseStats | None = None,
                 keep_msgs: Collection[str] = ()) -> Iterator[Record]:
    """Yield the service-log records of ``text`` in file order.

    * ``skip_levels``: level names (e.g. ``{"Dump"}``) whose records are counted but not built.
    * ``keep_msgs``: records of a skipped level whose message (leading blanks and line breaks
      ignored) starts with one of these texts are still built. Prefer this to ``keep_codes``.
    * ``keep_codes``: source numbers still built even when their level is skipped (the number
      changes between client builds: avoid).
    * ``stats``: optional counters.
    """
    text = _clean(text)
    st = stats if stats is not None else ParseStats()
    skip = frozenset(skip_levels)
    keep = frozenset(keep_codes)
    msgs = tuple(keep_msgs)
    peek = max((len(m) for m in msgs), default=0) + 8
    first_key = last_key = prev_key = None
    cur: re.Match | None = None
    for nxt in _SVC_RE.finditer(text):
        key = nxt.group(7, 5, 6, 8, 9, 10, 11)      # fixed-width digits: text order = time order
        if first_key is None:
            first_key = key
        last_key = key
        if prev_key is not None and key < prev_key:
            st.backward += 1
        prev_key = key
        if nxt.start() and text[nxt.start() - 1] != "\n":
            st.glued += 1
        if cur is None:
            _count_orphans(text, nxt.start(), st)
        else:
            rec = _build(text, cur, nxt.start(), src, skip, keep, msgs, peek, st)
            if rec is not None:
                yield rec
        cur = nxt
    if cur is None:
        _count_orphans(text, len(text), st)
    else:
        rec = _build(text, cur, len(text), src, skip, keep, msgs, peek, st)
        if rec is not None:
            yield rec
    st.first_any, st.last_any = _key_ts(first_key), _key_ts(last_key)


def _key_ts(key) -> datetime | None:
    if key is None:
        return None
    y, mo, d, h, mi, s, ms = (int(x) for x in key)
    try:
        return datetime(2000 + y, mo, d, h, mi, s, ms * 1000)  # noqa: DTZ001
    except ValueError:
        return None


def _count_orphans(text: str, end: int, st: ParseStats) -> None:
    head = text[:end]
    if head.strip():
        st.orphan_lines += sum(1 for ln in head.split("\n") if ln.strip())


def _build(text: str, m: re.Match, end: int, src: str, skip: frozenset, keep: frozenset,
           msgs: tuple, peek: int, st: ParseStats) -> Record | None:
    st.records += 1
    level = m.group(3).strip()
    st.levels[level] = st.levels.get(level, 0) + 1
    if level in skip and not (
            (keep and int(m.group(4)) in keep)
            or (msgs and text[m.end():min(end, m.end() + peek)].lstrip().startswith(msgs))):
        st.skipped += 1
        return None
    try:
        ts = datetime(  # noqa: DTZ001 - the logs carry no UTC offset
            2000 + int(m.group(7)), int(m.group(5)), int(m.group(6)),
            int(m.group(8)), int(m.group(9)), int(m.group(10)), int(m.group(11)) * 1000)
    except ValueError:
        st.unparseable += 1
        return None
    seg = text[m.end():end]
    seg = seg.removesuffix("\n")
    if "\n" in seg:
        first_line, _, rest = seg.partition("\n")
        extra = rest.split("\n")
    else:
        first_line, extra = seg, _NO_EXTRA
    if st.first is None:
        st.first = ts
    st.last = ts
    if extra:
        st.max_lines = max(st.max_lines, len(extra) + 1)
    elif not st.max_lines:
        st.max_lines = 1
    return Record(ts, int(m.group(1)), int(m.group(2)), level, int(m.group(4)),
                  first_line.strip(), src, extra)


def parse_records(text: str, src: str, **kwargs) -> tuple[list[Record], ParseStats]:
    """Eager variant of ``iter_records``: the list of records and the counters."""
    stats = kwargs.pop("stats", None) or ParseStats()
    return list(iter_records(text, src, stats=stats, **kwargs)), stats


def iter_event_log(text: str, src: str, stats: ParseStats | None = None) -> Iterator[EventLine]:
    """Yield the event-log lines in file order; lines that do not match are counted.

    ``stats.orphan_lines`` counts them (blank lines included: a blank line after an Error
    record is part of the real format); ``stats.unparseable`` counts invalid dates.
    """
    st = stats if stats is not None else ParseStats()
    lines = _clean(text).split("\n")
    if lines and lines[-1] == "":
        lines.pop()          # the file's final line terminator
    for line in lines:
        m = _EVENT_RE.match(line)
        if not m:
            st.orphan_lines += 1
            continue
        st.records += 1
        mo, d, y, h, mi, s, ms, level, msg = m.groups()
        try:
            ts = datetime(  # noqa: DTZ001 - the logs carry no UTC offset
                int(y), int(mo), int(d), int(h), int(mi), int(s), int(ms) * 1000)
        except ValueError:
            st.unparseable += 1
            continue
        if st.first is None:
            st.first = ts
        st.last = ts
        yield EventLine(ts, level, msg.strip(), src)


def parse_event_log(text: str, src: str) -> tuple[list[EventLine], int]:
    """Return the parsed lines and the number of lines that did not parse (bad date included)."""
    st = ParseStats()
    out = list(iter_event_log(text, src, st))
    return out, st.orphan_lines + st.unparseable

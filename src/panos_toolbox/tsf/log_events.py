"""Log events of the TSF report: kernel crashes, repeated daemon errors, commit/job context.

Step 6b of the System health tab (standard library only). The checks of this module are
appended to the System health view as the check group ``Logs`` (see :func:`apply_to_system_view`).
Three sources are read:

A) Kernel log ``var/log/messages`` (and rotations ``.1``, ``.old``, ``.gz``): syslog format
   without year and without UTC offset (``Apr 24 09:02:31 fw kernel: ...``). Only ``kernel:``
   lines are looked at, for three kinds of crash: ``segfault`` (``proc[1234]: segfault at``),
   ``general protection`` (``traps: proc[1234] general protection fault ip:``) and ``oom-kill``
   (``Out of memory: Kill(ed) process 1234 (name)``, ``oom-kill:...task=name,pid=1234``,
   ``Killed process 1234 (name)``; the lines of one kill are counted once, by (name, pid)).
   Events are counted per (process, type). ``KERNEL_CRASH`` (crit) when a pair has at least
   ``crash_min`` events, otherwise one ``KERNEL_CRASH_SEEN`` (info) lists the pairs. The times
   are shown as written (device local time, no year) and are NOT used for correlation.

B) Daemon logs ``var/log/pan/<daemon>.log`` and rotations (``.N``, ``.old``, ``.gz``) of the
   daemons in :data:`DAEMON_LOGS` (a tunable allowlist). A line is an *error line* when, after
   the timestamp(s) (``2026-11-06 11:18:48.794 +0100``; a doubled timestamp is stripped too;
   lines without a timestamp are accepted), it STARTS with a level token: ``ERROR``, ``ERR``,
   ``CRIT``, ``CRITICAL`` or ``FATAL`` in capitals (colon optional), or ``Error:``, ``error:``,
   ``Crit:``, ``fatal:`` ... with the colon. "error" in the middle of a message ("no error",
   "0 errors") is therefore not an error line. The message is normalised so that repeats of
   the same problem collapse: the level is canonicalised, ``0x...`` becomes ``0xH``, any run
   of 3 or more digits (pids, ids, line numbers, octets of an address) becomes ``N``;
   bracketed or quoted text containing a ``/`` (paths) is kept as it is; the key is cut at
   :data:`MSG_KEY_LEN` characters. Identical keys are counted per daemon. ``LOG_ERROR_REPEAT``
   (warn) for each (daemon, message) with at least ``log_repeat_min`` occurrences, with count,
   first and last time (UTC, only when the lines carry an offset) and files. Lines are not
   de-duplicated across rotated files (overlap between rotations of these logs is rare), so an
   overlap would double count.

   Budgets (declared in the view and in the report when hit): at most
   :data:`MAX_MSGS_PER_DAEMON_VIEW` messages per daemon in the view, :data:`MAX_REPEAT_FLAGS`
   individual flags (the rest in one aggregated flag), :data:`MAX_DISTINCT_PER_DAEMON` distinct
   messages counted per daemon while parsing (further new messages are only counted as
   dropped), :data:`MAX_COMMIT_TS` commit lines kept, :data:`MAX_WINDOWS_VIEW` commit windows
   and :data:`MAX_JOBS_VIEW` jobs in the timeline, :data:`MAX_NEAR_FINDINGS` ``NEAR_COMMIT``
   findings.

C) Commit and job context (informational only). ``configd.log`` lines whose text starts with
   ``COMMIT`` (``2026-11-09 02:06:51.823 +0100 COMMIT pan_cfg_mgr_...``) and, best effort,
   ``ms.log`` lines that start with ``COMMIT`` or ``commit`` have an explicit offset; lines
   within ``commit_gap_s`` of each other form one *commit window*. The CLI section
   ``show jobs processed`` lists jobs in device local time WITHOUT offset (``Enqueued`` with a
   date, ``Dequeued`` and ``Completed`` times only). A job is an interval [dequeued, completed]
   when both exist (a completed time before the dequeued one means the next day); a running job
   (``ACT``/``PEND``, ``NN%``) has no end and is only listed. The offset of a job is INFERRED
   from the explicit-offset headers of the same TSF (daemon logs, mp-monitor, dp-monitor),
   sampled once per date and hour: the observed local dates within one day of the job date
   (else around the nearest observed date, at most :data:`MAX_OFFSET_GAP_DAYS` days away). If
   the most frequent offset of those dates is the same and has at least
   :data:`OFFSET_DOMINANCE` of the samples, it is used; if it differs between the dates (a DST
   change) or no offset dominates: *ambiguous*; no observation nearby: *unknown*. (Some
   sources write another offset for the same instant, e.g. a subprocess with a different time
   zone, which is why a vote is used instead of "exactly one offset".) Ambiguous and unknown jobs are
   listed without UTC and never correlated. Every correlation that uses a job says "offset
   inferred (+HHMM)".

   Correlation: a PROC_CPU run (longest run of each flagged process), a management plane
   memory peak (``MP_MEMORY`` / ``MP_MEMORY_PAST_PEAK``) and a dataplane core peak
   (``CORE_PEAK``; ``CORE_PEAK_MINUTE`` covers the 15 minutes before its sample) is *near* a
   commit window or a job when its interval, widened by ``corr_window_s`` on both sides, overlaps
   it. The result is an info finding ``NEAR_COMMIT`` per correlated item, the "Commit and job
   timeline" table, and a short note appended to the text of the original flag. The original
   flag is never removed and its level never changes.

``Collected.log_data`` holds the store of :func:`new_store`; :func:`evaluate_log_events` builds
the JSON-serialisable view and :func:`apply_to_system_view` merges it into the System health
view. Tune LOG_THRESHOLDS with ``thresholds={...}`` or the ``--sys-<name>`` options.
"""
from __future__ import annotations

import calendar
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any

from .findings import CRITICAL, OK, WARNING, from_flags, module_status
from .system_health import iter_cli_sections

# Every number used by this module; part of the --sys-* option family.
LOG_THRESHOLDS = {
    'crash_min': 5,         # kernel events of one (process, type) at or above: KERNEL_CRASH
    'log_repeat_min': 20,   # identical daemon error messages at or above: LOG_ERROR_REPEAT
    'corr_window_s': 90,    # commit/job correlation margin, seconds, on both sides
    'commit_gap_s': 120,    # COMMIT lines closer than this form one commit window, seconds
    'log_recent_h': 24,     # LOG_ERROR_REPEAT counts occurrences in the last N hours of the TSF
    'commit_min_lines': 2,  # a commit window needs at least this many COMMIT lines
}

# Daemon logs read (var/log/pan/<name>.log and rotations). Tunable allowlist.
DAEMON_LOGS = (
    'ms', 'configd', 'mgmtsrvr', 'devsrv', 'authd', 'ha_agent', 'brdagent', 'pan_dha',
    'ikemgr', 'ikemgr-ng', 'sslvpn', 'appweb3', 'useridd', 'routed', 'logrcvr', 'sysd',
    'gpsvc', 'sslmgr', 'keymgr', 'varrcvr', 'distributord', 'iotd',
)
COMMIT_DAEMONS = ('configd', 'ms')

FLAG_CODES = ('KERNEL_CRASH', 'KERNEL_CRASH_SEEN', 'LOG_ERROR_REPEAT', 'LOG_ERROR_CHRONIC',
              'NEAR_COMMIT')
CODE_CHECK = {'KERNEL_CRASH': 'kernel', 'KERNEL_CRASH_SEEN': 'kernel',
              'LOG_ERROR_REPEAT': 'log_errors', 'LOG_ERROR_CHRONIC': 'log_errors',
              'NEAR_COMMIT': 'commits'}
GROUP_LOGS = 'Logs'
CMD_JOBS = 'show jobs processed'

MAX_MSGS_PER_DAEMON_VIEW = 50
MAX_REPEAT_FLAGS = 20
MAX_DISTINCT_PER_DAEMON = 5000
MAX_TS_PER_MSG = 100_000     # distinct timestamps kept per message (for the recent count)
MAX_COMMIT_TS = 200_000
MAX_WINDOWS_VIEW = 200
MAX_JOBS = 5000
MAX_JOBS_VIEW = 300
MAX_NEAR_FINDINGS = 30
MAX_KERNEL_KEYS = 200
MAX_MATCHES = 4              # windows / jobs listed per correlated item
MSG_KEY_LEN = 300
MAX_OFFSET_GAP_DAYS = 3
OFFSET_DOMINANCE = 0.6       # share of the samples the chosen offset needs in the window
MINUTE_PEAK_SPAN_MS = 15 * 60 * 1000   # CORE_PEAK_MINUTE: per-minute maxima of 15 minutes

_names = '|'.join(re.escape(n) for n in sorted(DAEMON_LOGS, key=len, reverse=True))
DAEMON_PATH_RE = re.compile(r'(?:^|/)var/log/pan/(' + _names + r')\.log(?:\.\d+|\.old)?$')
MESSAGES_PATH_RE = re.compile(r'(?:^|/)var/log/messages(?:\.\d+|\.old)?$')

_TS = r'(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))? ([+-])(\d{2})(\d{2})[ \t]*'
TS_RE = re.compile(_TS)
_LEVEL = (r'(?:ERROR|ERR|CRIT|CRITICAL|FATAL)\b:?|'
          r'(?:Error|Err|Crit|Critical|Fatal|error|err|crit|critical|fatal):')
# Matches only the lines that matter, at C speed (finditer over a chunk of text): groups 1-10 =
# the first timestamp (optional; a doubled one is skipped), 11 = a level token, 12 = a
# COMMIT/commit word at the start of the message, 13 = the rest of the line.
LINE_RE = re.compile(r'^(?:' + _TS + r'(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? '
                     r'[+-]\d{4}[ \t]*)*)?(?:(' + _LEVEL + r')|(COMMIT\b|[Cc]ommit\b))[ \t]*'
                     r'([^\r\n]*)', re.MULTILINE)
CHUNK_BYTES = 8 * 1024 * 1024    # daemon logs are decoded and scanned in chunks of this size
OFFSET_STEP = 16 * 1024          # one offset sample per this many characters of a daemon log
HEX_RE = re.compile(r'\b0x[0-9a-fA-F]+\b')
NUM_RE = re.compile(r'\b\d{3,}\b')
KEEP_RE = re.compile(r'(\[[^\]\n]*/[^\]\n]*\]|\'[^\'\n]*/[^\'\n]*\'|"[^"\n]*/[^"\n]*")')

SYSLOG_RE = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+kernel:\s?(.*)$')
SEGV_RE = re.compile(r'(?<!\S)(\S+?)\[(\d+)\]:\s+segfault at\b')
GPF_NAMED_RE = re.compile(r'(?<!\S)(\S+?)\[(\d+)\]\s+general protection\b')
GPF_ANY_RE = re.compile(r'\bgeneral protection (?:fault|ip:)')
OOM_OUT_RE = re.compile(r'Out of memory:\s+Kill(?:ed)? process\s+(\d+)\s+\(([^)]*)\)')
OOM_TASK_RE = re.compile(r'\boom-kill:.*?\btask=([^,\s]+),\s*pid=(\d+)')
OOM_KILLED_RE = re.compile(r'(?<![\w-])Killed process\s+(\d+)\s+\(([^)]*)\)')

JOB_RE = re.compile(r'^(\d{4})/(\d{2})/(\d{2})\s+(\d{2}:\d{2}:\d{2})\s+'
                    r'(?:(\d{2}:\d{2}:\d{2})\s+)?(\d+)\s+(.*?)\s*$')
TIME_RE = re.compile(r'^\d{2}:\d{2}:\d{2}$')


def new_store() -> dict[str, Any]:
    """Accumulator for the parse_* functions (stored in ``Collected.log_data``)."""
    return {
        'kernel': {'files': [], 'lines': 0, 'events': {}, 'oom_seen': set(), 'dropped': 0},
        'daemons': {},                  # name -> {'files': {base: lines}, 'lines', 'errors',
                                        #          'dropped', 'msgs': {key: [n, first, last, files]}}
        'commit_ts': [],                # (t_ms UTC, daemon, base file)
        'commit_dropped': 0,
        'jobs': {'rows': [], 'src': None, 'duplicates': 0},
        'last_ts': None,                # latest explicit-offset timestamp seen (ms UTC)
        'offset_days': {},              # local date 'YYYY-MM-DD' -> {'+0100': samples, ...}
    }


def has_data(store) -> bool:
    if not store:
        return False
    return bool(store['kernel']['files'] or store['daemons'] or store['commit_ts']
                or store['jobs']['rows'])


# --------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------
def _ts_ms(m) -> int | None:
    """Epoch ms (UTC) of a match whose groups 1-10 are a timestamp, or None when it is not a
    valid date or time."""
    y, mo, d, h, mi, s, frac, sign, oh, om = m.group(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
    y, mo, d, h, mi, s = int(y), int(mo), int(d), int(h), int(mi), int(s)
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 61):
        return None
    ms = int((frac or '0').ljust(3, '0')[:3])
    off = (int(oh) * 60 + int(om)) * 60
    if sign == '-':
        off = -off
    return (calendar.timegm((y, mo, d, h, mi, min(s, 59))) - off) * 1000 + ms


def utc_str(ms) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def _hms(ms) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%H:%M:%S')


def _span(start, end) -> str:
    if end is None or end == start:
        return utc_str(start)
    if end - start < 86_400_000 and _day(start) == _day(end):
        return f'{utc_str(start)[:-4]}-{_hms(end)} UTC'
    return f'{utc_str(start)} to {utc_str(end)}'


def _day(ms) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%d')


def _note_offset(line, days) -> None:
    m = TS_RE.match(line)
    if m:
        by_off = days.setdefault(line[:10], {})
        off = m.group(8) + m.group(9) + m.group(10)
        by_off[off] = by_off.get(off, 0) + 1


def _note_last(store, line) -> None:
    m = TS_RE.match(line)
    if m:
        t = _ts_ms(m)
        if t is not None and (store['last_ts'] is None or t > store['last_ts']):
            store['last_ts'] = t


def tap_offsets(lines, store):
    """Yields `lines` unchanged and records the (local date, offset) of the lines that start
    with an explicit-offset timestamp (``2026-11-06 11:18:48.794 +0100``): the monitor headers
    and daemon log lines. Used by the analyzer for dp-monitor and mp-monitor files. To stay
    cheap, a line is parsed when its date and hour (the first 13 characters) differ from the
    previous line's, so a change of offset at an hour boundary (DST) is still seen. The last
    timestamped line of the input also updates ``store['last_ts']`` (the end of the TSF)."""
    days = store['offset_days']
    prev = None
    last = None
    try:
        for line in lines:
            if line[:2] == '20':
                last = line
                h = line[:13]
                if h != prev:
                    prev = h
                    _note_offset(line, days)
            yield line
    finally:
        if last is not None:
            _note_last(store, last)


# --------------------------------------------------------------------------
# A) Kernel log
# --------------------------------------------------------------------------
def parse_messages(lines, src, store, warnings) -> int:
    """Adds the crash events of a ``var/log/messages`` file to `store`.

    Pass the files in rotation order, oldest first (the first/last time of an event follow that
    order). Returns the number of ``kernel:`` lines seen.
    """
    k = store['kernel']
    k['files'].append(src)
    events = k['events']
    n_kernel = 0
    for raw in lines:
        line = raw.rstrip('\r\n')
        if 'kernel:' not in line:
            continue
        m = SYSLOG_RE.match(line)
        if m:
            when, body = m.group(1), m.group(2)
        else:
            when, body = '', line.split('kernel:', 1)[1].strip()
        n_kernel += 1
        found = None
        if 'segfault at' in body:
            mm = SEGV_RE.search(body)
            found = (mm.group(1), 'segfault', mm.group(2)) if mm else None
        elif 'general protection' in body:
            mm = GPF_NAMED_RE.search(body)
            if mm:
                found = (mm.group(1), 'general protection', mm.group(2))
            elif GPF_ANY_RE.search(body):
                found = ('(unknown)', 'general protection', None)
        elif 'oom-kill:' in body or 'Out of memory' in body or 'Killed process' in body:
            mm = OOM_OUT_RE.search(body)
            if mm:
                name, pid = mm.group(2), mm.group(1)
            else:
                mm = OOM_TASK_RE.search(body)
                if mm:
                    name, pid = mm.group(1), mm.group(2)
                else:
                    mm = OOM_KILLED_RE.search(body)
                    name, pid = (mm.group(2), mm.group(1)) if mm else (None, None)
            if name is not None:
                if (name, pid) in k['oom_seen']:
                    continue               # another line of a kill already counted
                k['oom_seen'].add((name, pid))
                found = (name, 'oom-kill', pid)
        if found is None:
            continue
        name, kind, pid = found
        rec = events.get((name, kind))
        if rec is None:
            if len(events) >= MAX_KERNEL_KEYS:
                k['dropped'] += 1
                continue
            rec = events[(name, kind)] = {'count': 0, 'first': when, 'last': when,
                                          'pids': [], 'files': []}
        rec['count'] += 1
        rec['last'] = when
        if pid is not None and pid not in rec['pids'] and len(rec['pids']) < 5:
            rec['pids'].append(pid)
        if src not in rec['files']:
            rec['files'].append(src)
    k['lines'] += n_kernel
    return n_kernel


# --------------------------------------------------------------------------
# B) Daemon logs (and the COMMIT lines of C)
# --------------------------------------------------------------------------
def normalize_message(rest: str) -> str:
    """Message with variable parts replaced: ``0x..`` -> ``0xH``, runs of 3+ digits -> ``N``.
    Bracketed or quoted text that contains a ``/`` (a path) is kept verbatim."""
    parts = KEEP_RE.split(rest)
    for i in range(0, len(parts), 2):
        parts[i] = NUM_RE.sub('N', HEX_RE.sub('0xH', parts[i]))
    return ''.join(parts)


_CANON = {'e': 'Error', 'c': 'Crit', 'f': 'Fatal'}


def _chunks(data):
    """Yields text chunks of `data` (str, or bytes decoded leniently) cut at line ends."""
    if isinstance(data, str):
        yield data
        return
    pos, n = 0, len(data)
    while pos < n:
        end = n if n - pos <= CHUNK_BYTES else data.find(b'\n', pos + CHUNK_BYTES) + 1 or n
        yield data[pos:end].decode('utf-8', errors='replace')
        pos = end


def _sample_offsets(text, days) -> None:
    """Records the offset of the first line and of one line per OFFSET_STEP characters."""
    if text[:2] == '20':
        _note_offset(text, days)
    i, n = 0, len(text)
    while i < n:
        j = text.find('\n20', i)
        if j < 0:
            return
        _note_offset(text[j + 1:j + 40], days)
        i = j + OFFSET_STEP


# Substrings that every level token and COMMIT word contains. A line is only tried with
# LINE_RE when one of them occurs within MAX_PREFIX characters of its start (str.find is much
# faster than running the regex on every line). LINE_RE decides.
_HINTS = ('rror:', 'rr:', 'ERR', 'rit:', 'ritical:', 'CRIT', 'atal:', 'FATAL', 'ommit', 'OMMIT')
MAX_PREFIX = 100


def _candidate_lines(text) -> list[int]:
    """Sorted start offsets of the lines that may be error or COMMIT lines."""
    starts = set()
    for hint in _HINTS:
        i = text.find(hint)
        while i >= 0:
            ls = text.rfind('\n', 0, i) + 1
            if i - ls <= MAX_PREFIX:
                starts.add(ls)
            i = text.find(hint, i + 1)
    return sorted(starts)


def parse_daemon_log(data, daemon, src, store, warnings) -> int:
    """Counts the error lines of one daemon log file and collects its COMMIT lines.

    `data` is the content of the file (bytes or str), `daemon` a name of DAEMON_LOGS, `src` the
    file name. Rotations can be passed in any order (first/last times are min/max). The text is
    scanned with one multiline regex per chunk, so only the matching lines cost Python time.
    Returns the number of error lines found.
    """
    d = store['daemons'].setdefault(daemon, {'files': {}, 'lines': 0, 'errors': 0,
                                             'dropped': 0, 'msgs': {}})
    msgs = d['msgs']
    days = store['offset_days']
    commit_ts = store['commit_ts']
    want_commit = daemon in COMMIT_DAEMONS
    n_lines = n_err = 0
    for text in _chunks(data):
        n_lines += text.count('\n') + (1 if text and not text.endswith('\n') else 0)
        _sample_offsets(text, days)
        j = text.rfind('\n20')
        while j >= 0:                        # last timestamped line of the chunk: end of the log
            if TS_RE.match(text, j + 1):
                _note_last(store, text[j + 1:j + 40])
                break
            j = text.rfind('\n20', 0, j)
        for ls in _candidate_lines(text):
            m = LINE_RE.match(text, ls)
            if m is None:
                continue
            if m.group(12):                     # COMMIT line
                if want_commit and m.group(1):
                    if len(commit_ts) < MAX_COMMIT_TS:
                        t = _ts_ms(m)
                        if t is not None:
                            commit_ts.append((t, daemon, src))
                    else:
                        store['commit_dropped'] += 1
                continue
            n_err += 1
            key = f'{_CANON[m.group(11)[0].lower()]}: {normalize_message(m.group(13).strip())}'
            key = key[:MSG_KEY_LEN]
            rec = msgs.get(key)
            if rec is None:
                if len(msgs) >= MAX_DISTINCT_PER_DAEMON:
                    d['dropped'] += 1
                    continue
                rec = msgs[key] = [0, None, None, set(), {}]
            rec[0] += 1
            rec[3].add(src)
            if m.group(1):
                t = _ts_ms(m)
                if t is not None:
                    secs = rec[4]
                    if t in secs:
                        secs[t] += 1
                    elif len(secs) < MAX_TS_PER_MSG:
                        secs[t] = 1
                    if rec[1] is None or t < rec[1]:
                        rec[1] = t
                    if rec[2] is None or t > rec[2]:
                        rec[2] = t
    d['files'][src] = d['files'].get(src, 0) + n_lines
    d['lines'] += n_lines
    d['errors'] += n_err
    return n_err


# --------------------------------------------------------------------------
# C) Jobs
# --------------------------------------------------------------------------
def parse_jobs(lines, src, store, warnings) -> int:
    """Adds the rows of ``show jobs processed`` found in a CLI dump. The first occurrence wins
    (a repeat is counted). Returns the number of jobs taken."""
    jobs = store['jobs']
    taken = 0
    for cmd, body in iter_cli_sections(lines):
        if cmd != CMD_JOBS:
            continue
        if jobs['src'] is not None:
            jobs['duplicates'] += 1
            if jobs['src'] != src:
                warnings.append(f'{src}: "{CMD_JOBS}" already read from {jobs["src"]}, '
                                f'this copy ignored')
            continue
        jobs['src'] = src
        for line in body:
            m = JOB_RE.match(line.strip())
            if not m or len(jobs['rows']) >= MAX_JOBS:
                continue
            y, mo, d, enq, deq, jid, rest = m.groups()
            toks = rest.split()
            done = pct = None
            if toks and toks[-1].endswith('%'):
                pct = toks.pop()
            elif toks and TIME_RE.match(toks[-1]):
                done = toks.pop()
            if len(toks) < 2:
                continue
            result, status = toks.pop(), toks.pop()
            position = toks.pop(0) if toks and toks[0].isdigit() else None
            jobs['rows'].append({'id': jid, 'date': f'{y}-{mo}-{d}', 'enq': enq, 'deq': deq,
                                 'done': done, 'pct': pct, 'status': status, 'result': result,
                                 'type': ' '.join(toks), 'position': position})
            taken += 1
    return taken


def _day_ordinal(key: str) -> int:
    return date.fromisoformat(key).toordinal()


def infer_offset(store, day: date):
    """(offset like '+0100' or None, state): 'inferred', 'ambiguous' or 'unknown'.

    Uses the explicit-offset dates of the TSF (store['offset_days']: samples per offset and
    local date). The window is the observed dates within one day of `day`; when none was
    observed there, the observed dates around the nearest one, no more than MAX_OFFSET_GAP_DAYS
    away (else *unknown*). It is *ambiguous* when the most frequent offset differs between two
    dates of the window (a DST change nearby) or when no offset has at least OFFSET_DOMINANCE of
    the samples. Otherwise it is the most frequent offset. The vote is needed because some
    sources write a different offset for the same instant (for example a subprocess with another
    time zone in mp-monitor headers, or a boot-time log), so the offsets seen on a date are not
    always unique.
    """
    obs = {_day_ordinal(k): v for k, v in store['offset_days'].items()}
    if not obs:
        return None, 'unknown'
    o = day.toordinal()
    around = [x for x in (o - 1, o, o + 1) if x in obs]
    if not around:
        near = min(obs, key=lambda x: (abs(x - o), x))
        if abs(near - o) > MAX_OFFSET_GAP_DAYS:
            return None, 'unknown'
        around = [x for x in (near - 1, near, near + 1) if x in obs]

    def top(counts):
        return max(sorted(counts), key=lambda k: counts[k])

    if len({top(obs[x]) for x in around}) > 1:
        return None, 'ambiguous'
    total: dict[str, int] = {}
    for x in around:
        for off, n in obs[x].items():
            total[off] = total.get(off, 0) + n
    best = top(total)
    if total[best] < OFFSET_DOMINANCE * sum(total.values()):
        return None, 'ambiguous'
    return best, 'inferred'


def _off_ms(off: str) -> int:
    v = (int(off[1:3]) * 60 + int(off[3:5])) * 60_000
    return -v if off[0] == '-' else v


def _local_ms(dt: datetime) -> int:
    return calendar.timegm(dt.timetuple()) * 1000


def _job_view(job, store, cache):
    """Job dict for the view: UTC start/end (ms) when the offset can be inferred."""
    y, mo, d = (int(x) for x in job['date'].split('-'))
    try:
        enq = datetime.combine(date(y, mo, d), datetime.strptime(job['enq'], '%H:%M:%S').time())
        start = end = None
        if job['deq']:
            start = datetime.combine(enq.date(), datetime.strptime(job['deq'], '%H:%M:%S').time())
            if start < enq:
                start += timedelta(days=1)
            if job['done']:
                end = datetime.combine(start.date(),
                                       datetime.strptime(job['done'], '%H:%M:%S').time())
                if end < start:
                    end += timedelta(days=1)
    except ValueError:
        return None
    ref = (start or enq).date()
    if ref not in cache:
        cache[ref] = infer_offset(store, ref)
    off, state = cache[ref]
    out = {'id': job['id'], 'type': job['type'], 'status': job['status'],
           'result': job['result'], 'running': end is None, 'offset': off,
           'offset_state': state, 'enqueued': f'{job["date"]} {job["enq"]}',
           'dequeued': job['deq'], 'completed': job['done'], 'pct': job['pct'],
           'start': None, 'end': None}
    if off is not None:
        shift = _off_ms(off)
        base = start or enq
        out['start'] = _local_ms(base) - shift
        if end is not None:
            out['end'] = _local_ms(end) - shift
    return out


def commit_windows(store, gap_s) -> list[dict[str, Any]]:
    """COMMIT lines (explicit offset) grouped into windows: consecutive lines at most `gap_s`
    seconds apart. Each window: start, end (ms UTC), n lines, daemons, files."""
    wins: list[dict[str, Any]] = []
    for t, daemon, src in sorted(store['commit_ts']):
        if wins and t - wins[-1]['end'] <= gap_s * 1000:
            w = wins[-1]
            w['end'] = t
            w['n'] += 1
        else:
            w = {'start': t, 'end': t, 'n': 1, 'daemons': [], 'files': []}
            wins.append(w)
        if daemon not in w['daemons']:
            w['daemons'].append(daemon)
        if src not in w['files']:
            w['files'].append(src)
    return wins


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------
def events_from_views(mp_view, dph_view) -> list[dict[str, Any]]:
    """Items to correlate: {code, label, start, end (ms UTC), flag (the flag dict itself)}."""
    out: list[dict[str, Any]] = []
    if mp_view:
        procs = {p['name']: p for p in mp_view.get('procs', [])}
        peak_t = ((mp_view.get('memory') or {}).get('summary') or {}).get('peak_t')
        for f in mp_view.get('findings', []):
            if f['code'] == 'PROC_CPU':
                p = procs.get(f.get('subject'))
                if p and p.get('run_start') is not None:
                    out.append({'code': 'PROC_CPU', 'label': f'PROC_CPU {p["name"]}',
                                'start': p['run_start'], 'end': p['run_end'], 'flag': f})
            elif f['code'] in ('MP_MEMORY', 'MP_MEMORY_PAST_PEAK') and peak_t is not None:
                out.append({'code': f['code'], 'label': f'{f["code"]} (memory peak)',
                            'start': peak_t, 'end': peak_t, 'flag': f})
    if dph_view:
        for f in dph_view.get('findings', []):
            if f['code'] not in ('CORE_PEAK', 'CORE_PEAK_MINUTE'):
                continue
            key = 'core' if f['code'] == 'CORE_PEAK' else 'core_minute'
            t = ((dph_view.get('summary') or {}).get(f.get('dp')) or {}).get(key, {}).get('peak_t')
            if t is None:
                continue
            start = t - MINUTE_PEAK_SPAN_MS if f['code'] == 'CORE_PEAK_MINUTE' else t
            out.append({'code': f['code'], 'label': f'{f["code"]} DP {f.get("dp")}',
                        'start': start, 'end': t, 'flag': f})
    return out


def _overlaps(a0, a1, b0, b1, margin) -> bool:
    return a0 - margin <= b1 and b0 <= a1 + margin


def _job_desc(j) -> str:
    return (f'{j["type"] or "?"} job {j["id"]} (dequeued {j["dequeued"]} local, completed '
            f'{j["completed"]} local; {_span(j["start"], j["end"])}; offset inferred '
            f'({j["offset"]}))')


def _win_desc(w) -> str:
    return f'commit window {_span(w["start"], w["end"])} ({w["n"]} line(s), {"/".join(w["daemons"])})'


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def _flag(subject, code, level, text):
    return {'code': code, 'level': level, 'text': text, 'subject': subject,
            'check': CODE_CHECK[code]}


def _kernel_view(store, th, flags):
    k = store['kernel']
    events = [{'process': p, 'type': t, 'count': r['count'], 'first': r['first'],
               'last': r['last'], 'pids': list(r['pids']), 'files': list(r['files'])}
              for (p, t), r in k['events'].items()]
    events.sort(key=lambda e: (-e['count'], e['process'], e['type']))
    crash_min = th['crash_min']
    note = 'times as written in the log: device local time, no year, no offset'
    bad = [e for e in events if e['count'] >= crash_min]
    for e in bad:
        flags.append(_flag(f'{e["process"]} {e["type"]}', 'KERNEL_CRASH', 'crit', (
            f'Kernel log: {e["count"]} {e["type"]} event(s) of process {e["process"]} '
            f'(first {e["first"] or "?"}, last {e["last"] or "?"}; {note}), at or above '
            f'{crash_min:g}. A repeated crash of the same process is a bug or a resource problem; '
            f'check the core files and open a support case with the TSF.')))
    seen = [e for e in events if e['count'] < crash_min]
    if seen:
        listing = '; '.join(f'{e["process"]} {e["type"]} x{e["count"]} (last {e["last"] or "?"})'
                            for e in seen[:30])
        more = f' and {len(seen) - 30} more' if len(seen) > 30 else ''
        flags.append(_flag('kernel', 'KERNEL_CRASH_SEEN', 'info', (
            f'Kernel log: crash events below {crash_min:g} per process and type: {listing}{more} '
            f'({note}).')))
    return {'present': bool(k['files']), 'files': list(k['files']), 'lines': k['lines'],
            'events': events, 'dropped': k['dropped'], 'time_note': note}


def _recent_count(rec, lo, hi) -> int:
    return sum(n for t, n in rec[4].items() if lo <= t <= hi)


def _daemon_view(store, th, flags, budgets):
    rep_min = th['log_repeat_min']
    end = store.get('last_ts')
    lo = end - int(th['log_recent_h'] * 3_600_000) if end is not None else None
    rows = []
    recent_flagged = []          # (recent, total, daemon, msg, first, last, files)
    chronic: dict[str, list] = {}
    for name in sorted(store['daemons']):
        d = store['daemons'][name]
        items = sorted(d['msgs'].items(), key=lambda kv: (-kv[1][0], kv[0]))
        msgs = []
        n_recent = n_chronic = recent_occ = 0
        for msg, rec in items:
            n, t0, t1, files = rec[:4]
            rc = _recent_count(rec, lo, end) if end is not None else 0
            recent_occ += rc
            kind = ''
            if rc >= rep_min:
                kind = 'recent'
                n_recent += 1
                recent_flagged.append((rc, n, name, msg, t0, t1, sorted(files)))
            elif n >= rep_min:
                kind = 'chronic'
                n_chronic += 1
                chronic.setdefault(name, []).append((n, msg))
            if len(msgs) < MAX_MSGS_PER_DAEMON_VIEW:
                msgs.append({'msg': msg, 'count': n, 'recent': rc, 'first': t0, 'last': t1,
                             'files': sorted(files), 'flagged': kind == 'recent',
                             'kind': kind})
        omitted = max(0, len(items) - MAX_MSGS_PER_DAEMON_VIEW)
        if omitted:
            budgets.append(f'{name}: {omitted} less frequent message(s) not listed '
                           f'(at most {MAX_MSGS_PER_DAEMON_VIEW} per daemon)')
        if d['dropped']:
            budgets.append(f'{name}: {d["dropped"]} error line(s) with a new message were not '
                           f'counted after {MAX_DISTINCT_PER_DAEMON} distinct messages')
        level = 'warn' if n_recent else ('info' if n_chronic else '')
        rows.append({'daemon': name, 'files': sorted(d['files']), 'lines': d['lines'],
                     'errors': d['errors'], 'distinct': len(d['msgs']), 'dropped': d['dropped'],
                     'omitted': omitted, 'n_recent': n_recent, 'n_chronic': n_chronic,
                     'recent_errors': recent_occ, 'level': level, 'messages': msgs})
    recent_flagged.sort(key=lambda x: (-x[0], x[2], x[3]))
    for rc, n, name, msg, t0, t1, files in recent_flagged[:MAX_REPEAT_FLAGS]:
        flags.append(_flag(f'{name}: {msg[:60]}', 'LOG_ERROR_REPEAT', 'warn', (
            f'{name}.log: the error "{msg}" appears {rc:,} times in the last '
            f'{th["log_recent_h"]:g} h of the TSF (until {utc_str(end)}), {n:,} in total '
            f'(first {utc_str(t0)}, last {utc_str(t1)}; files {", ".join(files)}), at or above '
            f'{rep_min:g}. A message that repeats this often and still does is a persistent '
            f'condition, not an event; look it up with the daemon name and fix or silence its '
            f'cause.')))
    rest = recent_flagged[MAX_REPEAT_FLAGS:]
    if rest:
        budgets.append(f'{len(rest)} more recently repeated message(s) summarised in one flag '
                       f'(at most {MAX_REPEAT_FLAGS} are flagged one by one)')
        daemons = sorted({x[2] for x in rest})
        top = '; '.join(f'{x[2]}: "{x[3][:80]}" x{x[0]:,}' for x in rest[:5])
        flags.append(_flag('other repeated messages', 'LOG_ERROR_REPEAT', 'warn', (
            f'{len(rest)} more repeated error message(s) ({sum(x[0] for x in rest):,} recent '
            f'occurrences) in {", ".join(daemons)}, each at or above {rep_min:g} in the last '
            f'{th["log_recent_h"]:g} h; top: {top}.')))
    why = ('' if end is not None else ' No reference time (no timestamp with a UTC offset) could '
           'be found in the TSF, so no message can be called recent.')
    for name in sorted(chronic):
        items = sorted(chronic[name], key=lambda x: (-x[0], x[1]))
        top = '; '.join(f'"{m[:80]}" x{n:,}' for n, m in items[:3])
        flags.append(_flag(f'{name} (chronic)', 'LOG_ERROR_CHRONIC', 'info', (
            f'{name}.log: {len(items)} message(s) repeated at least {rep_min:g} times over the '
            f'whole log but not in the last {th["log_recent_h"]:g} h ({sum(n for n, _m in items):,}'
            f' occurrences in total); top {min(3, len(items))}: {top}.{why}')))
    return {'present': bool(store['daemons']), 'rows': rows, 'n_flagged': len(recent_flagged),
            'n_chronic': sum(len(v) for v in chronic.values()), 'ref_end': end,
            'recent_h': th['log_recent_h'], 'allowlist': list(DAEMON_LOGS)}


def _context_view(store, th, events, flags, budgets):
    all_wins = commit_windows(store, th['commit_gap_s'])
    wins = [w for w in all_wins if w['n'] >= th['commit_min_lines']]
    discarded = sum(w['n'] for w in all_wins if w['n'] < th['commit_min_lines'])
    cache: dict = {}
    jobs = [j for j in (_job_view(r, store, cache) for r in store['jobs']['rows']) if j]
    margin = int(th['corr_window_s'] * 1000)
    usable = [j for j in jobs if j['start'] is not None and j['end'] is not None]
    near: dict[int, dict[str, list]] = {}
    corr = []
    for i, ev in enumerate(events):
        mw = [w for w in wins if _overlaps(ev['start'], ev['end'], w['start'], w['end'], margin)]
        mj = [j for j in usable
              if _overlaps(ev['start'], ev['end'], j['start'], j['end'], margin)]
        if not (mw or mj):
            continue
        near[i] = {'windows': mw, 'jobs': mj}
        corr.append({'code': ev['code'], 'label': ev['label'], 'start': ev['start'],
                     'end': ev['end'],
                     'windows': [{'start': w['start'], 'end': w['end'], 'n': w['n']}
                                 for w in mw[:MAX_MATCHES]],
                     'jobs': [{'id': j['id'], 'type': j['type'], 'start': j['start'],
                               'end': j['end'], 'offset': j['offset']} for j in mj[:MAX_MATCHES]]})
    for item, (i, m) in zip(corr, near.items()):
        ev = events[i]
        parts = [_win_desc(w) for w in m['windows'][:MAX_MATCHES]]
        parts += [_job_desc(j) for j in m['jobs'][:MAX_MATCHES]]
        item['text'] = (f'{ev["label"]} ({_span(ev["start"], ev["end"])}) is within '
                        f'{th["corr_window_s"]:g} s of: ' + '; '.join(parts) + '.')
        short = [f'commit window {_hms(w["start"])}-{_hms(w["end"])} UTC' for w in m['windows'][:2]]
        short += [f'{j["type"] or "?"} job {j["id"]} (offset inferred {j["offset"]})'
                  for j in m['jobs'][:2]]
        ev['flag']['text'] += ' Near ' + ', '.join(short) + ' (informational; flag unchanged).'
    if len(corr) > MAX_NEAR_FINDINGS:
        budgets.append(f'{len(corr) - MAX_NEAR_FINDINGS} more correlated item(s) summarised in '
                       f'one finding (at most {MAX_NEAR_FINDINGS} are listed)')
    for item in corr[:MAX_NEAR_FINDINGS]:
        flags.append(_flag(item['label'], 'NEAR_COMMIT', 'info', item['text']))
    if len(corr) > MAX_NEAR_FINDINGS:
        flags.append(_flag('other items', 'NEAR_COMMIT', 'info', (
            f'{len(corr) - MAX_NEAR_FINDINGS} more item(s) near a commit or job: '
            + ', '.join(c['label'] for c in corr[MAX_NEAR_FINDINGS:][:10]) + '.')))
    near_by_win: dict[int, list] = {}
    near_by_job: dict[str, list] = {}
    for i, m in near.items():
        for w in m['windows']:
            near_by_win.setdefault(w['start'], []).append(events[i]['label'])
        for j in m['jobs']:
            near_by_job.setdefault(j['id'], []).append(events[i]['label'])
    rows = []
    for w in wins:
        rows.append({'kind': 'commit', 'label': f'COMMIT lines ({", ".join(w["daemons"])})',
                     'detail': f'{w["n"]} line(s) in {", ".join(w["files"])}',
                     'start': w['start'], 'end': w['end'], 'offset': 'explicit',
                     'offset_state': 'explicit', 'near': near_by_win.get(w['start'], [])})
    for j in jobs:
        det = f'{j["status"]} {j["result"]}' + (f' {j["pct"]}' if j['pct'] else '')
        det += f'; enqueued {j["enqueued"]} local, dequeued {j["dequeued"] or "-"}, ' \
               f'completed {j["completed"] or "-"}'
        rows.append({'kind': 'job', 'label': f'{j["type"] or "?"} job {j["id"]}',
                     'detail': det, 'start': j['start'], 'end': j['end'],
                     'offset': j['offset'], 'offset_state': j['offset_state'],
                     'running': j['running'], 'near': near_by_job.get(j['id'], [])})
    if len(wins) > MAX_WINDOWS_VIEW:
        budgets.append(f'timeline: {len(wins) - MAX_WINDOWS_VIEW} older commit window(s) not '
                       f'listed (at most {MAX_WINDOWS_VIEW})')
    if len(jobs) > MAX_JOBS_VIEW:
        budgets.append(f'timeline: {len(jobs) - MAX_JOBS_VIEW} older job(s) not listed '
                       f'(at most {MAX_JOBS_VIEW})')
    crow = sorted((r for r in rows if r['kind'] == 'commit'),
                  key=lambda r: -r['start'])[:MAX_WINDOWS_VIEW]
    jrow = [r for r in rows if r['kind'] == 'job'][:MAX_JOBS_VIEW]
    timeline = sorted(crow + jrow, key=lambda r: (r['start'] is None, -(r['start'] or 0)))
    if store['commit_dropped']:
        budgets.append(f'{store["commit_dropped"]} COMMIT line(s) not kept after '
                       f'{MAX_COMMIT_TS:,} lines')
    states: dict[str, int] = {}
    for j in jobs:
        states[j['offset_state']] = states.get(j['offset_state'], 0) + 1
    return {'present_commits': bool(all_wins), 'present_jobs': bool(jobs), 'n_windows': len(wins),
            'n_discarded_lines': discarded,
            'n_jobs': len(jobs), 'timeline': timeline, 'correlations': corr,
            'n_correlations': len(corr), 'job_offsets': states, 'jobs_src': store['jobs']['src'],
            'offset_days': {k: dict(sorted(v.items())) for k, v in sorted(store['offset_days'].items())}
            if len(store['offset_days']) <= 60 else {}}


def evaluate_log_events(store, thresholds=None, mp_view=None, dph_view=None) -> dict[str, Any]:
    """Builds the JSON-serialisable view of a log store.

    Keys: 'thresholds'; 'checks' (check dicts like system_health's, group ``Logs``: ids
    kernel, log_errors, commits); 'findings' (flag dicts {code, level, text, subject, check});
    'logs' ({'kernel': {present, files, lines, events [{process, type, count, first, last,
    pids, files}], dropped, time_note}, 'daemons': {present, rows [{daemon, files, lines,
    errors, distinct, dropped, omitted, messages [{msg, count, first, last (ms UTC or None),
    files, flagged}]}], n_flagged, allowlist}, 'context': {present_commits, present_jobs,
    n_windows, n_jobs, timeline [{kind, label, detail, start, end, offset, offset_state, near}],
    correlations [{code, label, start, end, windows, jobs, text}], n_correlations,
    job_offsets, jobs_src, offset_days}, 'budgets': [...]}); 'warnings'.
    `mp_view` / `dph_view` are the management plane and dataplane health views: the text of
    their PROC_CPU, MP_MEMORY*, CORE_PEAK* flags gets a note when near a commit or job (their
    level and code never change). The store is not modified.
    """
    th = dict(LOG_THRESHOLDS)
    unknown = set(thresholds or {}) - set(LOG_THRESHOLDS)
    if unknown:
        raise ValueError('unknown log threshold(s): ' + ', '.join(sorted(unknown)))
    th.update(thresholds or {})
    store = store or new_store()
    flags: list[dict[str, Any]] = []
    budgets: list[str] = []
    kernel = _kernel_view(store, th, flags)
    daemons = _daemon_view(store, th, flags, budgets)
    events = events_from_views(mp_view, dph_view)
    ctx = _context_view(store, th, events, flags, budgets)

    checks = []

    def add(cid, title, source, has, value, note):
        fl = [f for f in flags if f['check'] == cid]
        status = module_status(from_flags(fl), has)
        checks.append({'id': cid, 'group': GROUP_LOGS, 'title': title, 'source': source,
                       'status': status, 'value': value if has else '', 'note': note,
                       'n_flags': len(fl)})

    if kernel['present']:
        n_bad = sum(1 for e in kernel['events'] if e['count'] >= th['crash_min'])
        total = sum(e['count'] for e in kernel['events'])
        value = (f'{total} crash event(s) in {kernel["lines"]:,} kernel lines'
                 + (f', {n_bad} process/type at or above {th["crash_min"]:g}' if n_bad else ''))
        note = 'device local time, no year'
    else:
        value, note = '', 'No var/log/messages in the input.'
    add('kernel', 'Kernel crashes', 'var/log/messages (+ rotations)', kernel['present'],
        value, note)

    if daemons['present']:
        n_err = sum(r['errors'] for r in daemons['rows'])
        value = (f'{daemons["n_flagged"]} recently repeated, {daemons["n_chronic"]} chronic '
                 f'message(s); {n_err:,} error lines in {len(daemons["rows"])} daemon log(s)')
        note = '; '.join(budgets[:1]) if budgets else ''
    else:
        value, note = '', 'No daemon log of the allowlist in the input.'
    add('log_errors', 'Repeated daemon errors', 'var/log/pan/<daemon>.log (+ rotations)',
        daemons['present'], value, note)

    has_ctx = ctx['present_commits'] or ctx['present_jobs']
    if has_ctx:
        bad = ctx['job_offsets'].get('ambiguous', 0) + ctx['job_offsets'].get('unknown', 0)
        value = (f'{ctx["n_correlations"]} item(s) near a commit or job; {ctx["n_windows"]} '
                 f'commit window(s) ({ctx["n_discarded_lines"]} single line(s) ignored), '
                 f'{ctx["n_jobs"]} job(s)')
        note = (f'{bad} job(s) without a usable offset, not correlated' if bad else
                ('job offsets inferred' if ctx['n_jobs'] else ''))
    else:
        value, note = '', 'No COMMIT lines and no "show jobs processed" section found.'
    add('commits', 'Commit and job context', 'configd.log, ms.log; ' + CMD_JOBS, has_ctx,
        value, note)

    warnings = []
    if budgets:
        warnings.append('Log budgets reached: ' + '; '.join(budgets[:6])
                        + (f' (+{len(budgets) - 6} more)' if len(budgets) > 6 else '') + '.')
    return {'thresholds': th, 'checks': checks, 'findings': flags,
            'logs': {'kernel': kernel, 'daemons': daemons, 'context': ctx, 'budgets': budgets},
            'warnings': warnings}


def apply_to_system_view(sys_view, store, thresholds=None, mp_view=None, dph_view=None):
    """Appends the Logs checks, findings and tables to a System health view (in place) and
    returns it. Call it once, after the management plane and dataplane health views exist."""
    lv = evaluate_log_events(store, thresholds, mp_view, dph_view)
    sys_view['thresholds'].update(lv['thresholds'])
    sys_view['checks'].extend(lv['checks'])
    sys_view['findings'].extend(lv['findings'])
    sys_view['logs'] = lv['logs']
    sys_view['warnings'].extend(lv['warnings'])
    order = {OK: 0, WARNING: 1, CRITICAL: 2}
    statuses = [c['status'] for c in sys_view['checks'] if c['status'] in order]
    sys_view['status'] = max(statuses, key=lambda s: order[s]) if statuses else 'no_data'
    return sys_view

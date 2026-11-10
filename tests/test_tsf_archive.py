"""Tests for tsf/archive.py (safe in-memory archive reader) and its use by collect()."""
from __future__ import annotations

import gzip
import io
import os
import tarfile

import pytest

from panos_toolbox.tsf import analyzer, archive
from panos_toolbox.tsf.model import Inventory


def select(logical):
    if logical.endswith('.log') or '.log.' in logical:
        return 'logs'
    return None


def build_tar(path, entries):
    """entries: list of (name, data | ('sym', target) | ('hard', target) | ('fifo',))."""
    with tarfile.open(path, 'w:gz') as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            if isinstance(data, tuple):
                kind = data[0]
                if kind == 'sym':
                    info.type, info.linkname = tarfile.SYMTYPE, data[1]
                elif kind == 'hard':
                    info.type, info.linkname = tarfile.LNKTYPE, data[1]
                else:
                    info.type = tarfile.FIFOTYPE
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))


def read_all(path):
    inv = Inventory()
    members = list(archive.iter_members(str(path), select, inv))
    return members, inv


def test_path_traversal_and_absolute_rejected(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tar(p, [('../x.log', b'1'), ('/abs/y.log', b'2'), ('a/../../b.log', b'3'),
                  ('ok/z.log', b'4')])
    members, inv = read_all(p)
    assert [(m.name, m.data) for m in members] == [('ok/z.log', b'4')]
    assert inv.skipped == [('../x.log', 'unsafe path'), ('/abs/y.log', 'unsafe path'),
                           ('a/../../b.log', 'unsafe path')]
    assert inv.skipped_count('unsafe path') == 3


def test_dot_slash_prefix_works_and_is_normalized(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tar(p, [('./var/log/pan/x.log', b'1')])
    members, inv = read_all(p)
    assert [m.name for m in members] == ['var/log/pan/x.log']
    assert inv.skipped == []


def test_split_safe():
    assert archive.split_safe('./a/./b') == 'a/b'
    assert archive.split_safe('/etc/x') is None
    assert archive.split_safe('a/../../b') is None
    assert archive.split_safe('..') is None
    assert archive.split_safe('./') is None


def test_links_and_special_files_skipped(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tar(p, [('s.log', ('sym', 'real.log')), ('h.log', ('hard', 'real.log')),
                  ('f.log', ('fifo',)), ('real.log', b'data')])
    members, inv = read_all(p)
    assert [m.name for m in members] == ['real.log']
    assert inv.skipped == [('s.log', 'link'), ('h.log', 'link'), ('f.log', 'special file')]


def test_member_over_limit_keeps_tail_drops_partial_line(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, 'MAX_MEMBER_BYTES', 20)
    data = b'line one\nline two\nline three\nline four\n'   # 39 bytes
    p = tmp_path / 'a.tgz'
    build_tar(p, [('big.log', data)])
    members, inv = read_all(p)
    (m,) = members
    assert m.truncated and m.error is None
    # last 20 bytes = "ine three\nline four\n"; first partial line dropped
    assert m.data == b'line four\n'
    assert inv.family('logs').truncated == ['big.log']


@pytest.mark.parametrize('gz', [False, True])
def test_cut_on_line_boundary_keeps_complete_line(tmp_path, monkeypatch, gz):
    # The last 20 bytes start exactly at a line start: no complete line may be lost.
    monkeypatch.setattr(archive, 'MAX_MEMBER_BYTES', 20)
    monkeypatch.setattr(archive, '_CHUNK', 7)
    data = b'first line long\n' + b'line three\nline 4\n'   # 16 + 20 bytes
    name, payload = ('x.log.gz', gzip.compress(data)) if gz else ('x.log', data)
    p = tmp_path / 'a.tgz'
    build_tar(p, [(name, payload)])
    (m,), _inv = read_all(p)
    assert m.truncated and m.data == b'line three\nline 4\n'


def test_member_at_limit_not_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, 'MAX_MEMBER_BYTES', 9)
    p = tmp_path / 'a.tgz'
    build_tar(p, [('a.log', b'12345678\n')])
    (m,), _inv = read_all(p)
    assert not m.truncated and m.data == b'12345678\n'


def test_gz_member_read_and_real_name_kept(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tar(p, [('x.log.1.gz', gzip.compress(b'hello\n'))])
    (m,), inv = read_all(p)
    assert m.name == 'x.log.1.gz' and m.logical == 'x.log.1'
    assert m.data == b'hello\n' and not m.truncated
    assert inv.family('logs').found == ['x.log.1.gz']
    assert inv.family('logs').read == ['x.log.1.gz']


def test_gz_over_cap_keeps_tail(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, 'MAX_MEMBER_BYTES', 20)
    monkeypatch.setattr(archive, '_CHUNK', 7)
    data = b'line one\nline two\nline three\nline four\n'
    p = tmp_path / 'a.tgz'
    build_tar(p, [('x.log.gz', gzip.compress(data))])
    (m,), inv = read_all(p)
    assert m.truncated and m.data == b'line four\n'
    assert inv.family('logs').truncated == ['x.log.gz']


def test_gz_scan_cap_marks_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, 'MAX_GZ_SCAN_BYTES', 10)
    monkeypatch.setattr(archive, '_CHUNK', 5)
    p = tmp_path / 'a.tgz'
    build_tar(p, [('x.log.gz', gzip.compress(b'aaaa\n' * 100))])
    (m,), _inv = read_all(p)
    # The scan stops at the first chunk boundary at or past the cap.
    assert m.truncated and 10 <= len(m.data) < 10 + 5


def test_corrupt_gz_keeps_partial_and_reports_error(tmp_path):
    text = b''.join(b'row %d %d\n' % (i, i * 7919 % 1000) for i in range(2000))
    raw = gzip.compress(text)
    p = tmp_path / 'a.tgz'
    build_tar(p, [('x.log.gz', raw[:len(raw) * 9 // 10])])
    (m,), inv = read_all(p)
    assert m.error and m.data.startswith(b'row 0 0\n') and len(m.data) > 1000
    assert inv.family('logs').truncated == ['x.log.gz']


def test_max_members_stops_reading(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, 'MAX_MEMBERS', 2)
    p = tmp_path / 'a.tgz'
    build_tar(p, [('a.log', b'1'), ('b.log', b'2'), ('c.log', b'3')])
    members, inv = read_all(p)
    assert [m.name for m in members] == ['a.log', 'b.log']
    assert len(inv.notes) == 1 and 'member limit' in inv.notes[0]


def test_max_total_bytes_stops_reading(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, 'MAX_TOTAL_BYTES', 5)
    p = tmp_path / 'a.tgz'
    build_tar(p, [('a.log', b'123456'), ('b.log', b'2'), ('c.log', b'3')])
    members, inv = read_all(p)
    assert [m.name for m in members] == ['a.log']
    assert len(inv.notes) == 1 and 'total size' in inv.notes[0]
    assert inv.family('logs').found == ['a.log', 'b.log']   # b seen, not read
    assert inv.family('logs').read == ['a.log']


def test_rotation_order():
    names = ['d/dp-monitor.log', 'd/dp-monitor.log.old', 'd/dp-monitor.log.2.gz',
             'd/dp-monitor.log.10', 'd/dp-monitor.log.1']
    assert archive.sort_rotations(names) == [
        'd/dp-monitor.log.10', 'd/dp-monitor.log.2.gz', 'd/dp-monitor.log.1',
        'd/dp-monitor.log.old', 'd/dp-monitor.log']
    assert archive.sort_rotations(names) == archive.sort_rotations(names[::-1])
    # Same rotation, plain and gz: tie broken by name.
    assert archive.sort_rotations(['x.log.1.gz', 'x.log.1']) == ['x.log.1', 'x.log.1.gz']


def test_directory_mode_does_not_follow_symlinks(tmp_path):
    root = tmp_path / 'tsf'
    (root / 'sub').mkdir(parents=True)
    (root / 'sub' / 'a.log').write_bytes(b'real')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'secret.log').write_bytes(b'secret')
    os.symlink(outside, root / 'linkdir')
    os.symlink(outside / 'secret.log', root / 'link.log')
    members, inv = read_all(root)
    assert [m.name for m in members] == ['sub/a.log']
    assert sorted(inv.skipped) == [('link.log', 'link'), ('linkdir', 'link')]


def test_inventory_contents(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tar(p, [('a.log', b'1'), ('notes.txt', b'x'), ('l.log', ('sym', 'a.log')),
                  ('../e.log', b'2')])
    _members, inv = read_all(p)
    fam = inv.family('logs')
    assert fam.found == ['a.log'] and fam.read == ['a.log']
    assert fam.truncated == [] and fam.skipped == []
    assert list(inv.families) == ['logs']
    assert inv.members_seen == 4 and inv.bytes_read == 1
    assert inv.skipped_count() == 2


# --------------------------------------------------------------------------
# collect() integration
# --------------------------------------------------------------------------
def dp_text(kbps, ts='2026-10-27 08:20:20'):
    return (f'{ts} +0100 --- dp-monitor\ntarget-dp: *.dp0\n'
            f'Throughput: {kbps} kbps\n').encode()


def test_collect_rotation_order_independent_of_archive_order(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tar(p, [
        ('var/log/pan/dp-monitor.log', dp_text(333)),
        ('var/log/pan/dp-monitor.log.old', dp_text(222)),
        ('var/log/pan/dp-monitor.log.1.gz', gzip.compress(dp_text(111))),
    ])
    warnings = []
    col = analyzer.collect(str(p), warnings)
    # Oldest first wins on the duplicate (dp, t): the .1.gz content.
    assert [(s['src'], s['kbps']) for s in col.samples] == [('dp-monitor.log.1.gz', 111)]
    # Changed in step 2: the two dropped conflicting samples are now reported.
    assert col.n_files == 3
    assert warnings == [
        ('dp-monitor.log.old: sample dp0 @ 2026-10-27T07:20:20Z conflicts with '
         'dp-monitor.log.1.gz (kept the first)'),
        ('dp-monitor.log: sample dp0 @ 2026-10-27T07:20:20Z conflicts with '
         'dp-monitor.log.1.gz (kept the first)')]
    assert col.inventory.family('dp-monitor').read == [
        'var/log/pan/dp-monitor.log', 'var/log/pan/dp-monitor.log.old',
        'var/log/pan/dp-monitor.log.1.gz']


def test_collect_warns_on_unsafe_member(tmp_path):
    p = tmp_path / 'a.tgz'
    build_tar(p, [('../evil/var/log/pan/dp-monitor.log', dp_text(1)),
                  ('var/log/pan/dp-monitor.log', dp_text(2))])
    warnings = []
    col = analyzer.collect(str(p), warnings)
    assert [s['kbps'] for s in col.samples] == [2]
    assert warnings == ['../evil/var/log/pan/dp-monitor.log: unsafe member path, skipped']


def test_collect_directory_gz_rotation(tmp_path):
    d = tmp_path / 'var' / 'log' / 'pan'
    d.mkdir(parents=True)
    (d / 'dp-monitor.log').write_bytes(dp_text(2, '2026-10-27 08:21:20'))
    (d / 'dp-monitor.log.1.gz').write_bytes(gzip.compress(dp_text(1)))
    warnings = []
    col = analyzer.collect(str(tmp_path), warnings)
    assert [s['kbps'] for s in col.samples] == [1, 2]
    assert warnings == []


def test_collect_truncated_member_warns(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, 'MAX_MEMBER_BYTES', 60)
    p = tmp_path / 'a.tgz'
    build_tar(p, [('var/log/pan/dp-monitor.log', dp_text(1) * 3)])
    warnings = []
    analyzer.collect(str(p), warnings)
    assert any('larger than the read limit' in w for w in warnings)


@pytest.mark.parametrize('name', ['a.tgz'])
def test_collect_returns_collected_with_inventory(tmp_path, name):
    p = tmp_path / name
    build_tar(p, [('var/log/pan/dp-monitor.log', dp_text(1))])
    col = analyzer.collect(str(p), [])
    assert col.n_files == 1 and col.inventory.family('dp-monitor').read

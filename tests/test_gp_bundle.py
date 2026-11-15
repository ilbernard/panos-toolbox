"""Tests for gp/bundle.py: zip and folder reading, safety, limits, rotation, decoding.

Synthetic data only; nothing touches a real bundle.
"""
from __future__ import annotations

import io
import os
import tarfile
import zipfile

import pytest

from panos_toolbox.gp import bundle as bmod
from panos_toolbox.gp.bundle import Bundle, BundleError, classify, decode_text, sort_rotations


def make_zip(path, entries):
    """entries: list of (name, bytes) or (name, bytes, external_attr)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            info = zipfile.ZipInfo(entry[0])
            info.compress_type = zipfile.ZIP_DEFLATED
            if len(entry) > 2:
                info.create_system = 3
                info.external_attr = entry[2] << 16
            zf.writestr(info, entry[1])
    return path


def test_zip_inventory_and_read(tmp_path):
    z = make_zip(tmp_path / "b.zip", [
        ("PanGPS.log", b"hello\r\nworld\r\n"),
        ("pan_gp_event.log.old", b"x\n"),
        ("regval.txt", b"k=v\n"),
        ("random.bin", b"\x00\x01"),
    ])
    b = Bundle.open(z)
    try:
        inv = {m.name: m for m in b.inventory()}
        assert inv["PanGPS.log"].family == "service_log"
        assert inv["pan_gp_event.log.old"].family == "event_log"
        assert inv["regval.txt"].family == "registry_dump"
        assert inv["random.bin"].family == "other"          # unknown: listed, never an error
        assert inv["PanGPS.log"].status == "found"
        assert b.read_text("pangps.log", "test") == "hello\r\nworld\r\n"   # no newline translation
        assert inv["PanGPS.log"].status == "read" and inv["PanGPS.log"].used_for == "test"
    finally:
        b.close()


def test_directory_input(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "PanGPS.log").write_bytes(b"abc\n")
    (d / "empty.txt").write_bytes(b"")
    sub = d / "sub"
    sub.mkdir()
    (sub / "regval.txt").write_bytes(b"k\n")
    b = Bundle.open(d)
    try:
        assert b.read_bytes("PanGPS.log") == b"abc\n"
        assert b.members["empty.txt"].status == "empty"
        assert b.read_bytes("regval.txt") == b"k\n"
    finally:
        b.close()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks")
def test_directory_symlink_skipped(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "PanGPS.log").write_bytes(b"abc\n")
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    try:
        os.symlink(outside, d / "regval.txt")
    except OSError:
        pytest.skip("cannot create symlinks")
    b = Bundle.open(d)
    assert b.members["regval.txt"].status == "skipped"
    assert b.members["regval.txt"].reason == "link"
    assert b.read_bytes("regval.txt") is None


def test_path_traversal_and_absolute_members_skipped(tmp_path):
    z = make_zip(tmp_path / "b.zip", [
        ("../evil.txt", b"x"),
        ("/etc/passwd", b"x"),
        ("a/../../b.txt", b"x"),
        ("C:\\Windows\\win.ini", b"x"),
        ("PanGPS.log", b"ok\n"),
    ])
    b = Bundle.open(z)
    for name in ("evil.txt", "passwd", "b.txt", "win.ini"):
        assert b.members[name].status == "skipped", name
        assert b.members[name].reason == "unsafe path"
        assert b.read_bytes(name) is None
    assert b.read_text("PanGPS.log") == "ok\n"
    assert not (tmp_path.parent / "evil.txt").exists()


def test_link_and_special_zip_members_skipped(tmp_path):
    z = make_zip(tmp_path / "b.zip", [
        ("lnk.txt", b"/etc/passwd", 0o120777),
        ("fifo.txt", b"", 0o010644),
        ("PanGPS.log", b"ok\n", 0o100644),
    ])
    b = Bundle.open(z)
    assert b.members["lnk.txt"].reason == "link"
    assert b.members["fifo.txt"].reason == "special file"
    assert b.members["pangps.log"].status == "found"


def test_empty_member(tmp_path):
    b = Bundle.open(make_zip(tmp_path / "b.zip", [("PanGPS.log", b""), ("regval.txt", b"x")]))
    assert b.members["pangps.log"].status == "empty"
    assert b.read_bytes("PanGPS.log") == b""
    assert b.read_text("PanGPS.log") == ""


def test_member_over_limit_is_truncated_at_a_line(tmp_path, monkeypatch):
    monkeypatch.setattr(bmod, "MAX_MEMBER_BYTES", 25)
    z = make_zip(tmp_path / "b.zip", [("PanGPS.log", b"line one\nline two\nline three\nline four\n")])
    b = Bundle.open(z)
    data = b.read_bytes("PanGPS.log")
    assert data == b"line one\nline two\n"
    m = b.members["pangps.log"]
    assert m.status == "truncated" and "per-file limit" in m.reason
    assert any("truncated" in w for w in b.warnings)


def test_limit_does_not_trust_declared_size(tmp_path, monkeypatch):
    # A highly compressible member: 5 MB expanded, tiny in the zip.
    monkeypatch.setattr(bmod, "MAX_MEMBER_BYTES", 2 * 1024 * 1024)
    z = make_zip(tmp_path / "b.zip", [("PanGPS.log", b"".join([b"a" * 99 + b"\n"] * 52000))])
    b = Bundle.open(z)
    data = b.read_bytes("PanGPS.log")
    assert data is not None and len(data) <= 2 * 1024 * 1024
    assert b.members["pangps.log"].status == "truncated"


def test_total_limit_truncates_member(tmp_path, monkeypatch):
    monkeypatch.setattr(bmod, "MAX_TOTAL_BYTES", 15)
    z = make_zip(tmp_path / "b.zip", [("PanGPS.log", b"0123456789\nabcdefghij\n")])
    b = Bundle.open(z)
    assert b.read_bytes("PanGPS.log") == b"0123456789\n"
    assert b.members["pangps.log"].status == "truncated"
    assert "total size limit" in b.members["pangps.log"].reason


def test_total_limit_reached_skips_next(tmp_path, monkeypatch):
    monkeypatch.setattr(bmod, "MAX_TOTAL_BYTES", 11)
    z = make_zip(tmp_path / "b.zip", [("PanGPS.log", b"0123456789\n"), ("regval.txt", b"zzz\n")])
    b = Bundle.open(z)
    assert b.read_bytes("PanGPS.log") == b"0123456789\n"
    assert b.read_bytes("regval.txt") is None
    assert b.members["regval.txt"].status == "skipped"
    assert b.members["regval.txt"].reason == "total size limit reached"


def test_too_many_members(tmp_path, monkeypatch):
    monkeypatch.setattr(bmod, "MAX_MEMBERS", 3)
    z = make_zip(tmp_path / "b.zip", [(f"f{i}.txt", b"x") for i in range(10)])
    b = Bundle.open(z)
    assert len(b.members) == 3
    assert any("too many members" in w for w in b.warnings)


def test_duplicate_base_name_first_wins(tmp_path):
    z = make_zip(tmp_path / "b.zip", [("a/PanGPS.log", b"first\n"), ("b/PanGPS.log", b"second\n")])
    b = Bundle.open(z)
    assert b.read_text("PanGPS.log") == "first\n"
    assert any("duplicate" in w for w in b.warnings)


def test_not_a_bundle(tmp_path):
    bad = tmp_path / "x.zip"
    bad.write_bytes(b"not a zip")
    with pytest.raises(BundleError):
        Bundle.open(bad)
    with pytest.raises(BundleError):
        Bundle.open(tmp_path / "missing")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(BundleError):
        Bundle.open(empty)


def test_rotation_order_numeric():
    names = ["PanGPS.log", "PanGPS.1.log", "PanGPS.10.log", "PanGPS.2.log", "PanGPS.9.log", "PanGPS.8.log"]
    assert sort_rotations(names) == [
        "PanGPS.10.log", "PanGPS.9.log", "PanGPS.8.log", "PanGPS.2.log", "PanGPS.1.log", "PanGPS.log"]


def test_rotation_old_and_families():
    assert sort_rotations(["pan_gp_event.log", "pan_gp_event.log.old"]) == [
        "pan_gp_event.log.old", "pan_gp_event.log"]
    assert sort_rotations(["LogonUI.log", "LogonUI.log.old"]) == ["LogonUI.log.old", "LogonUI.log"]
    assert sort_rotations(["PanGpHip.log", "PanGpHip.1.log"]) == ["PanGpHip.1.log", "PanGpHip.log"]


def test_bundle_rotation_only_matches_stem_and_log_files(tmp_path):
    z = make_zip(tmp_path / "b.zip", [
        ("PanGPS.log", b"3\n"), ("PanGPS.2.log", b"1\n"), ("PanGPS.1.log", b"2\n"),
        ("PanGPS.dmp", b"x"), ("PanGPA.log", b"a\n"), ("PanGPS.3.log", b""),
        ("pan_gp_event.log", b"e\n"), ("pan_gp_event.log.old", b"o\n"),
    ])
    b = Bundle.open(z)
    assert b.rotation("PanGPS") == ["PanGPS.3.log", "PanGPS.2.log", "PanGPS.1.log", "PanGPS.log"]
    assert b.rotation("pangps") == b.rotation("PanGPS")
    assert b.rotation("pan_gp_event") == ["pan_gp_event.log.old", "pan_gp_event.log"]
    assert b.rotation("nothing") == []


def test_decode_fallback_and_newlines():
    assert decode_text(b"a\r\nb\rc\n") == "a\r\nb\rc\n"          # newlines untouched
    assert decode_text("caf\u00e9".encode("utf-8")) == "caf\u00e9"
    assert decode_text(b"caf\xe9") == "caf\u00e9"               # invalid UTF-8 -> latin-1
    assert decode_text(b"\xef\xbb\xbfabc") == "abc"
    assert decode_text("hi\r\n".encode("utf-16")) == "hi\r\n"
    assert decode_text(b"") == ""
    assert decode_text(b"\xff\xfe\x00") != ""                   # truncated utf-16 never raises


def test_classify():
    assert classify("PanGPS.8.log") == "service_log"
    assert classify("PanGPA.log") == "agent_log"
    assert classify("PanGpHipMp.1.log") == "hip_mp_log"
    assert classify("PanGpHip.log") == "hip_log"
    assert classify("LogonUI.log.old") == "logonui_log"
    assert classify("whatever.xyz") == "other"


# --------------------------------------------------------------------------- tar archives
def make_tar(path, entries, mode="w:gz"):
    """entries: (name, bytes) or (name, bytes, tarfile type) or (name, None, type, linkname)."""
    with tarfile.open(path, mode) as tf:
        for entry in entries:
            info = tarfile.TarInfo(entry[0])
            kind = entry[2] if len(entry) > 2 else tarfile.REGTYPE
            info.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = entry[3]
                tf.addfile(info)
            elif kind in (tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.DIRTYPE):
                tf.addfile(info)
            else:
                info.size = len(entry[1])
                tf.addfile(info, io.BytesIO(entry[1]))
    return path


@pytest.mark.parametrize("suffix,mode", [(".tgz", "w:gz"), (".tar.gz", "w:gz"), (".tar", "w"),
                                          (".tar.bz2", "w:bz2"), (".tar.xz", "w:xz")])
def test_tar_formats(tmp_path, suffix, mode):
    t = make_tar(tmp_path / f"b{suffix}", [("PanGPS.log", b"abc\r\n"), ("PanGPA.log", b"x\n")], mode)
    b = Bundle.open(t)
    try:
        assert b.kind == "tar"
        assert b.read_text("PanGPS.log") == "abc\r\n"
        assert b.members["pangpa.log"].family == "agent_log"
    finally:
        b.close()


def test_tar_detected_by_content_not_extension(tmp_path):
    t = make_tar(tmp_path / "logs.zip", [("PanGPS.log", b"abc\n")])
    b = Bundle.open(t)
    assert b.kind == "tar" and b.read_bytes("PanGPS.log") == b"abc\n"
    z = make_zip(tmp_path / "logs.tgz", [("PanGPS.log", b"zip\n")])
    assert Bundle.open(z).kind == "zip"


def test_tar_nested_folder_and_dir_members(tmp_path):
    t = make_tar(tmp_path / "b.tgz", [
        ("./", None, tarfile.DIRTYPE), ("collect/logs/", None, tarfile.DIRTYPE),
        ("collect/logs/PanGPS.log", b"svc\n"), ("collect/logs/PanGPS.1.log", b"old\n")])
    b = Bundle.open(t)
    assert b.rotation("PanGPS") == ["PanGPS.1.log", "PanGPS.log"]
    assert b.read_text("PanGPS.1.log") == "old\n"


def test_tar_unsafe_links_and_special_members(tmp_path):
    t = make_tar(tmp_path / "b.tar", [
        ("../evil.txt", b"x"), ("/etc/passwd", b"x"), ("a/../../b.txt", b"x"),
        ("lnk.txt", None, tarfile.SYMTYPE, "/etc/passwd"),
        ("hard.txt", None, tarfile.LNKTYPE, "PanGPS.log"),
        ("fifo.txt", None, tarfile.FIFOTYPE), ("dev.txt", None, tarfile.CHRTYPE),
        ("PanGPS.log", b"ok\n")], "w")
    b = Bundle.open(t)
    for name in ("evil.txt", "passwd", "b.txt"):
        assert b.members[name].reason == "unsafe path" and b.read_bytes(name) is None
    assert b.members["lnk.txt"].reason == "link" and b.members["hard.txt"].reason == "link"
    assert b.members["fifo.txt"].reason == "special file"
    assert b.members["dev.txt"].reason == "special file"
    assert b.read_bytes("lnk.txt") is None
    assert b.read_text("PanGPS.log") == "ok\n"


def test_tar_member_over_limit_and_total_limit(tmp_path, monkeypatch):
    t = make_tar(tmp_path / "b.tgz", [("PanGPS.log", b"".join([b"a" * 99 + b"\n"] * 40)),
                                      ("regval.txt", b"zzz\n")])
    monkeypatch.setattr(bmod, "MAX_MEMBER_BYTES", 1000)
    b = Bundle.open(t)
    data = b.read_bytes("PanGPS.log")
    assert data is not None and len(data) <= 1000 and data.endswith(b"\n")
    assert b.members["pangps.log"].status == "truncated"
    monkeypatch.setattr(bmod, "MAX_MEMBER_BYTES", 10_000)
    monkeypatch.setattr(bmod, "MAX_TOTAL_BYTES", 4000)
    b = Bundle.open(t)
    b.read_bytes("PanGPS.log")
    assert b.read_bytes("regval.txt") is None
    assert b.members["regval.txt"].reason == "total size limit reached"


def test_tar_member_count_and_declared_size_limits(tmp_path, monkeypatch):
    t = make_tar(tmp_path / "b.tar", [(f"f{i}.txt", b"x" * 10) for i in range(10)], "w")
    monkeypatch.setattr(bmod, "MAX_MEMBERS", 4)
    b = Bundle.open(t)
    assert len(b.members) == 4 and any("too many members" in w for w in b.warnings)
    monkeypatch.setattr(bmod, "MAX_MEMBERS", 100)
    monkeypatch.setattr(bmod, "MAX_TOTAL_BYTES", 35)
    b = Bundle.open(t)
    assert len(b.members) < 10 and any("declared sizes" in w for w in b.warnings)


def test_tar_truncated_archive_keeps_what_was_indexed(tmp_path):
    t = make_tar(tmp_path / "b.tar", [("PanGPS.log", b"a" * 2000), ("PanGPA.log", b"b" * 2000)], "w")
    data = t.read_bytes()
    t.write_bytes(data[:1024 + 2048 + 512 + 100])       # cut inside the second member
    b = Bundle.open(t)
    assert "pangps.log" in b.members
    with pytest.raises(BundleError):
        Bundle.open(tmp_path / "missing.tgz")


def test_duplicate_choice_is_deterministic(tmp_path):
    entries = [("deep/er/PanGPS.log", b"deep\n"), ("b/PanGPS.log", b"b\n"), ("a/PanGPS.log", b"a\n")]
    for order in (entries, entries[::-1]):
        b = Bundle.open(make_tar(tmp_path / "d.tar", order, "w"))
        assert b.read_text("PanGPS.log") in ("a\n",)
        assert len(b.duplicates) == 2 and all("kept" in d for d in b.duplicates)
    b = Bundle.open(make_zip(tmp_path / "e.zip", [("x/PanGPS.log", b"nested\n"), ("PanGPS.log", b"top\n")]))
    assert b.read_text("PanGPS.log") == "top\n"           # shallowest wins
    b = Bundle.open(make_zip(tmp_path / "f.zip", [("../PanGPS.log", b"evil\n"), ("z/q/PanGPS.log", b"ok\n")]))
    assert b.read_text("PanGPS.log") == "ok\n"            # a safe member beats an unsafe one


def test_agent_log_rotation_and_beyond_nine(tmp_path):
    names = ["PanGPA.log", "PanGPA.1.log", "PanGPS.log", "PanGPS.10.log", "PanGPS.9.log", "PanGPMsi.log"]
    t = make_tar(tmp_path / "b.tgz", [(n, b"x\n") for n in names])
    b = Bundle.open(t)
    assert b.rotation("PanGPA") == ["PanGPA.1.log", "PanGPA.log"]
    assert b.rotation("PanGPS") == ["PanGPS.10.log", "PanGPS.9.log", "PanGPS.log"]
    assert b.members["pangpmsi.log"].family == "msi_log"


def test_decode_damaged_utf16_bom_and_bomless():
    text = "=== Logging started: 20/07/2026  12:55:38 ===\r\n"
    raw = text.encode("utf-16-le")
    assert decode_text(b"\xef\xbf\xbd\xef\xbf\xbd" + raw) == text      # mangled BOM
    assert decode_text(raw) == text                                   # no BOM at all
    assert decode_text(b"\xff\xfe" + raw) == text

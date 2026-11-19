import gzip

import pytest

from panos_toolbox.runtime.store import CaptureReader, CaptureWriter, read_samples


def test_roundtrip_gzip_and_plain(tmp_path):
    for compress in (True, False):
        root = tmp_path / f"c{int(compress)}"
        w = CaptureWriter(root, compress=compress)
        assert w.add("pow", "2026-01-01T00:00:00.000Z", 0.25, True, "line1\nline2\n", cycle=1) == 1
        assert w.add("pow", "2026-01-01T00:00:30.000Z", 0.3, False, "x", note="two words") == 2
        w.write_manifest({"cycles": 2})
        w.close()
        r = CaptureReader(root)
        assert r.slugs() == ["pow"]
        s = r.samples("pow")
        assert [x.n for x in s] == [1, 2]
        assert s[0].text == "line1\nline2\n" and s[0].ok and s[0].attrs == {"cycle": "1"}
        assert not s[1].ok and s[1].attrs == {"note": "two_words"}
        assert r.manifest == {"cycles": 2}
        assert r.samples("missing") == []


def test_marker_lines_in_output_are_escaped(tmp_path):
    w = CaptureWriter(tmp_path / "c")
    w.add("x", "t", 0.1, True, "a\n#### END\n#### SAMPLE n=9\nb")
    w.close()
    s = CaptureReader(tmp_path / "c").samples("x")
    assert len(s) == 1 and s[0].text == "a\n#### END\n#### SAMPLE n=9\nb\n"


def test_truncated_gzip_keeps_complete_samples(tmp_path):
    w = CaptureWriter(tmp_path / "c")
    w.add("x", "t1", 0.1, True, "first")
    w.add("x", "t2", 0.1, True, "second")
    w.close()
    path = tmp_path / "c" / "raw" / "x.txt.gz"
    data = path.read_bytes()
    path.write_bytes(data[:-12])  # cut the stream, as after a kill
    s = read_samples(path)
    assert [x.text for x in s][:1] == ["first\n"]


def test_flush_makes_partial_capture_readable(tmp_path):
    w = CaptureWriter(tmp_path / "c")
    w.add("x", "t1", 0.1, True, "first")
    # not closed: the file must already be readable thanks to the sync flush
    assert [x.text for x in read_samples(tmp_path / "c" / "raw" / "x.txt.gz")] == ["first\n"]
    w.close()


def test_unfinished_last_sample_dropped(tmp_path):
    p = tmp_path / "raw"
    p.mkdir()
    (p / "x.txt").write_text("#### SAMPLE n=1 t=a dur=0 ok=1\nok\n#### END\n"
                             "#### SAMPLE n=2 t=b dur=0 ok=1\npartial\n")
    assert [x.n for x in read_samples(p / "x.txt")] == [1]


def test_reader_requires_raw_folder(tmp_path):
    with pytest.raises(ValueError):
        CaptureReader(tmp_path)


def test_gzip_files_are_real_gzip(tmp_path):
    w = CaptureWriter(tmp_path / "c")
    w.add("x", "t", 0.1, True, "hello")
    w.close()
    with gzip.open(tmp_path / "c" / "raw" / "x.txt.gz", "rt") as fh:
        assert "#### SAMPLE n=1" in fh.read()

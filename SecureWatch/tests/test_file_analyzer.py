import hashlib
import threading

from core.file_analyzer import analyze_file, iter_directory, scan_directory


def test_file_analysis_hash_and_local_indicator(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"SecureWatch test fixture")
    expected = hashlib.sha256(target.read_bytes()).hexdigest()
    result = analyze_file(target, [expected.upper()])
    assert result.sha256 == expected
    assert result.extension == ".bin"
    assert result.result == "Known indicator match"


def test_nonmatching_hash_is_not_labeled_safe(tmp_path):
    target = tmp_path / "sample.txt"
    target.write_text("local only", encoding="utf-8")
    result = analyze_file(target)
    assert result.result == "No local indicator match"
    assert "safe" not in result.result.lower()


def test_directory_scan_reports_files_and_cancel(tmp_path):
    (tmp_path / "first.txt").write_text("one", encoding="utf-8")
    (tmp_path / "second.txt").write_text("two", encoding="utf-8")
    progress = []
    rows = scan_directory(tmp_path, progress=lambda count, path: progress.append((count, path)))
    assert len(rows) == 2
    assert [count for count, _ in progress] == [1, 2]


def test_directory_rejects_non_directory(tmp_path):
    target = tmp_path / "file"
    target.write_text("x", encoding="utf-8")
    try:
        scan_directory(target)
    except ValueError as exc:
        assert "directory" in str(exc)
    else:
        raise AssertionError("Expected a non-directory path to be rejected.")


def test_directory_iterator_yields_incrementally_and_honors_cancel(tmp_path):
    (tmp_path / "first.txt").write_text("one", encoding="utf-8")
    (tmp_path / "second.txt").write_text("two", encoding="utf-8")
    cancel = threading.Event()

    def progress(_count, _path):
        cancel.set()

    rows = list(iter_directory(tmp_path, cancel=cancel, progress=progress))
    assert len(rows) == 1
    assert rows[0].sha256 in {
        hashlib.sha256(b"one").hexdigest(),
        hashlib.sha256(b"two").hexdigest(),
    }

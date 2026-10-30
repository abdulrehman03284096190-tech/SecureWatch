"""Local file metadata and SHA-256 analysis; files are never executed or uploaded."""
from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Iterator


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    if path.is_symlink() or (callable(is_junction) and is_junction()):
        return True
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & 0x400)


@dataclass(frozen=True)
class FileAnalysis:
    path: str
    size: int | None
    extension: str
    modified_at: str | None
    sha256: str | None
    result: str
    error: str = ""


def analyze_file(path: str | Path, indicators: Iterable[str] = ()) -> FileAnalysis:
    target = Path(path)
    if _is_link_or_junction(target):
        return FileAnalysis(str(target), None, target.suffix.lower(), None, None,
                            "Analysis incomplete", "Links and directory junctions are not followed.")
    try:
        before = target.stat()
        if not target.is_file():
            return FileAnalysis(str(target), None, target.suffix.lower(), None, None,
                                "Analysis incomplete", "Path is not a regular file.")
        digest = hashlib.sha256()
        with target.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        after = target.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            return FileAnalysis(str(target), after.st_size, target.suffix.lower(),
                                datetime.fromtimestamp(after.st_mtime).astimezone().isoformat(),
                                None, "Analysis incomplete", "File changed while being read.")
        hexdigest = digest.hexdigest()
        known = {value.strip().lower() for value in indicators}
        result = "Known indicator match" if hexdigest in known else "No local indicator match"
        return FileAnalysis(
            str(target), after.st_size, target.suffix.lower(),
            datetime.fromtimestamp(after.st_mtime).astimezone().isoformat(),
            hexdigest, result,
        )
    except (OSError, PermissionError) as exc:
        return FileAnalysis(str(target), None, target.suffix.lower(), None, None,
                            "File inaccessible", str(exc))


def scan_directory(
    directory: str | Path,
    indicators: Iterable[str] = (),
    cancel: threading.Event | None = None,
    progress: Callable[[int, str], None] | None = None,
) -> list[FileAnalysis]:
    return list(iter_directory(
        directory, indicators=indicators, cancel=cancel, progress=progress
    ))


def iter_directory(
    directory: str | Path,
    indicators: Iterable[str] = (),
    cancel: threading.Event | None = None,
    progress: Callable[[int, str], None] | None = None,
) -> Iterator[FileAnalysis]:
    root = Path(directory)
    if _is_link_or_junction(root):
        raise ValueError("Selected directory is a link or junction; links are not followed.")
    if not root.is_dir():
        raise ValueError("Selected path is not a directory.")
    known_hashes = tuple(indicators)
    visited = 0

    def record_walk_error(error: OSError) -> None:
        nonlocal visited
        visited += 1
        path = str(getattr(error, "filename", None) or root)
        result = FileAnalysis(
            path, None, Path(path).suffix.lower(), None, None,
            "File inaccessible", str(error),
        )
        pending_errors.append(result)
        if progress is not None:
            progress(visited, path)

    pending_errors: list[FileAnalysis] = []
    for current, directories, filenames in os.walk(
        root, topdown=True, onerror=record_walk_error, followlinks=False
    ):
        while pending_errors:
            yield pending_errors.pop(0)
        directories[:] = [
            name for name in directories
            if not _is_link_or_junction(Path(current) / name)
        ]
        for filename in filenames:
            if cancel is not None and cancel.is_set():
                return
            file_path = Path(current) / filename
            result = analyze_file(file_path, known_hashes)
            visited += 1
            if progress is not None:
                progress(visited, str(file_path))
            yield result
    while pending_errors:
        yield pending_errors.pop(0)

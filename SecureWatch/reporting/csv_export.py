"""CSV output helpers for user-selected local exports."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Mapping, Sequence


def _spreadsheet_safe(value: object) -> object:
    if not isinstance(value, str):
        return value
    trimmed = value.lstrip(" \t\r\n")
    if trimmed.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def export_csv(
    path: str | Path,
    headers: Sequence[str],
    rows: Iterable[Sequence[object] | Mapping[str, object]],
) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream)
        writer.writerow([_spreadsheet_safe(header) for header in headers])
        for row in rows:
            if isinstance(row, Mapping):
                writer.writerow([
                    _spreadsheet_safe(row.get(header, "")) for header in headers
                ])
            else:
                writer.writerow([_spreadsheet_safe(value) for value in row])

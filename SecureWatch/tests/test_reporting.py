import csv
import sqlite3

import pytest

from database.db_manager import DatabaseManager
from reporting.csv_export import export_csv
from reporting.pdf_report import generate_pdf_report


def test_csv_export_writes_headers_and_rows(tmp_path):
    path = tmp_path / "export.csv"
    export_csv(
        path, ["name", "status", "evidence"],
        [{"name": "process", "status": "running", "evidence": " =HYPERLINK(\"x\")"}],
    )
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.reader(stream))
    assert rows == [
        ["name", "status", "evidence"],
        ["process", "running", "' =HYPERLINK(\"x\")"],
    ]


def test_pdf_report_contains_persisted_sections(tmp_path):
    pytest.importorskip("reportlab")
    database = DatabaseManager(tmp_path / "securewatch.db")
    alert_id = database.create_alert(
        "Low", "Observed event", "<test> café 🔐 evidence", "Unit test", "TEST-RULE"
    )
    database.add_investigation_note(alert_id, "Reviewed & documented. 🔎")
    database.add_windows_events(
        "System",
        [{"Time": "2026-01-01T00:00:00+00:00", "Id": 1,
          "LevelDisplayName": "Information", "ProviderName": "Test",
          "Message": "Synthetic test event"}],
    )
    database.add_monitoring_run(
        '{"computer":"test-host","os":"test OS","cpu_percent":1,'
        '"memory_percent":2,"disk_percent":3,"process_count":4}'
    )
    output = generate_pdf_report(
        tmp_path / "report.pdf", database, computer="test-host",
        operating_system="test OS",
    )
    assert output.is_file()
    assert output.read_bytes().startswith(b"%PDF")
    assert output.stat().st_size > 1000


def test_pdf_report_handles_empty_database_without_inventing_findings(tmp_path):
    pytest.importorskip("reportlab")
    database = DatabaseManager(tmp_path / "empty.db")

    output = generate_pdf_report(tmp_path / "empty-report.pdf", database)

    assert output.read_bytes().startswith(b"%PDF")
    assert output.stat().st_size > 1000


def test_pdf_report_surfaces_database_errors(tmp_path):
    pytest.importorskip("reportlab")
    database = DatabaseManager(tmp_path / "broken.db")

    def fail_query(*_args, **_kwargs):
        raise sqlite3.OperationalError("database unavailable")

    database.alerts = fail_query

    with pytest.raises(sqlite3.OperationalError, match="database unavailable"):
        generate_pdf_report(tmp_path / "failed-report.pdf", database)

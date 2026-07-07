"""These tests protect the command-line glue.

They teach that the CLI should load input, call the analyzer, and print or
write a report while handling basic user-facing errors.
"""

import json
import sys
import types
from pathlib import Path

from security_log_analyzer.cli import main


def test_main_prints_report_for_valid_input(tmp_path, capsys):
    input_file = tmp_path / "signin_logs.json"
    input_file.write_text(
        json.dumps(
            [
                {
                    "createdDateTime": "2026-04-15T10:00:00Z",
                    "userPrincipalName": "alice@example.com",
                    "ipAddress": "203.0.113.10",
                    "status": {"errorCode": 0, "failureReason": None},
                    "isInteractive": True,
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main([str(input_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Security Log Analysis Report" in captured.out
    assert "Total sign-in events: 1" in captured.out
    assert "Failed sign-ins: 0" in captured.out
    assert "No suspicious findings were detected." in captured.out
    assert captured.err == ""


def test_main_returns_error_for_missing_file(capsys):
    missing_file = Path("/tmp/does-not-exist-signin-log.json")

    exit_code = main([str(missing_file)])

    captured = capsys.readouterr()
    assert exit_code != 0
    assert "Error:" in captured.err
    assert "does-not-exist-signin-log.json" in captured.err
    assert captured.out == ""


def test_main_writes_html_report_when_requested(tmp_path, capsys, monkeypatch):
    input_file = tmp_path / "signin_logs.json"
    html_dir = tmp_path / "reports" / "daily"
    html_file = html_dir / "report.html"
    input_file.write_text(
        json.dumps(
            [
                {
                    "createdDateTime": "2026-04-15T10:00:00Z",
                    "userPrincipalName": "alice@example.com",
                    "ipAddress": "203.0.113.10",
                    "status": {"errorCode": 0, "failureReason": None},
                    "isInteractive": True,
                }
            ]
        ),
        encoding="utf-8",
    )

    fake_html_module = types.ModuleType("security_log_analyzer.html_report")
    fake_html_module.build_html_report = lambda result: "<html><body>HTML report</body></html>"
    monkeypatch.setitem(sys.modules, "security_log_analyzer.html_report", fake_html_module)

    exit_code = main([str(input_file), "--html-out", str(html_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Security Log Analysis Report" in captured.out
    assert "Total sign-in events: 1" in captured.out
    assert html_file.exists()
    assert html_file.read_text(encoding="utf-8") == "<html><body>HTML report</body></html>"
    assert captured.err == ""

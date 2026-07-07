"""These tests protect the plain text summary.

They show how analysis results are turned into a stable, readable report that a
learner can scan quickly without digging into the implementation.
"""

from datetime import datetime
from zoneinfo import ZoneInfo

from security_log_analyzer.models import AnalysisResult, RepeatedFailureFinding, SignInEvent
from security_log_analyzer.report import build_report


def make_event(timestamp: datetime, username: str, ip_address: str) -> SignInEvent:
    return SignInEvent(
        timestamp=timestamp,
        username=username,
        ip_address=ip_address,
        success=True,
        interactive=True,
        error_code=0,
        failure_reason=None,
    )


def test_build_report_starts_with_summary_counts():
    result = AnalysisResult(
        total_events=4,
        failed_login_count=2,
        repeated_failure_findings=[
            RepeatedFailureFinding(
                username="alice@example.com",
                failure_count=3,
                window_start=datetime(2026, 4, 15, 8, 0, tzinfo=ZoneInfo("Europe/Oslo")),
                window_end=datetime(2026, 4, 15, 8, 15, tzinfo=ZoneInfo("Europe/Oslo")),
            )
        ],
        off_hours_events=[
            make_event(
                datetime(2026, 4, 15, 7, 45, tzinfo=ZoneInfo("Europe/Oslo")),
                "bob@example.com",
                "203.0.113.7",
            )
        ],
    )

    report = build_report(result)

    lines = report.splitlines()
    assert lines[:5] == [
        "Security Log Analysis Report",
        "Total sign-in events: 4",
        "Failed sign-ins: 2",
        "Repeated-failure findings: 1",
        "Off-hours sign-ins: 1",
    ]


def test_build_report_renders_repeated_failure_section():
    result = AnalysisResult(
        total_events=3,
        failed_login_count=3,
        repeated_failure_findings=[
            RepeatedFailureFinding(
                username="alice@example.com",
                failure_count=3,
                window_start=datetime(2026, 4, 15, 8, 0, tzinfo=ZoneInfo("Europe/Oslo")),
                window_end=datetime(2026, 4, 15, 8, 15, tzinfo=ZoneInfo("Europe/Oslo")),
            )
        ],
        off_hours_events=[],
    )

    report = build_report(result)

    assert (
        "Repeated failed logins\n"
        "- alice@example.com: 3 failed logins from 2026-04-15 08:00 +02:00 to 2026-04-15 08:15 +02:00"
        in report
    )


def test_build_report_renders_off_hours_summary_and_sample():
    result = AnalysisResult(
        total_events=8,
        failed_login_count=0,
        repeated_failure_findings=[],
        off_hours_events=[
            make_event(datetime(2026, 4, 15, 7, 0, tzinfo=ZoneInfo("Europe/Oslo")), "alice@example.com", "203.0.113.1"),
            make_event(datetime(2026, 4, 15, 7, 5, tzinfo=ZoneInfo("Europe/Oslo")), "bob@example.com", "203.0.113.2"),
            make_event(datetime(2026, 4, 15, 7, 10, tzinfo=ZoneInfo("Europe/Oslo")), "carol@example.com", "203.0.113.3"),
            make_event(datetime(2026, 4, 15, 7, 15, tzinfo=ZoneInfo("Europe/Oslo")), "alice@example.com", "203.0.113.4"),
            make_event(datetime(2026, 4, 15, 7, 20, tzinfo=ZoneInfo("Europe/Oslo")), "dave@example.com", "203.0.113.5"),
            make_event(datetime(2026, 4, 15, 7, 25, tzinfo=ZoneInfo("Europe/Oslo")), "alice@example.com", "203.0.113.6"),
            make_event(datetime(2026, 4, 15, 7, 30, tzinfo=ZoneInfo("Europe/Oslo")), "bob@example.com", "203.0.113.7"),
            make_event(datetime(2026, 4, 15, 7, 35, tzinfo=ZoneInfo("Europe/Oslo")), "erin@example.com", "203.0.113.8"),
        ],
    )

    report = build_report(result)

    assert (
        "Off-hours logins\n"
        "Total off-hours sign-ins: 8\n"
        "Top off-hours users\n"
        "- alice@example.com: 3\n"
        "- bob@example.com: 2\n"
        "- carol@example.com: 1\n"
        "- 2 more users omitted from summary\n"
        "Sample off-hours events\n"
        "- 2026-04-15 07:00 +02:00 | alice@example.com | 203.0.113.1\n"
        "- 2026-04-15 07:05 +02:00 | bob@example.com | 203.0.113.2\n"
        "- 2026-04-15 07:10 +02:00 | carol@example.com | 203.0.113.3\n"
        "- 2026-04-15 07:15 +02:00 | alice@example.com | 203.0.113.4\n"
        "- 2026-04-15 07:20 +02:00 | dave@example.com | 203.0.113.5\n"
        "- 3 more off-hours events omitted"
    ) in report


def test_build_report_shows_no_findings_message_when_empty():
    result = AnalysisResult(
        total_events=0,
        failed_login_count=0,
        repeated_failure_findings=[],
        off_hours_events=[],
    )

    report = build_report(result)

    assert report == (
        "Security Log Analysis Report\n"
        "Total sign-in events: 0\n"
        "Failed sign-ins: 0\n"
        "Repeated-failure findings: 0\n"
        "Off-hours sign-ins: 0\n"
        "\n"
        "Repeated failed logins\n"
        "- None\n"
        "\n"
        "Off-hours logins\n"
        "- None\n"
        "\n"
        "No suspicious findings were detected."
    )

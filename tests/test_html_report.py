"""These tests protect the HTML presentation layer.

They check that the standalone report stays readable, includes the key security
signals, and renders the same analysis data in a more visual format.
"""

from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from security_log_analyzer.html_report import build_html_report
from security_log_analyzer.models import (
    ActivityTimelinePoint,
    AnalysisResult,
    RecentWindowSummary,
    RepeatedFailureFinding,
    SignInEvent,
)


OSLO = ZoneInfo("Europe/Oslo")


def make_event(
    timestamp: datetime,
    username: str,
    ip_address: str,
    *,
    interactive: bool = True,
    success: bool = True,
) -> SignInEvent:
    return SignInEvent(
        timestamp=timestamp,
        username=username,
        ip_address=ip_address,
        success=success,
        interactive=interactive,
        error_code=0 if success else 50053,
        failure_reason=None if success else "Invalid username or password",
    )


def make_finding(username: str, failure_count: int, start: datetime, minutes: int = 15) -> RepeatedFailureFinding:
    return RepeatedFailureFinding(
        username=username,
        failure_count=failure_count,
        window_start=start,
        window_end=start + timedelta(minutes=minutes),
    )


def make_timeline_point(
    day: date,
    total_events: int,
    failed_login_count: int,
    off_hours_count: int,
    unique_user_count: int,
) -> ActivityTimelinePoint:
    return ActivityTimelinePoint(
        day=day,
        total_events=total_events,
        failed_login_count=failed_login_count,
        off_hours_count=off_hours_count,
        unique_user_count=unique_user_count,
    )


def make_recent_window(
    label: str,
    event_count: int,
    failed_login_count: int,
    off_hours_count: int,
    unique_user_count: int,
    repeated_failure_count: int,
) -> RecentWindowSummary:
    return RecentWindowSummary(
        label=label,
        event_count=event_count,
        failed_login_count=failed_login_count,
        off_hours_count=off_hours_count,
        unique_user_count=unique_user_count,
        repeated_failure_count=repeated_failure_count,
    )


def test_build_html_report_highlights_verdict_coverage_timeline_and_recent_windows():
    result = AnalysisResult(
        total_events=100,
        failed_login_count=35,
        repeated_failure_findings=[
            make_finding("zoe@example.com", 6, datetime(2026, 4, 7, 8, 0, tzinfo=OSLO)),
            make_finding("amy@example.com", 5, datetime(2026, 4, 7, 9, 0, tzinfo=OSLO)),
            make_finding("brad@example.com", 4, datetime(2026, 4, 7, 10, 0, tzinfo=OSLO)),
        ],
        off_hours_events=[
            make_event(datetime(2026, 4, 14, 14, 57, tzinfo=OSLO), "alice@example.com", "203.0.113.1"),
            make_event(datetime(2026, 4, 14, 14, 40, tzinfo=OSLO), "bob@example.com", "203.0.113.2", interactive=False),
        ],
        interactive_event_count=62,
        non_interactive_event_count=38,
        unique_user_count=11,
        earliest_event_time=datetime(2026, 4, 7, 8, 15, tzinfo=OSLO),
        latest_event_time=datetime(2026, 4, 14, 14, 57, tzinfo=OSLO),
        activity_timeline=[
            make_timeline_point(date(2026, 4, 7), 12, 3, 1, 4),
            make_timeline_point(date(2026, 4, 8), 18, 6, 2, 5),
            make_timeline_point(date(2026, 4, 9), 9, 1, 0, 3),
        ],
        recent_window_summaries=[
            make_recent_window("Last 24h", 14, 4, 2, 5, 2),
            make_recent_window("Last 7d", 55, 16, 6, 10, 4),
            make_recent_window("Last 30d", 100, 35, 8, 11, 8),
        ],
    )

    html = build_html_report(result)

    assert "Executive verdict" in html
    assert "Attention needed" in html
    assert "Coverage window" in html
    assert "2026-04-07 08:15 +02:00" in html
    assert "2026-04-14 14:57 +02:00" in html
    assert "11 unique users" in html
    assert "62% interactive" in html
    assert "38% non-interactive" in html
    assert "35% of events" in html
    assert "Activity timeline" in html
    assert "Daily failed sign-ins across the coverage window" in html
    assert "Last 24h" in html
    assert "Last 7d" in html
    assert "Last 30d" in html
    assert "Fresh suspicious activity" in html
    assert "Top repeated-failure findings" in html
    assert "Top off-hours drivers" in html
    assert "Recent off-hours events" in html


def test_build_html_report_renders_timeline_and_recency_context():
    result = AnalysisResult(
        total_events=20,
        failed_login_count=10,
        repeated_failure_findings=[
            make_finding("zoe@example.com", 6, datetime(2026, 4, 7, 8, 0, tzinfo=OSLO), minutes=30),
            make_finding("mike@example.com", 6, datetime(2026, 4, 7, 9, 0, tzinfo=OSLO), minutes=45),
            make_finding("amy@example.com", 4, datetime(2026, 4, 7, 10, 0, tzinfo=OSLO), minutes=15),
            make_finding("nina@example.com", 3, datetime(2026, 4, 7, 11, 0, tzinfo=OSLO), minutes=15),
        ],
        off_hours_events=[
            make_event(datetime(2026, 4, 14, 8, 0, tzinfo=OSLO), "user-1@example.com", "203.0.113.1"),
            make_event(datetime(2026, 4, 14, 9, 0, tzinfo=OSLO), "user-2@example.com", "203.0.113.2"),
            make_event(datetime(2026, 4, 14, 10, 0, tzinfo=OSLO), "user-3@example.com", "203.0.113.3"),
            make_event(datetime(2026, 4, 14, 11, 0, tzinfo=OSLO), "user-4@example.com", "203.0.113.4"),
            make_event(datetime(2026, 4, 14, 12, 0, tzinfo=OSLO), "user-5@example.com", "203.0.113.5"),
            make_event(datetime(2026, 4, 14, 13, 0, tzinfo=OSLO), "user-6@example.com", "203.0.113.6"),
        ],
        interactive_event_count=12,
        non_interactive_event_count=8,
        unique_user_count=6,
        earliest_event_time=datetime(2026, 4, 14, 8, 0, tzinfo=OSLO),
        latest_event_time=datetime(2026, 4, 14, 13, 0, tzinfo=OSLO),
        activity_timeline=[
            make_timeline_point(date(2026, 4, 12), 8, 1, 0, 4),
            make_timeline_point(date(2026, 4, 13), 11, 2, 1, 5),
            make_timeline_point(date(2026, 4, 14), 21, 7, 4, 6),
        ],
        recent_window_summaries=[
            make_recent_window("Last 24h", 6, 1, 0, 4, 0),
            make_recent_window("Last 7d", 18, 4, 2, 6, 1),
            make_recent_window("Last 30d", 60, 18, 6, 8, 4),
        ],
    )

    html = build_html_report(result)

    assert "Top 3 of 4" in html
    assert "Full repeated-failure list" in html
    assert html.index("mike@example.com") < html.index("zoe@example.com")
    assert "Last seen 2026-04-07 09:45 +02:00" in html
    assert html.index("Apr 12") < html.index("Apr 13") < html.index("Apr 14")
    assert "off-hours" in html
    assert "Fresh suspicious activity" in html
    assert "1 older off-hours event hidden" in html


def test_build_html_report_escapes_user_provided_values():
    result = AnalysisResult(
        total_events=1,
        failed_login_count=1,
        repeated_failure_findings=[
            make_finding('alice@example.com"><script>alert(1)</script>', 3, datetime(2026, 4, 15, 8, 0, tzinfo=OSLO))
        ],
        off_hours_events=[
            make_event(
                datetime(2026, 4, 15, 7, 30, tzinfo=OSLO),
                '<img src=x onerror="alert(1)">',
                '203.0.113.7 & "quoted"',
            )
        ],
        interactive_event_count=1,
        non_interactive_event_count=0,
        unique_user_count=1,
        earliest_event_time=datetime(2026, 4, 15, 7, 30, tzinfo=OSLO),
        latest_event_time=datetime(2026, 4, 15, 7, 30, tzinfo=OSLO),
        activity_timeline=[
            make_timeline_point(date(2026, 4, 15), 1, 1, 1, 1),
        ],
        recent_window_summaries=[
            make_recent_window("Last 24h", 1, 1, 1, 1, 1),
            make_recent_window("Last 7d", 1, 1, 1, 1, 1),
            make_recent_window("Last 30d", 1, 1, 1, 1, 1),
        ],
    )

    html = build_html_report(result)

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html
    assert "203.0.113.7 &amp; &quot;quoted&quot;" in html
    assert "<script>alert(1)</script>" not in html
    assert '<img src=x onerror="alert(1)">' not in html


def test_build_html_report_shows_low_concern_state_when_no_findings():
    result = AnalysisResult(
        total_events=0,
        failed_login_count=0,
        repeated_failure_findings=[],
        off_hours_events=[],
        interactive_event_count=0,
        non_interactive_event_count=0,
        unique_user_count=0,
        earliest_event_time=None,
        latest_event_time=None,
        activity_timeline=[],
        recent_window_summaries=[],
    )

    html = build_html_report(result)

    assert "Low concern" in html
    assert "No suspicious findings were detected." in html
    assert "Coverage window" in html

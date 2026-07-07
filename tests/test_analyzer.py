"""These tests protect the pure finding rules.

They teach that the analyzer should work only on normalized events and should
identify failures, repeated attempts, recency, and time-based patterns.
"""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from security_log_analyzer.analyzer import analyze_signin_events
from security_log_analyzer.models import (
    ActivityTimelinePoint,
    AnalysisConfig,
    RecentWindowSummary,
    SignInEvent,
)


def make_event(
    timestamp: datetime,
    username: str,
    *,
    success: bool,
    interactive: bool = True,
    error_code: int = 0,
    failure_reason: str | None = None,
    ip_address: str = "192.0.2.10",
) -> SignInEvent:
    return SignInEvent(
        timestamp=timestamp,
        username=username,
        ip_address=ip_address,
        success=success,
        interactive=interactive,
        error_code=error_code,
        failure_reason=failure_reason,
    )


def test_analyze_signin_events_counts_failed_logins():
    oslo = ZoneInfo("Europe/Oslo")
    events = [
        make_event(
            datetime(2026, 4, 13, 8, 0, tzinfo=oslo),
            "alice@example.com",
            success=True,
        ),
        make_event(
            datetime(2026, 4, 13, 8, 5, tzinfo=oslo),
            "alice@example.com",
            success=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 13, 8, 10, tzinfo=oslo),
            "bob@example.com",
            success=False,
            error_code=50074,
            failure_reason="User needs to reauthenticate.",
        ),
    ]

    result = analyze_signin_events(events)

    assert result.total_events == 3
    assert result.failed_login_count == 2
    assert result.repeated_failure_findings == []
    assert result.off_hours_events == []
    assert result.interactive_event_count == 3
    assert result.non_interactive_event_count == 0
    assert result.unique_user_count == 2
    assert result.earliest_event_time == datetime(2026, 4, 13, 8, 0, tzinfo=oslo)
    assert result.latest_event_time == datetime(2026, 4, 13, 8, 10, tzinfo=oslo)


def test_analyze_signin_events_detects_repeated_failed_logins_within_window():
    oslo = ZoneInfo("Europe/Oslo")
    events = [
        make_event(
            datetime(2026, 4, 13, 9, 0, tzinfo=oslo),
            "carol@example.com",
            success=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 13, 9, 6, tzinfo=oslo),
            "carol@example.com",
            success=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 13, 9, 14, tzinfo=oslo),
            "carol@example.com",
            success=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 13, 9, 20, tzinfo=oslo),
            "carol@example.com",
            success=True,
        ),
    ]
    config = AnalysisConfig(
        repeated_failure_threshold=3,
        repeated_failure_window=timedelta(minutes=15),
    )

    result = analyze_signin_events(events, config)

    assert result.failed_login_count == 3
    assert len(result.repeated_failure_findings) == 1
    finding = result.repeated_failure_findings[0]
    assert finding.username == "carol@example.com"
    assert finding.failure_count == 3
    assert finding.window_start == datetime(2026, 4, 13, 9, 0, tzinfo=oslo)
    assert finding.window_end == datetime(2026, 4, 13, 9, 14, tzinfo=oslo)


def test_analyze_signin_events_detects_off_hours_and_weekend_logins():
    oslo = ZoneInfo("Europe/Oslo")
    events = [
        make_event(
            datetime(2026, 4, 13, 7, 59, tzinfo=oslo),
            "dave@example.com",
            success=True,
        ),
        make_event(
            datetime(2026, 4, 13, 8, 0, tzinfo=oslo),
            "erin@example.com",
            success=True,
        ),
        make_event(
            datetime(2026, 4, 13, 16, 0, tzinfo=oslo),
            "frank@example.com",
            success=True,
        ),
        make_event(
            datetime(2026, 4, 11, 12, 0, tzinfo=oslo),
            "grace@example.com",
            success=True,
        ),
    ]

    result = analyze_signin_events(events)

    assert [event.username for event in result.off_hours_events] == [
        "dave@example.com",
        "frank@example.com",
        "grace@example.com",
    ]
    assert result.total_events == 4
    assert result.failed_login_count == 0


def test_analyze_signin_events_counts_interactive_and_non_interactive_events():
    oslo = ZoneInfo("Europe/Oslo")
    events = [
        make_event(
            datetime(2026, 4, 13, 9, 0, tzinfo=oslo),
            "alice@example.com",
            success=True,
            interactive=True,
        ),
        make_event(
            datetime(2026, 4, 13, 9, 5, tzinfo=oslo),
            "bob@example.com",
            success=False,
            interactive=False,
            error_code=50074,
            failure_reason="User needs to reauthenticate.",
        ),
    ]

    result = analyze_signin_events(events)

    assert result.interactive_event_count == 1
    assert result.non_interactive_event_count == 1
    assert result.unique_user_count == 2
    assert result.earliest_event_time == datetime(2026, 4, 13, 9, 0, tzinfo=oslo)
    assert result.latest_event_time == datetime(2026, 4, 13, 9, 5, tzinfo=oslo)


def test_analyze_signin_events_uses_none_for_time_metadata_when_empty():
    result = analyze_signin_events([])

    assert result.total_events == 0
    assert result.failed_login_count == 0
    assert result.interactive_event_count == 0
    assert result.non_interactive_event_count == 0
    assert result.unique_user_count == 0
    assert result.earliest_event_time is None
    assert result.latest_event_time is None
    assert result.repeated_failure_findings == []
    assert result.off_hours_events == []


def test_analyze_signin_events_builds_daily_timeline_across_coverage_window():
    oslo = ZoneInfo("Europe/Oslo")
    events = [
        make_event(
            datetime(2026, 4, 10, 9, 0, tzinfo=oslo),
            "alice@example.com",
            success=True,
            interactive=True,
        ),
        make_event(
            datetime(2026, 4, 10, 17, 15, tzinfo=oslo),
            "bob@example.com",
            success=False,
            interactive=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 12, 8, 0, tzinfo=oslo),
            "alice@example.com",
            success=False,
            interactive=True,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 12, 20, 0, tzinfo=oslo),
            "carol@example.com",
            success=True,
            interactive=False,
        ),
    ]

    result = analyze_signin_events(events)

    assert result.activity_timeline == [
        ActivityTimelinePoint(
            day=datetime(2026, 4, 10, tzinfo=oslo).date(),
            total_events=2,
            failed_login_count=1,
            off_hours_count=1,
            unique_user_count=2,
        ),
        ActivityTimelinePoint(
            day=datetime(2026, 4, 11, tzinfo=oslo).date(),
            total_events=0,
            failed_login_count=0,
            off_hours_count=0,
            unique_user_count=0,
        ),
        ActivityTimelinePoint(
            day=datetime(2026, 4, 12, tzinfo=oslo).date(),
            total_events=2,
            failed_login_count=1,
            off_hours_count=2,
            unique_user_count=2,
        ),
    ]


def test_analyze_signin_events_builds_recent_window_summaries():
    oslo = ZoneInfo("Europe/Oslo")
    events = [
        make_event(
            datetime(2026, 4, 10, 9, 0, tzinfo=oslo),
            "alice@example.com",
            success=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 10, 9, 5, tzinfo=oslo),
            "alice@example.com",
            success=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 10, 9, 10, tzinfo=oslo),
            "alice@example.com",
            success=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 12, 19, 50, tzinfo=oslo),
            "bob@example.com",
            success=False,
            interactive=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 12, 19, 55, tzinfo=oslo),
            "bob@example.com",
            success=False,
            interactive=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
        make_event(
            datetime(2026, 4, 12, 20, 0, tzinfo=oslo),
            "bob@example.com",
            success=False,
            interactive=False,
            error_code=50126,
            failure_reason="Invalid username or password.",
        ),
    ]

    result = analyze_signin_events(events)

    assert result.recent_window_summaries == [
        RecentWindowSummary(
            label="Last 24h",
            event_count=3,
            failed_login_count=3,
            off_hours_count=3,
            unique_user_count=1,
            repeated_failure_count=1,
        ),
        RecentWindowSummary(
            label="Last 7d",
            event_count=6,
            failed_login_count=6,
            off_hours_count=3,
            unique_user_count=2,
            repeated_failure_count=2,
        ),
        RecentWindowSummary(
            label="Last 30d",
            event_count=6,
            failed_login_count=6,
            off_hours_count=3,
            unique_user_count=2,
            repeated_failure_count=2,
        ),
    ]


def test_analyze_signin_events_returns_empty_timeline_and_recent_windows_for_no_events():
    result = analyze_signin_events([])

    assert result.activity_timeline == []
    assert result.recent_window_summaries == []

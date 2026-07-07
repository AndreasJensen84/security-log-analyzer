"""Run the security rules over normalized sign-in events.

This module keeps the detection logic pure and testable. A learner should
notice how the code groups events, applies thresholds, and builds findings
without reading files or printing output.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta

from .models import (
    ActivityTimelinePoint,
    AnalysisConfig,
    AnalysisResult,
    RecentWindowSummary,
    RepeatedFailureFinding,
    SignInEvent,
)


def analyze_signin_events(
    events: list[SignInEvent], config: AnalysisConfig | None = None
) -> AnalysisResult:
    config = config or AnalysisConfig()

    failed_login_count = sum(1 for event in events if not event.success)
    interactive_event_count = sum(1 for event in events if event.interactive)
    unique_user_count = len({event.username for event in events})
    earliest_event_time = min((event.timestamp for event in events), default=None)
    latest_event_time = max((event.timestamp for event in events), default=None)
    repeated_failure_findings = _find_repeated_failures(events, config)
    off_hours_events = [event for event in events if _is_off_hours(event, config)]
    activity_timeline = _build_activity_timeline(events, config)
    recent_window_summaries = _build_recent_window_summaries(
        events, repeated_failure_findings, latest_event_time, config
    )

    return AnalysisResult(
        total_events=len(events),
        failed_login_count=failed_login_count,
        repeated_failure_findings=repeated_failure_findings,
        off_hours_events=off_hours_events,
        interactive_event_count=interactive_event_count,
        non_interactive_event_count=len(events) - interactive_event_count,
        unique_user_count=unique_user_count,
        earliest_event_time=earliest_event_time,
        latest_event_time=latest_event_time,
        activity_timeline=activity_timeline,
        recent_window_summaries=recent_window_summaries,
    )


def _find_repeated_failures(
    events: list[SignInEvent], config: AnalysisConfig
) -> list[RepeatedFailureFinding]:
    failed_events_by_user: dict[str, list[SignInEvent]] = defaultdict(list)
    for event in events:
        if not event.success:
            failed_events_by_user[event.username].append(event)

    findings: list[RepeatedFailureFinding] = []
    for username, failed_events in failed_events_by_user.items():
        failed_events.sort(key=lambda event: event.timestamp)
        window_start_index = 0

        for window_end_index, window_end_event in enumerate(failed_events):
            while (
                window_end_event.timestamp - failed_events[window_start_index].timestamp
                > config.repeated_failure_window
            ):
                window_start_index += 1

            window_size = window_end_index - window_start_index + 1
            if window_size >= config.repeated_failure_threshold:
                findings.append(
                    RepeatedFailureFinding(
                        username=username,
                        failure_count=window_size,
                        window_start=failed_events[window_start_index].timestamp,
                        window_end=window_end_event.timestamp,
                    )
                )
                break

    return findings


def _is_off_hours(event: SignInEvent, config: AnalysisConfig) -> bool:
    timestamp = event.timestamp
    if timestamp.weekday() >= 5:
        return True

    local_time = timestamp.time()
    return local_time < config.workday_start or local_time >= config.workday_end


def _build_activity_timeline(
    events: list[SignInEvent], config: AnalysisConfig
) -> list[ActivityTimelinePoint]:
    if not events:
        return []

    events_by_day: dict[date, list[SignInEvent]] = defaultdict(list)
    for event in events:
        events_by_day[event.timestamp.date()].append(event)

    start_day = min(events_by_day)
    end_day = max(events_by_day)

    timeline: list[ActivityTimelinePoint] = []
    current_day = start_day
    while current_day <= end_day:
        day_events = events_by_day.get(current_day, [])
        timeline.append(
            ActivityTimelinePoint(
                day=current_day,
                total_events=len(day_events),
                failed_login_count=sum(1 for event in day_events if not event.success),
                off_hours_count=sum(1 for event in day_events if _is_off_hours(event, config)),
                unique_user_count=len({event.username for event in day_events}),
            )
        )
        current_day += timedelta(days=1)

    return timeline


def _build_recent_window_summaries(
    events: list[SignInEvent],
    repeated_failure_findings: list[RepeatedFailureFinding],
    latest_event_time: datetime | None,
    config: AnalysisConfig,
) -> list[RecentWindowSummary]:
    if not events or latest_event_time is None:
        return []

    windows = [
        ("Last 24h", timedelta(hours=24)),
        ("Last 7d", timedelta(days=7)),
        ("Last 30d", timedelta(days=30)),
    ]

    summaries: list[RecentWindowSummary] = []
    for label, window_size in windows:
        window_start = latest_event_time - window_size
        window_events = [
            event
            for event in events
            if window_start <= event.timestamp <= latest_event_time
        ]
        summaries.append(
            RecentWindowSummary(
                label=label,
                event_count=len(window_events),
                failed_login_count=sum(1 for event in window_events if not event.success),
                off_hours_count=sum(1 for event in window_events if _is_off_hours(event, config)),
                unique_user_count=len({event.username for event in window_events}),
                repeated_failure_count=sum(
                    1
                    for finding in repeated_failure_findings
                    if window_start <= finding.window_end <= latest_event_time
                ),
            )
        )

    return summaries

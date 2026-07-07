"""Data shapes used across the project.

This module defines the core event objects, findings, and analysis settings
that the rest of the code shares. A learner should notice how dataclasses
help keep the project's data readable and predictable.
"""

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta


@dataclass
class SignInEvent:
    timestamp: datetime
    username: str
    ip_address: str
    success: bool
    interactive: bool
    error_code: int
    failure_reason: str | None


@dataclass(frozen=True)
class AnalysisConfig:
    repeated_failure_threshold: int = 3
    repeated_failure_window: timedelta = timedelta(minutes=15)
    workday_start: time = time(hour=8)
    workday_end: time = time(hour=16)


@dataclass(frozen=True)
class RepeatedFailureFinding:
    username: str
    failure_count: int
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True)
class ActivityTimelinePoint:
    day: date
    total_events: int
    failed_login_count: int
    off_hours_count: int
    unique_user_count: int


@dataclass(frozen=True)
class RecentWindowSummary:
    label: str
    event_count: int
    failed_login_count: int
    off_hours_count: int
    unique_user_count: int
    repeated_failure_count: int


@dataclass(frozen=True)
class AnalysisResult:
    total_events: int
    failed_login_count: int
    repeated_failure_findings: list[RepeatedFailureFinding]
    off_hours_events: list[SignInEvent]
    interactive_event_count: int = 0
    non_interactive_event_count: int = 0
    unique_user_count: int = 0
    earliest_event_time: datetime | None = None
    latest_event_time: datetime | None = None
    activity_timeline: list[ActivityTimelinePoint] | None = None
    recent_window_summaries: list[RecentWindowSummary] | None = None

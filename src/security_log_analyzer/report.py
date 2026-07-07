"""Format analysis results as a readable text report.

This module turns structured findings into a simple console summary. A
learner should notice the difference between analysis logic and presentation
logic: the data is already computed here, so this file only explains it.
"""

from __future__ import annotations

from collections import defaultdict

from security_log_analyzer.models import AnalysisResult

TOP_OFF_HOURS_USER_LIMIT = 3
OFF_HOURS_SAMPLE_LIMIT = 5


def build_report(result: AnalysisResult) -> str:
    lines = [
        "Security Log Analysis Report",
        f"Total sign-in events: {result.total_events}",
        f"Failed sign-ins: {result.failed_login_count}",
        f"Repeated-failure findings: {len(result.repeated_failure_findings)}",
        f"Off-hours sign-ins: {len(result.off_hours_events)}",
        "",
        "Repeated failed logins",
    ]

    if result.repeated_failure_findings:
        for finding in result.repeated_failure_findings:
            lines.append(
                "- "
                f"{finding.username}: {finding.failure_count} failed logins "
                f"from {format_timestamp(finding.window_start)} "
                f"to {format_timestamp(finding.window_end)}"
            )
    else:
        lines.append("- None")

    lines.extend(["", "Off-hours logins"])

    if result.off_hours_events:
        lines.append(f"Total off-hours sign-ins: {len(result.off_hours_events)}")
        lines.append("Top off-hours users")
        for username, count in build_off_hours_user_summary(result.off_hours_events):
            lines.append(f"- {username}: {count}")
        omitted_users = count_off_hours_omitted_users(result.off_hours_events)
        if omitted_users:
            lines.append(
                f"- {omitted_users} more user{'s' if omitted_users != 1 else ''} omitted from summary"
            )
        lines.append("Sample off-hours events")
        for event in build_off_hours_sample(result.off_hours_events):
            lines.append(
                "- "
                f"{format_timestamp(event.timestamp)} | "
                f"{event.username} | "
                f"{event.ip_address}"
            )
        omitted_events = len(result.off_hours_events) - min(
            len(result.off_hours_events), OFF_HOURS_SAMPLE_LIMIT
        )
        if omitted_events:
            lines.append(
                f"- {omitted_events} more off-hours event{'s' if omitted_events != 1 else ''} omitted"
            )
    else:
        lines.append("- None")

    if not result.repeated_failure_findings and not result.off_hours_events:
        lines.extend(["", "No suspicious findings were detected."])

    return "\n".join(lines)


def format_timestamp(timestamp) -> str:
    offset = timestamp.strftime("%z")
    if offset:
        offset = f"{offset[:3]}:{offset[3:]}"
    return timestamp.strftime("%Y-%m-%d %H:%M ") + offset


def build_off_hours_user_summary(events):
    counts = defaultdict(int)
    for event in events:
        counts[event.username] += 1

    usernames = sorted(counts, key=lambda username: (-counts[username], username))
    return [(username, counts[username]) for username in usernames[:TOP_OFF_HOURS_USER_LIMIT]]


def count_off_hours_omitted_users(events):
    counts = defaultdict(int)
    for event in events:
        counts[event.username] += 1
    omitted = len(counts) - TOP_OFF_HOURS_USER_LIMIT
    return omitted if omitted > 0 else 0


def build_off_hours_sample(events):
    ordered_events = sorted(events, key=lambda event: (event.timestamp, event.username, event.ip_address))
    return ordered_events[:OFF_HOURS_SAMPLE_LIMIT]

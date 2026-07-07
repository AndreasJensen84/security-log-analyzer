"""Build the standalone HTML version of the report.

This file shows how the same analysis data can be presented for a browser
instead of the terminal. A learner should notice the focus on layout,
escaping, and making the important security signals easy to scan.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime
from html import escape

from .models import (
    ActivityTimelinePoint,
    AnalysisResult,
    RecentWindowSummary,
    RepeatedFailureFinding,
    SignInEvent,
)

TOP_REPEATED_FAILURE_LIMIT = 3
TOP_OFF_HOURS_USER_LIMIT = 3
RECENT_OFF_HOURS_EVENT_LIMIT = 5
RECENT_WINDOW_ORDER = {"Last 24h": 0, "Last 7d": 1, "Last 30d": 2}


def build_html_report(result: AnalysisResult) -> str:
    repeated_failures = _sorted_repeated_failures(result.repeated_failure_findings)
    off_hours_events = _sorted_recent_events(result.off_hours_events)
    activity_timeline = _sorted_activity_timeline(result.activity_timeline)
    recent_window_summaries = _sorted_recent_window_summaries(result.recent_window_summaries)
    top_repeated_failures = repeated_failures[:TOP_REPEATED_FAILURE_LIMIT]
    top_off_hours_users = _build_off_hours_user_summary(off_hours_events)
    recent_off_hours_events = off_hours_events[:RECENT_OFF_HOURS_EVENT_LIMIT]
    repeated_failure_count = len(result.repeated_failure_findings)
    off_hours_count = len(result.off_hours_events)
    total_events = result.total_events

    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>Security Log Analysis Report</title>",
            "<style>",
            _build_css(),
            "</style>",
            "</head>",
            "<body>",
            '<div class="page">',
            _build_hero_banner(
                result=result,
                repeated_failure_count=repeated_failure_count,
                off_hours_count=off_hours_count,
                total_events=total_events,
                top_repeated_failures=top_repeated_failures,
                top_off_hours_users=top_off_hours_users,
                recent_window_summaries=recent_window_summaries,
            ),
            _build_summary_cards(result=result, repeated_failure_count=repeated_failure_count, off_hours_count=off_hours_count),
            _build_recent_activity_strip(recent_window_summaries),
            _build_activity_timeline_section(activity_timeline),
            _build_activity_mix_panel(result),
            '<main class="content">',
            _build_repeated_failure_section(repeated_failures),
            _build_off_hours_section(off_hours_events, top_off_hours_users, recent_off_hours_events),
            _build_no_findings_callout(result),
            "</main>",
            "</div>",
            "</body>",
            "</html>",
        ]
    )


def _build_css() -> str:
    return """
:root {
  color-scheme: light;
  --bg: #e9e1d4;
  --bg-2: #f7f3ec;
  --panel: rgba(255, 255, 255, 0.88);
  --panel-strong: #ffffff;
  --panel-soft: #f6efe5;
  --text: #1d2530;
  --muted: #66707c;
  --border: #d8cdbd;
  --shadow: 0 18px 44px rgba(29, 37, 48, 0.12);
  --accent: #7d2430;
  --accent-soft: #f4e3e6;
  --warning: #c27a00;
  --success: #2f6d57;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  color: var(--text);
  font-family: "Avenir Next", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  line-height: 1.5;
  background:
    radial-gradient(circle at top left, rgba(125, 36, 48, 0.09), transparent 26%),
    radial-gradient(circle at top right, rgba(47, 109, 87, 0.1), transparent 28%),
    linear-gradient(180deg, #fcfbf8 0%, var(--bg-2) 22%, var(--bg) 100%);
}

.page {
  max-width: 1180px;
  margin: 0 auto;
  padding: 28px 22px 56px;
}

.hero {
  position: relative;
  overflow: hidden;
  display: grid;
  grid-template-columns: minmax(0, 1.5fr) minmax(320px, 0.9fr);
  gap: 20px;
  padding: 28px;
  border: 1px solid rgba(29, 37, 48, 0.08);
  border-radius: 28px;
  box-shadow: var(--shadow);
  background:
    linear-gradient(140deg, rgba(26, 34, 47, 0.98), rgba(61, 43, 50, 0.96)),
    linear-gradient(140deg, #2a3340, #141a22);
  color: #f6f1e8;
}

.hero::after {
  content: "";
  position: absolute;
  inset: auto -12% -42% auto;
  width: 280px;
  height: 280px;
  border-radius: 999px;
  background: radial-gradient(circle, rgba(235, 194, 88, 0.25), transparent 72%);
  pointer-events: none;
}

.eyebrow {
  margin: 0 0 10px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  font-size: 0.74rem;
  font-weight: 700;
  color: #f1c873;
}

h1,
h2,
h3 {
  margin: 0;
  font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
  font-weight: 700;
  line-height: 1.12;
}

h1 {
  font-size: clamp(2.2rem, 4vw, 3.9rem);
  letter-spacing: -0.03em;
}

.lede {
  max-width: 72ch;
  margin: 14px 0 0;
  color: rgba(246, 241, 232, 0.84);
  font-size: 1.03rem;
}

.hero__body {
  display: grid;
  align-content: start;
  gap: 2px;
}

.hero__facts {
  display: grid;
  gap: 12px;
  align-content: start;
}

.hero__fact {
  padding: 16px 16px 14px;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.12);
  backdrop-filter: blur(6px);
}

.hero__fact-label {
  display: block;
  margin-bottom: 6px;
  color: rgba(246, 241, 232, 0.68);
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.hero__fact-value {
  display: block;
  font-size: 1.02rem;
  font-weight: 700;
}

.hero__fact-subtle {
  display: block;
  margin-top: 4px;
  color: rgba(246, 241, 232, 0.72);
  font-size: 0.92rem;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
  margin-top: 18px;
}

.card {
  padding: 18px 18px 17px;
  border: 1px solid var(--border);
  border-radius: 20px;
  background: var(--panel);
  box-shadow: 0 10px 28px rgba(29, 37, 48, 0.08);
}

.card--accent {
  border-top: 4px solid var(--accent);
}

.card--success {
  border-top: 4px solid var(--success);
}

.card--warning {
  border-top: 4px solid var(--warning);
}

.card__label {
  display: block;
  color: var(--muted);
  font-size: 0.82rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.card__value {
  display: block;
  margin-top: 10px;
  font-size: clamp(1.8rem, 3vw, 2.7rem);
  font-weight: 800;
  color: var(--text);
}

.card__support,
.card__detail {
  display: block;
  margin-top: 5px;
  color: var(--muted);
  font-size: 0.95rem;
}

.card__detail {
  color: #4c5866;
}

.recent-strip {
  display: grid;
  gap: 16px;
  margin-top: 16px;
  padding: 18px 18px 20px;
  border: 1px solid var(--border);
  border-radius: 24px;
  background: linear-gradient(180deg, #ffffff, #fcfaf6);
  box-shadow: var(--shadow);
}

.recent-strip__header {
  display: grid;
  gap: 6px;
}

.recent-strip__title {
  font-size: 1.15rem;
}

.recent-strip__state {
  margin: 0;
  color: var(--muted);
}

.recent-strip__grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
}

.recent-card {
  display: grid;
  gap: 8px;
  padding: 16px;
  border-radius: 18px;
  border: 1px solid #e4d8c7;
  background: #fbf7f0;
}

.recent-card--fresh {
  border-top: 4px solid var(--accent);
  background: linear-gradient(180deg, #fff7f8, #fbf1f2);
}

.recent-card--quiet {
  border-top: 4px solid var(--success);
}

.recent-card--context {
  border-top: 4px solid var(--warning);
}

.recent-card__label {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  color: var(--text);
  font-weight: 800;
}

.recent-card__value {
  font-size: 1.8rem;
  font-weight: 800;
  letter-spacing: -0.03em;
}

.recent-card__support,
.recent-card__detail {
  color: var(--muted);
  font-size: 0.94rem;
}

.timeline-panel {
  display: grid;
  gap: 16px;
  margin-top: 16px;
  padding: 20px 20px 22px;
  border: 1px solid var(--border);
  border-radius: 24px;
  background: linear-gradient(180deg, #ffffff, #fcfaf6);
  box-shadow: var(--shadow);
}

.timeline-panel__header {
  display: grid;
  gap: 6px;
}

.timeline-panel__title {
  font-size: 1.18rem;
}

.timeline-panel__state {
  margin: 0;
  color: var(--muted);
}

.timeline-chart {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(104px, 1fr));
  gap: 12px;
}

.timeline-day {
  display: grid;
  gap: 10px;
  padding: 14px;
  border-radius: 18px;
  border: 1px solid #e6dbc9;
  background: linear-gradient(180deg, #fffdfb, #f8f3ea);
}

.timeline-day__label {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
  font-weight: 800;
}

.timeline-day__bar {
  position: relative;
  height: 136px;
  border-radius: 16px;
  background: linear-gradient(180deg, #ece4d7, #f8f3ea);
  overflow: hidden;
  display: flex;
  align-items: flex-end;
  padding: 8px;
}

.timeline-day__fill {
  width: 100%;
  height: var(--bar-height, 12%);
  min-height: 8%;
  border-radius: 12px 12px 8px 8px;
  background: linear-gradient(180deg, #7d2430, #ad5a63);
  box-shadow: 0 10px 24px rgba(125, 36, 48, 0.22);
}

.timeline-day__off-hours {
  position: absolute;
  right: 10px;
  top: 10px;
  padding: 3px 8px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.9);
  color: #7c5a27;
  border: 1px solid #eadfce;
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.timeline-day__counts {
  display: grid;
  gap: 4px;
  color: var(--muted);
  font-size: 0.92rem;
}

.timeline-day__primary {
  color: var(--text);
  font-weight: 800;
}

.context-strip {
  display: grid;
  grid-template-columns: 1.1fr 0.9fr 1fr;
  gap: 16px;
  margin-top: 16px;
}

.context-card {
  padding: 16px 18px;
  border-radius: 18px;
  border: 1px solid var(--border);
  background: linear-gradient(180deg, #ffffff, #f8f3ea);
  box-shadow: 0 10px 22px rgba(29, 37, 48, 0.06);
}

.context-card__label {
  display: block;
  color: var(--muted);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}

.context-card__value {
  display: block;
  margin-top: 8px;
  font-size: 1rem;
  font-weight: 700;
}

.mix {
  padding: 18px 18px 20px;
  border: 1px solid var(--border);
  border-radius: 22px;
  background: linear-gradient(180deg, #ffffff, #fcfaf6);
  box-shadow: var(--shadow);
  margin-top: 16px;
}

.mix__header {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}

.mix__title {
  font-size: 1.08rem;
}

.mix__subtitle {
  margin: 0;
  color: var(--muted);
  font-size: 0.95rem;
}

.mix__bar {
  overflow: hidden;
  display: flex;
  height: 18px;
  border-radius: 999px;
  background: #ece4d5;
}

.mix__bar span {
  display: block;
  height: 100%;
}

.mix__interactive {
  background: linear-gradient(90deg, #2f6d57, #4b8b73);
}

.mix__noninteractive {
  background: linear-gradient(90deg, #b96b2d, #d79a53);
}

.mix__meta {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
  margin-top: 14px;
}

.mix__stat {
  padding: 14px 14px 12px;
  border-radius: 16px;
  background: #f8f4eb;
  border: 1px solid #e7dccb;
}

.mix__stat-label {
  display: block;
  color: var(--muted);
  font-size: 0.76rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}

.mix__stat-value {
  display: block;
  margin-top: 6px;
  font-size: 1.1rem;
  font-weight: 800;
}

.content {
  display: grid;
  gap: 18px;
  margin-top: 18px;
}

.panel {
  padding: 24px;
  border: 1px solid var(--border);
  border-radius: 24px;
  background: var(--panel-strong);
  box-shadow: var(--shadow);
}

.panel__header {
  display: grid;
  gap: 8px;
  margin-bottom: 16px;
}

.panel__title {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 1.55rem;
}

.panel__title::before {
  content: "";
  width: 12px;
  height: 12px;
  border-radius: 999px;
  background: var(--accent);
  box-shadow: 0 0 0 6px var(--accent-soft);
}

.panel__text {
  margin: 0;
  color: var(--muted);
}

.finding-grid,
.off-hours-grid {
  display: grid;
  gap: 14px;
}

.finding-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.finding-card {
  display: grid;
  gap: 8px;
  padding: 16px;
  border-radius: 18px;
  border: 1px solid #e7ddd0;
  background: linear-gradient(180deg, #fffdfb, #f8f4ec);
}

.finding-card__rank {
  display: inline-flex;
  align-items: center;
  width: fit-content;
  padding: 3px 10px;
  border-radius: 999px;
  background: var(--accent-soft);
  color: var(--accent);
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.finding-card__title {
  font-size: 1.05rem;
  font-weight: 800;
}

.finding-card__meta {
  color: var(--muted);
  font-size: 0.95rem;
}

.subgrid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.mini-panel {
  padding: 18px;
  border-radius: 18px;
  border: 1px solid var(--border);
  background: linear-gradient(180deg, #ffffff, #fcf8f1);
}

.mini-panel h3 {
  margin-bottom: 12px;
  font-size: 1.08rem;
}

.list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: grid;
  gap: 10px;
}

.list li {
  padding: 11px 12px;
  border-radius: 14px;
  background: #f8f4eb;
  border: 1px solid #eadfce;
}

.list--compact li {
  background: transparent;
}

.list__label {
  display: block;
  font-weight: 700;
}

.list__meta {
  display: block;
  margin-top: 4px;
  color: var(--muted);
  font-size: 0.92rem;
}

.timeline {
  display: grid;
  gap: 10px;
}

.timeline__item {
  display: grid;
  gap: 4px;
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid #e7dccb;
  background: #fbf8f2;
}

.timeline__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 10px;
  color: var(--muted);
  font-size: 0.92rem;
}

.tag {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 999px;
  background: #ece6da;
  color: #52606f;
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.details {
  margin-top: 18px;
  padding: 0;
}

.details > summary {
  cursor: pointer;
  list-style: none;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  border-radius: 999px;
  border: 1px solid #ddd3c2;
  background: #faf6ef;
  color: var(--text);
  font-weight: 700;
}

.details > summary::-webkit-details-marker {
  display: none;
}

.details[open] > summary {
  margin-bottom: 14px;
}

.callout {
  padding: 18px 20px;
  border-radius: 18px;
  border: 1px solid #d9e0ea;
  background: linear-gradient(180deg, #f7f9fc, #eef3f8);
  color: #203040;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.72);
}

.callout strong {
  display: block;
  margin-bottom: 6px;
  font-size: 1.05rem;
}

.muted {
  color: var(--muted);
}

@media (max-width: 1080px) {
  .hero,
  .summary-grid,
  .context-strip,
  .recent-strip__grid,
  .timeline-chart,
  .finding-grid,
  .subgrid {
    grid-template-columns: 1fr 1fr;
  }

  .hero {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 760px) {
  .page {
    padding: 16px 12px 34px;
  }

  .hero,
  .panel,
  .mix {
    border-radius: 18px;
    padding: 18px;
  }

  .summary-grid,
  .context-strip,
  .recent-strip__grid,
  .timeline-chart,
  .finding-grid,
  .subgrid,
  .mix__meta {
    grid-template-columns: 1fr;
  }
}
""".strip()


def _build_hero_banner(
    *,
    result: AnalysisResult,
    repeated_failure_count: int,
    off_hours_count: int,
    total_events: int,
    top_repeated_failures: list[RepeatedFailureFinding],
    top_off_hours_users: list[tuple[str, int]],
    recent_window_summaries: list[RecentWindowSummary],
) -> str:
    headline, body = _build_verdict_text(
        result=result,
        repeated_failure_count=repeated_failure_count,
        off_hours_count=off_hours_count,
        top_repeated_failures=top_repeated_failures,
        top_off_hours_users=top_off_hours_users,
        recent_window_summaries=recent_window_summaries,
    )
    coverage_window = _format_coverage_window(result.earliest_event_time, result.latest_event_time)
    coverage_span = _format_span(result.earliest_event_time, result.latest_event_time)
    interactive_count = result.interactive_event_count
    non_interactive_count = result.non_interactive_event_count
    recency_label, recency_detail = _format_recency_banner(recent_window_summaries)

    return "\n".join(
        [
            '<header class="hero">',
            '<div class="hero__body">',
            '<p class="eyebrow">Executive verdict</p>',
            f"<h1>{escape(headline)}</h1>",
            f'<p class="lede">{escape(body)}</p>',
            "</div>",
            '<div class="hero__facts">',
            "\n".join(
                [
                    '<div class="hero__fact">',
                    '<span class="hero__fact-label">Coverage window</span>',
                    f'<span class="hero__fact-value">{escape(coverage_window)}</span>',
                    f'<span class="hero__fact-subtle">{escape(coverage_span)}</span>',
                    "</div>",
                ]
            ),
            "\n".join(
                [
                    '<div class="hero__fact">',
                    '<span class="hero__fact-label">Who to look at first</span>',
                    f'<span class="hero__fact-value">{escape(_format_priority_hint(top_repeated_failures, top_off_hours_users))}</span>',
                    f'<span class="hero__fact-subtle">{escape(_format_priority_subtext(top_repeated_failures, top_off_hours_users))}</span>',
                    "</div>",
                ]
            ),
            "\n".join(
                [
                    '<div class="hero__fact">',
                    '<span class="hero__fact-label">Activity mix</span>',
                    f'<span class="hero__fact-value">{escape(_format_mix_summary(interactive_count, non_interactive_count))}</span>',
                    f'<span class="hero__fact-subtle">{escape(_format_mix_detail(interactive_count, non_interactive_count, total_events))}</span>',
                    "</div>",
                ]
            ),
            "\n".join(
                [
                    '<div class="hero__fact">',
                    '<span class="hero__fact-label">Recency</span>',
                    f'<span class="hero__fact-value">{escape(recency_label)}</span>',
                    f'<span class="hero__fact-subtle">{escape(recency_detail)}</span>',
                    "</div>",
                ]
            ),
            "</div>",
            "</header>",
        ]
    )


def _build_summary_cards(*, result: AnalysisResult, repeated_failure_count: int, off_hours_count: int) -> str:
    total_events = result.total_events
    cards = [
        (
            "Total events",
            _format_count(total_events),
            _format_unique_user_support(result.unique_user_count),
            _format_coverage_card_detail(result.earliest_event_time, result.latest_event_time),
            "card--accent",
        ),
        (
            "Failed sign-ins",
            _format_count(result.failed_login_count),
            _format_percentage(result.failed_login_count, total_events, "of events"),
            "Attempts that did not complete successfully.",
            "card--warning",
        ),
        (
            "Repeated-failure findings",
            _format_count(repeated_failure_count),
            "Users with 3+ failures in 15 minutes.",
            "These are the clearest accounts to investigate first.",
            "card--accent",
        ),
        (
            "Off-hours sign-ins",
            _format_count(off_hours_count),
            _format_percentage(off_hours_count, total_events, "of events"),
            "Events outside 08:00 to 16:00 local time.",
            "card--warning",
        ),
    ]

    card_markup = []
    for label, value, support, detail, modifier in cards:
        card_markup.append(
            "\n".join(
                [
                    f'<section class="card {modifier}">',
                    f'<span class="card__label">{escape(str(label))}</span>',
                    f'<strong class="card__value">{escape(str(value))}</strong>',
                    f'<span class="card__support">{escape(str(support))}</span>',
                    f'<span class="card__detail">{escape(str(detail))}</span>',
                    "</section>",
                ]
            )
        )

    return '<section class="summary-grid">\n' + "\n".join(card_markup) + "\n</section>"


def _build_activity_mix_panel(result: AnalysisResult) -> str:
    interactive_count = result.interactive_event_count
    non_interactive_count = result.non_interactive_event_count
    total = interactive_count + non_interactive_count
    interactive_width = _percentage_value(interactive_count, total)
    non_interactive_width = max(0, 100 - interactive_width)

    return "\n".join(
        [
            '<section class="mix">',
            '<div class="mix__header">',
            '<div>',
            '<h2 class="mix__title">Interactive vs non-interactive activity</h2>',
            '<p class="mix__subtitle">This is useful for separating user-driven sign-ins from background or service-driven noise.</p>',
            "</div>",
            f'<div class="muted">{escape(_format_count(total))} total observations</div>',
            "</div>",
            '<div class="mix__bar" aria-hidden="true">',
            f'<span class="mix__interactive" style="width: {interactive_width}%"></span>',
            f'<span class="mix__noninteractive" style="width: {non_interactive_width}%"></span>',
            "</div>",
            '<div class="mix__meta">',
            "\n".join(
                [
                    '<div class="mix__stat">',
                    '<span class="mix__stat-label">Interactive activity</span>',
                    f'<span class="mix__stat-value">{escape(_format_count(interactive_count))} ({escape(_format_percentage(interactive_count, total, ""))})</span>',
                    "</div>",
                ]
            ),
            "\n".join(
                [
                    '<div class="mix__stat">',
                    '<span class="mix__stat-label">Non-interactive activity</span>',
                    f'<span class="mix__stat-value">{escape(_format_count(non_interactive_count))} ({escape(_format_percentage(non_interactive_count, total, ""))})</span>',
                    "</div>",
                ]
            ),
            "</div>",
            "</section>",
        ]
    )


def _build_recent_activity_strip(recent_window_summaries: list[RecentWindowSummary]) -> str:
    if not recent_window_summaries:
        return ""

    latest_window = next((summary for summary in recent_window_summaries if summary.label == "Last 24h"), recent_window_summaries[0])
    state_label, state_detail = _format_recent_window_state(latest_window, recent_window_summaries)

    lines = [
        '<section class="recent-strip">',
        '<div class="recent-strip__header">',
        '<h2 class="recent-strip__title">Recent activity windows</h2>',
        f'<p class="recent-strip__state">{escape(state_label)}. {escape(state_detail)}</p>',
        "</div>",
        '<div class="recent-strip__grid">',
    ]

    for summary in recent_window_summaries:
        card_class = _recent_window_card_class(summary)
        summary_state = _describe_recent_window(summary)
        lines.append(
            "\n".join(
                [
                    f'<article class="recent-card {card_class}">',
                    f'<div class="recent-card__label"><span>{escape(summary.label)}</span><span class="tag">{escape(summary_state)}</span></div>',
                    f'<div class="recent-card__value">{escape(_format_count(summary.event_count))}</div>',
                    f'<div class="recent-card__support">{escape(_format_recent_window_support(summary))}</div>',
                    f'<div class="recent-card__detail">{escape(_format_recent_window_detail(summary))}</div>',
                    "</article>",
                ]
            )
        )

    lines.extend(["</div>", "</section>"])
    return "\n".join(lines)


def _build_activity_timeline_section(activity_timeline: list[ActivityTimelinePoint]) -> str:
    if not activity_timeline:
        return ""

    max_failed = max(point.failed_login_count for point in activity_timeline)
    lines = [
        '<section class="timeline-panel">',
        '<div class="timeline-panel__header">',
        '<h2 class="timeline-panel__title">Activity timeline</h2>',
        '<p class="timeline-panel__state">Daily failed sign-ins across the coverage window. Off-hours counts are shown as context on each day.</p>',
        "</div>",
        '<div class="timeline-chart">',
    ]

    for point in activity_timeline:
        bar_height = _percentage_value(point.failed_login_count, max_failed)
        lines.append(
            "\n".join(
                [
                    '<article class="timeline-day">',
                    f'<div class="timeline-day__label"><span>{escape(_format_day(point.day))}</span><span class="tag">{escape(_format_day_peak(point.failed_login_count))}</span></div>',
                    f'<div class="timeline-day__bar" aria-label="{escape(_timeline_aria_label(point))}"><div class="timeline-day__fill" style="--bar-height: {max(bar_height, 8)}%"></div><div class="timeline-day__off-hours">{escape(_format_count(point.off_hours_count))} off-hours</div></div>',
                    f'<div class="timeline-day__counts"><span class="timeline-day__primary">{escape(_format_count(point.failed_login_count))} failed sign-ins</span><span>{escape(_format_timeline_support(point))}</span></div>',
                    "</article>",
                ]
            )
        )

    lines.extend(["</div>", "</section>"])
    return "\n".join(lines)


def _build_repeated_failure_section(repeated_failures: list[RepeatedFailureFinding]) -> str:
    lines = [
        '<section class="panel">',
        '<div class="panel__header">',
        '<h2 class="panel__title">Top repeated-failure findings</h2>',
        '<p class="panel__text">The first screen shows the top accounts to review, sorted by severity and last seen time.</p>',
        "</div>",
    ]

    if repeated_failures:
        lines.append('<div class="finding-grid">')
        for position, finding in enumerate(repeated_failures[:TOP_REPEATED_FAILURE_LIMIT], start=1):
            lines.append(
                "\n".join(
                    [
                        '<article class="finding-card">',
                        f'<span class="finding-card__rank">Top {position}</span>',
                        f'<div class="finding-card__title">{escape(finding.username)}</div>',
                        f'<div class="finding-card__meta">{escape(str(finding.failure_count))} failed logins within 15 minutes</div>',
                        f'<div class="finding-card__meta">Last seen {escape(_format_timestamp(finding.window_end))}</div>',
                        f'<div class="finding-card__meta">{escape(_format_timestamp(finding.window_start))} to {escape(_format_timestamp(finding.window_end))}</div>',
                        "</article>",
                    ]
                )
            )
        lines.append("</div>")
        if len(repeated_failures) > TOP_REPEATED_FAILURE_LIMIT:
            lines.append(
                f'<p class="panel__text">Showing Top {TOP_REPEATED_FAILURE_LIMIT} of {len(repeated_failures)} repeated-failure findings.</p>'
            )
        lines.append(
            "\n".join(
                [
                    '<details class="details">',
                    '<summary>Full repeated-failure list</summary>',
                    '<ul class="list">',
                ]
            )
        )
        for finding in repeated_failures:
            lines.append(
                "<li>"
                f'<span class="list__label">{escape(finding.username)}</span>'
                f'<span class="list__meta">{escape(str(finding.failure_count))} failures, last seen {escape(_format_timestamp(finding.window_end))}</span>'
                "</li>"
            )
        lines.extend(["</ul>", "</details>"])
    else:
        lines.append('<div class="callout">No repeated failure findings were detected.</div>')

    lines.append("</section>")
    return "\n".join(lines)


def _build_off_hours_section(
    off_hours_events: list[SignInEvent],
    top_off_hours_users: list[tuple[str, int]],
    recent_off_hours_events: list[SignInEvent],
) -> str:
    lines = [
        '<section class="panel">',
        '<div class="panel__header">',
        '<h2 class="panel__title">Off-hours logins</h2>',
        '<p class="panel__text">The first screen emphasizes the biggest drivers and the most recent suspicious activity.</p>',
        "</div>",
    ]

    if off_hours_events:
        lines.extend(
            [
                '<div class="subgrid">',
                '<section class="mini-panel">',
                "<h3>Top off-hours drivers</h3>",
                '<ul class="list list--compact">',
            ]
        )
        total = len(off_hours_events)
        for username, count in top_off_hours_users:
            lines.append(
                "<li>"
                f'<span class="list__label">{escape(username)}</span>'
                f'<span class="list__meta">{escape(_format_count(count))} events, {escape(_format_percentage(count, total, "of off-hours activity"))}</span>'
                "</li>"
            )
        omitted_users = _count_off_hours_omitted_users(off_hours_events)
        if omitted_users:
            lines.append(
                "<li class=\"muted\">"
                f"{escape(str(omitted_users))} more user{'s' if omitted_users != 1 else ''} omitted from the summary"
                "</li>"
            )
        lines.extend(
            [
                "</ul>",
                "</section>",
                '<section class="mini-panel">',
                "<h3>Recent off-hours events</h3>",
                '<div class="timeline">',
            ]
        )
        for event in recent_off_hours_events:
            lines.append(
                "\n".join(
                    [
                        '<div class="timeline__item">',
                        f'<div class="timeline__meta"><span>{escape(_format_timestamp(event.timestamp))}</span><span>{escape(event.username)}</span><span>{escape(event.ip_address)}</span><span class="tag">{escape("Interactive" if event.interactive else "Non-interactive")}</span></div>',
                        "</div>",
                    ]
                )
            )
        omitted_events = len(off_hours_events) - len(recent_off_hours_events)
        if omitted_events:
            lines.append(
                f'<p class="panel__text">{escape(str(omitted_events))} older off-hours event{"s" if omitted_events != 1 else ""} hidden.</p>'
            )
        lines.extend(["</div>", "</section>", "</div>"])
        lines.append(
            "\n".join(
                [
                    '<details class="details">',
                    '<summary>Full off-hours event list</summary>',
                    '<ul class="list">',
                ]
            )
        )
        for event in off_hours_events:
            lines.append(
                "<li>"
                f'<span class="list__label">{escape(_format_timestamp(event.timestamp))} | {escape(event.username)}</span>'
                f'<span class="list__meta">{escape(event.ip_address)} | {escape("Interactive" if event.interactive else "Non-interactive")}</span>'
                "</li>"
            )
        lines.extend(["</ul>", "</details>"])
    else:
        lines.append('<div class="callout">No off-hours logins were detected.</div>')

    lines.append("</section>")
    return "\n".join(lines)


def _build_no_findings_callout(result: AnalysisResult) -> str:
    if result.repeated_failure_findings or result.off_hours_events:
        return ""

    return "\n".join(
        [
            '<section class="callout">',
            "<strong>No suspicious findings were detected.</strong>",
            '<span class="muted">Activity appears normal within the current detection rules.</span>',
            "</section>",
        ]
    )


def _build_verdict_text(
    *,
    result: AnalysisResult,
    repeated_failure_count: int,
    off_hours_count: int,
    top_repeated_failures: list[RepeatedFailureFinding],
    top_off_hours_users: list[tuple[str, int]],
    recent_window_summaries: list[RecentWindowSummary],
) -> tuple[str, str]:
    total_events = result.total_events
    failed_rate = _percentage_value(result.failed_login_count, total_events)
    off_hours_rate = _percentage_value(off_hours_count, total_events)
    non_interactive_rate = _percentage_value(result.non_interactive_event_count, result.interactive_event_count + result.non_interactive_event_count)
    recency_sentence = _format_recency_sentence(recent_window_summaries)

    if repeated_failure_count == 0 and off_hours_count == 0:
        return (
            "Low concern",
            f"No suspicious patterns were detected. {recency_sentence}",
        )

    headline = "Attention needed" if repeated_failure_count else "Review recommended"
    parts = []
    if repeated_failure_count:
        parts.append(
            f"{_format_count(repeated_failure_count)} repeated-failure finding{'s' if repeated_failure_count != 1 else ''} need review"
        )
    if off_hours_count:
        parts.append(f"{_format_count(off_hours_count)} off-hours sign-ins were recorded")
    if top_repeated_failures:
        top_failure = top_repeated_failures[0]
        parts.append(
            f"Start with {top_failure.username} ({_format_count(top_failure.failure_count)} failed logins in 15 minutes)"
        )
    if top_off_hours_users:
        top_user, top_count = top_off_hours_users[0]
        parts.append(f"Largest off-hours driver: {top_user} ({_format_count(top_count)} events)")
    if failed_rate >= 30:
        parts.append(f"Failed sign-ins make up {failed_rate}% of all events")
    if off_hours_rate >= 40:
        parts.append(f"Off-hours activity makes up {off_hours_rate}% of all events")
    if non_interactive_rate >= 50:
        parts.append(f"Non-interactive activity makes up {non_interactive_rate}% of the observed volume")
    if recency_sentence:
        parts.append(recency_sentence)

    return headline, ". ".join(parts) + "."


def _build_off_hours_user_summary(events: list[SignInEvent]) -> list[tuple[str, int]]:
    counts = defaultdict(int)
    for event in events:
        counts[event.username] += 1

    usernames = sorted(counts, key=lambda username: (-counts[username], username))
    return [(username, counts[username]) for username in usernames[:TOP_OFF_HOURS_USER_LIMIT]]


def _count_off_hours_omitted_users(events: list[SignInEvent]) -> int:
    counts = defaultdict(int)
    for event in events:
        counts[event.username] += 1
    omitted = len(counts) - TOP_OFF_HOURS_USER_LIMIT
    return omitted if omitted > 0 else 0


def _sorted_repeated_failures(repeated_failures: list[RepeatedFailureFinding]) -> list[RepeatedFailureFinding]:
    return sorted(
        repeated_failures,
        key=lambda finding: (-finding.failure_count, -_timestamp_sort_key(finding.window_end), finding.username),
    )


def _sorted_recent_events(events: list[SignInEvent]) -> list[SignInEvent]:
    return sorted(events, key=lambda event: (event.timestamp, event.username, event.ip_address), reverse=True)


def _sorted_activity_timeline(activity_timeline: list[ActivityTimelinePoint] | None) -> list[ActivityTimelinePoint]:
    if not activity_timeline:
        return []
    return sorted(activity_timeline, key=lambda point: point.day)


def _sorted_recent_window_summaries(
    recent_window_summaries: list[RecentWindowSummary] | None,
) -> list[RecentWindowSummary]:
    if not recent_window_summaries:
        return []
    return sorted(recent_window_summaries, key=lambda summary: (_recent_window_sort_key(summary.label), summary.label))


def _format_timestamp(timestamp: datetime) -> str:
    offset = timestamp.strftime("%z")
    if offset:
        offset = f"{offset[:3]}:{offset[3:]}"
    return timestamp.strftime("%Y-%m-%d %H:%M ") + offset


def _format_day(day: date) -> str:
    return day.strftime("%b %d")


def _format_day_peak(failed_login_count: int) -> str:
    return f"Peak {failed_login_count}" if failed_login_count else "No failures"


def _timeline_aria_label(point: ActivityTimelinePoint) -> str:
    return (
        f"{point.day.isoformat()}: {point.failed_login_count} failed sign-ins, "
        f"{point.off_hours_count} off-hours sign-ins, {point.unique_user_count} unique users"
    )


def _format_timeline_support(point: ActivityTimelinePoint) -> str:
    return (
        f"{_format_count(point.total_events)} events total, "
        f"{_format_count(point.off_hours_count)} off-hours, "
        f"{_format_count(point.unique_user_count)} users"
    )


def _recent_window_sort_key(label: str) -> int:
    return RECENT_WINDOW_ORDER.get(label, len(RECENT_WINDOW_ORDER))


def _recent_window_card_class(summary: RecentWindowSummary) -> str:
    if summary.label == "Last 24h" and _recent_window_suspicious_count(summary) > 0:
        return "recent-card--fresh"
    if summary.label == "Last 24h":
        return "recent-card--quiet"
    return "recent-card--context"


def _describe_recent_window(summary: RecentWindowSummary) -> str:
    if summary.label == "Last 24h":
        return "Fresh" if _recent_window_suspicious_count(summary) > 0 else "Quiet"
    if summary.label == "Last 7d":
        return "Context"
    if summary.label == "Last 30d":
        return "Baseline"
    return "Window"


def _format_recent_window_support(summary: RecentWindowSummary) -> str:
    return (
        f"{_format_count(summary.failed_login_count)} failed, "
        f"{_format_count(summary.off_hours_count)} off-hours"
    )


def _format_recent_window_detail(summary: RecentWindowSummary) -> str:
    return (
        f"{_format_count(summary.unique_user_count)} users, "
        f"{_format_count(summary.repeated_failure_count)} repeated-failure windows"
    )


def _format_recent_window_state(
    latest_window: RecentWindowSummary,
    recent_window_summaries: list[RecentWindowSummary],
) -> tuple[str, str]:
    suspicious_count = _recent_window_suspicious_count(latest_window)
    if suspicious_count > 0:
        return (
            "Fresh suspicious activity",
            f"The last 24h window contains {_format_count(suspicious_count)} suspicious signals.",
        )

    older_suspicious = sum(_recent_window_suspicious_count(summary) for summary in recent_window_summaries if summary.label != "Last 24h")
    if older_suspicious > 0:
        return (
            "Suspicious activity is mostly stale",
            f"The last 24h is quiet, while older windows still contain {_format_count(older_suspicious)} suspicious signals.",
        )

    return (
        "No recent suspicious activity",
        "The recent windows are quiet and the suspicious signals appear stale or absent.",
    )


def _format_recency_sentence(recent_window_summaries: list[RecentWindowSummary]) -> str:
    if not recent_window_summaries:
        return "Recent activity windows were not provided."

    latest_window = next((summary for summary in recent_window_summaries if summary.label == "Last 24h"), recent_window_summaries[0])
    state, detail = _format_recent_window_state(latest_window, recent_window_summaries)
    return f"{state}. {detail.rstrip('.')}"


def _format_recency_banner(recent_window_summaries: list[RecentWindowSummary]) -> tuple[str, str]:
    if not recent_window_summaries:
        return "No window data", "Recent activity windows were not provided."

    latest_window = next((summary for summary in recent_window_summaries if summary.label == "Last 24h"), recent_window_summaries[0])
    state, detail = _format_recent_window_state(latest_window, recent_window_summaries)
    return state, detail


def _recent_window_suspicious_count(summary: RecentWindowSummary) -> int:
    return summary.failed_login_count + summary.off_hours_count + summary.repeated_failure_count


def _timestamp_sort_key(timestamp: datetime) -> int:
    return int(timestamp.timestamp())


def _format_coverage_window(start: datetime | None, end: datetime | None) -> str:
    if start and end:
        return f"{_format_timestamp(start)} to {_format_timestamp(end)}"
    if start:
        return f"From {_format_timestamp(start)}"
    if end:
        return f"Up to {_format_timestamp(end)}"
    return "Coverage unavailable"


def _format_span(start: datetime | None, end: datetime | None) -> str:
    if not start or not end:
        return "Coverage span unavailable"

    delta = end - start
    days = delta.days
    hours = delta.seconds // 3600
    minutes = (delta.seconds % 3600) // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if not days and minutes:
        parts.append(f"{minutes}m")
    return "Coverage span: " + " ".join(parts)


def _format_count(value: int) -> str:
    return f"{value:,}"


def _format_percentage(value: int, total: int, suffix: str) -> str:
    percent = _percentage_value(value, total)
    if suffix:
        return f"{percent}% {suffix}"
    return f"{percent}%"


def _percentage_value(value: int, total: int) -> int:
    if total <= 0:
        return 0
    return round((value / total) * 100)


def _format_unique_user_support(unique_user_count: int) -> str:
    if unique_user_count == 1:
        return "1 unique user"
    return f"{_format_count(unique_user_count)} unique users"


def _format_coverage_card_detail(start: datetime | None, end: datetime | None) -> str:
    if start and end:
        return f"Coverage: {_format_timestamp(start)} to {_format_timestamp(end)}"
    return "Coverage window not available"


def _format_mix_summary(interactive_count: int, non_interactive_count: int) -> str:
    return f"{_format_count(interactive_count)} interactive / {_format_count(non_interactive_count)} non-interactive"


def _format_mix_detail(interactive_count: int, non_interactive_count: int, total_events: int) -> str:
    if total_events <= 0:
        return "No observations in the current window"
    interactive_percent = _percentage_value(interactive_count, total_events)
    non_interactive_percent = _percentage_value(non_interactive_count, total_events)
    return f"{interactive_percent}% interactive, {non_interactive_percent}% non-interactive"


def _format_priority_hint(
    top_repeated_failures: list[RepeatedFailureFinding],
    top_off_hours_users: list[tuple[str, int]],
) -> str:
    if top_repeated_failures:
        return top_repeated_failures[0].username
    if top_off_hours_users:
        return top_off_hours_users[0][0]
    return "No clear priority"


def _format_priority_subtext(
    top_repeated_failures: list[RepeatedFailureFinding],
    top_off_hours_users: list[tuple[str, int]],
) -> str:
    if top_repeated_failures:
        finding = top_repeated_failures[0]
        return f"{_format_count(finding.failure_count)} failures in a 15 minute window"
    if top_off_hours_users:
        username, count = top_off_hours_users[0]
        return f"{username} has {_format_count(count)} off-hours events"
    return "There are no suspicious findings to prioritize"

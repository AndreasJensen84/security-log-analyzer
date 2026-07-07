"""These tests protect the loader boundary.

They show how raw Entra JSON becomes normalized `SignInEvent` objects, including
timezone conversion and file-versus-directory input handling.
"""

import json
from datetime import datetime
from zoneinfo import ZoneInfo

from security_log_analyzer.loader import load_signin_events


def test_load_signin_events_normalizes_entra_event(tmp_path):
    log_file = tmp_path / "signin_logs.json"
    log_file.write_text(
        json.dumps(
            [
                {
                    "createdDateTime": "2026-04-14T06:30:00Z",
                    "userPrincipalName": "alice@example.com",
                    "ipAddress": "192.168.1.10",
                    "status": {"errorCode": 0},
                    "isInteractive": True,
                },
            ]
        )
    )

    events = load_signin_events(log_file)

    assert len(events) == 1
    event = events[0]
    assert event.timestamp == datetime(2026, 4, 14, 8, 30, tzinfo=ZoneInfo("Europe/Oslo"))
    assert event.username == "alice@example.com"
    assert event.ip_address == "192.168.1.10"
    assert event.success is True
    assert event.interactive is True


def test_load_signin_events_preserves_failed_entra_metadata(tmp_path):
    log_file = tmp_path / "signin_logs.json"
    log_file.write_text(
        json.dumps(
            [
                {
                    "createdDateTime": "2026-04-14T10:15:00Z",
                    "userPrincipalName": "bob@example.com",
                    "ipAddress": "203.0.113.42",
                    "status": {
                        "errorCode": 50126,
                        "failureReason": "Invalid username or password.",
                    },
                    "isInteractive": False,
                },
            ]
        )
    )

    events = load_signin_events(log_file)

    assert len(events) == 1
    event = events[0]
    assert event.timestamp == datetime(2026, 4, 14, 12, 15, tzinfo=ZoneInfo("Europe/Oslo"))
    assert event.username == "bob@example.com"
    assert event.ip_address == "203.0.113.42"
    assert event.success is False
    assert event.interactive is False
    assert event.error_code == 50126
    assert event.failure_reason == "Invalid username or password."


def test_load_signin_events_combines_events_from_directory(tmp_path):
    exports_dir = tmp_path / "exports"
    exports_dir.mkdir()

    interactive_file = exports_dir / "interactive_signins.json"
    interactive_file.write_text(
        json.dumps(
            [
                {
                    "createdDateTime": "2026-04-14T07:00:00Z",
                    "userPrincipalName": "carol@example.com",
                    "ipAddress": "198.51.100.10",
                    "status": {"errorCode": 0},
                    "isInteractive": True,
                },
            ]
        )
    )

    noninteractive_file = exports_dir / "noninteractive_signins.json"
    noninteractive_file.write_text(
        json.dumps(
            [
                {
                    "createdDateTime": "2026-04-14T08:00:00Z",
                    "userPrincipalName": "dave@example.com",
                    "ipAddress": "198.51.100.11",
                    "status": {"errorCode": 50074},
                    "isInteractive": False,
                },
            ]
        )
    )

    events = load_signin_events(exports_dir)

    assert len(events) == 2
    assert [event.username for event in events] == [
        "carol@example.com",
        "dave@example.com",
    ]
    assert [event.interactive for event in events] == [True, False]

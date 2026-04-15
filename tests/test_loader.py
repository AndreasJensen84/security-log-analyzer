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

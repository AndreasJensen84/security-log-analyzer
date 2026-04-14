import json

from security_log_analyzer.loader import load_signin_events


def test_load_signin_events_returns_event_objects(tmp_path):
    log_file = tmp_path / "signin_logs.json"
    log_file.write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-04-14T08:30:00",
                    "username": "alice",
                    "ip_address": "192.168.1.10",
                    "success": True,
                },
                {
                    "timestamp": "2026-04-14T08:45:00",
                    "username": "bob",
                    "ip_address": "192.168.1.20",
                    "success": False,
                },
            ]
        )
    )

    events = load_signin_events(log_file)

    assert len(events) == 2
    assert events[0].username == "alice"
    assert events[1].success is False

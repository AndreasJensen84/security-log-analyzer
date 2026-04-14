import json
from pathlib import Path

from security_log_analyzer.models import SignInEvent


def load_signin_events(file_path: str | Path) -> list[SignInEvent]:
    with open(file_path, "r", encoding="utf-8") as file:
        raw_events = json.load(file)

    events = []
    for raw_event in raw_events:
        events.append(
            SignInEvent(
                timestamp=raw_event["timestamp"],
                username=raw_event["username"],
                ip_address=raw_event["ip_address"],
                success=raw_event["success"],
            )
        )

    return events

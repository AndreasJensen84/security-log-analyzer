"""Read raw Entra exports and turn them into internal events.

This is the boundary between messy input files and the clean Python objects
used by the analyzer. A learner should notice how the code normalizes field
names, timestamps, and success status before any analysis happens.
"""

import json
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo

from security_log_analyzer.models import SignInEvent

OSLO_TIMEZONE = ZoneInfo("Europe/Oslo")


def normalize_signin_event(raw_event: dict) -> SignInEvent:
    created_date_time = raw_event["createdDateTime"].replace("Z", "+00:00")
    timestamp_utc = datetime.fromisoformat(created_date_time)
    timestamp_local = timestamp_utc.astimezone(OSLO_TIMEZONE)

    return SignInEvent(
        timestamp=timestamp_local,
        username=raw_event["userPrincipalName"],
        ip_address=raw_event["ipAddress"],
        success=raw_event["status"]["errorCode"] == 0,
        interactive=raw_event["isInteractive"],
        error_code=raw_event["status"]["errorCode"],
        failure_reason=raw_event["status"].get("failureReason"),
    )


def load_signin_events(file_path: str | Path) -> list[SignInEvent]:
    path = Path(file_path)
    raw_events: list[dict] = []

    if path.is_dir():
        for json_file in sorted(path.iterdir()):
            if json_file.is_file() and json_file.suffix == ".json":
                with open(json_file, "r", encoding="utf-8") as file:
                    raw_events.extend(json.load(file))
    else:
        with open(path, "r", encoding="utf-8") as file:
            raw_events = json.load(file)

    return [normalize_signin_event(raw_event) for raw_event in raw_events]

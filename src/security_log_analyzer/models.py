from dataclasses import dataclass
from datetime import datetime


@dataclass
class SignInEvent:
    timestamp: datetime
    username: str
    ip_address: str
    success: bool
    interactive: bool

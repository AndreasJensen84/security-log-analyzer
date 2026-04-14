from dataclasses import dataclass


@dataclass
class SignInEvent:
    timestamp: str
    username: str
    ip_address: str
    success: bool

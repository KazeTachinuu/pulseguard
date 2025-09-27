"""Data models for PulseGuard."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class PasswordEntry:
    """A password entry with metadata.

    Attributes:
        name: Unique identifier for the password entry
        username: Username or email for the account
        password: The password
        url: Optional URL for the service
        notes: Optional notes about the entry
        created_at: Timestamp when the entry was created
    """

    name: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: Optional[datetime] = None

    def __post_init__(self):
        """Initialize created_at if not provided."""
        if self.created_at is None:
            self.created_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordEntry":
        """Create from dictionary for JSON deserialization."""
        if "created_at" in data and isinstance(data["created_at"], str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        return cls(**data)

"""Data models for password management."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class PasswordEntry:
    """A password entry with metadata."""

    name: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: Optional[datetime] = None

    def __post_init__(self):
        """Set creation timestamp if not provided."""
        if self.created_at is None:
            self.created_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON storage."""
        return {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "created_at": (
                self.created_at.isoformat() if self.created_at else None
            ),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordEntry":
        """Create PasswordEntry from dictionary."""
        if "created_at" in data and isinstance(data["created_at"], str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        return cls(**data)

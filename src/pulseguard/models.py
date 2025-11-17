"""Data models for password management."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .config import Config


@dataclass
class PasswordEntry:
    """A password entry with metadata and organization features."""

    name: str
    username: str
    password: str
    url: str = ""
    notes: str = ""

    # Organization & quick access
    category: str = (
        Config.DEFAULT_CATEGORY
    )  # Personal, Work, Banking, Social, Development, etc.
    tags: List[str] = field(default_factory=list)
    favorite: bool = False

    # Temporal tracking
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_accessed: Optional[datetime] = None
    access_count: int = 0

    def __post_init__(self):
        """Set timestamps if not provided."""
        now = datetime.now(timezone.utc)
        if self.created_at is None:
            self.created_at = now
        if self.updated_at is None:
            self.updated_at = now

    def mark_accessed(self) -> None:
        """Update access tracking when entry is retrieved."""
        self.last_accessed = datetime.now(timezone.utc)
        self.access_count += 1

    def mark_updated(self) -> None:
        """Update modification timestamp when entry is changed."""
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON storage."""
        return {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "category": self.category,
            "tags": self.tags,
            "favorite": self.favorite,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_accessed": (
                self.last_accessed.isoformat() if self.last_accessed else None
            ),
            "access_count": self.access_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordEntry":
        """Create PasswordEntry from dictionary."""
        # Convert ISO datetime strings
        for dt_field in ["created_at", "updated_at", "last_accessed"]:
            if dt_field in data and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])

        # Set defaults for backward compatibility (not needed now but good practice)
        data.setdefault("category", Config.DEFAULT_CATEGORY)
        data.setdefault("tags", [])
        data.setdefault("favorite", False)
        data.setdefault("access_count", 0)

        return cls(**data)

    def copy_with_updates(self, **updates) -> "PasswordEntry":
        """Create a new entry with updated fields, preserving unchanged ones."""
        data = {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "category": self.category,
            "tags": self.tags.copy(),  # Deep copy to avoid shared mutable state
            "favorite": self.favorite,
        }
        data.update(updates)
        return PasswordEntry(**data)  # type: ignore[arg-type]

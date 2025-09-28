"""Data models - the core data structures for password management.

Why these models:
- PasswordEntry contains all necessary metadata for password management
- Dataclass provides clean, readable structure with automatic methods
- JSON serialization enables simple file-based persistence
- Timestamps provide audit trail for password entries
- Optional fields allow flexible password organization
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class PasswordEntry:
    """A complete password entry with all necessary metadata.
    
    Why this design:
    - Contains everything needed for password management in one place
    - Dataclass provides automatic __init__, __repr__, and comparison methods
    - Optional fields (url, notes) allow flexible organization
    - Timestamps provide audit trail for security and debugging
    - JSON serialization enables simple file-based storage
    
    This is the core data structure - all password operations work with this model.
    """

    name: str  # Unique identifier - used for lookups and display
    username: str  # Username or email for the account
    password: str  # The actual password (stored in plain text for simplicity)
    url: str = ""  # Optional URL for the service (helps with organization)
    notes: str = ""  # Optional notes (reminders, security hints, etc.)
    created_at: Optional[datetime] = None  # When this entry was created

    def __post_init__(self):
        """Set creation timestamp if not provided.
        
        Why this approach:
        - Automatic timestamping ensures every entry has a creation time
        - Allows manual timestamp setting for testing or data migration
        - Provides audit trail for security and debugging
        """
        if self.created_at is None:
            self.created_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON file storage.
        
        Why this method:
        - Enables simple file-based persistence without complex ORM
        - ISO format timestamps are human-readable and sortable
        - Provides clean separation between data model and storage format
        """
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
        """Create PasswordEntry from dictionary (JSON deserialization).
        
        Why this method:
        - Enables loading password entries from JSON files
        - Handles timestamp conversion from ISO format strings
        - Provides type-safe deserialization with validation
        """
        # Convert ISO timestamp string back to datetime object
        if "created_at" in data and isinstance(data["created_at"], str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        return cls(**data)

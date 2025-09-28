"""Vault management - secure storage and retrieval of password entries.

Why this design:
- Simple JSON file storage - no complex database setup required
- Automatic persistence - changes are saved immediately
- In-memory operations - fast access for interactive use
- Error handling - graceful handling of corrupted or missing files
- Search functionality - find passwords by name or username

The vault provides a clean interface for all password operations while
handling the complexity of file I/O and error recovery internally.
"""

import json
import os
from pathlib import Path
from typing import List, Optional

from .config import config
from .models import PasswordEntry


class VaultError(Exception):
    """Base exception for all vault-related errors.
    
    Why this hierarchy:
    - Provides specific error types for different failure modes
    - Enables targeted error handling in calling code
    - Makes debugging easier with clear error categories
    """

    pass


class VaultNotFoundError(VaultError):
    """Raised when vault file doesn't exist.
    
    Why this specific error:
    - Distinguishes between missing file and corrupted file
    - Enables different handling for first-time setup vs errors
    """

    pass


class VaultCorruptedError(VaultError):
    """Raised when vault file exists but is unreadable.
    
    Why this specific error:
    - Indicates file exists but contains invalid data
    - Enables recovery suggestions or data migration
    - Helps users understand the difference from missing file
    """

    pass


class Vault:
    """Password vault with automatic JSON file persistence.
    
    Why this design:
    - In-memory storage provides fast access for interactive use
    - Automatic persistence ensures data is never lost
    - JSON format is human-readable and debuggable
    - Simple interface hides complexity of file I/O and error handling
    
    All password operations work on in-memory data, with changes
    automatically saved to disk for persistence.
    """

    def __init__(self, file_path: Optional[str] = None):
        """Initialize vault with optional custom file path.
        
        Why this approach:
        - Optional file_path enables testing with temporary files
        - Default path from config provides zero-configuration experience
        - Automatic loading ensures vault is ready to use immediately
        """
        self.file_path = file_path or config.vault_path
        self.entries: List[PasswordEntry] = []  # In-memory storage for fast access
        self._load()  # Load existing data from file

    def _load(self) -> None:
        """Load entries from JSON file."""
        if not os.path.exists(self.file_path):
            return

        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return  # Empty file is OK
                data = json.loads(content)
                for entry_data in data.get("entries", []):
                    self.entries.append(PasswordEntry.from_dict(entry_data))
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise VaultCorruptedError(f"Vault file is corrupted: {e}")

    def _save(self) -> None:
        """Save entries to JSON file."""
        config.ensure_vault_dir()
        data = {"entries": [entry.to_dict() for entry in self.entries]}
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def add(self, entry: PasswordEntry) -> None:
        """Add or update a password entry.

        Args:
            entry: The password entry to add
        """
        self.remove(entry.name)
        self.entries.append(entry)
        self._save()

    def remove(self, name: str) -> bool:
        """Remove a password entry by name.

        Args:
            name: Name of the entry to remove

        Returns:
            True if entry was removed, False if not found
        """
        original_count = len(self.entries)
        self.entries = [e for e in self.entries if e.name != name]
        if len(self.entries) < original_count:
            self._save()
            return True
        return False

    def get(self, name: str) -> Optional[PasswordEntry]:
        """Get a password entry by name.

        Args:
            name: Name of the entry to retrieve

        Returns:
            PasswordEntry if found, None otherwise
        """
        return next((e for e in self.entries if e.name == name), None)

    def get_all(self) -> List[PasswordEntry]:
        """Get all password entries.

        Returns:
            List of all entries
        """
        return self.entries.copy()

    def search(self, query: str) -> List[PasswordEntry]:
        """Search entries by name or username.

        Args:
            query: Search query (case-insensitive)

        Returns:
            List of matching entries
        """
        query_lower = query.lower()
        return [
            e
            for e in self.entries
            if query_lower in e.name.lower() or query_lower in e.username.lower()
        ]

    def count(self) -> int:
        """Get the number of entries.

        Returns:
            Number of entries
        """
        return len(self.entries)

    def exists(self, name: str) -> bool:
        """Check if an entry exists.

        Args:
            name: Name of the entry to check

        Returns:
            True if entry exists, False otherwise
        """
        return self.get(name) is not None

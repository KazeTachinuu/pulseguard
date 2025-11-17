"""Vault management - secure storage and retrieval of password entries."""

import base64
import hashlib
import json
import os
import stat
import tempfile
from typing import List, Optional

from . import SCHEMA_VERSION, __version__
from .config import Config, config
from .crypto import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    decrypt_data,
    encrypt_data,
)
from .models import PasswordEntry


class VaultError(Exception):
    """Base exception for vault-related errors."""

    pass


class VaultNotFoundError(VaultError):
    """Raised when vault file doesn't exist."""

    pass


class VaultCorruptedError(VaultError):
    """Raised when vault file exists but is unreadable."""

    pass


class VaultEncryptionError(VaultError):
    """Raised when vault encryption fails."""

    pass


class VaultDecryptionError(VaultError):
    """Raised when vault decryption fails."""

    pass


class Vault:
    """Password vault with encrypted JSON file persistence.

    All vaults are encrypted with AES-128 (Fernet) + Argon2id key derivation.
    Master password is required for all operations.
    """

    def __init__(self, file_path: Optional[str] = None, *, master_password: str):
        """Initialize vault with encrypted storage.

        Args:
            file_path: Optional custom vault file path (defaults to config.vault_path)
            master_password: Master password for encryption (required)

        Raises:
            VaultDecryptionError: If vault exists but cannot be decrypted
            VaultCorruptedError: If vault file is corrupted or invalid
        """
        self.file_path = file_path or config.vault_path
        self.master_password = master_password
        self.entries: List[PasswordEntry] = []
        self._salt: Optional[bytes] = None
        self._dirty = False

        # Version tracking
        self.schema_version: int = 1
        self.created_with: Optional[str] = None
        self.last_modified_with: Optional[str] = None

        self._load()

    def _load(self) -> None:
        """Load and decrypt entries from encrypted JSON file."""
        if not os.path.exists(self.file_path):
            return

        try:
            with open(self.file_path, "rb") as f:
                raw_content = f.read()

            if not raw_content:
                return

            try:
                content = raw_content.decode("utf-8").strip()
            except UnicodeDecodeError:
                raise VaultCorruptedError("Vault file has invalid encoding")

            # All vault files must be encrypted
            try:
                data = json.loads(content)
                if "salt" not in data or "data" not in data:
                    raise VaultCorruptedError(
                        "Vault file is missing required encrypted fields."
                    )

                self._salt = base64.b64decode(data["salt"])
                ciphertext = base64.b64decode(data["data"])

                plaintext = decrypt_data(ciphertext, self.master_password, self._salt)
                decrypted_content = plaintext.decode("utf-8")
                vault_data = json.loads(decrypted_content)

            except (DecryptionError, CryptoError) as e:
                raise VaultDecryptionError(f"Failed to decrypt vault: {e}") from e
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                raise VaultCorruptedError(
                    f"Vault file is corrupted or invalid: {e}"
                ) from e

            # Load version metadata (with defaults for backward compatibility)
            self.schema_version = vault_data.get("schema_version", 1)
            self.created_with = vault_data.get("created_with")
            self.last_modified_with = vault_data.get("last_modified_with")

            for entry_data in vault_data.get("entries", []):
                self.entries.append(PasswordEntry.from_dict(entry_data))

        except (VaultDecryptionError, VaultCorruptedError):
            raise
        except (OSError, IOError) as e:
            raise VaultCorruptedError(f"Failed to read vault file: {e}") from e

    def _save(self) -> None:
        """Save and encrypt entries to JSON file with atomic write."""
        config.ensure_vault_dir()

        # Set created_with on first save
        if self.created_with is None:
            self.created_with = __version__

        # Always update last_modified_with
        self.last_modified_with = __version__

        vault_data = {
            "schema_version": SCHEMA_VERSION,
            "created_with": self.created_with,
            "last_modified_with": self.last_modified_with,
            "entries": [entry.to_dict() for entry in self.entries],
        }
        json_content = json.dumps(vault_data, indent=2)

        # Create temp file in same directory for atomic move
        vault_dir = os.path.dirname(self.file_path)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=vault_dir, prefix=".vault_tmp_", suffix=".json"
        )

        try:
            # All vaults are always encrypted
            ciphertext, salt = encrypt_data(
                json_content.encode("utf-8"), self.master_password, self._salt
            )
            self._salt = salt

            encrypted_vault = {
                "salt": base64.b64encode(salt).decode("ascii"),
                "data": base64.b64encode(ciphertext).decode("ascii"),
            }

            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(encrypted_vault, f, indent=2)

            # Set permissions (0600)
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)

            # Atomic replace (works on Unix and Windows)
            os.replace(temp_path, self.file_path)

        except (EncryptionError, CryptoError) as e:
            self._cleanup_temp(temp_path)
            raise VaultEncryptionError(f"Failed to encrypt vault: {e}") from e
        except (OSError, IOError) as e:
            self._cleanup_temp(temp_path)
            raise VaultError(f"Failed to save vault: {e}") from e
        except Exception as e:
            self._cleanup_temp(temp_path)
            raise VaultError(f"Unexpected error saving vault: {e}") from e

    def _cleanup_temp(self, temp_path: str) -> None:
        """Remove temporary file if it exists."""
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass

    def save_if_dirty(self) -> bool:
        """Save vault if there are unsaved changes."""
        if self._dirty:
            self._save()
            self._dirty = False
            return True
        return False

    def add(self, entry: PasswordEntry, update_timestamp: bool = True) -> None:
        """Add or update a password entry."""
        if update_timestamp:
            entry.mark_updated()
        self.remove(entry.name)
        self.entries.append(entry)
        self._save()

    def remove(self, name: str) -> bool:
        """Remove a password entry by name."""
        original_count = len(self.entries)
        self.entries = [e for e in self.entries if e.name != name]
        if len(self.entries) < original_count:
            self._save()
            return True
        return False

    def get(self, name: str, track_access: bool = True) -> Optional[PasswordEntry]:
        """Get password entry by name. Call save_if_dirty() to persist access tracking."""
        entry = next((e for e in self.entries if e.name == name), None)
        if entry and track_access:
            entry.mark_accessed()
            self._dirty = True
        return entry

    def get_all(self) -> List[PasswordEntry]:
        """Get all password entries."""
        return self.entries.copy()

    def get_favorites(self) -> List[PasswordEntry]:
        """Get all favorite entries."""
        return [e for e in self.entries if e.favorite]

    def get_recent(self, limit: int = Config.MAX_RECENT_ENTRIES) -> List[PasswordEntry]:
        """Get recently accessed entries."""
        accessed = [e for e in self.entries if e.last_accessed is not None]
        # Sort by last_accessed descending (most recent first)
        # Type checker doesn't narrow None in lambda, but we've filtered above
        accessed.sort(key=lambda e: e.last_accessed or e.created_at, reverse=True)  # type: ignore[arg-type, return-value]
        return accessed[:limit]

    def search(self, query: str) -> List[PasswordEntry]:
        """Search entries by name, username, URL, or notes."""
        query_lower = query.lower()
        return [
            e
            for e in self.entries
            if query_lower in e.name.lower()
            or query_lower in e.username.lower()
            or query_lower in (e.url or "").lower()
            or query_lower in (e.notes or "").lower()
        ]

    def search_by_tag(self, tag: str) -> List[PasswordEntry]:
        """Search entries by tag."""
        tag_lower = tag.lower()
        return [e for e in self.entries if any(t.lower() == tag_lower for t in e.tags)]

    def get_all_tags(self) -> List[str]:
        """Get all unique tags used in vault."""
        tags = set()
        for entry in self.entries:
            tags.update(entry.tags)
        return sorted(list(tags))

    def get_all_categories(self) -> List[str]:
        """Get all unique categories used in vault, sorted."""
        categories = list(
            set((e.category or Config.DEFAULT_CATEGORY) for e in self.entries)
        )
        return sort_categories_uncategorized_last(categories)

    def get_by_category(self, category: str) -> List[PasswordEntry]:
        """Get all entries in a specific category."""
        return [e for e in self.entries if e.category == category]

    def get_entries_by_category(self) -> dict[str, List[PasswordEntry]]:
        """Get entries grouped by category."""
        by_category: dict[str, List[PasswordEntry]] = {}
        for entry in self.entries:
            cat = entry.category or Config.DEFAULT_CATEGORY
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(entry)
        return by_category

    def count(self) -> int:
        """Get the number of entries without loading them."""
        return len(self.entries)


# Vault analysis and maintenance utilities


def find_duplicates(vault: Vault) -> List[tuple[str, List[PasswordEntry]]]:
    """
    Find duplicate entries based on username+url combination.

    Returns list of tuples: (key, [entries]) where key is "username@url"
    """
    entries = vault.get_all()
    groups: dict[tuple[str, Optional[str]], List[PasswordEntry]] = {}

    for entry in entries:
        # Use tuple as key to avoid collisions (e.g., url="no-url" vs url=None)
        key = (entry.username, entry.url)
        if key not in groups:
            groups[key] = []
        groups[key].append(entry)

    # Return formatted string keys for display
    return [
        (f"{user}@{url or 'None'}", entries_list)
        for (user, url), entries_list in groups.items()
        if len(entries_list) > 1
    ]


def find_reused_passwords(vault: Vault) -> List[tuple[int, List[PasswordEntry]]]:
    """
    Find passwords that are reused across multiple entries.

    Returns list of tuples: (count, [entries using the same password])
    Note: Actual passwords are not returned to prevent accidental exposure.
    """
    entries = vault.get_all()
    password_usage: dict[str, List[PasswordEntry]] = {}

    for entry in entries:
        # Hash password to avoid storing plaintext as dict keys
        pwd_hash = hashlib.sha256(entry.password.encode()).hexdigest()
        if pwd_hash not in password_usage:
            password_usage[pwd_hash] = []
        password_usage[pwd_hash].append(entry)

    # Return only passwords used more than once (count, entries) without exposing password
    return [
        (len(entries_list), entries_list)
        for entries_list in password_usage.values()
        if len(entries_list) > 1
    ]


def get_vault_stats(vault: Vault) -> dict:
    """
    Get vault statistics.

    Returns:
        Dictionary with statistics:
        - total: Total number of entries
        - duplicates: Number of duplicate groups
        - reused: Number of reused passwords
    """
    entries = vault.get_all()
    duplicates = find_duplicates(vault)
    reused = find_reused_passwords(vault)

    return {
        "total": len(entries),
        "duplicates": len(duplicates),
        "reused": len(reused),
    }


def sort_categories_uncategorized_last(categories: List[str]) -> List[str]:
    """Sort categories alphabetically with DEFAULT_CATEGORY at the end."""
    sorted_cats = sorted(c for c in categories if c != Config.DEFAULT_CATEGORY)
    if Config.DEFAULT_CATEGORY in categories:
        sorted_cats.append(Config.DEFAULT_CATEGORY)
    return sorted_cats

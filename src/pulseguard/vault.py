"""Vault management - secure storage and retrieval of password entries."""

import base64
import hashlib
import json
import os
import stat
import tempfile
import warnings
from typing import List, Optional

from .config import config
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


class VaultPlaintextWarning(UserWarning):
    """Warning for plaintext vault detected."""

    pass


class Vault:
    """Password vault with encrypted JSON file persistence."""

    def __init__(
        self, file_path: Optional[str] = None, master_password: Optional[str] = None
    ):
        """Initialize vault with optional custom file path and master password."""
        self.file_path = file_path or config.vault_path
        self.master_password = master_password
        self.entries: List[PasswordEntry] = []
        self._salt: Optional[bytes] = None
        self._load()

    def _is_encrypted_file(self, content: str) -> bool:
        """Check if file content is encrypted format."""
        try:
            data = json.loads(content)
            return data.get("encrypted", False) and "salt" in data and "data" in data
        except (json.JSONDecodeError, KeyError):
            return False

    def _load(self) -> None:
        """Load entries from JSON file (encrypted or plaintext)."""
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

            if self._is_encrypted_file(content):
                if not self.master_password:
                    raise VaultDecryptionError(
                        "Vault is encrypted but no master password provided"
                    )

                try:
                    data = json.loads(content)
                    self._salt = base64.b64decode(data["salt"])
                    ciphertext = base64.b64decode(data["data"])

                    plaintext = decrypt_data(
                        ciphertext, self.master_password, self._salt
                    )
                    decrypted_content = plaintext.decode("utf-8")
                    vault_data = json.loads(decrypted_content)

                except (DecryptionError, CryptoError) as e:
                    raise VaultDecryptionError(f"Failed to decrypt vault: {e}") from e
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    raise VaultCorruptedError(
                        f"Decrypted vault has invalid format: {e}"
                    ) from e

            else:
                warnings.warn(
                    "SECURITY WARNING: Vault is stored in PLAINTEXT. "
                    "Passwords are NOT encrypted. Please migrate to encrypted vault.",
                    VaultPlaintextWarning,
                    stacklevel=2,
                )
                try:
                    vault_data = json.loads(content)
                except json.JSONDecodeError as e:
                    raise VaultCorruptedError(
                        f"Vault file has invalid JSON: {e}"
                    ) from e

            for entry_data in vault_data.get("entries", []):
                self.entries.append(PasswordEntry.from_dict(entry_data))

        except (VaultDecryptionError, VaultCorruptedError):
            raise
        except (OSError, IOError) as e:
            raise VaultCorruptedError(f"Failed to read vault file: {e}") from e

    def _save(self) -> None:
        """Save entries to JSON file with atomic write (encrypted if master password set)."""
        config.ensure_vault_dir()

        vault_data = {"entries": [entry.to_dict() for entry in self.entries]}
        json_content = json.dumps(vault_data, indent=2)

        # Create temp file in same directory for atomic move
        vault_dir = os.path.dirname(self.file_path)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=vault_dir, prefix=".vault_tmp_", suffix=".json"
        )

        try:
            if self.master_password is not None:
                ciphertext, salt = encrypt_data(
                    json_content.encode("utf-8"), self.master_password, self._salt
                )
                self._salt = salt

                encrypted_vault = {
                    "encrypted": True,
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "data": base64.b64encode(ciphertext).decode("ascii"),
                }

                with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                    json.dump(encrypted_vault, f, indent=2)
            else:
                warnings.warn(
                    "SECURITY WARNING: Saving vault in PLAINTEXT. "
                    "Passwords are NOT encrypted!",
                    VaultPlaintextWarning,
                    stacklevel=2,
                )
                with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                    f.write(json_content)

            # Set secure permissions (0600 - owner read/write only)
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

    def add(self, entry: PasswordEntry) -> None:
        """Add or update a password entry."""
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

    def get(self, name: str) -> Optional[PasswordEntry]:
        """Get a password entry by name."""
        return next((e for e in self.entries if e.name == name), None)

    def get_all(self) -> List[PasswordEntry]:
        """Get all password entries."""
        return self.entries.copy()

    def search(self, query: str) -> List[PasswordEntry]:
        """Search entries by name or username."""
        query_lower = query.lower()
        return [
            e
            for e in self.entries
            if query_lower in e.name.lower() or query_lower in e.username.lower()
        ]

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
    groups = {}

    for entry in entries:
        # Use tuple as key to avoid collisions (e.g., url="no-url" vs url=None)
        key = (entry.username, entry.url)
        if key not in groups:
            groups[key] = []
        groups[key].append(entry)

    # Return formatted string keys for display
    return [(f"{user}@{url or 'None'}", entries_list) for (user, url), entries_list in groups.items() if len(entries_list) > 1]


def find_reused_passwords(vault: Vault) -> List[tuple[int, List[PasswordEntry]]]:
    """
    Find passwords that are reused across multiple entries.

    Returns list of tuples: (count, [entries using the same password])
    Note: Actual passwords are not returned to prevent accidental exposure.
    """
    entries = vault.get_all()
    password_usage = {}

    for entry in entries:
        # Hash password to avoid storing plaintext as dict keys
        pwd_hash = hashlib.sha256(entry.password.encode()).hexdigest()
        if pwd_hash not in password_usage:
            password_usage[pwd_hash] = []
        password_usage[pwd_hash].append(entry)

    # Return only passwords used more than once (count, entries) without exposing password
    return [(len(entries_list), entries_list) for entries_list in password_usage.values() if len(entries_list) > 1]


def get_vault_stats(vault: Vault) -> dict:
    """
    Get comprehensive vault statistics.

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

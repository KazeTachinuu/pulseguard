"""PulseGuard password manager."""

# Version constants (must be defined before imports to avoid circular dependencies)
__version__ = "0.4.3"
SCHEMA_VERSION = 1

# ruff: noqa: E402
from .config import config
from .models import PasswordEntry
from .vault import (
    Vault,
    VaultCorruptedError,
    VaultDecryptionError,
    VaultEncryptionError,
    VaultError,
    VaultNotFoundError,
    find_duplicates,
    find_reused_passwords,
    get_vault_stats,
)

__all__ = [
    "PasswordEntry",
    "Vault",
    "config",
    "VaultError",
    "VaultNotFoundError",
    "VaultCorruptedError",
    "VaultEncryptionError",
    "VaultDecryptionError",
    "find_duplicates",
    "find_reused_passwords",
    "get_vault_stats",
]

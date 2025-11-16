"""PulseGuard password manager."""

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

__version__ = "0.1.0"
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

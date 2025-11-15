"""PulseGuard - A minimal, secure password manager."""

from .config import config
from .models import PasswordEntry
from .vault import (
    Vault,
    VaultCorruptedError,
    VaultDecryptionError,
    VaultEncryptionError,
    VaultError,
    VaultNotFoundError,
    VaultPlaintextWarning,
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
    "VaultPlaintextWarning",
    "find_duplicates",
    "find_reused_passwords",
    "get_vault_stats",
]

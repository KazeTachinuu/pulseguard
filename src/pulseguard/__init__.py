"""PulseGuard - A minimal, secure password manager."""

from .config import config
from .console import Console
from .models import PasswordEntry
from .vault import (
    Vault,
    VaultCorruptedError,
    VaultDecryptionError,
    VaultEncryptionError,
    VaultError,
    VaultNotFoundError,
    VaultPlaintextWarning,
)

__version__ = "0.1.0"
__all__ = [
    "PasswordEntry",
    "Vault",
    "Console",
    "config",
    "VaultError",
    "VaultNotFoundError",
    "VaultCorruptedError",
    "VaultEncryptionError",
    "VaultDecryptionError",
    "VaultPlaintextWarning",
]

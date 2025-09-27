"""PulseGuard - Simple password manager.

A minimal, secure password manager with CLI and interactive console.
"""

from .models import PasswordEntry
from .vault import Vault
from .console import Console
from .config import config

__version__ = "0.1.0"
__all__ = ["PasswordEntry", "Vault", "Console", "config"]

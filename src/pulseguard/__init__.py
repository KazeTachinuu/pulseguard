"""PulseGuard - Simple password manager.

A minimal, secure password manager with CLI and interactive console.
"""

from .cli import PasswordEntry, Vault, Console

__version__ = "0.1.0"
__all__ = ["PasswordEntry", "Vault", "Console"]
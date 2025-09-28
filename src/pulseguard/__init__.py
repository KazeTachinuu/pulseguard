"""PulseGuard - A minimal, secure password manager.

Why: Traditional password managers are bloated. This one is simple, fast, and scriptable.
Design: Zero config, data-driven commands, Unix philosophy.
"""

from .models import PasswordEntry
from .vault import Vault
from .console import Console
from .config import config

__version__ = "0.1.0"
__all__ = ["PasswordEntry", "Vault", "Console", "config"]

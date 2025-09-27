"""Configuration management for PulseGuard."""

import os
from pathlib import Path
from typing import Optional


class Config:
    """Configuration settings for PulseGuard."""

    # Default values
    DEFAULT_VAULT_PATH = "~/.pulseguard/vault.json"
    DEFAULT_PROMPT = "pulseguard> "
    DEFAULT_INTRO = "PulseGuard Console. Type 'help' for commands or 'quit' to exit."

    # Environment variable names
    VAULT_PATH_ENV = "PULSEGUARD_VAULT_PATH"

    def __init__(self):
        """Initialize configuration with environment variable support."""
        self.vault_path = self._get_vault_path()
        self.prompt = self.DEFAULT_PROMPT
        self.intro = self.DEFAULT_INTRO

    def _get_vault_path(self) -> str:
        """Get vault path from environment or use default."""
        env_path = os.getenv(self.VAULT_PATH_ENV)
        if env_path:
            return os.path.expanduser(env_path)
        return os.path.expanduser(self.DEFAULT_VAULT_PATH)

    def get_vault_dir(self) -> Path:
        """Get the directory containing the vault file."""
        return Path(self.vault_path).parent

    def ensure_vault_dir(self) -> None:
        """Ensure the vault directory exists."""
        self.get_vault_dir().mkdir(parents=True, exist_ok=True)


# Global config instance
config = Config()

"""Configuration management for PulseGuard."""

import os
from pathlib import Path


class Config:
    """Configuration settings for PulseGuard."""

    DEFAULT_VAULT_PATH = "~/.pulseguard/vault.json"
    VAULT_PATH_ENV = "PULSEGUARD_VAULT_PATH"
    DEFAULT_CATEGORY = "Uncategorized"

    # Security constants
    MAX_PASSWORD_ATTEMPTS = 3
    MAX_PASSWORD_LENGTH = 128  # Maximum character count
    MAX_PASSWORD_BYTES = 512  # Maximum byte length (UTF-8 encoded)

    # Display constants
    MAX_RECENT_ENTRIES = 5
    MAX_URL_DISPLAY_LENGTH = 35

    def __init__(self):
        """Initialize configuration with environment variable support."""
        self.vault_path = self._get_vault_path()

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


config = Config()

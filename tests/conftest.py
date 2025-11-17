"""Shared pytest fixtures for all tests."""

import os
import tempfile
from typing import Generator

import pytest

from pulseguard.crypto import generate_salt
from pulseguard.models import PasswordEntry
from pulseguard.vault import Vault

# ============================================================================
# File System Fixtures
# ============================================================================


@pytest.fixture
def temp_dir() -> Generator[str, None, None]:
    """Provide a temporary directory that's automatically cleaned up."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def vault_path(temp_dir: str) -> str:
    """Provide a temporary vault file path."""
    return os.path.join(temp_dir, "vault.json")


# ============================================================================
# Vault Fixtures
# ============================================================================


@pytest.fixture
def master_password() -> str:
    """Standard master password for tests."""
    return "TestMasterPassword123!"


@pytest.fixture
def vault(vault_path: str, master_password: str) -> Vault:
    """Provide an empty vault instance."""
    return Vault(file_path=vault_path, master_password=master_password)


@pytest.fixture
def vault_with_entries(vault: Vault) -> Vault:
    """Provide a vault with sample entries."""
    vault.add(PasswordEntry("Gmail", "user@gmail.com", "GmailPass123!"))
    vault.add(PasswordEntry("GitHub", "developer", "GitHubToken456!"))
    vault.add(
        PasswordEntry(
            "AWS",
            "admin",
            "AwsSecret789!",
            url="https://console.aws.amazon.com",
            notes="Production account",
        )
    )
    return vault


# ============================================================================
# Crypto Fixtures
# ============================================================================


@pytest.fixture
def salt() -> bytes:
    """Provide a random salt for testing."""
    return generate_salt()


@pytest.fixture
def test_data() -> bytes:
    """Provide test data for encryption/decryption."""
    return b"Secret test data for encryption"


# ============================================================================
# Model Fixtures
# ============================================================================


@pytest.fixture
def sample_entry() -> PasswordEntry:
    """Provide a sample password entry."""
    return PasswordEntry(
        name="TestService",
        username="testuser@example.com",
        password="SecurePassword123!",
        url="https://example.com",
        notes="Sample notes",
    )

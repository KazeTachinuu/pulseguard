"""Simple tests for PulseGuard.

Tests the core functionality of the password manager.
"""

import os
import tempfile

from pulseguard import PasswordEntry, Vault


def test_password_entry_creation():
    """Test PasswordEntry creation and initialization."""
    entry = PasswordEntry("Gmail", "user@gmail.com", "pass123")
    assert entry.name == "Gmail"
    assert entry.username == "user@gmail.com"
    assert entry.password == "pass123"
    assert entry.url == ""
    assert entry.notes == ""
    assert entry.created_at is not None


def test_password_entry_with_optional_fields():
    """Test PasswordEntry with optional fields."""
    entry = PasswordEntry(
        "GitHub", "dev", "token123", url="https://github.com", notes="Personal account"
    )
    assert entry.name == "GitHub"
    assert entry.username == "dev"
    assert entry.password == "token123"
    assert entry.url == "https://github.com"
    assert entry.notes == "Personal account"


def test_vault_operations():
    """Test Vault CRUD operations."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        temp_file = f.name

    try:
        vault = Vault(temp_file)

        # Test adding entry
        entry = PasswordEntry("Gmail", "user@gmail.com", "pass123")
        vault.add(entry)
        assert len(vault.entries) == 1

        # Test getting entry
        retrieved = vault.get("Gmail")
        assert retrieved is not None
        assert retrieved.name == "Gmail"
        assert retrieved.username == "user@gmail.com"

        # Test searching
        results = vault.search("gmail")
        assert len(results) == 1
        assert results[0].name == "Gmail"

        # Test case-insensitive search
        results = vault.search("GMAIL")
        assert len(results) == 1

        # Test removing
        vault.remove("Gmail")
        assert vault.get("Gmail") is None
        assert len(vault.entries) == 0

    finally:
        os.unlink(temp_file)


def test_vault_persistence():
    """Test Vault file persistence."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        temp_file = f.name

    try:
        # Create vault and add entry
        vault1 = Vault(temp_file)
        entry = PasswordEntry("Test", "user", "pass")
        vault1.add(entry)

        # Create new vault instance (simulates restart)
        vault2 = Vault(temp_file)
        assert len(vault2.entries) == 1
        assert vault2.get("Test").username == "user"

    finally:
        os.unlink(temp_file)


def test_vault_search_multiple():
    """Test searching with multiple entries."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        temp_file = f.name

    try:
        vault = Vault(temp_file)

        # Add multiple entries
        vault.add(PasswordEntry("Gmail", "user@gmail.com", "pass1"))
        vault.add(PasswordEntry("GitHub", "dev", "pass2"))
        vault.add(PasswordEntry("Twitter", "user@twitter.com", "pass3"))

        # Test search by name
        results = vault.search("gmail")
        assert len(results) == 1
        assert results[0].name == "Gmail"

        # Test search by username
        results = vault.search("dev")
        assert len(results) == 1
        assert results[0].name == "GitHub"

        # Test search with no matches
        results = vault.search("nonexistent")
        assert len(results) == 0

    finally:
        os.unlink(temp_file)


if __name__ == "__main__":
    test_password_entry_creation()
    test_password_entry_with_optional_fields()
    test_vault_operations()
    test_vault_persistence()
    test_vault_search_multiple()
    print("All tests passed!")

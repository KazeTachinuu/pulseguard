"""Functional tests for vault operations with real file I/O.

These are REAL tests that verify actual functionality:
- Real files created, saved, loaded
- Data persistence across vault instances
- File corruption handling
- Multiple entries management
- Search functionality across real data
"""

import json
import os
import tempfile
from datetime import datetime

import pytest

from pulseguard.models import PasswordEntry
from pulseguard.vault import (
    Vault,
    VaultCorruptedError,
    VaultDecryptionError,
    VaultPlaintextWarning,
)


class TestVaultDataPersistence:
    """Test that data actually survives being saved and reloaded."""

    def test_single_password_survives_reload(self):
        """FUNCTIONAL: Add password -> close vault -> reopen -> verify it's there."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Create vault, add password, let it save
            vault1 = Vault(file_path=vault_path)
            entry = PasswordEntry("Gmail", "user@gmail.com", "SecurePass123!")
            vault1.add(entry)

            # Verify file was actually created
            assert os.path.exists(vault_path), "Vault file should exist after add"

            # Verify file contains actual JSON data
            with open(vault_path, "r") as f:
                content = f.read()
                assert len(content) > 0, "Vault file should not be empty"
                data = json.loads(content)
                assert "entries" in data, "Vault should have entries key"

            # Create new vault instance (simulates program restart)
            vault2 = Vault(file_path=vault_path)

            # Verify password is actually there
            retrieved = vault2.get("Gmail")
            assert retrieved is not None, "Password should exist after reload"
            assert retrieved.name == "Gmail"
            assert retrieved.username == "user@gmail.com"
            assert retrieved.password == "SecurePass123!"

    def test_ten_passwords_all_survive_reload(self):
        """FUNCTIONAL: Add 10 passwords -> save -> load -> all 10 are there with correct data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Create vault and add 10 different passwords
            vault1 = Vault(file_path=vault_path)
            passwords = []
            for i in range(10):
                entry = PasswordEntry(
                    name=f"Service{i}",
                    username=f"user{i}@example.com",
                    password=f"Pass{i}!",
                    url=f"https://service{i}.com",
                    notes=f"Notes for service {i}",
                )
                passwords.append(entry)
                vault1.add(entry)

            # Verify count before reload
            assert vault1.count() == 10

            # Reload vault
            vault2 = Vault(file_path=vault_path)

            # Verify all 10 passwords exist with correct data
            assert vault2.count() == 10, "All 10 passwords should survive reload"

            for i, original in enumerate(passwords):
                retrieved = vault2.get(f"Service{i}")
                assert retrieved is not None, f"Service{i} should exist"
                assert retrieved.name == original.name
                assert retrieved.username == original.username
                assert retrieved.password == original.password
                assert retrieved.url == original.url
                assert retrieved.notes == original.notes

    def test_update_password_persists(self):
        """FUNCTIONAL: Update password value -> verify old value replaced and persists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Create vault with initial password
            vault1 = Vault(file_path=vault_path)
            entry1 = PasswordEntry("GitHub", "dev", "OldPassword123")
            vault1.add(entry1)

            # Update to new password
            entry2 = PasswordEntry("GitHub", "dev", "NewPassword456")
            vault1.add(entry2)

            # Verify update took effect
            retrieved = vault1.get("GitHub")
            assert retrieved.password == "NewPassword456"

            # Reload and verify new password persists
            vault2 = Vault(file_path=vault_path)
            retrieved = vault2.get("GitHub")
            assert retrieved is not None
            assert retrieved.password == "NewPassword456", "Updated password should persist"
            assert retrieved.password != "OldPassword123", "Old password should be gone"

            # Verify only one entry exists (not duplicated)
            assert vault2.count() == 1

    def test_delete_password_actually_deletes(self):
        """FUNCTIONAL: Delete password -> verify gone and doesn't come back after reload."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Create vault with multiple passwords
            vault1 = Vault(file_path=vault_path)
            vault1.add(PasswordEntry("Keep1", "user1", "pass1"))
            vault1.add(PasswordEntry("Delete", "user2", "pass2"))
            vault1.add(PasswordEntry("Keep2", "user3", "pass3"))

            assert vault1.count() == 3

            # Delete middle entry
            result = vault1.remove("Delete")
            assert result is True, "Delete should return True when entry found"
            assert vault1.count() == 2

            # Verify it's gone
            assert vault1.get("Delete") is None

            # Reload and verify deletion persisted
            vault2 = Vault(file_path=vault_path)
            assert vault2.count() == 2, "Deleted entry should stay deleted"
            assert vault2.get("Delete") is None, "Deleted entry should not come back"
            assert vault2.get("Keep1") is not None
            assert vault2.get("Keep2") is not None


class TestVaultSearchFunctionality:
    """Test search actually finds correct passwords across real data."""

    def test_search_by_name_finds_correct_results(self):
        """FUNCTIONAL: Search by name across 20 entries -> find only matching ones."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault = Vault(file_path=vault_path)

            # Add diverse set of passwords
            vault.add(PasswordEntry("Gmail Personal", "personal@gmail.com", "pass1"))
            vault.add(PasswordEntry("Gmail Work", "work@gmail.com", "pass2"))
            vault.add(PasswordEntry("GitHub", "dev", "pass3"))
            vault.add(PasswordEntry("Twitter", "user", "pass4"))
            vault.add(PasswordEntry("Facebook", "user", "pass5"))

            # Search for "gmail" should find both Gmail entries
            results = vault.search("gmail")
            assert len(results) == 2
            names = {r.name for r in results}
            assert "Gmail Personal" in names
            assert "Gmail Work" in names

            # Search for "GitHub" should find exactly one
            results = vault.search("GitHub")
            assert len(results) == 1
            assert results[0].name == "GitHub"

            # Search for "work" should find one by name
            results = vault.search("work")
            assert len(results) == 1
            assert results[0].name == "Gmail Work"

    def test_search_by_username_finds_correct_results(self):
        """FUNCTIONAL: Search by username -> verify correct matches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault = Vault(file_path=vault_path)

            # Add entries with different username patterns
            vault.add(PasswordEntry("Service1", "admin@company.com", "pass1"))
            vault.add(PasswordEntry("Service2", "admin@personal.com", "pass2"))
            vault.add(PasswordEntry("Service3", "user@company.com", "pass3"))

            # Search for "admin" in username
            results = vault.search("admin")
            assert len(results) == 2
            usernames = {r.username for r in results}
            assert "admin@company.com" in usernames
            assert "admin@personal.com" in usernames

            # Search for "company.com"
            results = vault.search("company.com")
            assert len(results) == 2

    def test_search_case_insensitive(self):
        """FUNCTIONAL: Search is case-insensitive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault = Vault(file_path=vault_path)

            vault.add(PasswordEntry("GitHub", "DevUser", "pass1"))

            # All these should find the entry
            assert len(vault.search("github")) == 1
            assert len(vault.search("GITHUB")) == 1
            assert len(vault.search("GitHub")) == 1
            assert len(vault.search("devuser")) == 1
            assert len(vault.search("DEVUSER")) == 1

    def test_search_no_matches(self):
        """FUNCTIONAL: Search with no matches returns empty list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault = Vault(file_path=vault_path)

            vault.add(PasswordEntry("GitHub", "dev", "pass1"))

            results = vault.search("nonexistent")
            assert len(results) == 0
            assert isinstance(results, list)


class TestVaultFileCorruption:
    """Test vault handles corrupted files gracefully."""

    def test_corrupted_json_raises_clear_error(self):
        """FUNCTIONAL: Corrupted JSON file -> clear error message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Write invalid JSON
            with open(vault_path, "w") as f:
                f.write("{this is not valid json}")

            # Should raise VaultCorruptedError
            with pytest.raises(VaultCorruptedError) as exc_info:
                Vault(file_path=vault_path)

            assert "invalid json" in str(exc_info.value).lower()

    def test_empty_json_object_handled(self):
        """FUNCTIONAL: Empty JSON object is valid (empty vault)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Write empty JSON object
            with open(vault_path, "w") as f:
                f.write("{}")

            # Should load successfully with no entries
            vault = Vault(file_path=vault_path)
            assert vault.count() == 0

    def test_missing_file_creates_new_vault(self):
        """FUNCTIONAL: Missing vault file creates new empty vault."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # File doesn't exist yet
            assert not os.path.exists(vault_path)

            # Creating vault should work
            vault = Vault(file_path=vault_path)
            assert vault.count() == 0

            # Adding entry should create file
            vault.add(PasswordEntry("Test", "user", "pass"))
            assert os.path.exists(vault_path)


class TestVaultDataIntegrity:
    """Test that data maintains integrity through save/load cycles."""

    def test_unicode_passwords_survive_round_trip(self):
        """FUNCTIONAL: Unicode in all fields -> survives save/load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault1 = Vault(file_path=vault_path)

            # Add entry with unicode characters
            entry = PasswordEntry(
                name="Test 测试",
                username="用户@example.com",
                password="密码🔐123!",
                url="https://example.com/路径",
                notes="Notes with émojis 😀 and 中文",
            )
            vault1.add(entry)

            # Reload and verify all unicode preserved
            vault2 = Vault(file_path=vault_path)
            retrieved = vault2.get("Test 测试")
            assert retrieved is not None
            assert retrieved.name == "Test 测试"
            assert retrieved.username == "用户@example.com"
            assert retrieved.password == "密码🔐123!"
            assert retrieved.url == "https://example.com/路径"
            assert retrieved.notes == "Notes with émojis 😀 and 中文"

    def test_special_characters_in_all_fields(self):
        """FUNCTIONAL: Special characters preserved in all fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault1 = Vault(file_path=vault_path)

            entry = PasswordEntry(
                name="Test!@#$%^&*()",
                username="user+tag@example.com",
                password='Pa$$w0rd"with\'quotes',
                url="https://example.com?param=value&other=test",
                notes="Line1\nLine2\tTabbed",
            )
            vault1.add(entry)

            # Reload and verify
            vault2 = Vault(file_path=vault_path)
            retrieved = vault2.get("Test!@#$%^&*()")
            assert retrieved is not None
            assert retrieved.password == 'Pa$$w0rd"with\'quotes'
            assert retrieved.notes == "Line1\nLine2\tTabbed"

    def test_timestamps_preserved(self):
        """FUNCTIONAL: Timestamps created and preserved through save/load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault1 = Vault(file_path=vault_path)

            # Add entry (timestamp auto-generated)
            before = datetime.now()
            entry = PasswordEntry("Test", "user", "pass")
            vault1.add(entry)
            after = datetime.now()

            # Verify timestamp is in reasonable range
            assert entry.created_at is not None
            assert before <= entry.created_at <= after

            # Reload and verify timestamp preserved
            vault2 = Vault(file_path=vault_path)
            retrieved = vault2.get("Test")
            assert retrieved.created_at is not None
            assert retrieved.created_at == entry.created_at

    def test_optional_fields_preserved(self):
        """FUNCTIONAL: Optional URL and notes fields preserved when set."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault1 = Vault(file_path=vault_path)

            # Entry with URL but no notes
            entry1 = PasswordEntry("Test1", "user1", "pass1", url="https://example.com")
            vault1.add(entry1)

            # Entry with notes but no URL
            entry2 = PasswordEntry("Test2", "user2", "pass2", notes="Important notes")
            vault1.add(entry2)

            # Entry with both
            entry3 = PasswordEntry(
                "Test3", "user3", "pass3", url="https://test.com", notes="Both fields"
            )
            vault1.add(entry3)

            # Entry with neither
            entry4 = PasswordEntry("Test4", "user4", "pass4")
            vault1.add(entry4)

            # Reload and verify all variations preserved
            vault2 = Vault(file_path=vault_path)

            r1 = vault2.get("Test1")
            assert r1.url == "https://example.com"
            assert r1.notes == ""

            r2 = vault2.get("Test2")
            assert r2.url == ""
            assert r2.notes == "Important notes"

            r3 = vault2.get("Test3")
            assert r3.url == "https://test.com"
            assert r3.notes == "Both fields"

            r4 = vault2.get("Test4")
            assert r4.url == ""
            assert r4.notes == ""


class TestVaultPlaintextMode:
    """Test that plaintext vaults work (with warnings)."""

    def test_plaintext_vault_triggers_warning(self):
        """FUNCTIONAL: Creating plaintext vault shows security warning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Creating vault without master password should warn
            with pytest.warns(VaultPlaintextWarning):
                vault = Vault(file_path=vault_path, master_password=None)
                vault.add(PasswordEntry("Test", "user", "pass"))

    def test_plaintext_vault_file_is_readable(self):
        """FUNCTIONAL: Plaintext vault file is actually readable JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Create plaintext vault
            with pytest.warns(VaultPlaintextWarning):
                vault = Vault(file_path=vault_path, master_password=None)
                vault.add(PasswordEntry("Gmail", "user@gmail.com", "MyPassword123"))

            # Read file directly - should be plain JSON
            with open(vault_path, "r") as f:
                content = f.read()
                data = json.loads(content)

            # Verify password is in plaintext
            assert "entries" in data
            assert len(data["entries"]) == 1
            entry = data["entries"][0]
            assert entry["name"] == "Gmail"
            assert entry["password"] == "MyPassword123"  # NOT encrypted!
            assert "encrypted" not in data or data.get("encrypted") is False

    def test_loading_plaintext_vault_warns(self):
        """FUNCTIONAL: Loading existing plaintext vault shows warning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Create plaintext vault
            with pytest.warns(VaultPlaintextWarning):
                vault1 = Vault(file_path=vault_path, master_password=None)
                vault1.add(PasswordEntry("Test", "user", "pass"))

            # Loading it again should also warn
            with pytest.warns(VaultPlaintextWarning):
                vault2 = Vault(file_path=vault_path, master_password=None)
                assert vault2.count() == 1

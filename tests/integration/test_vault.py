"""
Integration tests for encrypted vault operations.

This module tests the complete vault system including:
- Encryption/decryption integration
- Persistence to disk
- CRUD operations on entries
- Search and filtering functionality
- Data integrity and error handling
"""

import base64
import json

import pytest

from pulseguard.config import Config
from pulseguard.models import PasswordEntry
from pulseguard.vault import (
    Vault,
    VaultCorruptedError,
    VaultDecryptionError,
    find_duplicates,
    find_reused_passwords,
    get_vault_stats,
    sort_categories_uncategorized_last,
)


class TestVaultCreation:
    """Test vault creation and initialization."""

    def test_creates_empty_vault_when_file_missing(self, vault_path, master_password):
        """New vault should start empty when file doesn't exist."""
        vault = Vault(file_path=vault_path, master_password=master_password)

        assert vault.count() == 0, "New vault should be empty"

    def test_persists_encryption_salt(self, vault_path, master_password):
        """Vault should reuse same salt across saves."""
        vault = Vault(file_path=vault_path, master_password=master_password)
        vault.add(PasswordEntry("Entry1", "user1", "pass1"))

        with open(vault_path, "r") as f:
            data1 = json.loads(f.read())
            salt1 = data1["salt"]

        vault.add(PasswordEntry("Entry2", "user2", "pass2"))

        with open(vault_path, "r") as f:
            data2 = json.loads(f.read())
            salt2 = data2["salt"]

        assert salt1 == salt2, "Salt should be reused across saves"


class TestEncryptionIntegration:
    """Test that vault properly encrypts data on disk."""

    def test_stores_data_encrypted_not_plaintext(self, vault_path, master_password):
        """Vault file should contain only encrypted data, no plaintext."""
        vault = Vault(file_path=vault_path, master_password=master_password)
        vault.add(
            PasswordEntry(
                "SecretService",
                "admin@secret.com",
                "SuperSecretPassword123!",
                notes="Confidential info",
            )
        )

        with open(vault_path, "r") as f:
            content = f.read()
            data = json.loads(content)

        # Verify structure
        assert "salt" in data, "File should contain salt"
        assert "data" in data, "File should contain encrypted data"

        # Verify no plaintext leakage
        assert "SuperSecretPassword123!" not in content
        assert "admin@secret.com" not in content
        assert "SecretService" not in content
        assert "Confidential" not in content

        # Verify encrypted data is valid base64
        encrypted_bytes = base64.b64decode(data["data"])
        assert len(encrypted_bytes) > 0
        assert isinstance(encrypted_bytes, bytes)

    def test_correct_password_decrypts_successfully(self, vault_path, master_password):
        """Correct master password should decrypt vault."""
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(
            PasswordEntry(
                "GitHub",
                "developer",
                "GitHubToken456!",
                url="https://github.com",
                notes="Personal account",
            )
        )

        # Reload with correct password
        vault2 = Vault(file_path=vault_path, master_password=master_password)

        entry = vault2.get("GitHub")
        assert entry is not None
        assert entry.username == "developer"
        assert entry.password == "GitHubToken456!"
        assert entry.url == "https://github.com"
        assert entry.notes == "Personal account"

    def test_wrong_password_fails_decryption(self, vault_path, master_password):
        """Wrong master password should fail with clear error."""
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(PasswordEntry("Test", "user", "pass"))

        with pytest.raises(VaultDecryptionError) as exc:
            Vault(file_path=vault_path, master_password="WrongPassword!")

        assert "decrypt" in str(exc.value).lower()

    def test_detects_tampered_ciphertext(self, vault_path, master_password):
        """Tampered encrypted data should be detected."""
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(PasswordEntry("Test", "user", "pass"))

        # Tamper with encrypted data
        with open(vault_path, "r") as f:
            data = json.loads(f.read())

        encrypted_bytes = base64.b64decode(data["data"])
        tampered = bytearray(encrypted_bytes)
        tampered[len(tampered) // 2] ^= 0xFF  # Flip a bit
        data["data"] = base64.b64encode(bytes(tampered)).decode("ascii")

        with open(vault_path, "w") as f:
            json.dump(data, f)

        with pytest.raises(VaultDecryptionError):
            Vault(file_path=vault_path, master_password=master_password)

    def test_same_data_different_passwords_produce_different_vaults(self, temp_dir):
        """Same entries with different passwords should encrypt differently."""
        import os

        vault_path1 = os.path.join(temp_dir, "vault1.json")
        vault_path2 = os.path.join(temp_dir, "vault2.json")

        vault1 = Vault(file_path=vault_path1, master_password="password1")
        vault1.add(PasswordEntry("Test", "user", "pass"))

        vault2 = Vault(file_path=vault_path2, master_password="password2")
        vault2.add(PasswordEntry("Test", "user", "pass"))

        with open(vault_path1, "r") as f:
            data1 = f.read()
        with open(vault_path2, "r") as f:
            data2 = f.read()

        assert data1 != data2, "Different passwords must produce different ciphertext"


class TestDataPersistence:
    """Test that vault data persists correctly across reload cycles."""

    def test_single_entry_survives_reload(self, vault_path, master_password):
        """Single entry should persist correctly."""
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(PasswordEntry("Gmail", "user@gmail.com", "GmailPass123!"))

        vault2 = Vault(file_path=vault_path, master_password=master_password)

        entry = vault2.get("Gmail")
        assert entry is not None
        assert entry.name == "Gmail"
        assert entry.username == "user@gmail.com"
        assert entry.password == "GmailPass123!"

    def test_multiple_entries_survive_reload(self, vault_path, master_password):
        """All entries should persist correctly."""
        vault1 = Vault(file_path=vault_path, master_password=master_password)

        for i in range(10):
            vault1.add(
                PasswordEntry(
                    name=f"Service{i}",
                    username=f"user{i}@example.com",
                    password=f"Pass{i}!",
                    url=f"https://service{i}.com",
                    notes=f"Notes {i}",
                )
            )

        vault2 = Vault(file_path=vault_path, master_password=master_password)

        assert vault2.count() == 10, "All entries should persist"

        for i in range(10):
            entry = vault2.get(f"Service{i}")
            assert entry is not None
            assert entry.username == f"user{i}@example.com"
            assert entry.password == f"Pass{i}!"

    def test_update_persists_correctly(self, vault_path, master_password):
        """Updated entries should overwrite old ones."""
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(PasswordEntry("GitHub", "dev", "OldPassword123"))

        vault1.add(PasswordEntry("GitHub", "dev", "NewPassword456"))

        vault2 = Vault(file_path=vault_path, master_password=master_password)

        entry = vault2.get("GitHub")
        assert entry.password == "NewPassword456"
        assert vault2.count() == 1, "Should only have one entry after update"

    def test_delete_persists_correctly(self, vault_path, master_password):
        """Deleted entries should stay deleted."""
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(PasswordEntry("Keep1", "user1", "pass1"))
        vault1.add(PasswordEntry("Delete", "user2", "pass2"))
        vault1.add(PasswordEntry("Keep2", "user3", "pass3"))

        vault1.remove("Delete")

        vault2 = Vault(file_path=vault_path, master_password=master_password)

        assert vault2.count() == 2
        assert vault2.get("Delete") is None
        assert vault2.get("Keep1") is not None
        assert vault2.get("Keep2") is not None


class TestCRUDOperations:
    """Test Create, Read, Update, Delete operations."""

    def test_add_entry(self, vault):
        """Adding entry should work correctly."""
        vault.add(PasswordEntry("Test", "user", "pass"))

        assert vault.count() == 1
        assert vault.get("Test") is not None

    def test_get_entry(self, vault):
        """Getting entry should return correct data."""
        entry = PasswordEntry("Test", "user@test.com", "password123")
        vault.add(entry)

        retrieved = vault.get("Test")
        assert retrieved is not None
        assert retrieved.username == "user@test.com"
        assert retrieved.password == "password123"

    def test_get_nonexistent_entry(self, vault):
        """Getting nonexistent entry should return None."""
        assert vault.get("DoesNotExist") is None

    def test_remove_existing_entry(self, vault):
        """Removing existing entry should return True."""
        vault.add(PasswordEntry("Test", "user", "pass"))

        result = vault.remove("Test")

        assert result is True
        assert vault.count() == 0
        assert vault.get("Test") is None

    def test_remove_nonexistent_entry(self, vault):
        """Removing nonexistent entry should return False."""
        result = vault.remove("DoesNotExist")
        assert result is False

    def test_update_entry(self, vault):
        """Adding entry with same name should update it."""
        vault.add(PasswordEntry("Test", "user1", "pass1"))
        vault.add(PasswordEntry("Test", "user2", "pass2"))

        assert vault.count() == 1
        entry = vault.get("Test")
        assert entry.username == "user2"
        assert entry.password == "pass2"


class TestSearchAndFilter:
    """Test search and filtering functionality."""

    def test_search_by_name(self, vault):
        """Search should find entries by name."""
        vault.add(PasswordEntry("Gmail Personal", "personal@gmail.com", "pass1"))
        vault.add(PasswordEntry("Gmail Work", "work@gmail.com", "pass2"))
        vault.add(PasswordEntry("GitHub", "dev", "pass3"))

        results = vault.search("gmail")

        assert len(results) == 2
        names = {r.name for r in results}
        assert "Gmail Personal" in names
        assert "Gmail Work" in names

    def test_search_by_username(self, vault):
        """Search should find entries by username."""
        vault.add(PasswordEntry("Service1", "admin@company.com", "pass1"))
        vault.add(PasswordEntry("Service2", "admin@personal.com", "pass2"))
        vault.add(PasswordEntry("Service3", "user@company.com", "pass3"))

        results = vault.search("admin")

        assert len(results) == 2
        usernames = {r.username for r in results}
        assert "admin@company.com" in usernames
        assert "admin@personal.com" in usernames

    def test_search_is_case_insensitive(self, vault):
        """Search should be case-insensitive."""
        vault.add(PasswordEntry("GitHub", "DevUser", "pass"))

        assert len(vault.search("github")) == 1
        assert len(vault.search("GITHUB")) == 1
        assert len(vault.search("devuser")) == 1

    def test_search_returns_empty_list_for_no_matches(self, vault):
        """Search with no matches should return empty list."""
        vault.add(PasswordEntry("Test", "user", "pass"))

        results = vault.search("nonexistent")

        assert len(results) == 0
        assert isinstance(results, list)

    def test_get_favorites(self, vault):
        """Should return only favorited entries."""
        entry1 = PasswordEntry("Fav1", "user1", "pass1")
        entry1.favorite = True
        vault.add(entry1, update_timestamp=False)

        vault.add(PasswordEntry("NotFav", "user2", "pass2"))

        favorites = vault.get_favorites()

        assert len(favorites) == 1
        assert favorites[0].name == "Fav1"

    def test_get_recent(self, vault):
        """Should return recently accessed entries in order."""
        vault.add(PasswordEntry("S1", "u1", "p1"))
        vault.add(PasswordEntry("S2", "u2", "p2"))
        vault.add(PasswordEntry("S3", "u3", "p3"))

        # Access in specific order
        vault.get("S2")
        vault.get("S1")

        recent = vault.get_recent(limit=2)

        assert len(recent) == 2
        assert recent[0].name == "S1", "Most recent should be first"

    def test_search_by_tag(self, vault):
        """Should find entries by tag."""
        entry1 = PasswordEntry("S1", "u1", "p1")
        entry1.tags = ["work", "important"]
        vault.add(entry1, update_timestamp=False)

        entry2 = PasswordEntry("S2", "u2", "p2")
        entry2.tags = ["personal"]
        vault.add(entry2, update_timestamp=False)

        work_entries = vault.search_by_tag("work")

        assert len(work_entries) == 1
        assert work_entries[0].name == "S1"

    def test_get_all_tags(self, vault):
        """Should return all unique tags sorted."""
        entry1 = PasswordEntry("S1", "u1", "p1")
        entry1.tags = ["work", "urgent"]
        vault.add(entry1, update_timestamp=False)

        entry2 = PasswordEntry("S2", "u2", "p2")
        entry2.tags = ["personal", "urgent"]
        vault.add(entry2, update_timestamp=False)

        tags = vault.get_all_tags()

        assert set(tags) == {"work", "urgent", "personal"}
        assert tags == sorted(tags)

    def test_get_by_category(self, vault):
        """Should return entries in specific category."""
        entry1 = PasswordEntry("S1", "u1", "p1")
        entry1.category = "Work"
        vault.add(entry1, update_timestamp=False)

        entry2 = PasswordEntry("S2", "u2", "p2")
        entry2.category = "Work"
        vault.add(entry2, update_timestamp=False)

        entry3 = PasswordEntry("S3", "u3", "p3")
        entry3.category = "Personal"
        vault.add(entry3, update_timestamp=False)

        work_entries = vault.get_by_category("Work")

        assert len(work_entries) == 2


class TestVaultUtilities:
    """Test utility functions for vault analysis."""

    def test_find_duplicates(self, vault):
        """Should find duplicate username+url combinations."""
        vault.add(PasswordEntry("S1", "user@ex.com", "p1", url="https://ex.com"))
        vault.add(PasswordEntry("S2", "user@ex.com", "p2", url="https://ex.com"))
        vault.add(PasswordEntry("S3", "other@ex.com", "p3", url="https://other.com"))

        duplicates = find_duplicates(vault)

        assert len(duplicates) == 1
        key, entries = duplicates[0]
        assert len(entries) == 2

    def test_find_reused_passwords(self, vault):
        """Should find passwords used in multiple entries."""
        vault.add(PasswordEntry("S1", "u1", "SamePass123"))
        vault.add(PasswordEntry("S2", "u2", "SamePass123"))
        vault.add(PasswordEntry("S3", "u3", "UniquePass"))

        reused = find_reused_passwords(vault)

        assert len(reused) == 1
        count, entries = reused[0]
        assert count == 2

    def test_get_vault_stats(self, vault):
        """Should return vault statistics."""
        vault.add(PasswordEntry("S1", "u@ex.com", "pass1", url="https://ex.com"))
        vault.add(PasswordEntry("S2", "u@ex.com", "pass1", url="https://ex.com"))
        vault.add(PasswordEntry("S3", "other", "pass2"))

        stats = get_vault_stats(vault)

        assert stats["total"] == 3
        assert stats["duplicates"] == 1
        assert stats["reused"] == 1

    def test_sort_categories_uncategorized_last(self):
        """Should sort categories with 'Uncategorized' at end."""
        categories = ["Work", Config.DEFAULT_CATEGORY, "Personal", "Banking"]
        sorted_cats = sort_categories_uncategorized_last(categories)

        assert sorted_cats[-1] == Config.DEFAULT_CATEGORY
        assert sorted_cats[:-1] == ["Banking", "Personal", "Work"]


class TestDataIntegrity:
    """Test data integrity with special characters and edge cases."""

    def test_unicode_survives_persistence(self, vault_path, master_password):
        """Unicode characters should survive save/reload."""
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(
            PasswordEntry(
                name="测试账户",
                username="用户@example.com",
                password="密码🔐",
                url="https://example.com/路径",
                notes="备注 with émojis 😀",
            )
        )

        vault2 = Vault(file_path=vault_path, master_password=master_password)

        entry = vault2.get("测试账户")
        assert entry.username == "用户@example.com"
        assert entry.password == "密码🔐"
        assert entry.url == "https://example.com/路径"
        assert entry.notes == "备注 with émojis 😀"

    def test_special_characters_in_fields(self, vault_path, master_password):
        """Special characters should be handled correctly."""
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(
            PasswordEntry(
                name="Test!@#$%",
                username="user+tag@example.com",
                password="Pa$$w0rd\"with'quotes",
                notes="Line1\nLine2\tTabbed",
            )
        )

        vault2 = Vault(file_path=vault_path, master_password=master_password)

        entry = vault2.get("Test!@#$%")
        assert entry.password == "Pa$$w0rd\"with'quotes"
        assert entry.notes == "Line1\nLine2\tTabbed"


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_corrupted_json_raises_error(self, vault_path, master_password):
        """Corrupted JSON should raise clear error."""
        with open(vault_path, "w") as f:
            f.write("{invalid json}")

        with pytest.raises(VaultCorruptedError) as exc:
            Vault(file_path=vault_path, master_password=master_password)

        assert "corrupted or invalid" in str(exc.value).lower()

    def test_empty_json_object_raises_error(self, vault_path, master_password):
        """Empty JSON is not a valid encrypted vault."""
        with open(vault_path, "w") as f:
            f.write("{}")

        with pytest.raises(VaultCorruptedError) as exc:
            Vault(file_path=vault_path, master_password=master_password)

        assert "missing required" in str(exc.value).lower()

    def test_unicode_decode_error(self, vault_path, master_password):
        """Invalid UTF-8 should raise clear error."""
        with open(vault_path, "wb") as f:
            f.write(b"\xff\xfe\xfd")

        with pytest.raises(VaultCorruptedError, match="invalid encoding"):
            Vault(file_path=vault_path, master_password=master_password)

    def test_save_if_dirty_flag(self, vault):
        """Should only save when dirty flag is set."""
        # Initially not dirty
        assert vault.save_if_dirty() is False

        # Mark as dirty by accessing entry
        vault.add(PasswordEntry("Test", "user", "pass"))
        vault.get("Test", track_access=True)

        # Should save now
        assert vault.save_if_dirty() is True

        # No longer dirty after save
        assert vault.save_if_dirty() is False

"""Tests for encrypted vault operations."""

import json
import os
import tempfile
import warnings

import pytest

from pulseguard import PasswordEntry, Vault
from pulseguard.vault import (
    VaultCorruptedError,
    VaultDecryptionError,
    VaultPlaintextWarning,
)


class TestEncryptedVaultCreation:
    def test_create_encrypted_vault(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault = Vault(temp_file, master_password="test_password")

            entry = PasswordEntry("Test", "user", "pass123")
            vault.add(entry)

            with open(temp_file, "r") as f:
                content = f.read()
                data = json.loads(content)

                assert (
                    data.get("encrypted") is True
                ), "Vault must be marked as encrypted"
                assert "salt" in data, "Vault must contain salt"
                assert "data" in data, "Vault must contain encrypted data"
                assert "entries" not in data, "Vault must not have plaintext entries"

                assert "pass123" not in content, "Password must not be in plaintext"
                assert "Test" not in content, "Entry name must not be in plaintext"

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_create_plaintext_vault_with_warning(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")

                vault = Vault(temp_file, master_password=None)
                entry = PasswordEntry("Test", "user", "pass123")
                vault.add(entry)

                assert len(w) > 0, "Must warn about plaintext storage"
                assert issubclass(w[0].category, VaultPlaintextWarning)
                assert "PLAINTEXT" in str(w[0].message)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_encrypted_vault_persists_salt(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault = Vault(temp_file, master_password="password")

            vault.add(PasswordEntry("Entry1", "user1", "pass1"))

            with open(temp_file, "r") as f:
                data1 = json.loads(f.read())
                salt1 = data1["salt"]

            vault.add(PasswordEntry("Entry2", "user2", "pass2"))

            with open(temp_file, "r") as f:
                data2 = json.loads(f.read())
                salt2 = data2["salt"]

            # Salt should be the same
            assert salt1 == salt2, "Salt must be reused across saves"

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class TestEncryptedVaultLoading:
    def test_load_encrypted_vault_correct_password(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault1 = Vault(temp_file, master_password="correct_password")
            vault1.add(PasswordEntry("Gmail", "user@gmail.com", "secret123"))

            vault2 = Vault(temp_file, master_password="correct_password")

            assert vault2.count() == 1
            entry = vault2.get("Gmail")
            assert entry is not None
            assert entry.username == "user@gmail.com"
            assert entry.password == "secret123"

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_load_encrypted_vault_wrong_password(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault1 = Vault(temp_file, master_password="correct_password")
            vault1.add(PasswordEntry("Test", "user", "pass"))

            with pytest.raises(VaultDecryptionError) as exc_info:
                Vault(temp_file, master_password="wrong_password")

            assert "decrypt" in str(exc_info.value).lower()

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_load_encrypted_vault_no_password(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault1 = Vault(temp_file, master_password="password")
            vault1.add(PasswordEntry("Test", "user", "pass"))

            with pytest.raises(VaultDecryptionError) as exc_info:
                Vault(temp_file, master_password=None)

            assert "no master password" in str(exc_info.value).lower()

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class TestPlaintextVaultBackwardCompatibility:
    def test_load_plaintext_vault_with_warning(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            plaintext_data = {
                "entries": [
                    {
                        "name": "Test",
                        "username": "user",
                        "password": "pass",
                        "url": "",
                        "notes": "",
                        "created_at": "2024-01-01T00:00:00",
                    }
                ]
            }
            with open(temp_file, "w") as f:
                json.dump(plaintext_data, f)

            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")

                vault = Vault(temp_file, master_password=None)

                assert len(w) > 0, "Must warn about plaintext vault"
                assert issubclass(w[0].category, VaultPlaintextWarning)

            assert vault.count() == 1
            entry = vault.get("Test")
            assert entry.username == "user"
            assert entry.password == "pass"

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_migrate_plaintext_to_encrypted(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                vault1 = Vault(temp_file, master_password=None)
                vault1.add(PasswordEntry("OldEntry", "user", "pass"))

            vault2 = Vault(temp_file, master_password="new_password")

            vault2.add(PasswordEntry("NewEntry", "user2", "pass2"))

            with open(temp_file, "r") as f:
                data = json.loads(f.read())
                assert data.get("encrypted") is True, "Vault should now be encrypted"

            vault3 = Vault(temp_file, master_password="new_password")
            assert vault3.count() == 2
            assert vault3.get("OldEntry") is not None
            assert vault3.get("NewEntry") is not None

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class TestEncryptedVaultOperations:
    def test_add_entry_to_encrypted_vault(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault = Vault(temp_file, master_password="password")

            vault.add(PasswordEntry("Gmail", "user1@gmail.com", "pass1"))
            vault.add(PasswordEntry("GitHub", "user2", "token123"))
            vault.add(PasswordEntry("Twitter", "user3", "pass3"))

            assert vault.count() == 3

            # Reload and verify
            vault2 = Vault(temp_file, master_password="password")
            assert vault2.count() == 3
            assert vault2.get("Gmail").password == "pass1"
            assert vault2.get("GitHub").password == "token123"

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_remove_entry_from_encrypted_vault(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault = Vault(temp_file, master_password="password")
            vault.add(PasswordEntry("Entry1", "user1", "pass1"))
            vault.add(PasswordEntry("Entry2", "user2", "pass2"))

            assert vault.remove("Entry1") is True
            assert vault.count() == 1

            # Reload and verify
            vault2 = Vault(temp_file, master_password="password")
            assert vault2.count() == 1
            assert vault2.get("Entry1") is None
            assert vault2.get("Entry2") is not None

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_search_in_encrypted_vault(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault = Vault(temp_file, master_password="password")
            vault.add(PasswordEntry("Gmail", "user@gmail.com", "pass1"))
            vault.add(PasswordEntry("GitHub", "developer", "pass2"))
            vault.add(PasswordEntry("Twitter", "user@twitter.com", "pass3"))

            results = vault.search("git")
            assert len(results) == 1
            assert results[0].name == "GitHub"

            results = vault.search("gmail")
            assert len(results) == 1
            assert results[0].name == "Gmail"

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_update_entry_in_encrypted_vault(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault = Vault(temp_file, master_password="password")
            vault.add(PasswordEntry("Test", "user", "old_password"))

            vault.add(PasswordEntry("Test", "user", "new_password"))

            assert vault.count() == 1
            assert vault.get("Test").password == "new_password"

            # Reload and verify
            vault2 = Vault(temp_file, master_password="password")
            assert vault2.get("Test").password == "new_password"

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class TestEncryptedVaultErrors:
    def test_corrupted_encrypted_vault(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault1 = Vault(temp_file, master_password="password")
            vault1.add(PasswordEntry("Test", "user", "pass"))

            # Corrupt the encrypted data
            with open(temp_file, "r") as f:
                data = json.loads(f.read())

            # Corrupt the ciphertext
            data["data"] = "corrupted_data_not_base64"

            with open(temp_file, "w") as f:
                json.dump(data, f)

            with pytest.raises((VaultDecryptionError, VaultCorruptedError)):
                Vault(temp_file, master_password="password")

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_invalid_json_vault(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            with open(temp_file, "w") as f:
                f.write("{ invalid json")

            with pytest.raises(VaultCorruptedError):
                Vault(temp_file, master_password=None)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_missing_encrypted_fields(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            with open(temp_file, "w") as f:
                json.dump({"encrypted": True, "salt": "c29tZXNhbHQ="}, f)

            # but has no "entries" field, so it loads as empty vault with warning
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                vault = Vault(temp_file, master_password=None)

                assert len(w) > 0
                assert issubclass(w[0].category, VaultPlaintextWarning)

            # Vault should be empty (no entries field)
            assert vault.count() == 0

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class TestEncryptedVaultSecurity:
    def test_vault_file_not_human_readable(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault = Vault(temp_file, master_password="password")
            vault.add(
                PasswordEntry(
                    "MySecret",
                    "admin@example.com",
                    "super_secret_password_123",
                    url="https://example.com",
                    notes="Important account",
                )
            )

            with open(temp_file, "r") as f:
                content = f.read()

            assert "super_secret_password_123" not in content
            assert "admin@example.com" not in content
            assert "MySecret" not in content
            assert "Important account" not in content

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_different_passwords_produce_different_vaults(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file1 = f.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file2 = f.name

        try:
            vault1 = Vault(temp_file1, master_password="password1")
            vault1.add(PasswordEntry("Test", "user", "pass"))

            vault2 = Vault(temp_file2, master_password="password2")
            vault2.add(PasswordEntry("Test", "user", "pass"))

            with open(temp_file1, "r") as f:
                data1 = f.read()

            with open(temp_file2, "r") as f:
                data2 = f.read()

            assert (
                data1 != data2
            ), "Different passwords must produce different encrypted vaults"

        finally:
            if os.path.exists(temp_file1):
                os.unlink(temp_file1)
            if os.path.exists(temp_file2):
                os.unlink(temp_file2)

    def test_empty_password_allowed_but_different(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file1 = f.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file2 = f.name

        try:
            # Vault with empty password (encrypted)
            vault1 = Vault(temp_file1, master_password="")
            vault1.add(PasswordEntry("Test", "user", "pass"))

            # Vault with no password (plaintext)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                vault2 = Vault(temp_file2, master_password=None)
                vault2.add(PasswordEntry("Test", "user", "pass"))

            with open(temp_file1, "r") as f:
                data1 = json.loads(f.read())

            with open(temp_file2, "r") as f:
                data2 = json.loads(f.read())

            # Empty password vault should be encrypted
            assert data1.get("encrypted") is True
            # No password vault should be plaintext
            assert data2.get("encrypted") is not True
            assert "entries" in data2

        finally:
            if os.path.exists(temp_file1):
                os.unlink(temp_file1)
            if os.path.exists(temp_file2):
                os.unlink(temp_file2)

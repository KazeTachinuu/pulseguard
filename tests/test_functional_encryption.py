"""Tests for encrypted vault operations."""

import base64
import json
import os
import tempfile

import pytest

from pulseguard.models import PasswordEntry
from pulseguard.vault import Vault, VaultDecryptionError


class TestEncryptedVaultCreation:
    def test_encrypted_vault_file_is_not_plaintext(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "SecureMasterPass123!"

            vault = Vault(file_path=vault_path, master_password=master_password)
            vault.add(
                PasswordEntry("Gmail", "user@gmail.com", "SuperSecretPassword123!")
            )

            with open(vault_path, "r") as f:
                content = f.read()
                data = json.loads(content)

            assert "salt" in data, "File should contain salt"
            assert "data" in data, "File should contain encrypted data"

            assert (
                "SuperSecretPassword123!" not in content
            ), "Password should NOT be in plaintext"
            assert (
                "user@gmail.com" not in content
            ), "Username should NOT be in plaintext"
            assert "Gmail" not in content, "Entry name should NOT be in plaintext"

            encrypted_data = data["data"]
            try:
                decoded = base64.b64decode(encrypted_data)
                assert len(decoded) > 0
                assert isinstance(decoded, bytes)
            except Exception:
                pytest.fail("Encrypted data should be valid base64")

    def test_wrong_master_password_cannot_decrypt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            correct_password = "CorrectPassword123!"
            wrong_password = "WrongPassword456!"

            vault1 = Vault(file_path=vault_path, master_password=correct_password)
            vault1.add(PasswordEntry("Test", "user", "pass"))

            with pytest.raises(VaultDecryptionError) as exc_info:
                Vault(file_path=vault_path, master_password=wrong_password)

            assert "decrypt" in str(exc_info.value).lower()

    def test_correct_master_password_decrypts_successfully(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "MyMasterPassword123!"

            vault1 = Vault(file_path=vault_path, master_password=master_password)
            vault1.add(
                PasswordEntry(
                    "GitHub",
                    "developer",
                    "SecretToken123",
                    url="https://github.com",
                    notes="Personal account",
                )
            )

            # Open with correct password
            vault2 = Vault(file_path=vault_path, master_password=master_password)

            entry = vault2.get("GitHub")
            assert entry is not None, "Entry should be decrypted and accessible"
            assert entry.username == "developer"
            assert entry.password == "SecretToken123"
            assert entry.url == "https://github.com"
            assert entry.notes == "Personal account"

    def test_wrong_password_cannot_open_encrypted_vault(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            vault1 = Vault(file_path=vault_path, master_password="Password123!")
            vault1.add(PasswordEntry("Test", "user", "pass"))

            with pytest.raises(VaultDecryptionError) as exc_info:
                Vault(file_path=vault_path, master_password="WrongPassword")

            assert "decrypt" in str(exc_info.value).lower()


class TestEncryptionRoundTrips:
    def test_single_password_encryption_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "MasterPass123!"

            vault1 = Vault(file_path=vault_path, master_password=master_password)
            original_entry = PasswordEntry(
                "Test",
                "user@test.com",
                "ComplexP@ssw0rd!",
                url="https://test.com",
                notes="Test notes",
            )
            vault1.add(original_entry)

            # Round trip 1: Load and verify
            vault2 = Vault(file_path=vault_path, master_password=master_password)
            entry2 = vault2.get("Test")
            assert entry2.password == "ComplexP@ssw0rd!"

            # Modify and save
            entry2.password = "NewP@ssw0rd!"
            vault2.add(entry2)

            # Round trip 2: Load and verify change
            vault3 = Vault(file_path=vault_path, master_password=master_password)
            entry3 = vault3.get("Test")
            assert entry3.password == "NewP@ssw0rd!"

            # Round trip 3: Add another entry
            vault3.add(PasswordEntry("Second", "user2", "pass2"))

            # Round trip 4: Verify both entries
            vault4 = Vault(file_path=vault_path, master_password=master_password)
            assert vault4.count() == 2
            assert vault4.get("Test").password == "NewP@ssw0rd!"
            assert vault4.get("Second").password == "pass2"

    def test_multiple_passwords_survive_encryption(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "SecurePassword123!"

            vault1 = Vault(file_path=vault_path, master_password=master_password)
            for i in range(50):
                vault1.add(
                    PasswordEntry(
                        name=f"Service{i}",
                        username=f"user{i}@example.com",
                        password=f"UniquePassword{i}!",
                    )
                )

            # Reload and verify all 50
            vault2 = Vault(file_path=vault_path, master_password=master_password)
            assert vault2.count() == 50

            for i in range(50):
                entry = vault2.get(f"Service{i}")
                assert entry is not None
                assert entry.username == f"user{i}@example.com"
                assert entry.password == f"UniquePassword{i}!"

    def test_unicode_survives_encryption(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "密码123!"

            vault1 = Vault(file_path=vault_path, master_password=master_password)
            vault1.add(
                PasswordEntry(
                    name="测试账户",
                    username="用户@example.com",
                    password="密码🔐🎉",
                    url="https://example.com/路径",
                    notes="备注信息 with émojis 😀",
                )
            )

            # Reload and verify all unicode preserved
            vault2 = Vault(file_path=vault_path, master_password=master_password)
            entry = vault2.get("测试账户")
            assert entry is not None
            assert entry.username == "用户@example.com"
            assert entry.password == "密码🔐🎉"
            assert entry.url == "https://example.com/路径"
            assert entry.notes == "备注信息 with émojis 😀"


class TestEncryptionSecurity:
    def test_same_password_different_encryption_each_time(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path1 = os.path.join(tmpdir, "vault1.json")
            vault_path2 = os.path.join(tmpdir, "vault2.json")
            master_password = "SamePassword123!"

            vault1 = Vault(file_path=vault_path1, master_password=master_password)
            vault1.add(PasswordEntry("Test", "user", "identical_password"))

            vault2 = Vault(file_path=vault_path2, master_password=master_password)
            vault2.add(PasswordEntry("Test", "user", "identical_password"))

            with open(vault_path1, "r") as f:
                data1 = json.loads(f.read())
            with open(vault_path2, "r") as f:
                data2 = json.loads(f.read())

            # Ciphertext should be different (due to random IV and salt)
            assert (
                data1["data"] != data2["data"]
            ), "Same data should encrypt differently each time"
            assert data1["salt"] != data2["salt"], "Each vault should have unique salt"

    def test_salt_is_stored_and_reused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "Password123!"

            vault1 = Vault(file_path=vault_path, master_password=master_password)
            vault1.add(PasswordEntry("Test1", "user1", "pass1"))

            with open(vault_path, "r") as f:
                data1 = json.loads(f.read())
                salt1 = data1["salt"]

            vault2 = Vault(file_path=vault_path, master_password=master_password)
            vault2.add(PasswordEntry("Test2", "user2", "pass2"))

            with open(vault_path, "r") as f:
                data2 = json.loads(f.read())
                salt2 = data2["salt"]

            assert salt1 == salt2, "Salt should be reused for same vault"

    def test_modifying_encrypted_file_causes_decryption_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "Password123!"

            vault1 = Vault(file_path=vault_path, master_password=master_password)
            vault1.add(PasswordEntry("Test", "user", "pass"))

            # Tamper with encrypted data
            with open(vault_path, "r") as f:
                data = json.loads(f.read())

            # Modify the encrypted data
            encrypted_bytes = base64.b64decode(data["data"])
            # Flip some bits
            tampered = bytearray(encrypted_bytes)
            tampered[0] ^= 0xFF
            data["data"] = base64.b64encode(bytes(tampered)).decode("ascii")

            with open(vault_path, "w") as f:
                json.dump(data, f)

            with pytest.raises(VaultDecryptionError):
                Vault(file_path=vault_path, master_password=master_password)

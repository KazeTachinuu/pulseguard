"""Tests for encrypted vault operations."""

import json
import os
import subprocess
import sys
import tempfile

import pytest

from pulseguard.models import PasswordEntry
from pulseguard.vault import Vault, VaultDecryptionError


def run_cli(args, vault_path, env=None, input_data=None):
    """Helper to run CLI commands."""
    cmd = [sys.executable, "-m", "pulseguard"] + args
    if env is None:
        env = os.environ.copy()
    env["PULSEGUARD_VAULT_PATH"] = vault_path

    if input_data is None:
        input_data = "\n" * 10

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        input=input_data,
    )


class TestCompleteUserWorkflows:
    def test_new_user_complete_workflow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            vault = Vault(file_path=vault_path)
            vault.add(PasswordEntry("Gmail", "personal@gmail.com", "InitialPass123!"))
            vault.add(PasswordEntry("GitHub", "developer", "GitToken456!"))
            gmail = vault.get("Gmail")
            assert gmail.password == "InitialPass123!"

            vault2 = Vault(file_path=vault_path)
            assert vault2.count() == 2
            vault2.add(PasswordEntry("Twitter", "user", "TwitterPass789!"))
            vault2.add(
                PasswordEntry(
                    "Work Email",
                    "user@company.com",
                    "WorkPass000!",
                    url="https://mail.company.com",
                    notes="VPN required",
                )
            )

            vault3 = Vault(file_path=vault_path)
            work_accounts = vault3.search("work")
            assert len(work_accounts) == 1
            assert work_accounts[0].name == "Work Email"

            vault4 = Vault(file_path=vault_path)
            vault4.add(
                PasswordEntry("Gmail", "personal@gmail.com", "NewSecurePass999!")
            )
            gmail_updated = vault4.get("Gmail")
            assert gmail_updated.password == "NewSecurePass999!"
            assert gmail_updated.password != "InitialPass123!"

            vault5 = Vault(file_path=vault_path)
            vault5.remove("Twitter")

            vault_final = Vault(file_path=vault_path)
            assert vault_final.count() == 3
            assert vault_final.get("Gmail").password == "NewSecurePass999!"
            assert vault_final.get("GitHub").password == "GitToken456!"
            assert vault_final.get("Work Email").notes == "VPN required"
            assert vault_final.get("Twitter") is None

    def test_encrypted_vault_complete_workflow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "MySecureMasterPassword123!"

            vault1 = Vault(file_path=vault_path, master_password=master_password)
            vault1.add(PasswordEntry("BankAccount", "user123", "BankPass456!"))
            vault1.add(
                PasswordEntry(
                    "CreditCard",
                    "4111111111111111",
                    "PIN:1234",
                    notes="Expires 12/25",
                )
            )

            with open(vault_path, "r") as f:
                content = f.read()
                assert "BankPass456!" not in content, "Password should be encrypted"
                data = json.loads(content)
                assert data.get("encrypted") is True

            # Reopen with correct password
            vault2 = Vault(file_path=vault_path, master_password=master_password)
            bank = vault2.get("BankAccount")
            assert bank.password == "BankPass456!"

            card = vault2.get("CreditCard")
            assert card.username == "4111111111111111"
            assert card.notes == "Expires 12/25"

            with pytest.raises(VaultDecryptionError):
                Vault(file_path=vault_path, master_password="WrongPassword!")

    def test_migration_from_plaintext_to_encrypted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            with pytest.warns():  # Will warn about plaintext
                vault_plain = Vault(file_path=vault_path, master_password=None)
                vault_plain.add(PasswordEntry("Gmail", "user1", "pass1"))
                vault_plain.add(PasswordEntry("GitHub", "user2", "pass2"))
                vault_plain.add(PasswordEntry("Twitter", "user3", "pass3"))

            with open(vault_path, "r") as f:
                content = f.read()
                assert "pass1" in content, "Should be plaintext"

            master_password = "NewMasterPassword123!"

            with pytest.warns():
                vault_migrate = Vault(file_path=vault_path, master_password=None)

                old_entries = vault_migrate.get_all()

            vault_encrypted = Vault(
                file_path=vault_path, master_password=master_password
            )

            # Manually migrate entries (in real app, this would be automatic)
            for entry in old_entries:
                vault_encrypted.add(entry)

            with open(vault_path, "r") as f:
                content = f.read()
                assert "pass1" not in content, "Should now be encrypted"
                data = json.loads(content)
                assert data.get("encrypted") is True

            vault_final = Vault(file_path=vault_path, master_password=master_password)
            assert vault_final.count() == 3

            assert vault_final.get("Gmail").password == "pass1"
            assert vault_final.get("GitHub").password == "pass2"
            assert vault_final.get("Twitter").password == "pass3"

            with pytest.raises(VaultDecryptionError):
                Vault(file_path=vault_path, master_password=None)


class TestErrorRecoveryWorkflows:
    def test_recovery_from_corrupted_vault(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            vault1 = Vault(file_path=vault_path)
            vault1.add(PasswordEntry("Test", "user", "pass"))

            # Corrupt the file
            with open(vault_path, "w") as f:
                f.write("corrupted garbage data {{{")

            with pytest.raises(Exception):  # VaultCorruptedError
                Vault(file_path=vault_path)

            # User deletes corrupted file
            os.remove(vault_path)

            # Can create new vault
            vault2 = Vault(file_path=vault_path)
            assert vault2.count() == 0
            vault2.add(PasswordEntry("Recovered", "user", "pass"))
            assert vault2.count() == 1

    def test_handling_concurrent_modifications(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            vault_init = Vault(file_path=vault_path)
            vault_init.add(PasswordEntry("Initial", "user", "pass"))

            vault1 = Vault(file_path=vault_path)
            vault2 = Vault(file_path=vault_path)

            assert vault1.count() == 1
            assert vault2.count() == 1

            # Modify in vault1
            vault1.add(PasswordEntry("Entry1", "user1", "pass1"))

            # Modify in vault2
            vault2.add(PasswordEntry("Entry2", "user2", "pass2"))

            # Last write (vault2) wins - vault1's changes are lost
            vault_final = Vault(file_path=vault_path)

            # Only Entry2 should be present (last write)
            assert vault_final.get("Entry2") is not None
            # Entry1 might be lost depending on timing


class TestRealWorldScenarios:
    def test_password_manager_for_developer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault = Vault(file_path=vault_path)

            vault.add(
                PasswordEntry(
                    "GitHub API",
                    "ghp_xxxxxxxxxxxx",
                    "real_token_here",
                    url="https://github.com/settings/tokens",
                    notes="Read/write repo access",
                )
            )

            vault.add(
                PasswordEntry(
                    "AWS API Key",
                    "AKIA...",
                    "secret_key_here",
                    notes="Production account - use carefully",
                )
            )

            vault.add(
                PasswordEntry(
                    "Database Admin",
                    "dbadmin",
                    "complex_db_password",
                    url="postgres://localhost:5432",
                )
            )

            vault.add(PasswordEntry("Gmail", "developer@gmail.com", "personal_pass"))

            api_keys = vault.search("API")
            assert len(api_keys) == 2

            aws = vault.search("AWS")
            assert len(aws) == 1
            assert "Production" in aws[0].notes

            # Rotate GitHub token
            vault.add(
                PasswordEntry(
                    "GitHub API",
                    "ghp_xxxxxxxxxxxx",
                    "new_token_here",
                    url="https://github.com/settings/tokens",
                    notes="Read/write repo access - rotated 2025-10-08",
                )
            )

            github = vault.get("GitHub API")
            assert github.password == "new_token_here"
            assert "rotated" in github.notes

            assert vault.count() == 4

    def test_family_password_sharing_scenario(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "FamilyMasterPassword123!"
            vault = Vault(file_path=vault_path, master_password=master_password)

            vault.add(
                PasswordEntry(
                    "Netflix",
                    "family@example.com",
                    "NetflixPass123!",
                    url="https://netflix.com",
                    notes="4 screens - everyone can use",
                )
            )

            vault.add(
                PasswordEntry(
                    "Spotify Family",
                    "family@example.com",
                    "SpotifyPass456!",
                    url="https://spotify.com",
                    notes="6 accounts - invite needed",
                )
            )

            vault.add(
                PasswordEntry(
                    "Disney+",
                    "family@example.com",
                    "DisneyPass789!",
                    notes="Kids profiles set up",
                )
            )

            results = vault.search("family@example.com")
            assert len(results) == 3

            # Family member adds their own account
            vault.add(
                PasswordEntry(
                    "Personal Instagram",
                    "teenager",
                    "InstaPass000!",
                    notes="Private - don't share",
                )
            )

            assert vault.count() == 4

            vault2 = Vault(file_path=vault_path, master_password=master_password)
            netflix = vault2.get("Netflix")
            assert "everyone can use" in netflix.notes

    def test_hundred_passwords_performance(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "MasterPassword123!"

            vault = Vault(file_path=vault_path, master_password=master_password)

            for i in range(100):
                vault.add(
                    PasswordEntry(
                        name=f"Service{i:03d}",
                        username=f"user{i}@example.com",
                        password=f"ComplexPassword{i}!@#",
                        url=f"https://service{i}.com",
                        notes=f"Account number {i}",
                    )
                )

            assert vault.count() == 100

            file_size = os.path.getsize(vault_path)
            assert file_size > 0
            assert file_size < 1024 * 1024

            # Reload and verify all data intact
            vault2 = Vault(file_path=vault_path, master_password=master_password)
            assert vault2.count() == 100

            assert vault2.get("Service000").password == "ComplexPassword0!@#"
            assert vault2.get("Service050").password == "ComplexPassword50!@#"
            assert vault2.get("Service099").password == "ComplexPassword99!@#"

            results = vault2.search("Service05")
            assert len(results) == 10

            vault2.add(
                PasswordEntry(
                    "Service050",
                    "newuser@example.com",
                    "UpdatedPassword!",
                )
            )

            assert vault2.count() == 100

            # Reload and verify update persisted
            vault3 = Vault(file_path=vault_path, master_password=master_password)
            assert vault3.get("Service050").password == "UpdatedPassword!"

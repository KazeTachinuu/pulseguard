"""Functional integration tests for complete user workflows.

These are REAL end-to-end tests that verify PulseGuard works as a complete system:
- Real user scenarios from start to finish
- Multiple components working together
- CLI + Vault + Encryption integration
- Error recovery scenarios
- Migration workflows
"""

import json
import os
import subprocess
import sys
import tempfile

import pytest

from pulseguard.models import PasswordEntry
from pulseguard.vault import Vault, VaultDecryptionError
from unittest.mock import patch


def run_cli(args, vault_path, env=None, input_data=None): # <-- AJOUTER input_data
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
        input=input_data # <-- UTILISER input_data
    )


class TestCompleteUserWorkflows:
    """Test complete user scenarios from start to finish."""

    def test_new_user_complete_workflow(self):
        """FUNCTIONAL: New user creates vault, adds passwords, uses them, updates, deletes.

        This simulates a real user's journey:
        1. First time user creates vault
        2. Adds several passwords over time
        3. Searches for specific password
        4. Updates a password
        5. Deletes old account
        6. Verifies everything persists
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Day 1: User adds first passwords
            vault = Vault(file_path=vault_path)
            vault.add(PasswordEntry("Gmail", "personal@gmail.com", "InitialPass123!"))
            vault.add(PasswordEntry("GitHub", "developer", "GitToken456!"))

            # Verify they can retrieve them
            gmail = vault.get("Gmail")
            assert gmail.password == "InitialPass123!"

            # Day 2: User adds more passwords (simulates restart)
            vault2 = Vault(file_path=vault_path)
            assert vault2.count() == 2, "Previous passwords should persist"

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

            # Day 3: User searches for work-related accounts
            vault3 = Vault(file_path=vault_path)
            work_accounts = vault3.search("work")
            assert len(work_accounts) == 1
            assert work_accounts[0].name == "Work Email"

            # Day 4: User updates Gmail password (security rotation)
            vault4 = Vault(file_path=vault_path)
            vault4.add(
                PasswordEntry("Gmail", "personal@gmail.com", "NewSecurePass999!")
            )

            # Verify old password is gone
            gmail_updated = vault4.get("Gmail")
            assert gmail_updated.password == "NewSecurePass999!"
            assert gmail_updated.password != "InitialPass123!"

            # Day 5: User deletes Twitter account
            vault5 = Vault(file_path=vault_path)
            vault5.remove("Twitter")

            # Final verification: Check complete state
            vault_final = Vault(file_path=vault_path)
            assert vault_final.count() == 3  # Gmail, GitHub, Work Email
            assert vault_final.get("Gmail").password == "NewSecurePass999!"
            assert vault_final.get("GitHub").password == "GitToken456!"
            assert vault_final.get("Work Email").notes == "VPN required"
            assert vault_final.get("Twitter") is None

    # def test_cli_and_vault_interoperability(self):
    #     """FUNCTIONAL: Changes made via CLI are visible to Vault API and vice versa.

    #     This verifies that the CLI and direct Vault API work on the same data:
    #     1. Create encrypted vault via API
    #     2. Add via Vault API
    #     3. Read via CLI
    #     4. Update via CLI
    #     5. Read via Vault API
    #     """
    #     master_password = "test_password_123"

    #     with tempfile.TemporaryDirectory() as tmpdir:
    #         vault_path = os.path.join(tmpdir, "vault.json")

    #         # Create encrypted vault via API
    #         vault = Vault(file_path=vault_path, master_password=master_password)
    #         vault.add(PasswordEntry("Gmail", "user", "VaultPassword123!"))

    #         # Read via CLI (needs password input)
    #         env = os.environ.copy()
    #         env["PULSEGUARD_VAULT_PATH"] = vault_path
    #         result = subprocess.run(
    #             [sys.executable, "-m", "pulseguard", "get", "Gmail"],
    #             capture_output=True,
    #             text=True,
    #             env=env,
    #             input=f"{master_password}\n",
    #         )
    #         assert result.returncode == 0
    #         assert "VaultPassword123!" in result.stdout

    #         # Update via CLI
    #         result = subprocess.run(
    #             [
    #                 sys.executable,
    #                 "-m",
    #                 "pulseguard",
    #                 "add",
    #                 "Gmail",
    #                 "user",
    #                 "CLIPassword456!",
    #             ],
    #             capture_output=True,
    #             text=True,
    #             env=env,
    #             input=f"{master_password}\n",
    #         )
    #         assert result.returncode == 0

    #         # Read via Vault API to verify CLI update
    #         vault2 = Vault(file_path=vault_path, master_password=master_password)
    #         entry = vault2.get("Gmail")
    #         assert entry.password == "CLIPassword456!"

    #         # Add another via CLI
    #         subprocess.run(
    #             [
    #                 sys.executable,
    #                 "-m",
    #                 "pulseguard",
    #                 "add",
    #                 "GitHub",
    #                 "dev",
    #                 "CLIGitHub789!",
    #             ],
    #             capture_output=True,
    #             text=True,
    #             env=env,
    #             input=f"{master_password}\n",
    #         )

    #         # List via Vault API should show both
    #         vault3 = Vault(file_path=vault_path, master_password=master_password)
    #         assert vault3.count() == 2
    #         assert vault3.get("Gmail") is not None
    #         assert vault3.get("GitHub") is not None



    def test_encrypted_vault_complete_workflow(self):
        """FUNCTIONAL: Complete workflow with encrypted vault.

        Simulates user using encryption:
        1. Create encrypted vault
        2. Add passwords
        3. Close and reopen with password
        4. Verify data survived encryption
        5. Verify wrong password fails
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "MySecureMasterPassword123!"

            # Create encrypted vault and add data
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

            # Verify file is encrypted
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

            # Try with wrong password
            with pytest.raises(VaultDecryptionError):
                Vault(file_path=vault_path, master_password="WrongPassword!")

    def test_migration_from_plaintext_to_encrypted(self):
        """FUNCTIONAL: User migrates from plaintext vault to encrypted vault.

        Real scenario:
        1. User starts with plaintext vault (no encryption)
        2. Adds several passwords
        3. Decides to enable encryption
        4. Migrates to encrypted vault
        5. Verifies all data survived migration
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Phase 1: User starts without encryption
            with pytest.warns():  # Will warn about plaintext
                vault_plain = Vault(file_path=vault_path, master_password=None)
                vault_plain.add(PasswordEntry("Gmail", "user1", "pass1"))
                vault_plain.add(PasswordEntry("GitHub", "user2", "pass2"))
                vault_plain.add(PasswordEntry("Twitter", "user3", "pass3"))

            # Verify plaintext file
            with open(vault_path, "r") as f:
                content = f.read()
                assert "pass1" in content, "Should be plaintext"

            # Phase 2: User enables encryption
            master_password = "NewMasterPassword123!"

            # Load plaintext vault (will warn)
            with pytest.warns():
                vault_migrate = Vault(file_path=vault_path, master_password=None)
                vault_migrate.count()

                # Get all entries before migration
                old_entries = vault_migrate.get_all()

            # Create encrypted vault and migrate data
            vault_encrypted = Vault(
                file_path=vault_path, master_password=master_password
            )

            # Manually migrate entries (in real app, this would be automatic)
            for entry in old_entries:
                vault_encrypted.add(entry)

            # Phase 3: Verify migration successful
            with open(vault_path, "r") as f:
                content = f.read()
                assert "pass1" not in content, "Should now be encrypted"
                data = json.loads(content)
                assert data.get("encrypted") is True

            # Verify all data accessible with master password
            vault_final = Vault(file_path=vault_path, master_password=master_password)
            assert vault_final.count() == 3

            assert vault_final.get("Gmail").password == "pass1"
            assert vault_final.get("GitHub").password == "pass2"
            assert vault_final.get("Twitter").password == "pass3"

            # Verify cannot access without password
            with pytest.raises(VaultDecryptionError):
                Vault(file_path=vault_path, master_password=None)


class TestErrorRecoveryWorkflows:
    """Test how the system handles errors and recovers."""

    def test_recovery_from_corrupted_vault(self):
        """FUNCTIONAL: User can recover from corrupted vault file.

        Scenario:
        1. User has working vault
        2. File gets corrupted (disk error, manual edit, etc.)
        3. System detects corruption
        4. User can delete corrupted file and start fresh
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Create working vault
            vault1 = Vault(file_path=vault_path)
            vault1.add(PasswordEntry("Test", "user", "pass"))

            # Corrupt the file
            with open(vault_path, "w") as f:
                f.write("corrupted garbage data {{{")

            # Loading should fail with clear error
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
        """FUNCTIONAL: Last write wins when vault modified concurrently.

        Scenario:
        1. Load vault in two instances
        2. Modify in both
        3. Last save wins (this is the current behavior)
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")

            # Create initial vault
            vault_init = Vault(file_path=vault_path)
            vault_init.add(PasswordEntry("Initial", "user", "pass"))

            # Load in two instances
            vault1 = Vault(file_path=vault_path)
            vault2 = Vault(file_path=vault_path)

            # Both see initial state
            assert vault1.count() == 1
            assert vault2.count() == 1

            # Modify in vault1
            vault1.add(PasswordEntry("Entry1", "user1", "pass1"))

            # Modify in vault2
            vault2.add(PasswordEntry("Entry2", "user2", "pass2"))

            # Last write (vault2) wins - vault1's changes are lost
            # This is expected behavior for file-based storage without locking
            vault_final = Vault(file_path=vault_path)

            # Only Entry2 should be present (last write)
            assert vault_final.get("Entry2") is not None
            # Entry1 might be lost depending on timing


class TestRealWorldScenarios:
    """Test real-world usage patterns."""

    def test_password_manager_for_developer(self):
        """FUNCTIONAL: Developer manages API keys and service passwords.

        Realistic scenario:
        - Multiple API keys
        - Service accounts
        - Personal accounts
        - Regular password rotation
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            vault = Vault(file_path=vault_path)

            # Add API keys
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

            # Add service accounts
            vault.add(
                PasswordEntry(
                    "Database Admin",
                    "dbadmin",
                    "complex_db_password",
                    url="postgres://localhost:5432",
                )
            )

            # Add personal accounts
            vault.add(PasswordEntry("Gmail", "developer@gmail.com", "personal_pass"))

            # Search for API keys
            api_keys = vault.search("API")
            assert len(api_keys) == 2

            # Search for AWS
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

            # Verify rotation
            github = vault.get("GitHub API")
            assert github.password == "new_token_here"
            assert "rotated" in github.notes

            # Final count
            assert vault.count() == 4

    def test_family_password_sharing_scenario(self):
        """FUNCTIONAL: Family shares passwords for streaming services.

        Scenario:
        - Multiple streaming services
        - Shared accounts
        - Notes about who can use what
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "FamilyMasterPassword123!"
            vault = Vault(file_path=vault_path, master_password=master_password)

            # Add streaming services
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

            # Search for all streaming
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

            # Verify all accounts accessible
            assert vault.count() == 4

            # Simulate sharing: Another family member opens vault
            vault2 = Vault(file_path=vault_path, master_password=master_password)
            netflix = vault2.get("Netflix")
            assert "everyone can use" in netflix.notes

    def test_hundred_passwords_performance(self):
        """FUNCTIONAL: Vault handles 100+ passwords efficiently.

        Verifies:
        - Can store many passwords
        - Search remains fast
        - File I/O handles large data
        - Encryption/decryption works with large vaults
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, "vault.json")
            master_password = "MasterPassword123!"

            # Create encrypted vault with 100 passwords
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

            # Verify count
            assert vault.count() == 100

            # Verify file size reasonable
            file_size = os.path.getsize(vault_path)
            assert file_size > 0
            # Should be less than 1MB for 100 entries
            assert file_size < 1024 * 1024

            # Reload and verify all data intact
            vault2 = Vault(file_path=vault_path, master_password=master_password)
            assert vault2.count() == 100

            # Verify random entries
            assert vault2.get("Service000").password == "ComplexPassword0!@#"
            assert vault2.get("Service050").password == "ComplexPassword50!@#"
            assert vault2.get("Service099").password == "ComplexPassword99!@#"

            # Search should work
            results = vault2.search("Service05")
            # Should find Service050-059
            assert len(results) == 10

            # Update one entry
            vault2.add(
                PasswordEntry(
                    "Service050",
                    "newuser@example.com",
                    "UpdatedPassword!",
                )
            )

            # Verify still 100 entries (update, not add)
            assert vault2.count() == 100

            # Reload and verify update persisted
            vault3 = Vault(file_path=vault_path, master_password=master_password)
            assert vault3.get("Service050").password == "UpdatedPassword!"

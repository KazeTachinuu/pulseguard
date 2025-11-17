"""
End-to-end workflow tests simulating real user scenarios.

This module tests complete user workflows including:
- New user setup and initial usage
- Daily password manager operations
- Password rotation and updates
- Team/family sharing scenarios
- Large vault performance
"""

import os

import pytest

from pulseguard.models import PasswordEntry
from pulseguard.vault import Vault, VaultCorruptedError, VaultDecryptionError


class TestNewUserWorkflow:
    """Test complete workflow for a new user setting up PulseGuard."""

    def test_complete_first_time_user_journey(self, vault_path, master_password):
        """
        Simulate a new user's complete first session:
        1. Create vault with first password
        2. Add more passwords
        3. Search for password
        4. Update password
        5. Delete password
        6. Verify all changes persist
        """
        # Step 1: New user creates vault and adds first password
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(PasswordEntry("Gmail", "personal@gmail.com", "InitialPass123!"))

        # Verify first entry saved
        assert vault1.count() == 1

        # Step 2: User adds more passwords
        vault2 = Vault(file_path=vault_path, master_password=master_password)
        vault2.add(PasswordEntry("GitHub", "developer", "GitToken456!"))
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

        # Step 3: User searches for work accounts
        vault3 = Vault(file_path=vault_path, master_password=master_password)
        work_accounts = vault3.search("work")

        assert len(work_accounts) == 1
        assert work_accounts[0].name == "Work Email"

        # Step 4: User updates Gmail password
        vault4 = Vault(file_path=vault_path, master_password=master_password)
        vault4.add(PasswordEntry("Gmail", "personal@gmail.com", "NewSecurePass999!"))

        gmail_updated = vault4.get("Gmail")
        assert gmail_updated.password == "NewSecurePass999!"

        # Step 5: User deletes Twitter account
        vault5 = Vault(file_path=vault_path, master_password=master_password)
        vault5.remove("Twitter")

        # Step 6: Verify final state
        vault_final = Vault(file_path=vault_path, master_password=master_password)

        assert vault_final.count() == 3
        assert vault_final.get("Gmail").password == "NewSecurePass999!"
        assert vault_final.get("GitHub").password == "GitToken456!"
        assert vault_final.get("Work Email").notes == "VPN required"
        assert vault_final.get("Twitter") is None


class TestDeveloperWorkflow:
    """Test workflows for software developers managing API keys and credentials."""

    def test_developer_managing_api_keys(self, vault_path, master_password):
        """
        Developer workflow:
        1. Store API keys and tokens
        2. Search for specific API
        3. Rotate GitHub token
        4. Verify all credentials secure
        """
        vault = Vault(file_path=vault_path, master_password=master_password)

        # Store various API credentials
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

        # Search for API keys
        api_keys = vault.search("API")
        assert len(api_keys) == 2

        # Find AWS specifically
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

        # Verify total count
        assert vault.count() == 4


class TestFamilySharingWorkflow:
    """Test workflows for family password sharing."""

    def test_family_shared_streaming_services(self, vault_path):
        """
        Family scenario:
        1. Setup shared streaming services
        2. Add personal accounts
        3. Verify all family members can access
        """
        family_password = "FamilyMasterPassword123!"
        vault = Vault(file_path=vault_path, master_password=family_password)

        # Add shared streaming services
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

        # Search for family email
        results = vault.search("family@example.com")
        assert len(results) == 3

        # Family member adds personal account
        vault.add(
            PasswordEntry(
                "Personal Instagram",
                "teenager",
                "InstaPass000!",
                notes="Private - don't share",
            )
        )

        assert vault.count() == 4

        # Verify shared services persist
        vault2 = Vault(file_path=vault_path, master_password=family_password)
        netflix = vault2.get("Netflix")
        assert "everyone can use" in netflix.notes


class TestPerformanceWorkflow:
    """Test workflows with large numbers of passwords."""

    def test_managing_100_passwords(self, vault_path, master_password):
        """
        Test performance and reliability with 100 passwords:
        1. Add 100 entries
        2. Verify all persist
        3. Update one
        4. Search among many
        5. Verify file size reasonable
        """
        vault = Vault(file_path=vault_path, master_password=master_password)

        # Add 100 passwords
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

        # Verify file size is reasonable (should be under 1MB)
        file_size = os.path.getsize(vault_path)
        assert file_size > 0
        assert (
            file_size < 1024 * 1024
        ), "Encrypted vault should be < 1MB for 100 entries"

        # Reload and verify all intact
        vault2 = Vault(file_path=vault_path, master_password=master_password)
        assert vault2.count() == 100

        # Verify specific entries
        assert vault2.get("Service000").password == "ComplexPassword0!@#"
        assert vault2.get("Service050").password == "ComplexPassword50!@#"
        assert vault2.get("Service099").password == "ComplexPassword99!@#"

        # Search should work efficiently
        results = vault2.search("Service05")
        assert len(results) == 10  # Service050-059

        # Update one entry
        vault2.add(
            PasswordEntry(
                "Service050",
                "newuser@example.com",
                "UpdatedPassword!",
            )
        )

        assert vault2.count() == 100  # Still 100 (update, not add)

        # Verify update persisted
        vault3 = Vault(file_path=vault_path, master_password=master_password)
        assert vault3.get("Service050").password == "UpdatedPassword!"


class TestErrorRecoveryWorkflow:
    """Test error handling and recovery scenarios."""

    def test_recovery_from_wrong_password(self, vault_path, master_password):
        """
        User recovery scenario:
        1. Create vault with password
        2. Try to open with wrong password (fails)
        3. Open with correct password (succeeds)
        """
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(PasswordEntry("Important", "user", "pass"))

        # Wrong password should fail
        with pytest.raises(VaultDecryptionError):
            Vault(file_path=vault_path, master_password="WrongPassword!")

        # Correct password should work
        vault2 = Vault(file_path=vault_path, master_password=master_password)
        assert vault2.get("Important") is not None

    def test_recovery_from_corrupted_vault(self, vault_path, master_password):
        """
        Disaster recovery scenario:
        1. Vault gets corrupted
        2. User detects corruption
        3. User deletes and starts fresh
        """
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault1.add(PasswordEntry("Test", "user", "pass"))

        # Corrupt the vault file
        with open(vault_path, "w") as f:
            f.write("corrupted garbage data {{{")

        # Should detect corruption
        with pytest.raises(VaultCorruptedError):
            Vault(file_path=vault_path, master_password=master_password)

        # User deletes corrupted file and starts fresh
        os.remove(vault_path)

        vault2 = Vault(file_path=vault_path, master_password=master_password)
        assert vault2.count() == 0
        vault2.add(PasswordEntry("Recovered", "user", "pass"))
        assert vault2.count() == 1

    def test_concurrent_access_last_write_wins(self, vault_path, master_password):
        """
        Concurrent access scenario:
        1. Two processes open same vault
        2. Both make changes
        3. Last write wins
        """
        # Initialize vault
        vault_init = Vault(file_path=vault_path, master_password=master_password)
        vault_init.add(PasswordEntry("Initial", "user", "pass"))

        # Two "processes" open the vault
        vault1 = Vault(file_path=vault_path, master_password=master_password)
        vault2 = Vault(file_path=vault_path, master_password=master_password)

        assert vault1.count() == 1
        assert vault2.count() == 1

        # Both make changes
        vault1.add(PasswordEntry("Entry1", "user1", "pass1"))
        vault2.add(PasswordEntry("Entry2", "user2", "pass2"))

        # Last write (vault2) should win
        vault_final = Vault(file_path=vault_path, master_password=master_password)

        # Entry2 should be present (last write)
        assert vault_final.get("Entry2") is not None


class TestSecurityWorkflow:
    """Test security-focused workflows."""

    def test_password_rotation_workflow(self, vault_path, master_password):
        """
        Security best practice workflow:
        1. Store initial passwords
        2. Identify reused passwords
        3. Rotate compromised password
        4. Verify no reuse
        """
        vault = Vault(file_path=vault_path, master_password=master_password)

        # User stores passwords (accidentally reuses one)
        vault.add(PasswordEntry("Gmail", "user@gmail.com", "CommonPass123"))
        vault.add(PasswordEntry("Facebook", "user", "CommonPass123"))
        vault.add(PasswordEntry("Twitter", "user", "UniquePass456"))

        # Check for reused passwords
        from pulseguard.vault import find_reused_passwords

        reused = find_reused_passwords(vault)
        assert len(reused) == 1  # One password reused

        # User rotates Gmail password
        vault.add(PasswordEntry("Gmail", "user@gmail.com", "NewUniquePass789"))

        # Verify reuse is reduced
        reused_after = find_reused_passwords(vault)
        # Now only Facebook and Twitter have unique passwords
        assert len(reused_after) == 0  # No more reuse

    def test_vault_encryption_never_leaks_plaintext(self, vault_path, master_password):
        """
        Security verification:
        1. Store sensitive data
        2. Verify file contains only ciphertext
        3. Verify no plaintext leakage at any point
        """
        vault = Vault(file_path=vault_path, master_password=master_password)

        sensitive_data = [
            ("SSN", "user", "123-45-6789", "https://ssa.gov", "DO NOT SHARE"),
            (
                "Credit Card",
                "4111111111111111",
                "CVV:123",
                "https://bank.com",
                "Expires 12/25",
            ),
            ("Bank PIN", "account123", "PIN:9876", "https://mybank.com", "ATM access"),
        ]

        for name, username, password, url, notes in sensitive_data:
            vault.add(PasswordEntry(name, username, password, url=url, notes=notes))

        # Read raw file contents
        with open(vault_path, "r") as f:
            file_contents = f.read()

        # Verify NO sensitive data appears in plaintext
        for name, username, password, url, notes in sensitive_data:
            assert (
                password not in file_contents
            ), f"Password '{password}' leaked in plaintext!"
            assert username not in file_contents, f"Username '{username}' leaked!"
            assert name not in file_contents, f"Name '{name}' leaked!"
            if notes and len(notes) > 10:  # Only check longer notes
                assert notes not in file_contents, f"Notes '{notes}' leaked!"

        # Verify file contains encrypted data
        assert "salt" in file_contents
        assert "data" in file_contents

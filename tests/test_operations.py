"""Comprehensive tests for operations module.

Tests all operation handlers including:
- Success paths with valid inputs
- Error cases (entry not found, invalid input)
- Edge cases (empty vault, special characters)
- Interactive flows (edit command with mocked input)
- Demo data insertion
- checks password generation + clipboard success
- checks fallback display when clipboard unavailable
- ensures mutual exclusion is enforced
- covers direct password generator command
- simulates interactive edit + generator path
- tests generator error handling and fallback manual input
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from pulseguard.models import PasswordEntry
from pulseguard.operations import (
    add_password,
    delete_password,
    edit_password,
    generate_password_command,
    get_password,
    list_passwords,
    run_demo,
    search_passwords,
)
from pulseguard.vault import Vault


@pytest.fixture
def temp_vault():
    """Create a temporary vault for testing."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        temp_file = f.name

    vault = Vault(temp_file)
    yield vault

    # Cleanup
    if os.path.exists(temp_file):
        os.unlink(temp_file)


def _temp_vault(tmp_path):
    p = tmp_path / "v.json"
    return Vault(str(p))


@pytest.fixture
def populated_vault(temp_vault):
    """Create a vault with sample entries."""
    entries = [
        PasswordEntry(
            "Gmail", "user@gmail.com", "pass123", "https://gmail.com", "Work email"
        ),
        PasswordEntry(
            "GitHub", "developer", "gh_token", "https://github.com", "Dev account"
        ),
        PasswordEntry("Twitter", "user@twitter.com", "tweet_pass", "", ""),
    ]
    for entry in entries:
        temp_vault.add(entry)
    return temp_vault


class TestListPasswords:
    """Test list_passwords operation."""

    def test_list_empty_vault(self, temp_vault, capsys):
        """Test listing when vault is empty."""
        list_passwords(temp_vault)
        captured = capsys.readouterr()
        assert "No entries found" in captured.out

    def test_list_single_entry(self, temp_vault, capsys):
        """Test listing with a single entry."""
        temp_vault.add(PasswordEntry("Test", "user", "pass"))
        list_passwords(temp_vault)
        captured = capsys.readouterr()
        assert "Found 1 entry(ies)" in captured.out
        assert "Test - user" in captured.out

    def test_list_multiple_entries(self, populated_vault, capsys):
        """Test listing with multiple entries."""
        list_passwords(populated_vault)
        captured = capsys.readouterr()
        assert "Found 3 entry(ies)" in captured.out
        assert "Gmail - user@gmail.com" in captured.out
        assert "GitHub - developer" in captured.out
        assert "Twitter - user@twitter.com" in captured.out

    def test_list_shows_numbered_entries(self, populated_vault, capsys):
        """Test that entries are numbered sequentially."""
        list_passwords(populated_vault)
        captured = capsys.readouterr()
        assert "1. " in captured.out
        assert "2. " in captured.out
        assert "3. " in captured.out


class TestAddPassword:
    """Test add_password operation."""

    def test_add_minimal_entry(self, temp_vault, capsys):
        """Test adding entry with only required fields."""
        add_password(temp_vault, "TestSite", "testuser", "testpass")
        captured = capsys.readouterr()
        assert "Added entry 'TestSite' successfully" in captured.out
        assert temp_vault.get("TestSite") is not None
        assert temp_vault.get("TestSite").username == "testuser"
        assert temp_vault.get("TestSite").password == "testpass"

    def test_add_entry_with_url(self, temp_vault, capsys):
        """Test adding entry with URL."""
        add_password(temp_vault, "Site", "user", "pass", url="https://example.com")
        captured = capsys.readouterr()
        assert "Added entry 'Site' successfully" in captured.out
        entry = temp_vault.get("Site")
        assert entry.url == "https://example.com"

    def test_add_entry_with_notes(self, temp_vault, capsys):
        """Test adding entry with notes."""
        add_password(temp_vault, "Site", "user", "pass", notes="Important note")
        captured = capsys.readouterr()
        assert "Added entry 'Site' successfully" in captured.out
        entry = temp_vault.get("Site")
        assert entry.notes == "Important note"

    def test_add_entry_with_all_fields(self, temp_vault, capsys):
        """Test adding entry with all optional fields."""
        add_password(
            temp_vault,
            "CompleteSite",
            "fulluser",
            "fullpass",
            url="https://complete.com",
            notes="Complete entry",
        )
        captured = capsys.readouterr()
        assert "Added entry 'CompleteSite' successfully" in captured.out
        entry = temp_vault.get("CompleteSite")
        assert entry.username == "fulluser"
        assert entry.password == "fullpass"
        assert entry.url == "https://complete.com"
        assert entry.notes == "Complete entry"

    def test_add_updates_existing_entry(self, temp_vault, capsys):
        """Test that adding entry with existing name updates it."""
        add_password(temp_vault, "Site", "user1", "pass1")
        add_password(temp_vault, "Site", "user2", "pass2")

        entry = temp_vault.get("Site")
        assert entry.username == "user2"
        assert entry.password == "pass2"
        assert temp_vault.count() == 1  # Still only one entry

    def test_add_special_characters_in_password(self, temp_vault, capsys):
        """Test adding password with special characters."""
        special_pass = "p@ssw0rd!#$%^&*()_+-=[]{}|;:',.<>?/~`"
        add_password(temp_vault, "Site", "user", special_pass)
        entry = temp_vault.get("Site")
        assert entry.password == special_pass

    def test_add_unicode_characters(self, temp_vault, capsys):
        """Test adding entry with Unicode characters."""
        add_password(temp_vault, "日本語サイト", "用户", "密码123", notes="中文笔记")
        entry = temp_vault.get("日本語サイト")
        assert entry.username == "用户"
        assert entry.password == "密码123"
        assert entry.notes == "中文笔记"


class TestGetPassword:
    """Test get_password operation."""

    def test_get_existing_entry(self, populated_vault, capsys):
        """Test getting an existing entry."""
        get_password(populated_vault, "Gmail")
        captured = capsys.readouterr()
        assert "Password: Gmail" in captured.out
        assert "Username: user@gmail.com" in captured.out
        assert "Password: pass123" in captured.out
        assert "URL: https://gmail.com" in captured.out
        assert "Notes: Work email" in captured.out

    def test_get_entry_without_optional_fields(self, populated_vault, capsys):
        """Test getting entry that has no URL or notes."""
        get_password(populated_vault, "Twitter")
        captured = capsys.readouterr()
        assert "Password: Twitter" in captured.out
        assert "Username: user@twitter.com" in captured.out
        # URL and Notes should not appear if empty
        assert captured.out.count("URL:") == 0
        assert captured.out.count("Notes:") == 0

    def test_get_nonexistent_entry(self, temp_vault, capsys):
        """Test getting entry that doesn't exist."""
        get_password(temp_vault, "NonExistent")
        captured = capsys.readouterr()
        assert "Entry 'NonExistent' not found" in captured.out

    def test_get_case_sensitive(self, populated_vault, capsys):
        """Test that get is case-sensitive."""
        get_password(populated_vault, "gmail")  # lowercase
        captured = capsys.readouterr()
        assert "Entry 'gmail' not found" in captured.out


class TestEditPassword:
    """Test edit_password operation."""

    def test_edit_nonexistent_entry(self, temp_vault, capsys):
        """Test editing entry that doesn't exist."""
        edit_password(temp_vault, "NonExistent")
        captured = capsys.readouterr()
        assert "Entry 'NonExistent' not found" in captured.out

    @patch(
        "builtins.input",
        side_effect=["newuser", "n", "newpass", "https://new.com", "New notes"],
    )
    def test_edit_all_fields(self, mock_input, populated_vault, capsys):
        """Test editing all fields of an entry."""
        edit_password(populated_vault, "Gmail")
        captured = capsys.readouterr()

        assert "Editing password 'Gmail'" in captured.out
        assert "Added entry 'Gmail' successfully" in captured.out

        entry = populated_vault.get("Gmail")
        assert entry.username == "newuser"
        assert entry.password == "newpass"
        assert entry.url == "https://new.com"
        assert entry.notes == "New notes"

    @patch("builtins.input", side_effect=["", "", "", "", ""])
    def test_edit_keep_all_fields(self, mock_input, populated_vault, capsys):
        """Test editing with all empty inputs (keep current values)."""
        original_entry = populated_vault.get("Gmail")
        original_username = original_entry.username
        original_password = original_entry.password
        original_url = original_entry.url
        original_notes = original_entry.notes

        edit_password(populated_vault, "Gmail")

        entry = populated_vault.get("Gmail")
        assert entry.username == original_username
        assert entry.password == original_password
        assert entry.url == original_url
        assert entry.notes == original_notes

    @patch("builtins.input", side_effect=["newuser", "", "", "", ""])
    def test_edit_partial_fields(self, mock_input, populated_vault, capsys):
        """Test editing only some fields."""
        edit_password(populated_vault, "Gmail")

        entry = populated_vault.get("Gmail")
        assert entry.username == "newuser"
        assert entry.password == "pass123"  # Original password unchanged
        assert entry.url == "https://gmail.com"  # Original URL unchanged

    @patch("builtins.input", side_effect=["", "", "", "", ""])
    def test_edit_entry_without_optional_fields(self, mock_input, temp_vault, capsys):
        """Test editing entry that has no URL or notes."""
        temp_vault.add(PasswordEntry("Simple", "user", "pass"))
        edit_password(temp_vault, "Simple")

        entry = temp_vault.get("Simple")
        assert entry.username == "user"
        assert entry.password == "pass"

    @patch("builtins.input", side_effect=["newuser", "", "p@ssw0rd!#$%", "", ""])
    def test_edit_special_characters(self, mock_input, temp_vault, capsys):
        """Test editing with special characters in password."""
        temp_vault.add(PasswordEntry("Test", "user", "pass"))
        edit_password(temp_vault, "Test")

        entry = temp_vault.get("Test")
        assert entry.password == "p@ssw0rd!#$%"


class TestDeletePassword:
    """Test delete_password operation."""

    def test_delete_existing_entry(self, populated_vault, capsys):
        """Test deleting an existing entry."""
        delete_password(populated_vault, "Gmail")
        captured = capsys.readouterr()
        assert "Deleted entry 'Gmail' successfully" in captured.out
        assert populated_vault.get("Gmail") is None
        assert populated_vault.count() == 2  # 3 - 1 = 2

    def test_delete_nonexistent_entry(self, temp_vault, capsys):
        """Test deleting entry that doesn't exist."""
        delete_password(temp_vault, "NonExistent")
        captured = capsys.readouterr()
        assert "Entry 'NonExistent' not found" in captured.out

    def test_delete_from_empty_vault(self, temp_vault, capsys):
        """Test deleting from empty vault."""
        delete_password(temp_vault, "Test")
        captured = capsys.readouterr()
        assert "Entry 'Test' not found" in captured.out

    def test_delete_all_entries(self, populated_vault, capsys):
        """Test deleting all entries one by one."""
        delete_password(populated_vault, "Gmail")
        delete_password(populated_vault, "GitHub")
        delete_password(populated_vault, "Twitter")

        assert populated_vault.count() == 0
        assert len(populated_vault.entries) == 0


class TestSearchPasswords:
    """Test search_passwords operation."""

    def test_search_by_name(self, populated_vault, capsys):
        """Test searching by entry name."""
        search_passwords(populated_vault, "Gmail")
        captured = capsys.readouterr()
        assert "Found 1 entry(ies) matching 'Gmail'" in captured.out
        assert "Gmail - user@gmail.com" in captured.out

    def test_search_by_username(self, populated_vault, capsys):
        """Test searching by username."""
        search_passwords(populated_vault, "developer")
        captured = capsys.readouterr()
        assert "Found 1 entry(ies) matching 'developer'" in captured.out
        assert "GitHub - developer" in captured.out

    def test_search_case_insensitive(self, populated_vault, capsys):
        """Test that search is case-insensitive."""
        search_passwords(populated_vault, "GMAIL")
        captured = capsys.readouterr()
        assert "Found 1 entry(ies)" in captured.out
        assert "Gmail" in captured.out

    def test_search_partial_match(self, populated_vault, capsys):
        """Test searching with partial match."""
        search_passwords(populated_vault, "git")
        captured = capsys.readouterr()
        assert "Found 1 entry(ies) matching 'git'" in captured.out
        assert "GitHub" in captured.out

    def test_search_multiple_results(self, populated_vault, capsys):
        """Test searching with multiple matching entries."""
        # Add another entry with "user" in username
        populated_vault.add(PasswordEntry("LinkedIn", "user@linkedin.com", "pass"))

        search_passwords(populated_vault, "user")
        captured = capsys.readouterr()
        assert "Found 3 entry(ies) matching 'user'" in captured.out
        assert "Gmail" in captured.out
        assert "Twitter" in captured.out
        assert "LinkedIn" in captured.out

    def test_search_no_results(self, populated_vault, capsys):
        """Test searching with no matching entries."""
        search_passwords(populated_vault, "nonexistent")
        captured = capsys.readouterr()
        assert "No entries found matching 'nonexistent'" in captured.out

    def test_search_empty_vault(self, temp_vault, capsys):
        """Test searching in empty vault."""
        search_passwords(temp_vault, "anything")
        captured = capsys.readouterr()
        assert "No entries found matching 'anything'" in captured.out

    def test_search_special_characters(self, temp_vault, capsys):
        """Test searching with special characters."""
        temp_vault.add(PasswordEntry("Test@Site", "user@test.com", "pass"))
        search_passwords(temp_vault, "@")
        captured = capsys.readouterr()
        assert "Found 1 entry(ies)" in captured.out


class TestRunDemo:
    """Test run_demo operation."""

    def test_demo_adds_entries(self, temp_vault, capsys):
        """Test that demo adds sample entries."""
        initial_count = temp_vault.count()
        run_demo(temp_vault)
        captured = capsys.readouterr()

        assert "Running PulseGuard demo" in captured.out
        assert "Demo complete!" in captured.out
        assert temp_vault.count() > initial_count

    def test_demo_adds_correct_number(self, temp_vault, capsys):
        """Test that demo adds exactly 3 sample entries."""
        run_demo(temp_vault)
        captured = capsys.readouterr()
        assert "Added 3 sample passwords" in captured.out

    def test_demo_adds_specific_entries(self, temp_vault, capsys):
        """Test that demo adds expected entries."""
        run_demo(temp_vault)
        captured = capsys.readouterr()

        # Check output shows added entries
        assert "Added: Gmail" in captured.out
        assert "Added: GitHub" in captured.out
        assert "Added: Bank" in captured.out

        # Verify entries exist in vault
        assert temp_vault.get("Gmail") is not None
        assert temp_vault.get("GitHub") is not None
        assert temp_vault.get("Bank") is not None

    def test_demo_entry_details(self, temp_vault, capsys):
        """Test that demo entries have correct details."""
        run_demo(temp_vault)

        gmail = temp_vault.get("Gmail")
        assert gmail.username == "user@gmail.com"
        assert gmail.password == "demo_password_123"
        assert gmail.url == "https://gmail.com"
        assert gmail.notes == "Personal email account"

    def test_demo_on_populated_vault(self, populated_vault, capsys):
        """Test running demo on vault that already has entries."""
        populated_vault.count()
        run_demo(populated_vault)

        # Demo updates existing entries with same names
        # Original Gmail, GitHub entries get replaced, Bank is new
        # Twitter remains
        assert populated_vault.count() == 4  # Gmail, GitHub, Twitter, Bank

    def test_demo_help_message(self, temp_vault, capsys):
        """Test that demo shows help message."""
        run_demo(temp_vault)
        captured = capsys.readouterr()
        assert "pulseguard list" in captured.out
        assert "pulseguard" in captured.out


class TestAddPasswordGeneration:
    @patch("pulseguard.operations.copy_to_clipboard", return_value=True)
    @patch("pulseguard.operations.generate_password", return_value="A1b!A1b!A1b!A1b!")
    def test_add_with_gen_clipboard_true(self, mock_gen, mock_clip, tmp_path, capsys):
        v = _temp_vault(tmp_path)
        add_password(
            v,
            name="G",
            username="u",
            password="",
            gen=True,
            length=16,
            lower=True,
            upper=True,
            digits=True,
            symbols=True,
        )
        out = capsys.readouterr().out
        assert "Added entry 'G' successfully" in out
        assert "length=16" in out
        # password not printed when clipboard is True
        assert "Password:" not in out
        assert v.get("G").password == "A1b!A1b!A1b!A1b!"

    @patch("pulseguard.operations.copy_to_clipboard", return_value=False)
    @patch("pulseguard.operations.generate_password", return_value="XXXXYYYYZZZZ1111")
    def test_add_with_gen_clipboard_false_prints_password(
        self, mock_gen, mock_clip, tmp_path, capsys
    ):
        v = _temp_vault(tmp_path)
        add_password(v, "S", "u", "", gen=True, length=16, symbols=False)
        out = capsys.readouterr().out
        assert "! Clipboard unavailable" in out
        assert "Password:" in out or "XXXXYYYYZZZZ1111" in out
        assert v.get("S").password == "XXXXYYYYZZZZ1111"

    def test_add_with_gen_and_password_conflict(self, tmp_path, capsys):
        v = _temp_vault(tmp_path)
        # gen True + provided password should be rejected in operations.add_password
        add_password(v, "C", "u", "p", gen=True)
        out = capsys.readouterr().out.lower()
        assert "cannot use --gen together with a manual password" in out
        assert "provide either a password or --gen" in out


class TestGeneratePasswordCommand:
    @patch("pulseguard.operations.copy_to_clipboard", return_value=False)
    @patch("pulseguard.operations.generate_password", return_value="DET_PASS")
    def test_generate_password_command_prints_when_no_clipboard(
        self, mock_gen, mock_clip, tmp_path, capsys
    ):
        v = _temp_vault(tmp_path)
        generate_password_command(
            v, length=12, lower=False, upper=True, digits=True, symbols=True
        )
        out = capsys.readouterr().out
        assert "Generated password:" in out
        assert "DET_PASS" in out
        # Do not assert a fixed length value; just ensure the length/max trailer is printed

        assert "(length=" in out
        assert "max=25" in out


class TestEditPasswordGeneratorFlow:
    @patch("pulseguard.operations.copy_to_clipboard", return_value=False)
    @patch("pulseguard.operations.generate_password", return_value="NEWGENPASS!")
    def test_edit_uses_generator_then_prints_password(
        self, mock_gen, mock_clip, tmp_path, capsys, monkeypatch
    ):
        v = _temp_vault(tmp_path)
        v.add(PasswordEntry("X", "user", "old"))
        # Inputs: username(empty => keep), use_generator = 'y', length '', lower '', upper '', digits '', symbols 'y',
        # (we pass empty strings to use defaults except forcing symbols yes)
        monkeypatch.setattr(
            "builtins.input",
            lambda prompt="": {
                0: "",  # Username keep
                1: "y",  # Use generator
                2: "",  # Length (default)
                3: "",  # lower (default Y)
                4: "",  # upper (default Y)
                5: "",  # digits (default Y)
                6: "y",  # symbols yes
                7: "",  # URL keep
                8: "",  # notes keep
            }[getattr(monkeypatch, "_idx", 0)],
        )

        # small trick to increment the index on each call
        def _adv(prompt=""):
            i = getattr(monkeypatch, "_idx", 0)
            setattr(monkeypatch, "_idx", i + 1)
            return {0: "", 1: "y", 2: "", 3: "", 4: "", 5: "", 6: "y", 7: "", 8: ""}[i]

        monkeypatch.setattr("builtins.input", _adv)

        edit_password(v, "X")
        out = capsys.readouterr().out
        assert "Editing password 'X'" in out
        assert "! Clipboard unavailable" in out
        assert v.get("X").password == "NEWGENPASS!"

    @patch(
        "pulseguard.operations.generate_password", side_effect=ValueError("bad opts")
    )
    def test_edit_generator_error_falls_back_to_manual(
        self, mock_gen, tmp_path, capsys, monkeypatch
    ):
        v = _temp_vault(tmp_path)
        v.add(PasswordEntry("Y", "u", "old"))
        # Username keep, choose generator -> error, then manual pass provided, url/notes keep
        inputs = iter(["", "y", "", "", "", "", "", "MANUAL", "", ""])
        monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
        edit_password(v, "Y")
        assert v.get("Y").password == "MANUAL"

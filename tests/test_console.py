"""Comprehensive tests for console module.

Tests the interactive console including:
- Console initialization
- Command resolution and alias handling
- Command execution via default()
- Help command functionality
- Quit/exit commands
- Error handling for unknown commands
- Empty line handling
"""

import os
import tempfile
from io import StringIO
from unittest.mock import patch

import pytest

from pulseguard.console import Console
from pulseguard.models import PasswordEntry
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


@pytest.fixture
def console_with_vault(temp_vault):
    """Create console with temporary vault."""
    console = Console(vault=temp_vault)
    # Disable intro and prompt for cleaner test output
    console.intro = ""
    console.prompt = ""
    return console


@pytest.fixture
def populated_console(temp_vault):
    """Create console with populated vault."""
    temp_vault.add(PasswordEntry("Gmail", "user@gmail.com", "pass123"))
    temp_vault.add(PasswordEntry("GitHub", "dev", "token"))
    console = Console(vault=temp_vault)
    console.intro = ""
    console.prompt = ""
    return console


class TestConsoleInitialization:
    """Test Console initialization."""

    def test_console_init_default_vault(self):
        """Test console initialization with default vault."""
        console = Console()
        assert console.vault is not None
        assert isinstance(console.vault, Vault)

    def test_console_init_custom_vault(self, temp_vault):
        """Test console initialization with custom vault."""
        console = Console(vault=temp_vault)
        assert console.vault is temp_vault

    def test_console_has_intro_message(self):
        """Test that console has intro message."""
        console = Console()
        assert console.intro is not None
        assert "PulseGuard" in console.intro

    def test_console_has_prompt(self):
        """Test that console has prompt."""
        console = Console()
        assert console.prompt is not None
        assert "pulseguard>" in console.prompt


class TestCommandExecution:
    """Test command execution via default() method."""

    def test_execute_list_command(self, console_with_vault, capsys):
        """Test executing list command."""
        console_with_vault.default("list")
        captured = capsys.readouterr()
        assert "No entries found" in captured.out

    def test_execute_list_with_entries(self, populated_console, capsys):
        """Test executing list with entries in vault."""
        populated_console.default("list")
        captured = capsys.readouterr()
        assert "Found 2 entry(ies)" in captured.out
        assert "Gmail" in captured.out

    def test_execute_add_command(self, console_with_vault, capsys):
        """Test executing add command."""
        console_with_vault.default("add TestSite testuser testpass")
        captured = capsys.readouterr()
        assert "Added entry 'TestSite' successfully" in captured.out

    def test_execute_add_with_optional_args(self, console_with_vault, capsys):
        """Test executing add with URL and notes."""
        console_with_vault.default("add Site user pass --url https://test.com --notes Important")
        captured = capsys.readouterr()
        assert "Added entry 'Site' successfully" in captured.out

        entry = console_with_vault.vault.get("Site")
        assert entry.url == "https://test.com"
        assert entry.notes == "Important"

    def test_execute_add_insufficient_args(self, console_with_vault, capsys):
        """Test executing add with insufficient arguments."""
        console_with_vault.default("add TestSite testuser")
        captured = capsys.readouterr()
        assert "Usage: add" in captured.out

    def test_execute_get_command(self, populated_console, capsys):
        """Test executing get command."""
        populated_console.default("get Gmail")
        captured = capsys.readouterr()
        assert "Password: Gmail" in captured.out
        assert "Username: user@gmail.com" in captured.out

    def test_execute_get_nonexistent(self, console_with_vault, capsys):
        """Test executing get for nonexistent entry."""
        console_with_vault.default("get NonExistent")
        captured = capsys.readouterr()
        assert "Entry 'NonExistent' not found" in captured.out

    def test_execute_delete_command(self, populated_console, capsys):
        """Test executing delete command."""
        populated_console.default("delete Gmail")
        captured = capsys.readouterr()
        assert "Deleted entry 'Gmail' successfully" in captured.out

    def test_execute_search_command(self, populated_console, capsys):
        """Test executing search command."""
        populated_console.default("search gmail")
        captured = capsys.readouterr()
        assert "Found 1 entry(ies) matching 'gmail'" in captured.out

    @patch('builtins.input', side_effect=['newuser', '', '', ''])
    def test_execute_edit_command(self, mock_input, populated_console, capsys):
        """Test executing edit command."""
        populated_console.default("edit Gmail")
        captured = capsys.readouterr()
        assert "Editing password 'Gmail'" in captured.out

    def test_execute_demo_command(self, console_with_vault, capsys):
        """Test executing demo command."""
        console_with_vault.default("demo")
        captured = capsys.readouterr()
        assert "Running PulseGuard demo" in captured.out


class TestAliasResolution:
    """Test command alias resolution."""

    def test_execute_list_alias_ls(self, console_with_vault, capsys):
        """Test executing 'ls' alias for list."""
        console_with_vault.default("ls")
        captured = capsys.readouterr()
        assert "No entries found" in captured.out

    def test_execute_list_alias_l(self, console_with_vault, capsys):
        """Test executing 'l' alias for list."""
        console_with_vault.default("l")
        captured = capsys.readouterr()
        assert "No entries found" in captured.out

    def test_execute_add_alias_a(self, console_with_vault, capsys):
        """Test executing 'a' alias for add."""
        console_with_vault.default("a Test user pass")
        captured = capsys.readouterr()
        assert "Added entry 'Test' successfully" in captured.out

    def test_execute_add_alias_new(self, console_with_vault, capsys):
        """Test executing 'new' alias for add."""
        console_with_vault.default("new Test user pass")
        captured = capsys.readouterr()
        assert "Added entry 'Test' successfully" in captured.out

    def test_execute_get_alias_g(self, populated_console, capsys):
        """Test executing 'g' alias for get."""
        populated_console.default("g Gmail")
        captured = capsys.readouterr()
        assert "Password: Gmail" in captured.out

    def test_execute_get_alias_show(self, populated_console, capsys):
        """Test executing 'show' alias for get."""
        populated_console.default("show Gmail")
        captured = capsys.readouterr()
        assert "Password: Gmail" in captured.out

    def test_execute_get_alias_view(self, populated_console, capsys):
        """Test executing 'view' alias for get."""
        populated_console.default("view Gmail")
        captured = capsys.readouterr()
        assert "Password: Gmail" in captured.out

    def test_execute_delete_alias_d(self, populated_console, capsys):
        """Test executing 'd' alias for delete."""
        populated_console.default("d Gmail")
        captured = capsys.readouterr()
        assert "Deleted entry 'Gmail' successfully" in captured.out

    def test_execute_delete_alias_del(self, populated_console, capsys):
        """Test executing 'del' alias for delete."""
        populated_console.default("del Gmail")
        captured = capsys.readouterr()
        assert "Deleted entry 'Gmail' successfully" in captured.out

    def test_execute_delete_alias_remove(self, populated_console, capsys):
        """Test executing 'remove' alias for delete."""
        populated_console.default("remove Gmail")
        captured = capsys.readouterr()
        assert "Deleted entry 'Gmail' successfully" in captured.out

    def test_execute_delete_alias_rm(self, populated_console, capsys):
        """Test executing 'rm' alias for delete."""
        populated_console.default("rm Gmail")
        captured = capsys.readouterr()
        assert "Deleted entry 'Gmail' successfully" in captured.out

    def test_execute_search_alias_s(self, populated_console, capsys):
        """Test executing 's' alias for search."""
        populated_console.default("s gmail")
        captured = capsys.readouterr()
        assert "Found 1 entry(ies)" in captured.out

    def test_execute_search_alias_find(self, populated_console, capsys):
        """Test executing 'find' alias for search."""
        populated_console.default("find gmail")
        captured = capsys.readouterr()
        assert "Found 1 entry(ies)" in captured.out

    @patch('builtins.input', side_effect=['', '', '', ''])
    def test_execute_edit_alias_e(self, mock_input, populated_console, capsys):
        """Test executing 'e' alias for edit."""
        populated_console.default("e Gmail")
        captured = capsys.readouterr()
        assert "Editing password 'Gmail'" in captured.out

    @patch('builtins.input', side_effect=['', '', '', ''])
    def test_execute_edit_alias_modify(self, mock_input, populated_console, capsys):
        """Test executing 'modify' alias for edit."""
        populated_console.default("modify Gmail")
        captured = capsys.readouterr()
        assert "Editing password 'Gmail'" in captured.out

    @patch('builtins.input', side_effect=['', '', '', ''])
    def test_execute_edit_alias_update(self, mock_input, populated_console, capsys):
        """Test executing 'update' alias for edit."""
        populated_console.default("update Gmail")
        captured = capsys.readouterr()
        assert "Editing password 'Gmail'" in captured.out


class TestHelpCommand:
    """Test help command functionality."""

    def test_do_help_without_args(self, console_with_vault, capsys):
        """Test help command without arguments shows all commands."""
        console_with_vault.do_help("")
        captured = capsys.readouterr()
        assert "Available commands:" in captured.out
        assert "list" in captured.out
        assert "add" in captured.out
        assert "get" in captured.out

    def test_help_shows_aliases(self, console_with_vault, capsys):
        """Test that help shows command aliases."""
        console_with_vault.do_help("")
        captured = capsys.readouterr()
        assert "aliases:" in captured.out
        assert "ls, l" in captured.out

    def test_help_shows_quit_exit(self, console_with_vault, capsys):
        """Test that help shows quit and exit commands."""
        console_with_vault.do_help("")
        captured = capsys.readouterr()
        assert "quit" in captured.out
        assert "exit" in captured.out


class TestQuitExitCommands:
    """Test quit and exit commands."""

    def test_do_quit_returns_true(self, console_with_vault, capsys):
        """Test that quit command returns True to exit."""
        result = console_with_vault.do_quit("")
        assert result is True

    def test_do_quit_shows_goodbye(self, console_with_vault, capsys):
        """Test that quit command shows goodbye message."""
        console_with_vault.do_quit("")
        captured = capsys.readouterr()
        assert "Goodbye!" in captured.out

    def test_do_exit_returns_true(self, console_with_vault, capsys):
        """Test that exit command returns True to exit."""
        result = console_with_vault.do_exit("")
        assert result is True

    def test_do_exit_shows_goodbye(self, console_with_vault, capsys):
        """Test that exit command shows goodbye message."""
        console_with_vault.do_exit("")
        captured = capsys.readouterr()
        assert "Goodbye!" in captured.out


class TestErrorHandling:
    """Test error handling in console."""

    def test_unknown_command(self, console_with_vault, capsys):
        """Test handling of unknown command."""
        console_with_vault.default("unknowncommand")
        captured = capsys.readouterr()
        assert "Unknown syntax: unknowncommand" in captured.out

    def test_empty_command(self, console_with_vault, capsys):
        """Test handling of empty command."""
        # Should not output anything
        console_with_vault.default("")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_whitespace_only_command(self, console_with_vault, capsys):
        """Test handling of whitespace-only command."""
        console_with_vault.default("   ")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_emptyline_does_nothing(self, console_with_vault, capsys):
        """Test that empty line doesn't repeat last command."""
        # First command
        console_with_vault.default("list")
        capsys.readouterr()  # Clear output

        # Empty line should not repeat list
        console_with_vault.emptyline()
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_command_with_exception(self, console_with_vault, capsys):
        """Test handling of command that raises exception."""
        # Try to get from a corrupted vault (simulate error)
        with patch.object(console_with_vault.vault, 'get', side_effect=Exception("Test error")):
            console_with_vault.default("get Test")
            captured = capsys.readouterr()
            assert "Error executing command" in captured.out


class TestCommandParsing:
    """Test command parsing and argument handling."""

    def test_command_with_no_args(self, console_with_vault, capsys):
        """Test command with no arguments."""
        console_with_vault.default("list")
        captured = capsys.readouterr()
        assert "No entries found" in captured.out

    def test_command_with_single_arg(self, populated_console, capsys):
        """Test command with single argument."""
        populated_console.default("get Gmail")
        captured = capsys.readouterr()
        assert "Password: Gmail" in captured.out

    def test_command_with_multiple_args(self, console_with_vault, capsys):
        """Test command with multiple arguments."""
        console_with_vault.default("add Test user password")
        captured = capsys.readouterr()
        assert "Added entry 'Test' successfully" in captured.out

    def test_command_with_quoted_args(self, console_with_vault, capsys):
        """Test command parsing with spaces in arguments."""
        # Note: Current implementation doesn't support quoted strings
        # This test documents current behavior
        console_with_vault.default("add Site user my pass word")
        # Will parse "my" as password, "pass" and "word" as extra args
        # This is a known limitation
        captured = capsys.readouterr()
        # Should still add the entry with "my" as password
        assert console_with_vault.vault.get("Site") is not None

    def test_search_with_multi_word_query(self, populated_console, capsys):
        """Test search with multi-word query."""
        # Current implementation treats everything after command as query
        populated_console.default("search gmail user")
        captured = capsys.readouterr()
        # Will search for "gmail user" (both words)
        assert "Found" in captured.out or "No entries" in captured.out


class TestConsoleIntegration:
    """Test console integration scenarios."""

    def test_add_then_list(self, console_with_vault, capsys):
        """Test adding entry then listing."""
        console_with_vault.default("add Test user pass")
        capsys.readouterr()  # Clear output

        console_with_vault.default("list")
        captured = capsys.readouterr()
        assert "Test - user" in captured.out

    def test_add_then_get(self, console_with_vault, capsys):
        """Test adding entry then retrieving it."""
        console_with_vault.default("add Test user pass")
        capsys.readouterr()

        console_with_vault.default("get Test")
        captured = capsys.readouterr()
        assert "Username: user" in captured.out

    def test_add_then_delete(self, console_with_vault, capsys):
        """Test adding entry then deleting it."""
        console_with_vault.default("add Test user pass")
        capsys.readouterr()

        console_with_vault.default("delete Test")
        captured = capsys.readouterr()
        assert "Deleted entry 'Test' successfully" in captured.out

    def test_add_search_delete_workflow(self, console_with_vault, capsys):
        """Test complete workflow: add, search, delete."""
        # Add entries
        console_with_vault.default("add Gmail user@gmail.com pass1")
        console_with_vault.default("add GitHub dev pass2")
        capsys.readouterr()

        # Search
        console_with_vault.default("search gmail")
        captured = capsys.readouterr()
        assert "Found 1 entry(ies)" in captured.out

        # Delete
        console_with_vault.default("delete Gmail")
        captured = capsys.readouterr()
        assert "Deleted" in captured.out

    def test_multiple_commands_same_entry(self, console_with_vault, capsys):
        """Test multiple operations on same entry."""
        console_with_vault.default("add Test user pass")
        console_with_vault.default("get Test")
        console_with_vault.default("add Test user newpass")  # Update
        console_with_vault.default("get Test")

        captured = capsys.readouterr()
        assert "newpass" in captured.out

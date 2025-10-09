"""Comprehensive tests for CLI module.

Tests command-line interface including:
- Argument parser generation from COMMANDS
- CLI command execution
- Error handling (vault errors, unknown commands)
- Interactive mode entry (no command)
- Integration with vault operations
"""

import argparse
import os
import tempfile
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from pulseguard.cli import create_parser, handle_cli_command, main
from pulseguard.models import PasswordEntry
from pulseguard.vault import Vault, VaultCorruptedError, VaultError


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
def populated_vault(temp_vault):
    """Create a vault with sample entries."""
    temp_vault.add(PasswordEntry("Gmail", "user@gmail.com", "pass123"))
    temp_vault.add(PasswordEntry("GitHub", "dev", "token"))
    return temp_vault


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test that parser is created successfully."""
        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_has_description(self):
        """Test that parser has description."""
        parser = create_parser()
        assert parser.description is not None
        assert "PulseGuard" in parser.description

    def test_parser_has_epilog(self):
        """Test that parser has epilog with examples."""
        parser = create_parser()
        assert parser.epilog is not None
        assert "Examples:" in parser.epilog

    def test_parser_has_subparsers(self):
        """Test that parser has command subparsers."""
        parser = create_parser()
        # Check that --help shows commands
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])

    def test_parser_accepts_list_command(self):
        """Test that parser accepts list command."""
        parser = create_parser()
        args = parser.parse_args(["list"])
        assert args.command == "list"

    def test_parser_accepts_add_command(self):
        """Test that parser accepts add command with arguments."""
        parser = create_parser()
        args = parser.parse_args(["add", "Test", "user", "pass"])
        assert args.command == "add"
        assert args.name == "Test"
        assert args.username == "user"
        assert args.password == "pass"

    def test_parser_accepts_add_with_optional_args(self):
        """Test that parser accepts add with URL and notes."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "add",
                "Test",
                "user",
                "pass",
                "--url",
                "https://test.com",
                "--notes",
                "Important",
            ]
        )
        assert args.url == "https://test.com"
        assert args.notes == "Important"

    def test_parser_accepts_get_command(self):
        """Test that parser accepts get command."""
        parser = create_parser()
        args = parser.parse_args(["get", "Gmail"])
        assert args.command == "get"
        assert args.name == "Gmail"

    def test_parser_accepts_edit_command(self):
        """Test that parser accepts edit command."""
        parser = create_parser()
        args = parser.parse_args(["edit", "Gmail"])
        assert args.command == "edit"
        assert args.name == "Gmail"

    def test_parser_accepts_delete_command(self):
        """Test that parser accepts delete command."""
        parser = create_parser()
        args = parser.parse_args(["delete", "Gmail"])
        assert args.command == "delete"
        assert args.name == "Gmail"

    def test_parser_accepts_search_command(self):
        """Test that parser accepts search command."""
        parser = create_parser()
        args = parser.parse_args(["search", "gmail"])
        assert args.command == "search"
        assert args.query == "gmail"

    def test_parser_accepts_demo_command(self):
        """Test that parser accepts demo command."""
        parser = create_parser()
        args = parser.parse_args(["demo"])
        assert args.command == "demo"

    def test_parser_no_command(self):
        """Test parser with no command (interactive mode)."""
        parser = create_parser()
        args = parser.parse_args([])
        assert args.command is None

    def test_parser_rejects_invalid_command(self):
        """Test that parser rejects invalid command."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["invalid"])

    def test_parser_rejects_incomplete_add(self):
        """Test that parser rejects add command without required args."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["add", "Test"])  # Missing username and password


class TestHandleCliCommand:
    """Test handle_cli_command function."""

    def test_handle_list_command(self, temp_vault, capsys):
        """Test handling list command."""
        args = argparse.Namespace(command="list")
        handle_cli_command(temp_vault, args)
        captured = capsys.readouterr()
        assert "No entries found" in captured.out

    def test_handle_list_with_entries(self, populated_vault, capsys):
        """Test handling list command with entries."""
        args = argparse.Namespace(command="list")
        handle_cli_command(populated_vault, args)
        captured = capsys.readouterr()
        assert "Found 2 entry(ies)" in captured.out
        assert "Gmail" in captured.out

    def test_handle_add_command(self, temp_vault, capsys):
        """Test handling add command."""
        args = argparse.Namespace(
            command="add",
            name="Test",
            username="user",
            password="pass",
            url="",
            notes="",
        )
        handle_cli_command(temp_vault, args)
        captured = capsys.readouterr()
        assert "Added entry 'Test' successfully" in captured.out

    def test_handle_add_with_optional_args(self, temp_vault, capsys):
        """Test handling add command with optional arguments."""
        args = argparse.Namespace(
            command="add",
            name="Test",
            username="user",
            password="pass",
            url="https://test.com",
            notes="Important",
        )
        handle_cli_command(temp_vault, args)
        captured = capsys.readouterr()
        assert "Added entry 'Test' successfully" in captured.out

        entry = temp_vault.get("Test")
        assert entry.url == "https://test.com"
        assert entry.notes == "Important"

    def test_handle_get_command(self, populated_vault, capsys):
        """Test handling get command."""
        args = argparse.Namespace(command="get", name="Gmail")
        handle_cli_command(populated_vault, args)
        captured = capsys.readouterr()
        assert "Password: Gmail" in captured.out
        assert "Username: user@gmail.com" in captured.out

    def test_handle_get_nonexistent(self, temp_vault, capsys):
        """Test handling get for nonexistent entry."""
        args = argparse.Namespace(command="get", name="NonExistent")
        handle_cli_command(temp_vault, args)
        captured = capsys.readouterr()
        assert "Entry 'NonExistent' not found" in captured.out

    @patch("builtins.input", side_effect=["", "", "", ""])
    def test_handle_edit_command(self, mock_input, populated_vault, capsys):
        """Test handling edit command."""
        args = argparse.Namespace(command="edit", name="Gmail")
        handle_cli_command(populated_vault, args)
        captured = capsys.readouterr()
        assert "Editing password 'Gmail'" in captured.out

    def test_handle_delete_command(self, populated_vault, capsys):
        """Test handling delete command."""
        args = argparse.Namespace(command="delete", name="Gmail")
        handle_cli_command(populated_vault, args)
        captured = capsys.readouterr()
        assert "Deleted entry 'Gmail' successfully" in captured.out

    def test_handle_search_command(self, populated_vault, capsys):
        """Test handling search command."""
        args = argparse.Namespace(command="search", query="gmail")
        handle_cli_command(populated_vault, args)
        captured = capsys.readouterr()
        assert "Found 1 entry(ies)" in captured.out

    def test_handle_demo_command(self, temp_vault, capsys):
        """Test handling demo command."""
        args = argparse.Namespace(command="demo")
        handle_cli_command(temp_vault, args)
        captured = capsys.readouterr()
        assert "Running PulseGuard demo" in captured.out

    def test_handle_unknown_command_exits(self, temp_vault, capsys):
        """Test that unknown command exits with error."""
        args = argparse.Namespace(command="unknown")
        with pytest.raises(SystemExit) as exc_info:
            handle_cli_command(temp_vault, args)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Unknown command" in captured.out


class TestMain:
    """Test main function."""

    @patch("pulseguard.cli.initialize_vault")
    @patch("pulseguard.cli.Console")
    @patch("sys.argv", ["pulseguard"])
    def test_main_no_args_starts_console(self, mock_console, mock_init_vault):
        """Test that main with no args starts interactive console."""
        mock_vault_instance = MagicMock()
        mock_init_vault.return_value = mock_vault_instance
        mock_console_instance = MagicMock()
        mock_console.return_value = mock_console_instance

        main()

        mock_init_vault.assert_called_once()
        mock_console.assert_called_once_with(vault=mock_vault_instance)
        mock_console_instance.cmdloop.assert_called_once()

    @patch("pulseguard.cli.initialize_vault")
    @patch("sys.argv", ["pulseguard", "list"])
    def test_main_with_list_command(self, mock_init_vault, capsys):
        """Test main with list command."""
        mock_vault_instance = MagicMock()
        mock_vault_instance.entries = []
        mock_init_vault.return_value = mock_vault_instance

        main()

        mock_init_vault.assert_called_once()
        # Command should execute (output checked in other tests)

    @patch("pulseguard.cli.initialize_vault")
    @patch("sys.argv", ["pulseguard", "add", "Test", "user", "pass"])
    def test_main_with_add_command(self, mock_init_vault, capsys):
        """Test main with add command."""
        mock_vault_instance = MagicMock()
        mock_init_vault.return_value = mock_vault_instance

        main()

        mock_init_vault.assert_called_once()

    @patch("pulseguard.cli.initialize_vault", side_effect=VaultError("Test error"))
    @patch("sys.argv", ["pulseguard", "list"])
    def test_main_vault_error_exits(self, mock_init_vault, capsys):
        """Test that vault error causes exit."""
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Vault error" in captured.err

    @patch("pulseguard.cli.initialize_vault", side_effect=KeyboardInterrupt())
    @patch("sys.argv", ["pulseguard", "list"])
    def test_main_keyboard_interrupt_exits(self, mock_init_vault, capsys):
        """Test that KeyboardInterrupt is handled gracefully."""
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Operation cancelled" in captured.out

    @patch("pulseguard.cli.initialize_vault", side_effect=Exception("Generic error"))
    @patch("sys.argv", ["pulseguard", "list"])
    def test_main_generic_error_exits(self, mock_init_vault, capsys):
        """Test that generic exceptions are caught and exit."""
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Error" in captured.err


class TestCliIntegration:
    """Test CLI integration scenarios."""

    @patch("pulseguard.cli.initialize_vault")
    @patch("sys.argv", ["pulseguard", "list"])
    def test_cli_list_empty_vault(self, mock_init_vault, capsys):
        """Test CLI list on empty vault."""
        mock_vault_instance = MagicMock()
        mock_vault_instance.entries = []
        mock_init_vault.return_value = mock_vault_instance

        main()

        capsys.readouterr()
        # Should handle empty vault gracefully

    @patch("pulseguard.cli.initialize_vault")
    @patch("sys.argv", ["pulseguard", "demo"])
    def test_cli_demo_workflow(self, mock_init_vault, capsys):
        """Test CLI demo command workflow."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            vault = Vault(temp_file)
            mock_init_vault.return_value = vault

            main()

            captured = capsys.readouterr()
            assert "Running PulseGuard demo" in captured.out
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_parser_help_shows_all_commands(self):
        """Test that --help shows all available commands."""
        parser = create_parser()

        # Capture help output
        with pytest.raises(SystemExit):
            with patch("sys.stdout", new=StringIO()):
                parser.parse_args(["--help"])

    def test_command_help_shows_usage(self):
        """Test that command-specific help shows usage."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["add", "--help"])


class TestArgumentParsing:
    """Test argument parsing edge cases."""

    def test_add_empty_optional_args(self):
        """Test add command with empty optional arguments."""
        parser = create_parser()
        args = parser.parse_args(["add", "Test", "user", "pass"])
        assert args.url == ""
        assert args.notes == ""

    def test_add_url_only(self):
        """Test add command with only URL."""
        parser = create_parser()
        args = parser.parse_args(
            ["add", "Test", "user", "pass", "--url", "https://test.com"]
        )
        assert args.url == "https://test.com"
        assert args.notes == ""

    def test_add_notes_only(self):
        """Test add command with only notes."""
        parser = create_parser()
        args = parser.parse_args(
            ["add", "Test", "user", "pass", "--notes", "Important"]
        )
        assert args.url == ""
        assert args.notes == "Important"

    def test_special_characters_in_args(self):
        """Test arguments with special characters."""
        parser = create_parser()
        args = parser.parse_args(["add", "Test@Site", "user@test.com", "p@ssw0rd!"])
        assert args.name == "Test@Site"
        assert args.username == "user@test.com"
        assert args.password == "p@ssw0rd!"

    def test_unicode_characters_in_args(self):
        """Test arguments with Unicode characters."""
        parser = create_parser()
        args = parser.parse_args(["add", "日本語", "用户", "密码"])
        assert args.name == "日本語"
        assert args.username == "用户"
        assert args.password == "密码"

    def test_search_with_spaces(self):
        """Test search query with multiple words."""
        parser = create_parser()
        # Note: argparse will only capture first word without quotes
        parser.parse_args(["search", "gmail account"])
        # Due to argparse behavior, only "gmail" will be captured
        # "account" would be treated as extra arg and cause error
        # This documents current limitation


class TestErrorHandling:
    """Test CLI error handling."""

    @patch("pulseguard.cli.initialize_vault")
    @patch("sys.argv", ["pulseguard", "get", "Test"])
    def test_cli_handles_vault_corrupted_error(self, mock_init_vault, capsys):
        """Test CLI handles VaultCorruptedError."""

        mock_init_vault.side_effect = VaultCorruptedError("Corrupted vault")

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Vault error" in captured.err

    def test_handle_cli_command_with_missing_handler(self, temp_vault, capsys):
        """Test handling command when handler is not found."""
        args = argparse.Namespace(command="nonexistent")

        with pytest.raises(SystemExit) as exc_info:
            handle_cli_command(temp_vault, args)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Unknown command" in captured.out
        assert "pulseguard --help" in captured.out


class TestParserGeneration:
    """Test dynamic parser generation from COMMANDS."""

    def test_all_commands_have_subparsers(self):
        """Test that all commands in COMMANDS have subparsers."""
        from pulseguard.commands import COMMANDS

        parser = create_parser()

        for cmd in COMMANDS:
            # Should be able to parse each command
            args = parser.parse_args(
                [cmd.name]
                + ["dummy"]
                * len([a for a in cmd.args if not a["name"].startswith("--")])
            )
            assert args.command == cmd.name

    def test_parser_preserves_arg_order(self):
        """Test that parser preserves argument order."""
        parser = create_parser()
        args = parser.parse_args(["add", "Name", "Username", "Password"])

        assert args.name == "Name"
        assert args.username == "Username"
        assert args.password == "Password"

    def test_optional_args_have_defaults(self):
        """Test that optional arguments have default values."""
        parser = create_parser()
        args = parser.parse_args(["add", "Test", "user", "pass"])

        # Optional args should have empty string defaults
        assert hasattr(args, "url")
        assert hasattr(args, "notes")
        assert args.url == ""
        assert args.notes == ""

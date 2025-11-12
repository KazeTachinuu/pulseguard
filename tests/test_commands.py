"""Comprehensive tests for commands module.

Tests the command registry system including:
- Command lookup by name
- Alias resolution
- Handler extraction
- Argument specification retrieval
- Help text generation (CLI and console)
- Command resolution from aliases
"""

import pytest

from pulseguard.commands import (
    COMMANDS,
    Command,
    generate_console_help,
    generate_help_epilog,
    get_command,
    get_command_args,
    get_command_by_alias,
    get_command_handler,
    resolve_command_name,
)
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


class TestCommandDataStructure:
    """Test the Command dataclass and COMMANDS registry."""

    def test_commands_list_not_empty(self):
        """Test that COMMANDS list contains commands."""
        assert len(COMMANDS) > 0

    def test_commands_have_required_fields(self):
        """Test that all commands have required fields."""
        for cmd in COMMANDS:
            assert isinstance(cmd, Command)
            assert isinstance(cmd.name, str)
            assert len(cmd.name) > 0
            assert isinstance(cmd.description, str)
            assert isinstance(cmd.usage, str)
            assert isinstance(cmd.example, str)
            assert isinstance(cmd.console_help, str)
            assert callable(cmd.handler)
            assert isinstance(cmd.args, list)
            assert isinstance(cmd.aliases, list)

    def test_all_command_names_unique(self):
        """Test that all command names are unique."""
        names = [cmd.name for cmd in COMMANDS]
        assert len(names) == len(set(names))

    def test_all_aliases_unique_across_commands(self):
        """Test that aliases don't conflict with command names or other aliases."""
        all_names = {cmd.name for cmd in COMMANDS}
        all_aliases = set()

        for cmd in COMMANDS:
            for alias in cmd.aliases:
                # Alias should not conflict with any command name
                assert (
                    alias not in all_names
                ), f"Alias '{alias}' conflicts with command name"
                # Alias should not be duplicated
                assert alias not in all_aliases, f"Alias '{alias}' is duplicated"
                all_aliases.add(alias)

    def test_command_handlers_are_functions(self):
        """Test that all handlers are callable functions."""
        expected_handlers = {
            list_passwords,
            add_password,
            get_password,
            edit_password,
            delete_password,
            search_passwords,
            run_demo,
            generate_password_command,
        }

        registered_handlers = {cmd.handler for cmd in COMMANDS}
        assert registered_handlers == expected_handlers

    def test_specific_commands_exist(self):
        """Test that expected commands are registered."""
        command_names = {cmd.name for cmd in COMMANDS}
        expected_commands = {
            "list",
            "add",
            "get",
            "edit",
            "delete",
            "search",
            "demo",
            "genpass",
        }
        assert command_names == expected_commands


class TestGetCommand:
    """Test get_command function."""

    def test_get_existing_command(self):
        """Test getting a command that exists."""
        cmd = get_command("list")
        assert cmd is not None
        assert cmd.name == "list"
        assert cmd.handler == list_passwords

    def test_get_all_commands(self):
        """Test getting each registered command."""
        for expected_cmd in COMMANDS:
            cmd = get_command(expected_cmd.name)
            assert cmd == expected_cmd

    def test_get_nonexistent_command(self):
        """Test getting a command that doesn't exist."""
        cmd = get_command("nonexistent")
        assert cmd is None

    def test_get_command_case_sensitive(self):
        """Test that command lookup is case-sensitive."""
        cmd = get_command("LIST")  # uppercase
        assert cmd is None

    def test_get_command_with_alias(self):
        """Test get_command doesn't work with aliases."""
        # "ls" is an alias for "list"
        cmd = get_command("ls")
        assert cmd is None  # Should not find by alias


class TestGetCommandHandler:
    """Test get_command_handler function."""

    def test_get_handler_for_existing_command(self):
        """Test getting handler for existing command."""
        handler = get_command_handler("list")
        assert handler == list_passwords

    def test_get_handler_for_all_commands(self):
        """Test getting handlers for all commands."""
        handlers = {
            "list": list_passwords,
            "add": add_password,
            "get": get_password,
            "edit": edit_password,
            "delete": delete_password,
            "search": search_passwords,
            "demo": run_demo,
            "genpass": generate_password_command,
        }

        for cmd_name, expected_handler in handlers.items():
            handler = get_command_handler(cmd_name)
            assert handler == expected_handler

    def test_get_handler_for_nonexistent_command(self):
        """Test getting handler for nonexistent command."""
        handler = get_command_handler("nonexistent")
        assert handler is None

    def test_handler_is_callable(self):
        """Test that returned handlers are callable."""
        for cmd in COMMANDS:
            handler = get_command_handler(cmd.name)
            assert callable(handler)


class TestGetCommandArgs:
    """Test get_command_args function."""

    def test_get_args_for_list_command(self):
        """Test getting args for list command (no args)."""
        args = get_command_args("list")
        assert args == []

    def test_get_args_for_add_command(self):
        """Test getting args for add command (multiple args)."""
        args = get_command_args("add")
        assert len(args) == 11  # name, username, password, --url, --notes
        assert args[0]["name"] == "name"
        assert args[1]["name"] == "username"
        assert args[2]["name"] == "password"
        assert args[3]["name"] == "--url"
        assert args[4]["name"] == "--notes"
        assert args[5]["name"] == "--gen"
        assert args[10]["name"] == "--symbols"

    def test_get_args_for_get_command(self):
        """Test getting args for get command (single arg)."""
        args = get_command_args("get")
        assert len(args) == 1
        assert args[0]["name"] == "name"

    def test_get_args_for_search_command(self):
        """Test getting args for search command."""
        args = get_command_args("search")
        assert len(args) == 1
        assert args[0]["name"] == "query"

    def test_get_args_for_nonexistent_command(self):
        """Test getting args for nonexistent command."""
        args = get_command_args("nonexistent")
        assert args == []

    def test_args_have_required_fields(self):
        """Test that all args have required fields."""
        for cmd in COMMANDS:
            args = get_command_args(cmd.name)
            for arg in args:
                assert "name" in arg
                assert "help" in arg
                assert isinstance(arg["name"], str)
                assert isinstance(arg["help"], str)


class TestGetCommandByAlias:
    """Test get_command_by_alias function."""

    def test_get_command_by_valid_alias(self):
        """Test getting command by valid alias."""
        cmd = get_command_by_alias("ls")
        assert cmd is not None
        assert cmd.name == "list"

    def test_get_command_by_all_aliases(self):
        """Test getting command by each registered alias."""
        expected_aliases = {
            "ls": "list",
            "l": "list",
            "a": "add",
            "new": "add",
            "g": "get",
            "show": "get",
            "view": "get",
            "e": "edit",
            "modify": "edit",
            "update": "edit",
            "d": "delete",
            "del": "delete",
            "remove": "delete",
            "rm": "delete",
            "s": "search",
            "find": "search",
        }

        for alias, expected_name in expected_aliases.items():
            cmd = get_command_by_alias(alias)
            assert cmd is not None, f"Alias '{alias}' not found"
            assert cmd.name == expected_name, f"Alias '{alias}' mapped to wrong command"

    def test_get_command_by_nonexistent_alias(self):
        """Test getting command by nonexistent alias."""
        cmd = get_command_by_alias("nonexistent")
        assert cmd is None

    def test_get_command_by_canonical_name_returns_none(self):
        """Test that canonical names don't work with get_command_by_alias."""
        cmd = get_command_by_alias("list")  # canonical name, not alias
        assert cmd is None


class TestResolveCommandName:
    """Test resolve_command_name function."""

    def test_resolve_canonical_name(self):
        """Test resolving canonical command name."""
        resolved = resolve_command_name("list")
        assert resolved == "list"

    def test_resolve_all_canonical_names(self):
        """Test resolving all canonical names."""
        for cmd in COMMANDS:
            resolved = resolve_command_name(cmd.name)
            assert resolved == cmd.name

    def test_resolve_alias_to_canonical_name(self):
        """Test resolving alias to canonical name."""
        resolved = resolve_command_name("ls")
        assert resolved == "list"

    def test_resolve_all_aliases(self):
        """Test resolving all aliases."""
        expected_resolutions = {
            "ls": "list",
            "l": "list",
            "a": "add",
            "new": "add",
            "g": "get",
            "show": "get",
            "view": "get",
            "e": "edit",
            "modify": "edit",
            "update": "edit",
            "d": "delete",
            "del": "delete",
            "remove": "delete",
            "rm": "delete",
            "s": "search",
            "find": "search",
        }

        for alias, expected_name in expected_resolutions.items():
            resolved = resolve_command_name(alias)
            assert (
                resolved == expected_name
            ), f"Alias '{alias}' didn't resolve to '{expected_name}'"

    def test_resolve_nonexistent_name(self):
        """Test resolving nonexistent command/alias."""
        resolved = resolve_command_name("nonexistent")
        assert resolved is None

    def test_resolve_case_sensitive(self):
        """Test that resolution is case-sensitive."""
        resolved = resolve_command_name("LIST")
        assert resolved is None


class TestGenerateHelpEpilog:
    """Test generate_help_epilog function."""

    def test_epilog_contains_examples_header(self):
        """Test that epilog contains Examples header."""
        epilog = generate_help_epilog()
        assert "Examples:" in epilog

    def test_epilog_contains_interactive_mode_example(self):
        """Test that epilog shows interactive mode example."""
        epilog = generate_help_epilog()
        assert "pulseguard" in epilog
        assert "interactive console" in epilog.lower()

    def test_epilog_contains_all_commands(self):
        """Test that epilog contains examples for all commands."""
        epilog = generate_help_epilog()
        for cmd in COMMANDS:
            assert cmd.example in epilog, f"Missing example for {cmd.name}"

    def test_epilog_format(self):
        """Test that epilog follows expected format."""
        epilog = generate_help_epilog()
        lines = epilog.split("\n")

        assert lines[0] == "Examples:"
        # Each example line should start with spaces (indentation)
        for line in lines[1:]:
            if line:  # Skip empty lines
                assert line.startswith("  ")

    def test_epilog_includes_descriptions(self):
        """Test that epilog includes command descriptions."""
        epilog = generate_help_epilog()
        for cmd in COMMANDS:
            assert cmd.description in epilog


class TestGenerateConsoleHelp:
    """Test generate_console_help function."""

    def test_console_help_contains_header(self):
        """Test that console help contains header."""
        help_text = generate_console_help()
        assert "Available commands:" in help_text

    def test_console_help_contains_all_commands(self):
        """Test that console help lists all commands."""
        help_text = generate_console_help()
        for cmd in COMMANDS:
            assert cmd.name in help_text

    def test_console_help_shows_aliases(self):
        """Test that console help shows aliases."""
        help_text = generate_console_help()

        # Check that aliases are shown for commands that have them
        assert "aliases: ls, l" in help_text  # list command
        assert "aliases: a, new" in help_text  # add command
        assert "aliases: g, show, view" in help_text  # get command

    def test_console_help_includes_help_command(self):
        """Test that console help includes help command."""
        help_text = generate_console_help()
        assert "help" in help_text

    def test_console_help_includes_quit_command(self):
        """Test that console help includes quit/exit commands."""
        help_text = generate_console_help()
        assert "quit" in help_text
        assert "exit" in help_text

    def test_console_help_format(self):
        """Test that console help follows expected format."""
        help_text = generate_console_help()
        lines = help_text.split("\n")

        assert lines[0] == "Available commands:"
        # Command lines should be indented
        for line in lines[1:]:
            if line and not line.startswith("#"):
                assert line.startswith("  ")

    def test_console_help_no_aliases_for_demo(self):
        """Test that demo command shows correctly (has no aliases)."""
        help_text = generate_console_help()
        # Find the demo line
        for line in help_text.split("\n"):
            if "demo" in line and "Run demo" in line:
                # Should not have "(aliases: ...)" text
                assert "(aliases:" not in line
                break
        else:
            pytest.fail("Demo command not found in console help")


class TestCommandIntegrity:
    """Test overall command system integrity."""

    def test_no_orphaned_handlers(self):
        """Test that all operation functions are registered."""
        operation_handlers = {
            list_passwords,
            add_password,
            get_password,
            edit_password,
            delete_password,
            search_passwords,
            run_demo,
            generate_password_command,
        }

        registered_handlers = {cmd.handler for cmd in COMMANDS}
        assert operation_handlers == registered_handlers

    def test_command_examples_valid(self):
        """Test that command examples start with 'pulseguard'."""
        for cmd in COMMANDS:
            assert cmd.example.startswith(
                "pulseguard"
            ), f"Invalid example for {cmd.name}"

    def test_command_usage_patterns(self):
        """Test that usage patterns start with command name."""
        for cmd in COMMANDS:
            assert cmd.usage.startswith(cmd.name), f"Invalid usage for {cmd.name}"

    def test_console_help_patterns(self):
        """Test that console help patterns start with command name."""
        for cmd in COMMANDS:
            # Console help should start with command name (possibly with spaces before)
            assert cmd.name in cmd.console_help, f"Invalid console_help for {cmd.name}"

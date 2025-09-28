"""Command system - data-driven architecture for CLI and console.

Why: Eliminates duplication, makes adding commands trivial, ensures consistency.
Contains: CLI parsers, help text, handlers, aliases - all in one place.
"""

from dataclasses import dataclass
from typing import Callable, List, Optional, Dict, Any

from .operations import (
    add_password,
    delete_password,
    edit_password,
    get_password,
    list_passwords,
    run_demo,
    search_passwords,
)


@dataclass
class Command:
    """Complete command specification - everything needed to implement a command.
    
    Why: All metadata in one place, function pointer pattern, automatic CLI generation.
    Adding a new command = add one Command to COMMANDS list.
    """

    name: str  # Canonical name
    description: str  # Help text
    usage: str  # Usage pattern
    example: str  # Example command
    console_help: str  # Formatted help line
    handler: Callable  # Function that does the work
    args: List[Dict[str, Any]]  # CLI argument specs
    aliases: List[str]  # User shortcuts (ls, g, s, etc.)


# Command definitions
COMMANDS = [
    Command(
        name="list",
        description="List all entries",
        usage="list",
        example="pulseguard list",
        console_help="list                    List all entries",
        handler=list_passwords,
        args=[],
        aliases=["ls", "l"],
    ),
    Command(
        name="add",
        description="Add a new entry",
        usage="add <name> <username> <password> [--url URL] [--notes NOTES]",
        example="pulseguard add Gmail user@example.com password123",
        console_help="add <name> <user> <pwd> Add a new entry",
        handler=add_password,
        args=[
            {"name": "name", "help": "Entry name"},
            {"name": "username", "help": "Username or email"},
            {"name": "password", "help": "Password"},
            {"name": "--url", "default": "", "help": "URL for the service"},
            {"name": "--notes", "default": "", "help": "Notes about the entry"},
        ],
        aliases=["a", "new"],
    ),
    Command(
        name="get",
        description="Get entry details",
        usage="get <name>",
        example="pulseguard get Gmail",
        console_help="get <name>              Get entry details",
        handler=get_password,
        args=[{"name": "name", "help": "Entry name"}],
        aliases=["g", "show", "view"],
    ),
    Command(
        name="edit",
        description="Edit entry (interactive)",
        usage="edit <name>",
        example="pulseguard edit Gmail",
        console_help="edit <name>             Edit entry (interactive)",
        handler=edit_password,
        args=[{"name": "name", "help": "Entry name"}],
        aliases=["e", "modify", "update"],
    ),
    Command(
        name="delete",
        description="Delete an entry",
        usage="delete <name>",
        example="pulseguard delete Gmail",
        console_help="delete <name>           Delete an entry",
        handler=delete_password,
        args=[{"name": "name", "help": "Entry name"}],
        aliases=["d", "del", "remove", "rm"],
    ),
    Command(
        name="search",
        description="Search entries",
        usage="search <query>",
        example="pulseguard search gmail",
        console_help="search <query>          Search entries",
        handler=search_passwords,
        args=[{"name": "query", "help": "Search query"}],
        aliases=["s", "find"],
    ),
    Command(
        name="demo",
        description="Run demo with sample data",
        usage="demo",
        example="pulseguard demo",
        console_help="demo                    Run demo with sample data",
        handler=run_demo,
        args=[],
        aliases=[],
    ),
]


def generate_help_epilog() -> str:
    """Generate CLI help examples from command definitions.
    
    Why: Keeps help in sync with commands automatically, prevents documentation drift.
    """
    lines = ["Examples:"]
    lines.append("  pulseguard                    # Start interactive console")

    for cmd in COMMANDS:
        lines.append(f"  {cmd.example}          # {cmd.description}")

    return "\n".join(lines)


def generate_console_help() -> str:
    """Generate console help text with aliases.
    
    Why: Shows aliases inline, stays in sync with commands automatically.
    """
    lines = ["Available commands:"]

    for cmd in COMMANDS:
        help_line = f"  {cmd.console_help}"
        if cmd.aliases:
            aliases_str = ", ".join(cmd.aliases)
            help_line += f" (aliases: {aliases_str})"
        lines.append(help_line)

    lines.extend(
        [
            "  help                    Show this help",
            "  quit, exit              Exit the console",
        ]
    )

    return "\n".join(lines)


def get_command(name: str) -> Optional[Command]:
    """Find a command by its canonical name.
    
    Why: Clean interface, safe error handling, centralizes lookup logic.
    """
    return next((cmd for cmd in COMMANDS if cmd.name == name), None)


def get_command_handler(name: str) -> Optional[Callable]:
    """Extract the handler function for a command.
    
    Why: Separates lookup from extraction, enables dynamic dispatch, type safety.
    """
    cmd = get_command(name)
    return cmd.handler if cmd else None


def get_command_args(name: str) -> List[Dict[str, Any]]:
    """Extract argument specifications for a command.
    
    Why: Enables dynamic CLI parser generation, keeps args with command metadata.
    """
    cmd = get_command(name)
    return cmd.args if cmd else []


def get_command_by_alias(alias: str) -> Optional[Command]:
    """Find a command by one of its aliases.
    
    Why: Enables user shortcuts (ls, g, s), separates alias resolution from canonical lookup.
    """
    for cmd in COMMANDS:
        if alias in cmd.aliases:
            return cmd
    return None


def resolve_command_name(name_or_alias: str) -> Optional[str]:
    """Convert any command name or alias to its canonical name.
    
    Why: Unified resolution for CLI and console, handles both names and aliases transparently.
    """
    # Check canonical names first (more common)
    if get_command(name_or_alias):
        return name_or_alias
    
    # Fall back to alias resolution
    cmd = get_command_by_alias(name_or_alias)
    return cmd.name if cmd else None

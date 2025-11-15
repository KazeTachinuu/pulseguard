"""Command system - data-driven architecture for CLI and console."""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .operations import (
    add_password,
    delete_password,
    edit_password,
    generate_password_command,
    get_password,
    list_passwords,
    run_demo,
    search_passwords,
)


def str_to_bool(value: str) -> bool:
    """Convert string to boolean for argparse."""
    if value.lower() in ("true", "t", "yes", "y", "1"):
        return True
    elif value.lower() in ("false", "f", "no", "n", "0"):
        return False
    else:
        raise ValueError(f"Boolean value expected, got: {value}")


@dataclass
class Command:
    """Complete command specification."""

    name: str
    description: str
    usage: str
    example: str
    console_help: str
    handler: Callable
    args: List[Dict[str, Any]]
    aliases: List[str]


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
        usage="add <name> <username> <password> [--url URL] [--notes NOTES] "
        "[--gen] [--length N] [--lower true|false] [--upper true|false] "
        "[--digits true|false] [--symbols true|false]",
        example="pulseguard add Gmail user@example.com password123",
        console_help="add <name> <user> <pwd> Add a new entry",
        handler=add_password,
        args=[
            {"name": "name", "help": "Entry name"},
            {"name": "username", "help": "Username or email"},
            {"name": "password", "help": "Password"},
            {"name": "--url", "default": "", "help": "URL for the service"},
            {"name": "--notes", "default": "", "help": "Notes about the entry"},
            {
                "name": "--gen",
                "action": "store_true",
                "help": "Generate password instead of using provided value",
            },
            {
                "name": "--length",
                "type": int,
                "default": 16,
                "help": "Generated length (<=25)",
            },
            {
                "name": "--lower",
                "type": str_to_bool,
                "default": True,
                "help": "Include lowercase",
            },
            {
                "name": "--upper",
                "type": str_to_bool,
                "default": True,
                "help": "Include uppercase",
            },
            {
                "name": "--digits",
                "type": str_to_bool,
                "default": True,
                "help": "Include digits",
            },
            {
                "name": "--symbols",
                "type": str_to_bool,
                "default": False,
                "help": "Include symbols",
            },
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
        name="genpass",
        description="Generate a secure password",
        usage="genpass [--length N] [--lower true|false] [--upper true|false] "
        "[--digits true|false] [--symbols true|false]",
        example="pulseguard genpass --length 20 --symbols true",
        console_help="genpass                 Generate a secure password",
        handler=generate_password_command,
        args=[
            {"name": "--length", "type": int, "default": 16, "help": "Length (<=25)"},
            {
                "name": "--lower",
                "type": str_to_bool,
                "default": True,
                "help": "Include lowercase",
            },
            {
                "name": "--upper",
                "type": str_to_bool,
                "default": True,
                "help": "Include uppercase",
            },
            {
                "name": "--digits",
                "type": str_to_bool,
                "default": True,
                "help": "Include digits",
            },
            {
                "name": "--symbols",
                "type": str_to_bool,
                "default": False,
                "help": "Include symbols",
            },
        ],
        aliases=[],
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
    """Generate CLI help examples from command definitions."""
    lines = ["Examples:"]
    lines.append("  pulseguard                    # Start interactive console")

    for cmd in COMMANDS:
        lines.append(f"  {cmd.example}          # {cmd.description}")

    return "\n".join(lines)


def generate_console_help() -> str:
    """Generate console help text with aliases."""
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
    """Find a command by its canonical name."""
    return next((cmd for cmd in COMMANDS if cmd.name == name), None)


def get_command_handler(name: str) -> Optional[Callable]:
    """Extract the handler function for a command."""
    cmd = get_command(name)
    return cmd.handler if cmd else None


def get_command_args(name: str) -> List[Dict[str, Any]]:
    """Extract argument specifications for a command."""
    cmd = get_command(name)
    return cmd.args if cmd else []


def get_command_by_alias(alias: str) -> Optional[Command]:
    """Find a command by one of its aliases."""
    for cmd in COMMANDS:
        if alias in cmd.aliases:
            return cmd
    return None


def resolve_command_name(name_or_alias: str) -> Optional[str]:
    """Convert any command name or alias to its canonical name."""
    if get_command(name_or_alias):
        return name_or_alias

    cmd = get_command_by_alias(name_or_alias)
    return cmd.name if cmd else None

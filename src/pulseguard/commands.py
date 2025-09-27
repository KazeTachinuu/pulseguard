"""Command definitions and help generation for PulseGuard."""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Command:
    """Represents a CLI command."""
    name: str
    description: str
    usage: str
    example: str
    console_help: str


# Command definitions
COMMANDS = [
    Command(
        name="list",
        description="List all entries",
        usage="list",
        example="pulseguard list",
        console_help="list                    List all entries"
    ),
    Command(
        name="add",
        description="Add a new entry",
        usage="add <name> <username> <password> [--url URL] [--notes NOTES]",
        example="pulseguard add Gmail user@example.com password123",
        console_help="add <name> <user> <pwd> Add a new entry"
    ),
    Command(
        name="get",
        description="Get entry details",
        usage="get <name>",
        example="pulseguard get Gmail",
        console_help="get <name>              Get entry details"
    ),
    Command(
        name="edit",
        description="Edit entry (interactive)",
        usage="edit <name>",
        example="pulseguard edit Gmail",
        console_help="edit <name>             Edit entry (interactive)"
    ),
    Command(
        name="delete",
        description="Delete an entry",
        usage="delete <name>",
        example="pulseguard delete Gmail",
        console_help="delete <name>           Delete an entry"
    ),
    Command(
        name="search",
        description="Search entries",
        usage="search <query>",
        example="pulseguard search gmail",
        console_help="search <query>          Search entries"
    ),
    Command(
        name="demo",
        description="Run demo with sample data",
        usage="demo",
        example="pulseguard demo",
        console_help="demo                    Run demo with sample data"
    ),
]


def generate_help_epilog() -> str:
    """Generate help epilog from command definitions."""
    lines = ["Examples:"]
    lines.append("  pulseguard                    # Start interactive console")
    
    for cmd in COMMANDS:
        lines.append(f"  {cmd.example}          # {cmd.description}")
    
    
    return "\n".join(lines)


def generate_console_help() -> str:
    """Generate console help from command definitions."""
    lines = ["Available commands:"]
    
    for cmd in COMMANDS:
        lines.append(f"  {cmd.console_help}")
    
    lines.extend([
        "  help                    Show this help",
        "  quit, exit              Exit the console"
    ])
    
    return "\n".join(lines)


def get_command(name: str) -> Optional[Command]:
    """Get command by name."""
    return next((cmd for cmd in COMMANDS if cmd.name == name), None)

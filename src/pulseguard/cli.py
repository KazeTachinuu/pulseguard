"""Command-line interface for PulseGuard."""

import argparse
import sys
from typing import List

from .commands import generate_help_epilog
from .config import config
from .console import Console
from .messages import (
    ERROR_GENERIC,
    ERROR_OPERATION_CANCELLED,
    ERROR_UNKNOWN_COMMAND,
    INFO_HELP,
)
from .operations import (
    add_password,
    delete_password,
    edit_password,
    get_password,
    list_passwords,
    run_demo,
    search_passwords,
)
from .vault import Vault, VaultError


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        description="PulseGuard - Simple password manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=generate_help_epilog(),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # List command
    subparsers.add_parser("list", help="List all entries")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new entry")
    add_parser.add_argument("name", help="Entry name")
    add_parser.add_argument("username", help="Username or email")
    add_parser.add_argument("password", help="Password")
    add_parser.add_argument("--url", default="", help="URL for the service")
    add_parser.add_argument("--notes", default="", help="Notes about the entry")

    # Get command
    get_parser = subparsers.add_parser("get", help="Get entry details")
    get_parser.add_argument("name", help="Entry name")

    # Edit command
    edit_parser = subparsers.add_parser("edit", help="Edit entry (interactive)")
    edit_parser.add_argument("name", help="Entry name")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete an entry")
    delete_parser.add_argument("name", help="Entry name")

    # Search command
    search_parser = subparsers.add_parser("search", help="Search entries")
    search_parser.add_argument("query", help="Search query")

    # Demo command
    subparsers.add_parser("demo", help="Run demo with sample data")

    return parser


def handle_cli_command(vault: Vault, args: argparse.Namespace) -> None:
    """Handle CLI command execution."""
    if args.command == "list":
        list_passwords(vault)
    elif args.command == "add":
        add_password(vault, args.name, args.username, args.password, args.url, args.notes)
    elif args.command == "get":
        get_password(vault, args.name)
    elif args.command == "edit":
        edit_password(vault, args.name)
    elif args.command == "delete":
        delete_password(vault, args.name)
    elif args.command == "search":
        search_passwords(vault, args.query)
    elif args.command == "demo":
        run_demo(vault)
    else:
        print(ERROR_UNKNOWN_COMMAND.format(command=args.command))
        print(INFO_HELP)
        sys.exit(1)


def main() -> None:
    """Main entry point for PulseGuard."""
    parser = create_parser()

    try:
        args = parser.parse_args()

        if not args.command:
            # Start interactive console
            Console().cmdloop()
            return

        # CLI mode
        try:
            vault = Vault()
            handle_cli_command(vault, args)
        except VaultError as e:
            print(f"Vault error: {e}")
            sys.exit(1)

    except KeyboardInterrupt:
        print(ERROR_OPERATION_CANCELLED)
        sys.exit(1)
    except Exception as e:
        print(ERROR_GENERIC.format(error=e))
        sys.exit(1)


if __name__ == "__main__":
    main()
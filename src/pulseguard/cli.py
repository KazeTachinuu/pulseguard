"""Command-line interface - fast, scriptable password management.

Why: Fast access, data-driven parser generation, automatic argument handling.
Generates parsers from COMMANDS definitions - no duplication with console.
"""

import argparse
import sys

from .commands import (
    COMMANDS,
    generate_help_epilog,
    get_command_handler,
    get_command_args,
)
from .config import config
from .console import Console
from .messages import (
    ERROR_GENERIC,
    ERROR_OPERATION_CANCELLED,
    ERROR_UNKNOWN_COMMAND,
    INFO_HELP,
)
from .vault import Vault, VaultError


def create_parser() -> argparse.ArgumentParser:
    """Generate CLI argument parser from command definitions.
    
    Why: Commands define their own args, CLI and console stay in sync automatically.
    """
    parser = argparse.ArgumentParser(
        description="PulseGuard - Simple password manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=generate_help_epilog(),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Generate subparsers dynamically from COMMANDS
    for cmd in COMMANDS:
        subparser = subparsers.add_parser(cmd.name, help=cmd.description)

        # Add arguments from command definition
        for arg in cmd.args:
            arg_name = arg["name"]
            arg_help = arg["help"]

            if arg_name.startswith("--"):
                # Optional argument
                subparser.add_argument(
                    arg_name, default=arg.get("default", ""), help=arg_help
                )
            else:
                # Positional argument
                subparser.add_argument(arg_name, help=arg_help)

    return parser


def handle_cli_command(vault: Vault, args: argparse.Namespace) -> None:
    """Execute a CLI command by dynamically calling its handler.
    
    Why: No if/elif chains, automatic argument passing, consistent error handling.
    """
    handler = get_command_handler(args.command)
    if not handler:
        print(ERROR_UNKNOWN_COMMAND.format(command=args.command))
        print(INFO_HELP)
        sys.exit(1)

    # Build argument list for handler function
    cmd_args = get_command_args(args.command)
    handler_args = [vault]  # All handlers expect vault as first argument

    # Add arguments based on command definition
    for arg in cmd_args:
        arg_name = arg["name"].lstrip("-")  # Remove -- prefix for optional args
        if hasattr(args, arg_name):
            handler_args.append(getattr(args, arg_name))

    # Call handler with all arguments
    handler(*handler_args)


def main() -> None:
    """Main entry point - handles both CLI and interactive modes.
    
    Why: Single entry point, no command = interactive, command = CLI mode.
    """
    parser = create_parser()

    try:
        args = parser.parse_args()

        if not args.command:
            # No command = interactive console
            Console().cmdloop()
            return

        # Command provided = CLI mode
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

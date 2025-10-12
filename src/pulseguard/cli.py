"""Command-line interface for PulseGuard."""

import argparse
import os
import sys

from .auth import prompt_create_master_password, prompt_unlock_vault
from .commands import (
    COMMANDS,
    generate_help_epilog,
    get_command_args,
    get_command_handler,
)
from .console import Console
from .messages import (
    ERROR_GENERIC,
    ERROR_OPERATION_CANCELLED,
    ERROR_UNKNOWN_COMMAND,
    INFO_HELP,
)
from .vault import Vault, VaultDecryptionError, VaultError


def create_parser() -> argparse.ArgumentParser:
    """Generate CLI argument parser from command definitions."""
    parser = argparse.ArgumentParser(
        description="PulseGuard - Simple password manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=generate_help_epilog(),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    for cmd in COMMANDS:
        subparser = subparsers.add_parser(cmd.name, help=cmd.description)
        for arg in cmd.args:
            arg_name = arg["name"]
            arg_help = arg.get("help", "")
            if arg_name.startswith("--"):
                kwargs = {"help": arg_help}
                if "action" in arg:
                    kwargs["action"] = arg["action"]
                if "type" in arg:
                    kwargs["type"] = arg["type"]
                if "default" in arg:
                    kwargs["default"] = arg["default"]
                if arg.get("type") is bool:
                    kwargs["type"] = lambda v: str(v).lower() in ("1", "true", "yes", "y")

                subparser.add_argument(arg_name, **kwargs)
            else:
                subparser.add_argument(arg_name, help=arg_help)
    return parser


def handle_cli_command(vault: Vault, args: argparse.Namespace) -> None:
    """Execute a CLI command by calling its handler."""
    handler = get_command_handler(args.command)
    if not handler:
        print(ERROR_UNKNOWN_COMMAND.format(command=args.command))
        print(INFO_HELP)
        sys.exit(1)

    cmd_args = get_command_args(args.command)
    handler_args = [vault]

    for arg in cmd_args:
        arg_name = arg["name"].lstrip("-")
        if hasattr(args, arg_name):
            handler_args.append(getattr(args, arg_name))

    handler(*handler_args)


def initialize_vault() -> Vault:
    """Initialize vault - create new or unlock existing."""
    from .config import config

    vault_exists = os.path.exists(config.vault_path)

    if not vault_exists:
        # New vault - always encrypted
        try:
            master_password = prompt_create_master_password()
            vault = Vault(master_password=master_password)
            print("\n✓ Vault created successfully")
            print(f"  Location: {config.vault_path}\n")
            return vault
        except (KeyboardInterrupt, EOFError, ValueError) as e:
            print(f"\nVault creation cancelled: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Existing vault - unlock it
        attempts = 0
        max_attempts = 3

        while attempts < max_attempts:
            try:
                master_password = prompt_unlock_vault()
                vault = Vault(master_password=master_password)
                print("✓ Vault unlocked\n")
                return vault
            except VaultDecryptionError:
                attempts += 1
                remaining = max_attempts - attempts
                if remaining > 0:
                    print(
                        f"\n✗ Incorrect password ({remaining} attempts remaining)\n",
                        file=sys.stderr,
                    )
                else:
                    print("\n✗ Maximum attempts exceeded", file=sys.stderr)
                    sys.exit(1)
            except (KeyboardInterrupt, EOFError):
                print("\nVault unlock cancelled", file=sys.stderr)
                sys.exit(1)

        # Should never reach here but satisfy type checker
        sys.exit(1)


def main() -> None:
    """Main entry point - handles both CLI and interactive modes."""
    parser = create_parser()

    try:
        args = parser.parse_args()

        if not args.command:
            vault = initialize_vault()
            Console(vault=vault).cmdloop()
            return

        try:
            vault = initialize_vault()
            handle_cli_command(vault, args)
        except VaultError as e:
            print(f"Vault error: {e}", file=sys.stderr)
            sys.exit(1)

    except KeyboardInterrupt:
        print(ERROR_OPERATION_CANCELLED)
        sys.exit(1)
    except Exception as e:
        print(ERROR_GENERIC.format(error=e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

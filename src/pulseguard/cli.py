"""Modern CLI using Typer framework."""

import os
import sys
from getpass import getpass
from typing import Optional

import questionary
import typer
from rich.prompt import Confirm
from typing_extensions import Annotated

from . import ui
from .config import config
from .models import PasswordEntry
from .passwordgen import DEFAULT_LEN, GenOptions, copy_to_clipboard, generate_password
from .ui import select_entry
from .vault import (
    Vault,
    VaultDecryptionError,
    find_duplicates,
    find_reused_passwords,
    get_vault_stats,
)

app = typer.Typer(
    name="pulseguard",
    help="Secure password manager with modern CLI",
    add_completion=True,
    no_args_is_help=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


_vault: Optional[Vault] = None


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    vault: Annotated[
        Optional[str],
        typer.Option(
            "--vault",
            "-v",
            help="Path to vault file (default: ~/.pulseguard/vault.json)",
        ),
    ] = None,
):
    """PulseGuard password manager - runs interactive mode if no command given."""
    if vault:
        config.vault_path = os.path.expanduser(vault)

    if ctx.invoked_subcommand is None:
        interactive_mode()
        raise typer.Exit(0)


def get_vault() -> Vault:
    """Get or initialize vault instance."""
    global _vault
    if _vault is None:
        _vault = initialize_vault()
    return _vault


def initialize_vault() -> Vault:
    """Initialize vault - create new or unlock existing."""
    from .config import config

    vault_exists = os.path.exists(config.vault_path)

    if not vault_exists:
        try:
            ui.info(f"Creating new vault at {config.vault_path}")
            master_password = prompt_create_master_password()
            vault = Vault(master_password=master_password)
            vault._save()
            ui.success("Vault created successfully")
            return vault
        except (KeyboardInterrupt, EOFError, ValueError) as e:
            ui.error(f"Vault creation cancelled: {e}")
            raise typer.Exit(1)
    else:
        attempts = 0
        max_attempts = 3

        while attempts < max_attempts:
            try:
                master_password = prompt_unlock_vault()
                vault = Vault(master_password=master_password)
                ui.success("Vault unlocked")
                return vault
            except VaultDecryptionError:
                attempts += 1
                remaining = max_attempts - attempts
                if remaining > 0:
                    ui.error(f"Incorrect password ({remaining} attempts remaining)")
                else:
                    ui.error("Maximum attempts exceeded")
                    raise typer.Exit(1)
            except (KeyboardInterrupt, EOFError):
                ui.error("Vault unlock cancelled")
                raise typer.Exit(1)

        # Should never reach here, but mypy needs this
        raise typer.Exit(1)


def interactive_mode() -> None:
    """Interactive menu for vault operations."""
    vault = get_vault()

    while True:
        ui.console.print()
        choice = questionary.select(
            "What would you like to do?",
            choices=[
                "List all entries",
                "Add new entry",
                "Get/view entry",
                "Edit entry",
                "Delete entry",
                "Search entries",
                "Generate password",
                "Vault statistics",
                "Security health check",
                "Exit",
            ],
            style=questionary.Style(
                [
                    ("highlighted", "fg:cyan bold"),
                    ("pointer", "fg:cyan bold"),
                ]
            ),
        ).ask()

        if choice is None or choice == "Exit":
            ui.info("Goodbye!")
            break

        try:
            if choice == "List all entries":
                entries = vault.get_all()
                if entries:
                    ui.show_entries_table(entries)
                else:
                    ui.info("No entries found")

            elif choice == "Add new entry":
                core_add_entry(vault)

            elif choice == "Get/view entry":
                show = Confirm.ask("Show password in terminal?", default=False)
                core_get_entry(vault, show=show)

            elif choice == "Edit entry":
                core_edit_entry(vault)

            elif choice == "Delete entry":
                core_delete_entry(vault)

            elif choice == "Search entries":
                query = ui.prompt("Search query")
                core_search_entries(vault, query)

            elif choice == "Generate password":
                password = prompt_and_generate_password()
                if not password:
                    ui.info("Cancelled")
                    continue

            elif choice == "Vault statistics":
                display_vault_stats(vault)

            elif choice == "Security health check":
                display_security_health_check(vault)

        except (KeyboardInterrupt, EOFError):
            ui.info("\nCancelled")
            continue


def prompt_create_master_password() -> str:
    """Prompt for master password creation with confirmation."""
    ui.warning("Choose a strong master password - you cannot recover it if lost!")

    while True:
        password = getpass("Master password: ")
        if not password:
            ui.error("Password cannot be empty")
            continue

        confirm = getpass("Confirm password: ")
        if password != confirm:
            ui.error("Passwords do not match")
            continue

        return password


def prompt_unlock_vault() -> str:
    """Prompt for master password to unlock vault."""
    return getpass("Master password: ")


def prompt_and_generate_password() -> Optional[str]:
    """
    Prompt user for password generation options and generate password.

    Note: Caller should ask if user wants to generate password before calling this.

    Returns:
        Generated password string, or None if user cancels/error
    """
    ui.console.print("\n[cyan]Password Generation Options[/cyan]")

    # Prompt for length
    length_str = ui.prompt("Password length", str(DEFAULT_LEN))
    try:
        length = int(length_str)
        if length < 1:
            ui.error("Length must be at least 1")
            return None
        if length > 256:
            ui.warning("Very long password! (>256 characters)")
    except ValueError:
        ui.error("Invalid number")
        return None

    # Use checkboxes for character type options
    options = questionary.checkbox(
        "Select character types to include:",
        choices=[
            questionary.Choice("Lowercase letters (a-z)", checked=True),
            questionary.Choice("Uppercase letters (A-Z)", checked=True),
            questionary.Choice("Numbers (0-9)", checked=True),
            questionary.Choice("Special characters (!@#$%^&*)", checked=False),
        ],
        style=questionary.Style(
            [
                ("highlighted", "fg:cyan bold"),
                ("pointer", "fg:cyan bold"),
            ]
        ),
    ).ask()

    if options is None:  # User cancelled
        return None

    # Parse selected options
    lower = "Lowercase letters (a-z)" in options
    upper = "Uppercase letters (A-Z)" in options
    digits = "Numbers (0-9)" in options
    symbols = "Special characters (!@#$%^&*)" in options

    # Validate at least one option selected
    if not (lower or upper or digits or symbols):
        ui.error("At least one character type must be selected")
        return None

    # Validate length against number of enabled character classes
    required_chars = sum([lower, upper, digits, symbols])
    if length < required_chars:
        ui.error(
            f"Password length ({length}) must be at least {required_chars} "
            f"to include one character from each enabled character class"
        )
        return None

    opts = GenOptions(
        length=length,
        lower=lower,
        upper=upper,
        digits=digits,
        symbols=symbols,
    )
    password = generate_password(opts)
    copied = copy_to_clipboard(password)
    ui.show_password_generated(password, copied)
    return password


def display_vault_stats(vault: Vault) -> None:
    """Display vault statistics."""
    stats = get_vault_stats(vault)
    ui.console.print("\n[bold cyan]Vault Statistics[/bold cyan]")
    ui.console.print(f"  Total entries: {stats['total']}")
    if stats["reused"] > 0:
        ui.console.print(f"  [yellow]Reused passwords: {stats['reused']}[/yellow]")
    if stats["duplicates"] > 0:
        ui.console.print(f"  [yellow]Duplicate entries: {stats['duplicates']}[/yellow]")


def display_security_health_check(vault: Vault) -> None:
    """Run and display security health check."""
    ui.console.print("\n[bold cyan]Running security health check...[/bold cyan]\n")

    reused = find_reused_passwords(vault)
    if reused:
        ui.warning(f"Found {len(reused)} reused passwords:")
        for count, entries in reused:
            names = [e.name for e in entries]
            ui.console.print(f"  - Reused {count} times by: {', '.join(names)}")
    else:
        ui.success("No reused passwords found")

    duplicates = find_duplicates(vault)
    if duplicates:
        ui.warning(f"Found {len(duplicates)} duplicate entries:")
        for key, entries in duplicates:
            names = [e.name for e in entries]
            ui.console.print(f"  - {key}: {', '.join(names)}")
    else:
        ui.success("No duplicate entries found")


# ============================================================================
# Core operation functions - shared between CLI and interactive modes
# ============================================================================


def core_add_entry(
    vault: Vault,
    name: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    url: str = "",
    notes: str = "",
    gen: bool = False,
    length: int = DEFAULT_LEN,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = False,
) -> None:
    """Core logic for adding an entry - used by both CLI and interactive modes."""
    # Prompt for missing required fields
    if not name:
        name = ui.prompt("Entry name")
    if not username:
        username = ui.prompt("Username")

    # Handle password generation or prompt
    if gen:
        opts = GenOptions(
            length=length,
            lower=lower,
            upper=upper,
            digits=digits,
            symbols=symbols,
        )
        password = generate_password(opts)
        copied = copy_to_clipboard(password)
        ui.show_password_generated(password, copied)
    elif not password:
        # Ask if user wants to generate (only when not specified)
        if Confirm.ask("Generate password?", default=True):
            password = prompt_and_generate_password()
            if not password:
                return  # User cancelled or error
        else:
            password = getpass("Password: ")

    entry = PasswordEntry(
        name=name, username=username, password=password, url=url, notes=notes
    )
    vault.add(entry)
    ui.success(f"Added entry '{name}'")


def core_get_entry(
    vault: Vault,
    name: Optional[str] = None,
    show: bool = False,
) -> None:
    """Core logic for getting/viewing an entry - used by both CLI and interactive modes."""
    # Get entry by name or interactive selection
    if name:
        entry = vault.get(name)
        if not entry:
            ui.error(f"Entry '{name}' not found")
            return
    else:
        entry = select_entry(vault, "Select entry to view")
        if not entry:
            return

    # Copy to clipboard unless showing
    if not show:
        copied = copy_to_clipboard(entry.password)
        if copied:
            ui.success("Password copied to clipboard")

    ui.show_entry_panel(entry, show_password=show)


def core_edit_entry(
    vault: Vault,
    name: Optional[str] = None,
) -> None:
    """Core logic for editing an entry - used by both CLI and interactive modes."""
    # Get entry by name or interactive selection
    if name:
        entry = vault.get(name)
        if not entry:
            ui.error(f"Entry '{name}' not found")
            return
    else:
        entry = select_entry(vault, "Select entry to edit")
        if not entry:
            return

    ui.info(f"Editing '{entry.name}' (press Enter to keep current value)")

    new_username = ui.prompt("Username", entry.username)
    new_url = ui.prompt("URL", entry.url)
    new_notes = ui.prompt("Notes", entry.notes)

    # Handle password change
    if Confirm.ask("Change password?", default=False):
        if Confirm.ask("Generate new password?", default=True):
            new_password = prompt_and_generate_password()
            if new_password is None:
                new_password = entry.password  # Keep existing if generation cancelled
        else:
            new_password = getpass("New password: ")
    else:
        new_password = entry.password

    updated_entry = PasswordEntry(
        name=entry.name,
        username=new_username,
        password=new_password,
        url=new_url,
        notes=new_notes,
    )
    vault.add(updated_entry)
    ui.success(f"Updated entry '{entry.name}'")


def core_delete_entry(
    vault: Vault,
    name: Optional[str] = None,
    force: bool = False,
) -> None:
    """Core logic for deleting an entry - used by both CLI and interactive modes."""
    # Get entry by name or interactive selection
    if name:
        entry = vault.get(name)
        if not entry:
            ui.error(f"Entry '{name}' not found")
            return
    else:
        entry = select_entry(vault, "Select entry to delete")
        if not entry:
            return

    # Confirm deletion unless forced
    if not force:
        if not Confirm.ask(f"Delete '{entry.name}'?", default=False):
            ui.info("Cancelled")
            return

    vault.remove(entry.name)
    ui.success(f"Deleted entry '{entry.name}'")


def core_search_entries(vault: Vault, query: str) -> None:
    """Core logic for searching entries - used by both CLI and interactive modes."""
    results = vault.search(query)
    if results:
        ui.show_entries_table(results, title=f"Search results for '{query}'")
    else:
        ui.info(f"No matches for '{query}'")


@app.command("list", help="List all password entries")
def list_entries(
    search: Annotated[
        Optional[str], typer.Option("--search", "-s", help="Filter by name or username")
    ] = None,
):
    """List all password entries."""
    vault = get_vault()
    entries = vault.get_all()

    if search:
        search_lower = search.lower()
        entries = [
            e
            for e in entries
            if search_lower in e.name.lower() or search_lower in e.username.lower()
        ]

    if entries:
        ui.show_entries_table(entries)
    else:
        ui.info("No entries found")


@app.command("add", help="Add a new password entry")
def add_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
    username: Annotated[Optional[str], typer.Argument(help="Username")] = None,
    password: Annotated[
        Optional[str], typer.Argument(help="Password (or use --gen)")
    ] = None,
    url: Annotated[str, typer.Option(help="Service URL")] = "",
    notes: Annotated[str, typer.Option(help="Additional notes")] = "",
    gen: Annotated[bool, typer.Option("--gen", help="Generate password")] = False,
    length: Annotated[
        int, typer.Option(help="Generated password length (default: 16)")
    ] = DEFAULT_LEN,
    lower: Annotated[
        bool, typer.Option("--lower/--no-lower", help="Include lowercase letters")
    ] = True,
    upper: Annotated[
        bool, typer.Option("--upper/--no-upper", help="Include uppercase letters")
    ] = True,
    digits: Annotated[
        bool, typer.Option("--digits/--no-digits", help="Include numbers")
    ] = True,
    symbols: Annotated[
        bool, typer.Option("--symbols/--no-symbols", help="Include special characters")
    ] = False,
):
    """Add a new password entry."""
    vault = get_vault()

    if gen and password:
        ui.error("Cannot specify both password and --gen")
        raise typer.Exit(1)

    if gen and length < 1:
        ui.error("Password length must be at least 1")
        raise typer.Exit(1)

    if gen and not (lower or upper or digits or symbols):
        ui.error("At least one character type must be selected for password generation")
        raise typer.Exit(1)

    # Validate length against number of enabled character classes
    if gen:
        required_chars = sum([lower, upper, digits, symbols])
        if length < required_chars:
            ui.error(
                f"Password length ({length}) must be at least {required_chars} "
                f"to include one character from each enabled character class"
            )
            raise typer.Exit(1)

    core_add_entry(
        vault,
        name=name,
        username=username,
        password=password,
        url=url,
        notes=notes,
        gen=gen,
        length=length,
        lower=lower,
        upper=upper,
        digits=digits,
        symbols=symbols,
    )


@app.command("get", help="Get password details")
def get_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
    show: Annotated[
        bool, typer.Option("--show", help="Show password in terminal")
    ] = False,
):
    """Get password details with interactive selection."""
    vault = get_vault()
    core_get_entry(vault, name=name, show=show)


@app.command("edit", help="Edit an existing entry")
def edit_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
):
    """Edit an existing entry interactively."""
    vault = get_vault()
    core_edit_entry(vault, name=name)


@app.command("delete", help="Delete an entry")
def delete_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation")
    ] = False,
):
    """Delete an entry with confirmation."""
    vault = get_vault()
    core_delete_entry(vault, name=name, force=force)


@app.command("search", help="Search entries")
def search_entries(
    query: Annotated[str, typer.Argument(help="Search query")],
):
    """Search entries by name or username."""
    vault = get_vault()
    core_search_entries(vault, query)


@app.command("genpass", help="Generate a password")
def generate_standalone_password(
    length: Annotated[
        int, typer.Option(help="Password length (default: 16)")
    ] = DEFAULT_LEN,
    lower: Annotated[
        bool, typer.Option("--lower/--no-lower", help="Include lowercase letters")
    ] = True,
    upper: Annotated[
        bool, typer.Option("--upper/--no-upper", help="Include uppercase letters")
    ] = True,
    digits: Annotated[
        bool, typer.Option("--digits/--no-digits", help="Include numbers")
    ] = True,
    symbols: Annotated[
        bool, typer.Option("--symbols/--no-symbols", help="Include special characters")
    ] = False,
):
    """Generate a standalone password."""
    if length < 1:
        ui.error("Password length must be at least 1")
        raise typer.Exit(1)

    if not (lower or upper or digits or symbols):
        ui.error("At least one character type must be selected")
        raise typer.Exit(1)

    # Validate length against number of enabled character classes
    required_chars = sum([lower, upper, digits, symbols])
    if length < required_chars:
        ui.error(
            f"Password length ({length}) must be at least {required_chars} "
            f"to include one character from each enabled character class"
        )
        raise typer.Exit(1)

    opts = GenOptions(
        length=length,
        lower=lower,
        upper=upper,
        digits=digits,
        symbols=symbols,
    )
    password = generate_password(opts)
    copied = copy_to_clipboard(password)
    ui.show_password_generated(password, copied)


@app.command("stats", help="Show vault statistics")
def show_stats():
    """Display vault statistics and health check."""
    vault = get_vault()
    display_vault_stats(vault)
    ui.console.print()


@app.command("check", help="Security health check")
def health_check():
    """Run security health check on vault."""
    vault = get_vault()
    display_security_health_check(vault)
    ui.console.print()


def main() -> None:
    """Main entry point."""
    try:
        app()
    except KeyboardInterrupt:
        ui.error("Operation cancelled")
        sys.exit(1)
    except typer.Exit:
        # Let Typer handle its own exit codes
        raise


if __name__ == "__main__":
    main()

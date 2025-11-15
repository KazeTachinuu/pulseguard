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
            style=questionary.Style([
                ('highlighted', 'fg:cyan bold'),
                ('pointer', 'fg:cyan bold'),
            ]),
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
                name = ui.prompt("Entry name")
                username = ui.prompt("Username")

                if Confirm.ask("Generate password?", default=True):
                    password = prompt_for_password_generation(for_interactive_mode=True)
                    if not password:
                        continue
                else:
                    password = getpass("Password: ")

                url = ui.prompt("URL (optional)", "")
                notes = ui.prompt("Notes (optional)", "")
                entry = PasswordEntry(name=name, username=username, password=password, url=url, notes=notes)
                vault.add(entry)
                ui.success(f"Added entry '{name}'")

            elif choice == "Get/view entry":
                entry = select_entry(vault, "Select entry to view")
                if entry:
                    if Confirm.ask("Show password in terminal?", default=False):
                        ui.show_entry_panel(entry, show_password=True)
                    else:
                        copied = copy_to_clipboard(entry.password)
                        if copied:
                            ui.success("Password copied to clipboard")
                        ui.show_entry_panel(entry, show_password=False)

            elif choice == "Edit entry":
                entry = select_entry(vault, "Select entry to edit")
                if entry:
                    ui.info(f"Editing '{entry.name}' (press Enter to keep current value)")
                    new_username = ui.prompt("Username", entry.username)
                    new_url = ui.prompt("URL", entry.url)
                    new_notes = ui.prompt("Notes", entry.notes)

                    if Confirm.ask("Change password?", default=False):
                        new_password = prompt_for_password_generation(for_interactive_mode=True)
                        if new_password is None:
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

            elif choice == "Delete entry":
                entry = select_entry(vault, "Select entry to delete")
                if entry:
                    if Confirm.ask(f"Delete '{entry.name}'?", default=False):
                        vault.remove(entry.name)
                        ui.success(f"Deleted entry '{entry.name}'")
                    else:
                        ui.info("Cancelled")

            elif choice == "Search entries":
                query = ui.prompt("Search query")
                results = vault.search(query)
                if results:
                    ui.show_entries_table(results, title=f"Search results for '{query}'")
                else:
                    ui.info(f"No matches for '{query}'")

            elif choice == "Generate password":
                length_str = ui.prompt("Password length", str(DEFAULT_LEN))
                try:
                    length = int(length_str)
                    if not (8 <= length <= 25):
                        ui.error("Length must be between 8 and 25")
                        continue
                except ValueError:
                    ui.error("Invalid number")
                    continue
                symbols = Confirm.ask("Include symbols?", default=False)
                opts = GenOptions(length=length, symbols=symbols)
                password = generate_password(opts)
                copied = copy_to_clipboard(password)
                ui.show_password_generated(password, copied)

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


def prompt_for_password_generation(for_interactive_mode: bool = False) -> Optional[str]:
    """
    Prompt user to generate a password interactively.

    Args:
        for_interactive_mode: If True, uses continue for errors; if False, raises typer.Exit

    Returns:
        Generated password string, or None if user cancels
    """
    if not Confirm.ask("Generate new password?", default=True):
        return None

    length_str = ui.prompt("Password length", str(DEFAULT_LEN))
    try:
        length = int(length_str)
        if not (8 <= length <= 25):
            ui.error("Length must be between 8 and 25")
            if for_interactive_mode:
                return None
            raise typer.Exit(1)
    except ValueError:
        ui.error("Invalid number")
        if for_interactive_mode:
            return None
        raise typer.Exit(1)

    symbols = Confirm.ask("Include symbols?", default=False)
    opts = GenOptions(length=length, symbols=symbols)
    password = generate_password(opts)
    copied = copy_to_clipboard(password)
    ui.show_password_generated(password, copied)
    return password


def display_vault_stats(vault: Vault) -> None:
    """Display vault statistics."""
    stats = get_vault_stats(vault)
    ui.console.print("\n[bold cyan]Vault Statistics[/bold cyan]")
    ui.console.print(f"  Total entries: {stats['total']}")
    if stats['reused'] > 0:
        ui.console.print(f"  [yellow]Reused passwords: {stats['reused']}[/yellow]")
    if stats['duplicates'] > 0:
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


@app.command("list", help="List all password entries")
def list_entries(
    search: Annotated[Optional[str], typer.Option("--search", "-s", help="Filter by name or username")] = None,
):
    """List all password entries."""
    vault = get_vault()
    entries = vault.get_all()

    if search:
        search_lower = search.lower()
        entries = [
            e for e in entries
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
    password: Annotated[Optional[str], typer.Argument(help="Password (or use --gen)")] = None,
    url: Annotated[str, typer.Option(help="Service URL")] = "",
    notes: Annotated[str, typer.Option(help="Additional notes")] = "",
    gen: Annotated[bool, typer.Option("--gen", help="Generate password")] = False,
    length: Annotated[int, typer.Option(min=8, max=25, help="Generated password length")] = DEFAULT_LEN,
    symbols: Annotated[bool, typer.Option(help="Include symbols in generation")] = False,
):
    """Add a new password entry."""
    vault = get_vault()

    if not name:
        name = ui.prompt("Entry name")
    if not username:
        username = ui.prompt("Username")

    if gen and password:
        ui.error("Cannot specify both password and --gen")
        raise typer.Exit(1)

    if gen:
        opts = GenOptions(length=length, symbols=symbols)
        password = generate_password(opts)
        copied = copy_to_clipboard(password)
        ui.show_password_generated(password, copied)
    elif not password:
        password = getpass("Password: ")

    entry = PasswordEntry(name=name, username=username, password=password, url=url, notes=notes)
    vault.add(entry)
    ui.success(f"Added entry '{name}'")


@app.command("get", help="Get password details")
def get_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
    show: Annotated[bool, typer.Option("--show", help="Show password in terminal")] = False,
):
    """Get password details with interactive selection."""
    vault = get_vault()

    if name:
        entry = vault.get(name)
        if not entry:
            ui.error(f"Entry '{name}' not found")
            raise typer.Exit(1)
    else:
        entry = select_entry(vault, "Select entry to view")
        if not entry:
            ui.info("Cancelled")
            return

    if not show:
        copied = copy_to_clipboard(entry.password)
        if copied:
            ui.success("Password copied to clipboard")

    ui.show_entry_panel(entry, show_password=show)


@app.command("edit", help="Edit an existing entry")
def edit_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
):
    """Edit an existing entry interactively."""
    vault = get_vault()

    if name:
        entry = vault.get(name)
        if not entry:
            ui.error(f"Entry '{name}' not found")
            raise typer.Exit(1)
    else:
        entry = select_entry(vault, "Select entry to edit")
        if not entry:
            ui.info("Cancelled")
            return

    ui.info(f"Editing '{entry.name}' (press Enter to keep current value)")

    new_username = ui.prompt("Username", entry.username)
    new_url = ui.prompt("URL", entry.url)
    new_notes = ui.prompt("Notes", entry.notes)

    if Confirm.ask("Change password?", default=False):
        new_password = prompt_for_password_generation(for_interactive_mode=False)
        if new_password is None:
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


@app.command("delete", help="Delete an entry")
def delete_entry(
    name: Annotated[Optional[str], typer.Argument(help="Entry name")] = None,
    force: Annotated[bool, typer.Option("--force", "-f", help="Skip confirmation")] = False,
):
    """Delete an entry with confirmation."""
    vault = get_vault()

    if name:
        entry = vault.get(name)
        if not entry:
            ui.error(f"Entry '{name}' not found")
            raise typer.Exit(1)
    else:
        entry = select_entry(vault, "Select entry to delete")
        if not entry:
            ui.info("Cancelled")
            return

    if not force:
        if not Confirm.ask(f"Delete '{entry.name}'?", default=False):
            ui.info("Cancelled")
            return

    vault.remove(entry.name)
    ui.success(f"Deleted entry '{entry.name}'")


@app.command("search", help="Search entries")
def search_entries(
    query: Annotated[str, typer.Argument(help="Search query")],
):
    """Search entries by name or username."""
    vault = get_vault()
    results = vault.search(query)

    if results:
        ui.show_entries_table(results, title=f"Search results for '{query}'")
    else:
        ui.info(f"No matches for '{query}'")


@app.command("genpass", help="Generate a password")
def generate_standalone_password(
    length: Annotated[int, typer.Option(min=8, max=25)] = DEFAULT_LEN,
    symbols: Annotated[bool, typer.Option(help="Include symbols")] = False,
):
    """Generate a standalone password."""
    opts = GenOptions(length=length, symbols=symbols)
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

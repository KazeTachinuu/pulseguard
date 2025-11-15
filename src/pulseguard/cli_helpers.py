"""Helper functions, enums, and interactive mode for CLI."""

import os
from enum import Enum
from getpass import getpass
from typing import Optional

import questionary
import typer
from rich.prompt import Confirm

from . import ui
from .config import config
from .models import PasswordEntry
from .passwordgen import DEFAULT_LEN, GenOptions, copy_to_clipboard, generate_password
from .ui import select_entry, select_style
from .vault import (
    Vault,
    VaultDecryptionError,
    find_duplicates,
    find_reused_passwords,
    get_vault_stats,
)

# Command aliases mapping
COMMAND_ALIASES = {
    "list": ["ls"],
    "add": ["a"],
    "get": ["g"],
    "edit": ["e"],
    "delete": ["d", "del"],
    "search": ["s"],
    "genpass": ["gen"],
}


def get_help_with_aliases(base_help: str, command_name: str) -> str:
    """Auto-generate help text with aliases notation."""
    aliases = COMMAND_ALIASES.get(command_name, [])
    if aliases:
        return f"{base_help} [aliases: {', '.join(aliases)}]"
    return base_help


class MainMenu(str, Enum):
    """Main interactive menu choices."""

    BROWSE_CATEGORY = "Browse by category"
    FIND_ENTRY = "Find entry (quick search)"
    ADD_ENTRY = "Add new entry"
    GENERATE_PASSWORD = "Generate password"
    MANAGE_CATEGORIES = "Manage categories"
    VAULT_STATS = "Vault statistics"
    SECURITY_CHECK = "Security health check"
    EXIT = "Exit"


class CategoryMenu(str, Enum):
    """Category management menu choices."""

    LIST = "List all categories"
    RENAME = "Rename category"
    MOVE = "Move entries between categories"


class QuickAction(str, Enum):
    """Quick action menu choices for entry details."""

    SHOW_PASSWORD = "Show password"
    COPY_PASSWORD = "Copy password"
    COPY_USERNAME = "Copy username"
    COPY_URL = "Copy URL"
    EDIT = "Edit"
    DELETE = "Delete"
    ADD_FAVORITE = "Add to favorites"
    REMOVE_FAVORITE = "Remove from favorites"


class UIPrompt(str, Enum):
    """Special UI prompts and markers."""

    CREATE_CATEGORY = "[Create new category]"
    VIEW_ALL_CATEGORIES = "All categories (view all)"
    BACK = "← Back"


class Message(str, Enum):
    """Common messages."""

    NO_ENTRIES = "No entries found"
    NO_CATEGORIES = "No categories found"
    CANCELLED = "Cancelled"


_vault: Optional[Vault] = None


def get_vault() -> Vault:
    """Get or initialize vault instance."""
    global _vault
    if _vault is None:
        _vault = initialize_vault()
    return _vault


def initialize_vault() -> Vault:
    """Initialize vault - create new or unlock existing."""
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

        raise typer.Exit(1)


def prompt_create_master_password() -> str:
    """Prompt user to create and confirm a master password."""
    while True:
        password = getpass("Create master password: ")
        if not password:
            ui.error("Password cannot be empty")
            continue

        confirm = getpass("Confirm master password: ")
        if password != confirm:
            ui.error("Passwords don't match. Try again.")
            continue

        return password


def prompt_unlock_vault() -> str:
    """Prompt user to unlock vault with master password."""
    return getpass("Master password: ")


def prompt_and_generate_password() -> Optional[str]:
    """Interactive password generation."""
    try:
        length_str = ui.prompt(
            f"Password length (default {DEFAULT_LEN})", default=str(DEFAULT_LEN)
        )
        length = int(length_str) if length_str else DEFAULT_LEN

        # Use checkbox for character type selection
        char_types = questionary.checkbox(
            "Select character types:",
            choices=[
                questionary.Choice(
                    "Lowercase letters (a-z)", value="lower", checked=True
                ),
                questionary.Choice(
                    "Uppercase letters (A-Z)", value="upper", checked=True
                ),
                questionary.Choice("Digits (0-9)", value="digits", checked=True),
                questionary.Choice("Symbols (!@#$...)", value="symbols", checked=False),
            ],
            style=select_style,
        ).ask()

        if not char_types:
            ui.error("At least one character type must be selected")
            return None

        # Convert selected types to boolean flags
        lower = "lower" in char_types
        upper = "upper" in char_types
        digits = "digits" in char_types
        symbols = "symbols" in char_types

        required_chars = len(char_types)
        if length < required_chars:
            ui.error(
                f"Password length ({length}) must be at least {required_chars} "
                "to include one character from each enabled character class"
            )
            return None

        # Generate and display
        opts = GenOptions(
            length=length, lower=lower, upper=upper, digits=digits, symbols=symbols
        )
        password = generate_password(opts)
        copied = copy_to_clipboard(password)
        ui.show_password_generated(password, copied)
        return password

    except (KeyboardInterrupt, EOFError):
        ui.info("\nCancelled")
        return None


def display_vault_stats(vault: Vault) -> None:
    """Display vault statistics."""
    stats = get_vault_stats(vault)
    ui.console.print("\n[bold cyan]Vault Statistics[/bold cyan]\n")
    ui.console.print(f"Total entries: {stats['total']}")
    ui.console.print(f"Duplicate entries: {stats['duplicates']}")
    ui.console.print(f"Reused passwords: {stats['reused']}\n")


def display_security_health_check(vault: Vault) -> None:
    """Display security health check results."""
    duplicates = find_duplicates(vault)
    reused = find_reused_passwords(vault)

    ui.console.print("\n[bold cyan]Security Health Check[/bold cyan]\n")

    if duplicates:
        ui.console.print("[yellow]Duplicate entries found:[/yellow]")
        for key, entries in duplicates:
            ui.console.print(f"  {key}:")
            for entry in entries:
                ui.console.print(f"    - {entry.name}")
        ui.console.print()

    if reused:
        ui.console.print("[yellow]Reused passwords found:[/yellow]")
        for password_hash, entries in reused:
            ui.console.print(f"  Password used in {len(entries)} entries:")
            for entry in entries:
                ui.console.print(f"    - {entry.name}")
        ui.console.print()

    if not duplicates and not reused:
        ui.console.print("[green]✓ No security issues found[/green]\n")


def interactive_mode() -> None:
    """Interactive menu for vault operations."""
    from .cli_operations import (
        core_add_entry,
        core_browse_category,
        core_list_categories,
        core_move_entries_to_category,
        core_rename_category,
        show_entry_with_quick_actions,
    )

    vault = get_vault()

    while True:
        ui.console.print()

        choices = []
        favorites = vault.get_favorites()
        recent = vault.get_recent()

        if favorites:
            choices.append(f"Favorites ({len(favorites)})")
        if recent:
            choices.append(f"Recently used ({len(recent)})")

        if favorites or recent:
            choices.append(questionary.Separator())  # type: ignore[arg-type]

        # Questionary accepts mixed str/Separator but mypy doesn't understand
        choices.extend(
            [  # type: ignore[list-item]
                MainMenu.BROWSE_CATEGORY.value,
                MainMenu.FIND_ENTRY.value,
                MainMenu.ADD_ENTRY.value,
                MainMenu.GENERATE_PASSWORD.value,
                questionary.Separator(),  # type: ignore[list-item]
                MainMenu.MANAGE_CATEGORIES.value,
                MainMenu.VAULT_STATS.value,
                MainMenu.SECURITY_CHECK.value,
                MainMenu.EXIT.value,
            ]
        )

        choice = questionary.select(
            "What would you like to do?", choices=choices, style=select_style
        ).ask()

        if choice is None or choice == MainMenu.EXIT.value:
            ui.info("Goodbye!")
            break

        try:
            if choice and choice.startswith("Favorites"):
                entry = select_entry(vault, "Select favorite entry", entries=favorites)
                if entry:
                    if copy_to_clipboard(entry.password):
                        ui.success("Password copied to clipboard")
                    show_entry_with_quick_actions(vault, entry)

            elif choice and choice.startswith("Recently used"):
                entry = select_entry(vault, "Select recent entry", entries=recent)
                if entry:
                    if copy_to_clipboard(entry.password):
                        ui.success("Password copied to clipboard")
                    show_entry_with_quick_actions(vault, entry)

            elif choice == MainMenu.BROWSE_CATEGORY.value:
                entry = core_browse_category(vault)
                if entry:
                    if copy_to_clipboard(entry.password):
                        ui.success("Password copied to clipboard")
                    show_entry_with_quick_actions(vault, entry)

            elif choice == MainMenu.FIND_ENTRY.value:
                entry = select_entry(vault, "Type to search, or select entry")
                if entry:
                    if copy_to_clipboard(entry.password):
                        ui.success("Password copied to clipboard")
                    show_entry_with_quick_actions(vault, entry)

            elif choice == MainMenu.ADD_ENTRY.value:
                core_add_entry(vault)

            elif choice == MainMenu.GENERATE_PASSWORD.value:
                password = prompt_and_generate_password()
                if password and Confirm.ask("Save this password as a new entry?", default=True):  # type: ignore[arg-type]
                    entry = PasswordEntry(
                        name=ui.prompt("Entry name"),
                        username=ui.prompt("Username"),
                        password=password,
                        url=ui.prompt("URL (optional)", ""),
                        notes=ui.prompt("Notes (optional)", ""),
                    )
                    vault.add(entry)
                    ui.success(f"Saved entry '{entry.name}'")

            elif choice == MainMenu.MANAGE_CATEGORIES.value:
                while True:
                    cat_choice = questionary.select(
                        "Category management:",
                        choices=[
                            CategoryMenu.LIST.value,
                            CategoryMenu.RENAME.value,
                            CategoryMenu.MOVE.value,
                            UIPrompt.BACK.value,
                        ],
                        style=select_style,
                    ).ask()

                    if cat_choice is None or cat_choice == UIPrompt.BACK.value:
                        break

                    if cat_choice == CategoryMenu.LIST.value:
                        core_list_categories(vault)
                    elif cat_choice == CategoryMenu.RENAME.value:
                        core_rename_category(vault)
                    elif cat_choice == CategoryMenu.MOVE.value:
                        core_move_entries_to_category(vault)

            elif choice == MainMenu.VAULT_STATS.value:
                display_vault_stats(vault)

            elif choice == MainMenu.SECURITY_CHECK.value:
                display_security_health_check(vault)

        except (KeyboardInterrupt, EOFError):
            ui.info("\nCancelled")
            continue

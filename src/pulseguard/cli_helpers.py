"""CLI helpers and interactive mode."""

from enum import Enum
from pathlib import Path
from typing import Optional

import inquirer  # type: ignore[import-untyped]
import questionary
import typer

from . import __version__, ui
from .config import Config, config
from .passwordgen import (
    DEFAULT_LEN,
    GenOptions,
    copy_to_clipboard_with_autoclear,
    generate_password,
)
from .ui import UIPrompt, select_style
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


class MainMenu(str, Enum):
    """Main menu choices."""

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
    """
    Initialize vault - always requires master password encryption.

    Security: The CLI enforces that all vaults are encrypted with a master password.
    This is a mandatory security requirement for CLI usage.
    """
    vault_exists = Path(config.vault_path).exists()

    if not vault_exists:
        try:
            ui.info(f"Creating new vault at {config.vault_path}")
            master_password = prompt_create_master_password()
            # Security: CLI always creates encrypted vaults
            vault = Vault(master_password=master_password)
            vault._save()
            ui.success("Vault created")
            return vault
        except (KeyboardInterrupt, EOFError, ValueError) as e:
            ui.error(f"Vault creation cancelled: {e}")
            raise typer.Exit(1)
    else:
        attempts = 0

        while attempts < Config.MAX_PASSWORD_ATTEMPTS:
            try:
                master_password = prompt_unlock_vault()  # type: ignore[assignment]
                # User cancelled the prompt
                if master_password is None:
                    ui.error("Vault unlock cancelled")
                    raise typer.Exit(1)
                # Security: Ensure password is not empty
                if not master_password:
                    ui.error("Password cannot be empty")
                    attempts += 1
                    continue

                # Security: Ensure password length is within limits
                password_chars = len(master_password)
                password_bytes = len(master_password.encode("utf-8"))

                if password_chars > Config.MAX_PASSWORD_LENGTH:
                    ui.error(
                        f"Password cannot exceed {Config.MAX_PASSWORD_LENGTH} characters"
                    )
                    attempts += 1
                    continue

                if password_bytes > Config.MAX_PASSWORD_BYTES:
                    ui.error(
                        f"Password size cannot exceed {Config.MAX_PASSWORD_BYTES} bytes"
                    )
                    attempts += 1
                    continue
                vault = Vault(master_password=master_password)
                ui.success("Vault unlocked")
                return vault
            except VaultDecryptionError:
                attempts += 1
                remaining = Config.MAX_PASSWORD_ATTEMPTS - attempts
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
    """
    Prompt for master password creation with confirmation.

    Returns:
        Non-empty master password string (never None or empty).

    Security: Enforces non-empty password requirement.
    """
    from rich.panel import Panel
    from rich.text import Text

    # Show informative panel
    content = Text()
    content.append("Creating new vault\n\n", style="bold cyan")
    content.append("Location: ", style="dim")
    content.append(f"{config.vault_path}\n\n", style="white")
    content.append("Your master password will encrypt all entries.\n", style="dim")
    content.append(
        "Choose a strong, memorable password - you cannot recover it if lost.",
        style="yellow",
    )

    panel = Panel(
        content,
        border_style="cyan",
        padding=(1, 2),
    )
    ui.console.print(panel)
    ui.console.print()

    while True:
        password = questionary.password(
            "Create master password:", style=ui.select_style
        ).ask()
        if password is None:
            raise typer.Exit(1)
        if not password:
            ui.error("Password cannot be empty")
            continue

        password_chars = len(password)
        password_bytes = len(password.encode("utf-8"))

        if password_chars > Config.MAX_PASSWORD_LENGTH:
            ui.error(f"Password cannot exceed {Config.MAX_PASSWORD_LENGTH} characters")
            continue

        if password_bytes > Config.MAX_PASSWORD_BYTES:
            ui.error(f"Password size cannot exceed {Config.MAX_PASSWORD_BYTES} bytes")
            continue

        confirm = questionary.password(
            "Confirm master password:", style=ui.select_style
        ).ask()
        if confirm is None:
            raise typer.Exit(1)
        if password != confirm:
            ui.error("Passwords don't match. Try again.")
            continue

        return password


def prompt_unlock_vault() -> Optional[str]:
    """
    Prompt for master password to unlock vault.

    Returns:
        Master password string, or None if cancelled.

    Note: Empty password validation is handled by the caller (initialize_vault).
    """
    from rich.panel import Panel
    from rich.text import Text

    # Show vault info panel
    content = Text()
    content.append("Unlocking vault\n\n", style="bold cyan")
    content.append("Location: ", style="dim")
    content.append(f"{config.vault_path}", style="white")

    panel = Panel(
        content,
        border_style="cyan",
        padding=(1, 2),
    )
    ui.console.print(panel)
    ui.console.print()

    result = questionary.password("Master password:", style=ui.select_style).ask()
    return result if result is not None else None  # Return None if cancelled


def prompt_and_generate_password() -> Optional[str]:
    """Generate password."""
    try:
        length_str = ui.prompt(
            f"Password length (default {DEFAULT_LEN})", default=str(DEFAULT_LEN)
        )
        length = int(length_str) if length_str else DEFAULT_LEN

        # Checkbox selection using inquirer
        questions = [
            inquirer.Checkbox(
                "char_types",
                message="Select character types (space to toggle)",
                choices=[
                    ("Lowercase (a-z)", "lower"),
                    ("Uppercase (A-Z)", "upper"),
                    ("Digits (0-9)", "digits"),
                    ("Symbols (!@#$...)", "symbols"),
                ],
                default=["lower", "upper", "digits"],
            ),
        ]

        answers = inquirer.prompt(questions)
        if not answers or not answers["char_types"]:
            ui.error("At least one character type must be selected")
            return None

        selected = answers["char_types"]
        lower = "lower" in selected
        upper = "upper" in selected
        digits = "digits" in selected
        symbols = "symbols" in selected

        required_chars = len(selected)
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
        try:
            password = generate_password(opts)
            copied = copy_to_clipboard_with_autoclear(password)
            ui.show_password_generated(password, copied)
            return password
        except ValueError as e:
            ui.error(str(e))
            return None

    except (KeyboardInterrupt, EOFError):
        ui.info("\nCancelled")
        return None


def display_vault_stats(vault: Vault) -> None:
    """Display vault statistics."""
    from rich.panel import Panel
    from rich.table import Table

    stats = get_vault_stats(vault)

    # Create stats table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="cyan", ratio=1)
    table.add_column(ratio=1)

    # Version information
    table.add_row("Schema version", str(vault.schema_version))
    if vault.created_with:
        table.add_row("Created with", f"v{vault.created_with}")
    if vault.last_modified_with:
        table.add_row("Last modified", f"v{vault.last_modified_with}")

    # Add separator
    table.add_row("", "")

    # Entry statistics
    table.add_row("Total entries", str(stats["total"]))
    table.add_row("Duplicates", str(stats["duplicates"]))
    table.add_row("Reused passwords", str(stats["reused"]))

    panel = Panel(
        table,
        title="[bold cyan]Vault Statistics[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    ui.console.print()
    ui.console.print(panel)


def _get_security_status(duplicates: int, reused: int) -> tuple[str, str]:
    """Get security status text and border color."""
    total_issues = duplicates + reused
    if total_issues == 0:
        return "[green]✓ No issues[/green]", "green"

    issues = []
    if duplicates:
        plural = "s" if duplicates > 1 else ""
        issues.append(f"{duplicates} duplicate{plural}")
    if reused:
        issues.append(f"{reused} reused")

    status_text = f"⚠ {', '.join(issues)}"
    color = "yellow" if total_issues <= 2 else "red"
    return f"[{color}]{status_text}[/{color}]", color


def display_welcome_banner(vault: Vault) -> None:
    """Display welcome banner with version information."""
    from rich.panel import Panel
    from rich.table import Table

    # Get stats
    stats = get_vault_stats(vault)
    security_status, border_color = _get_security_status(
        stats["duplicates"], stats["reused"]
    )

    # Create table
    table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    table.add_column(style="dim", ratio=1)
    table.add_column(ratio=1)
    table.add_column(style="dim", ratio=1)
    table.add_column(ratio=2)

    # Add rows
    table.add_row("PulseGuard", f"v{__version__}", "Vault path", vault.file_path)
    table.add_row(
        "Created with" if vault.created_with else "",
        f"v{vault.created_with}" if vault.created_with else "",
        "Entries",
        str(stats["total"]),
    )
    table.add_row(
        "Favorites", str(len(vault.get_favorites())), "Security", security_status
    )
    if vault.last_modified_with and vault.last_modified_with != vault.created_with:
        table.add_row("Last modified", f"v{vault.last_modified_with}", "", "")

    panel = Panel(
        table,
        title="[bold cyan]PulseGuard Password Manager[/bold cyan]",
        border_style=border_color,
        expand=True,
        padding=(1, 2),
    )
    ui.console.print(panel)


def display_security_health_check(vault: Vault) -> None:
    """Security health check."""
    from rich.panel import Panel
    from rich.table import Table

    duplicates = find_duplicates(vault)
    reused = find_reused_passwords(vault)

    if not duplicates and not reused:
        panel = Panel(
            "[green]✓ No security issues found[/green]",
            title="[bold cyan]Security Health Check[/bold cyan]",
            border_style="green",
            padding=(1, 2),
        )
        ui.console.print()
        ui.console.print(panel)
        return

    # Create issues table
    table = Table(show_header=True, box=None, padding=(0, 2))
    table.add_column("Issue Type", style="yellow", no_wrap=True)
    table.add_column("Details", style="white")

    if duplicates:
        for key, entries in duplicates:
            entry_names = ", ".join(e.name for e in entries)
            table.add_row("Duplicate", f"{key}\n  → {entry_names}")

    if reused:
        for count, entries in reused:
            entry_names = ", ".join(e.name for e in entries)
            table.add_row(
                "Reused password", f"Used in {len(entries)} entries\n  → {entry_names}"
            )

    panel = Panel(
        table,
        title="[bold cyan]Security Health Check[/bold cyan]",
        border_style="yellow",
        padding=(1, 2),
    )
    ui.console.print()
    ui.console.print(panel)


def interactive_mode() -> None:
    """Interactive mode."""
    from .cli_operations import (
        core_add_entry,
        core_browse_category,
        core_list_categories,
        core_move_entries_to_category,
        core_rename_category,
        select_and_show_entry,
    )

    vault = get_vault()
    display_welcome_banner(vault)

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
                select_and_show_entry(vault, "Select favorite entry", entries=favorites)

            elif choice and choice.startswith("Recently used"):
                select_and_show_entry(vault, "Select recent entry", entries=recent)

            elif choice == MainMenu.BROWSE_CATEGORY.value:
                entry = core_browse_category(vault)
                if entry:
                    ui.copy_password_with_feedback(entry.password)
                    from .cli_operations import show_entry_with_quick_actions

                    show_entry_with_quick_actions(vault, entry)

            elif choice == MainMenu.FIND_ENTRY.value:
                select_and_show_entry(vault, "Type to search, or select entry")

            elif choice == MainMenu.ADD_ENTRY.value:
                core_add_entry(vault)

            elif choice == MainMenu.GENERATE_PASSWORD.value:
                prompt_and_generate_password()

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

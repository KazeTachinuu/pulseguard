"""Rich UI utilities for beautiful terminal output."""

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .models import PasswordEntry

if TYPE_CHECKING:
    from .vault import Vault

console = Console()


def success(message: str) -> None:
    """Display success message."""
    console.print(f"[green]✓[/green] {message}")


def error(message: str) -> None:
    """Display error message."""
    console.print(f"[red]✗[/red] {message}")


def info(message: str) -> None:
    """Display info message."""
    console.print(f"[blue]i[/blue] {message}")


def warning(message: str) -> None:
    """Display warning message."""
    console.print(f"[yellow]![/yellow] {message}")


def confirm(message: str, default: bool = False) -> bool:
    """Ask for confirmation."""
    return Confirm.ask(message, default=default)


def prompt(message: str, default: str = "") -> str:
    """Prompt for input with optional default."""
    if default:
        return Prompt.ask(message, default=default)
    return Prompt.ask(message)


def humanize_date(dt: Optional[datetime]) -> str:
    """Convert datetime to human-readable format like '2d ago'."""
    if not dt:
        return "—"

    # Use timezone-aware now if dt is aware, else naive
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    diff = now - dt

    # Handle future dates (clock skew or data issues)
    if diff.days < 0 or diff.total_seconds() < 0:
        return "just now"

    if diff.days == 0:
        hours = diff.seconds // 3600
        if hours == 0:
            minutes = diff.seconds // 60
            return f"{minutes}m ago" if minutes > 0 else "just now"
        return f"{hours}h ago"
    elif diff.days < 7:
        return f"{diff.days}d ago"
    elif diff.days < 30:
        weeks = diff.days // 7
        return f"{weeks}w ago"
    elif diff.days < 365:
        months = diff.days // 30
        return f"{months}mo ago"
    else:
        years = diff.days // 365
        return f"{years}y ago"


def show_entries_table(
    entries: List[PasswordEntry], title: str = "Password Vault"
) -> None:
    """Display entries in a beautiful table."""
    if not entries:
        info("No entries found")
        return

    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("Name", style="cyan bold", no_wrap=True)
    table.add_column("Username", style="green")
    table.add_column("URL", style="blue dim")
    table.add_column("Created", style="yellow", justify="right")

    for entry in entries:
        table.add_row(
            entry.name,
            entry.username,
            entry.url or "—",
            humanize_date(entry.created_at),
        )

    console.print(table)
    console.print(f"[dim]Total: {len(entries)} entries[/dim]")


def show_entry_panel(entry: PasswordEntry, show_password: bool = False) -> None:
    """Display single entry in a detailed panel."""
    content = []
    content.append(f"[cyan bold]Name:[/cyan bold] {entry.name}")
    content.append(f"[green bold]Username:[/green bold] {entry.username}")

    if show_password:
        content.append(f"[red bold]Password:[/red bold] {entry.password}")
    else:
        content.append(f"[red bold]Password:[/red bold] {'•' * 8}")

    if entry.url:
        content.append(f"[blue bold]URL:[/blue bold] {entry.url}")

    if entry.notes:
        content.append(f"[yellow bold]Notes:[/yellow bold] {entry.notes}")

    content.append(f"[dim]Created: {humanize_date(entry.created_at)}[/dim]")

    panel = Panel(
        "\n".join(content),
        title=f"{entry.name}",
        border_style="cyan",
        expand=False,
    )
    console.print(panel)


def show_password_generated(password: str, copied: bool = False) -> None:
    """Display generated password status (shows password only if clipboard failed)."""
    if copied:
        # Password copied - don't display it for security
        success("Password generated and copied to clipboard")
    else:
        # Clipboard failed - must show password so user can copy manually
        warning("Clipboard unavailable - password shown below:")
        panel = Panel(
            f"[yellow bold]{password}[/yellow bold]",
            title="Generated Password",
            border_style="yellow",
            expand=False,
        )
        console.print(panel)


def select_entry(
    vault: "Vault", message: str = "Select entry"
) -> Optional[PasswordEntry]:
    """
    Interactive entry selector with fuzzy search.

    Returns None if user cancels (Ctrl+C).
    """
    entries = vault.get_all()

    if not entries:
        return None

    sorted_entries = sorted(entries, key=lambda e: e.name.lower())
    choices = [f"{entry.name} ({entry.username})" for entry in sorted_entries]
    name_map = {
        f"{entry.name} ({entry.username})": entry.name for entry in sorted_entries
    }

    try:
        answer = questionary.autocomplete(
            message,
            choices=choices,
            style=questionary.Style(
                [
                    ("highlighted", "fg:cyan bold"),
                    ("pointer", "fg:cyan bold"),
                ]
            ),
        ).ask()

        if answer is None:  # User cancelled
            return None

        return vault.get(name_map[answer])

    except KeyboardInterrupt:
        return None

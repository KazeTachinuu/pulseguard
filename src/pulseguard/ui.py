"""UI utilities."""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, List, Optional

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import Config
from .models import PasswordEntry

if TYPE_CHECKING:
    from .vault import Vault


class UIPrompt(str, Enum):
    """Special UI prompts and markers."""

    CREATE_CATEGORY = "[Create new category]"
    VIEW_ALL_CATEGORIES = "All categories (view all)"
    BACK = "← Back"


console = Console()

# Clean questionary style - minimal highlighting for select/autocomplete
select_style = questionary.Style(
    [
        ("qmark", "fg:#5f87af bold"),  # Question mark
        ("question", "bold"),  # Question text
        ("pointer", "fg:#5f87af bold"),  # Selection pointer (>)
        ("highlighted", "fg:#ffffff bg:#5f87af"),  # Current line highlight
        ("selected", ""),  # Selected items
        ("separator", "fg:#6c6c6c"),  # Separators
        ("instruction", "fg:#6c6c6c"),  # Instructions
        ("text", ""),  # Plain text
        ("answer", "fg:#5f87af bold"),  # User's answer
    ]
)


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
    result = questionary.confirm(message, default=default, style=select_style).ask()
    return result if result is not None else False


def prompt(message: str, default: str = "") -> str:
    """Prompt for input with optional default."""
    try:
        result = questionary.text(message, default=default, style=select_style).ask()
        return result if result is not None else ""
    except (KeyboardInterrupt, EOFError):
        return ""


def humanize_date(dt: Optional[datetime]) -> str:
    """Format datetime as absolute timestamp."""
    if not dt:
        return "—"

    # Convert to local time for display
    if dt.tzinfo:
        # Convert UTC to local time
        local_dt = dt.astimezone()
    else:
        local_dt = dt

    # Format as "YYYY-MM-DD HH:MM"
    return local_dt.strftime("%Y-%m-%d %H:%M")


def copy_with_feedback(text: str, label: str = "Text") -> bool:
    """Copy text to clipboard and show feedback message."""
    from .passwordgen import CLIPBOARD_TIMEOUT_SECONDS, copy_to_clipboard_with_autoclear

    if copy_to_clipboard_with_autoclear(text):
        success(f"{label} copied (clears in {CLIPBOARD_TIMEOUT_SECONDS}s)")
        return True
    else:
        warning("Clipboard unavailable")
        return False


def copy_password_with_feedback(password: str) -> bool:
    """Copy password to clipboard and show feedback message."""
    return copy_with_feedback(password, "Password")


def show_entries_table(
    entries: List[PasswordEntry], title: str = "Password Vault"
) -> None:
    """Display entries table."""
    if not entries:
        info("No entries found")
        return

    table = Table(title=title, show_lines=False, expand=True)
    table.add_column("Name", style="cyan bold", no_wrap=True)
    table.add_column("Username", style="green")
    table.add_column("Category", style="magenta")
    table.add_column("URL", style="blue dim")
    table.add_column("Updated", style="dim", justify="right")

    for entry in sorted(entries, key=lambda e: e.name.lower()):
        name_display = f"★ {entry.name}" if entry.favorite else entry.name
        table.add_row(
            name_display,
            entry.username,
            entry.category or "—",
            entry.url or "—",
            humanize_date(entry.updated_at),
        )

    console.print(table)
    console.print(f"[dim]Total: {len(entries)} entries[/dim]")


def show_entry_panel(entry: PasswordEntry, show_password: bool = False) -> None:
    """Display entry details."""
    content = []

    # Title
    title = f"{'★ ' if entry.favorite else ''}{entry.name}"

    # Info with subtle coloring
    content.append(f"[green]Username:[/green] {entry.username}")

    if show_password:
        content.append(f"[yellow]Password:[/yellow] {entry.password}")
    else:
        pwd_len = len(entry.password)
        strength = "Strong" if pwd_len >= 16 else "Medium" if pwd_len >= 12 else "Weak"
        strength_color = (
            "green" if pwd_len >= 16 else "yellow" if pwd_len >= 12 else "red"
        )
        content.append(
            f"[yellow]Password:[/yellow] {'•' * 12}  "
            f"[dim]([{strength_color}]{strength}[/{strength_color}], {pwd_len} chars)[/dim]"
        )

    if entry.url:
        content.append(f"[blue]URL:[/blue] {entry.url}")

    if entry.category and entry.category != Config.DEFAULT_CATEGORY:
        content.append(f"[magenta]Category:[/magenta] {entry.category}")

    if entry.notes:
        content.append(f"\n[cyan]Notes:[/cyan]\n{entry.notes}")

    if entry.tags:
        content.append(f"\n[magenta]Tags:[/magenta] {', '.join(entry.tags)}")

    # Temporal info
    content.append("")
    content.append(f"[dim]Updated {humanize_date(entry.updated_at)}[/dim]")
    if entry.last_accessed:
        content.append(
            f"[dim]Last used {humanize_date(entry.last_accessed)} • Used {entry.access_count} times[/dim]"
        )

    panel = Panel(
        "\n".join(content),
        title=title,
        border_style="cyan",
        expand=False,
    )
    console.print(panel)


def show_password_generated(password: str, copied: bool = False) -> None:
    """Display generated password."""
    from .passwordgen import CLIPBOARD_TIMEOUT_SECONDS

    if copied:
        # Password copied - don't display it for security
        success(
            f"Password generated and copied (clears in {CLIPBOARD_TIMEOUT_SECONDS}s)"
        )
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
    vault: "Vault",
    message: str = "Select entry",
    track_access: bool = True,
    entries: Optional[List[PasswordEntry]] = None,
) -> Optional[PasswordEntry]:
    """
    Select entry.

    Args:
        vault: Vault instance
        message: Prompt message
        track_access: Whether to track access
        entries: Optional list of entries to choose from (if None, uses all)

    Returns None if user cancels (Ctrl+C).
    """
    if entries is None:
        entries = vault.get_all()

    if not entries:
        info("No entries found")
        return None

    sorted_entries = sorted(entries, key=lambda e: e.name.lower())

    # Build simple choice labels
    choices = []
    name_map = {}

    for entry in sorted_entries:
        # Simple format: Name (username) or ★ Name (username) for favorites
        prefix = "★ " if entry.favorite else ""
        label = f"{prefix}{entry.name} ({entry.username})"
        choices.append(label)
        name_map[label] = entry.name

    try:
        answer = questionary.autocomplete(
            message,
            choices=choices,
            style=select_style,
        ).ask()

        if answer is None or answer == "" or answer not in name_map:
            return None

        return vault.get(name_map[answer], track_access=track_access)

    except KeyboardInterrupt:
        return None


def select_category(
    vault: Optional["Vault"], message: str = "Select category", include_new: bool = True
) -> Optional[str]:
    """Select category."""
    existing = vault.get_all_categories() if vault else []
    choices = existing.copy()
    if include_new:
        choices.insert(0, UIPrompt.CREATE_CATEGORY.value)

    try:
        answer = questionary.select(
            message,
            choices=choices,
            style=select_style,
        ).ask()

        if answer is None:
            return None

        if answer == UIPrompt.CREATE_CATEGORY.value:
            new_cat = prompt("New category name")
            return new_cat if new_cat else None

        return answer

    except KeyboardInterrupt:
        return None

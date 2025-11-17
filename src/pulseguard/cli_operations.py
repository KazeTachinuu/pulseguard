"""Core operations for CLI commands."""

from typing import Optional

import questionary

from . import ui
from .cli_helpers import (
    Message,
    QuickAction,
    UIPrompt,
    prompt_and_generate_password,
)
from .config import Config
from .models import PasswordEntry
from .ui import select_category, select_entry, select_style
from .vault import Vault


def select_and_show_entry(vault: Vault, prompt: str, entries=None) -> None:
    """Select entry, copy password, and show quick actions."""
    entry = select_entry(vault, prompt, entries=entries)
    if entry:
        ui.copy_password_with_feedback(entry.password)
        show_entry_with_quick_actions(vault, entry)


def core_add_entry(vault: Vault) -> None:
    """Add entry."""
    # Always prompt for required fields
    name = ui.prompt("Entry name")
    if not name:
        ui.info(Message.CANCELLED.value)
        return

    username = ui.prompt("Username")
    if not username:
        ui.info(Message.CANCELLED.value)
        return

    # Select category
    category = select_category(vault, "Select category", include_new=True)
    if not category:
        category = Config.DEFAULT_CATEGORY

    # Always ask if user wants to generate password
    if ui.confirm("Generate password?", default=True):
        password = prompt_and_generate_password()
        if not password:
            return  # User cancelled
    else:
        password = questionary.password("Password:", style=ui.select_style).ask()
        if password is None:
            ui.info(Message.CANCELLED.value)
            return

    # Optional fields
    url = ui.prompt("URL (optional)", "")
    notes = ui.prompt("Notes (optional)", "")

    entry = PasswordEntry(
        name=name,
        username=username,
        password=password,
        url=url,
        notes=notes,
        category=category,
        tags=[],
    )
    vault.add(entry)
    ui.success(f"Added entry '{name}' to category '{category}'")


def show_entry_with_quick_actions(vault: Vault, entry: PasswordEntry) -> bool:
    """
    Show entry and provide contextual quick actions.

    Returns True if entry was deleted (to break out of parent loops).
    """
    while True:
        # Show entry details
        ui.show_entry_panel(entry, show_password=False)

        # Build action menu - ordered by frequency of use
        actions = [
            QuickAction.SHOW_PASSWORD.value,
            QuickAction.COPY_PASSWORD.value,
            QuickAction.COPY_USERNAME.value,
        ]

        if entry.url:
            actions.append(QuickAction.COPY_URL.value)

        actions.extend(
            [
                QuickAction.EDIT.value,
                (
                    QuickAction.REMOVE_FAVORITE.value
                    if entry.favorite
                    else QuickAction.ADD_FAVORITE.value
                ),
                QuickAction.DELETE.value,
                UIPrompt.BACK.value,
            ]
        )

        try:
            action = questionary.select(
                "Quick actions:",
                choices=actions,
                style=select_style,
            ).ask()

            if action is None or action == UIPrompt.BACK.value:
                vault.save_if_dirty()
                return False

            if action == QuickAction.SHOW_PASSWORD.value:
                ui.console.print()
                ui.show_entry_panel(entry, show_password=True)
                ui.prompt("Press Enter to hide password")
                # Clear screen to remove password from terminal history
                ui.console.clear()

            elif action == QuickAction.COPY_PASSWORD.value:
                ui.copy_password_with_feedback(entry.password)

            elif action == QuickAction.COPY_USERNAME.value:
                ui.copy_with_feedback(entry.username, "Username")

            elif action == QuickAction.COPY_URL.value:
                ui.copy_with_feedback(entry.url, "URL")

            elif action == QuickAction.EDIT.value:
                # Edit the current entry (without re-selecting)
                refreshed = edit_existing_entry(vault, entry)
                if not refreshed:
                    ui.info("Entry was deleted")
                    return True
                entry = refreshed

            elif action in (
                QuickAction.ADD_FAVORITE.value,
                QuickAction.REMOVE_FAVORITE.value,
            ):
                entry.favorite = not entry.favorite
                vault.add(entry, update_timestamp=False)
                ui.success(
                    f"{'Added to favorites' if entry.favorite else 'Removed from favorites'}: '{entry.name}'"
                )
                # Refresh to show star in panel
                refreshed = vault.get(entry.name, track_access=False)
                if refreshed:
                    entry = refreshed

            elif action == QuickAction.DELETE.value:
                if ui.confirm(f"Delete '{entry.name}'?", default=False):
                    vault.remove(entry.name)
                    ui.success(f"Deleted entry '{entry.name}'")
                    return True
                else:
                    ui.info("Deletion cancelled")

        except (KeyboardInterrupt, EOFError):
            ui.info(f"\n{Message.CANCELLED.value}")
            vault.save_if_dirty()
            return False


def core_get_entry(vault: Vault) -> None:
    """Get entry."""
    entry = select_entry(vault, "Select entry to view")
    if not entry:
        return

    # Copy to clipboard
    ui.copy_password_with_feedback(entry.password)

    show_entry_with_quick_actions(vault, entry)


def edit_existing_entry(vault: Vault, entry: PasswordEntry) -> Optional[PasswordEntry]:
    """
    Edit an existing entry (without re-selecting it).

    Returns updated entry, or None if the entry cannot be retrieved after update.
    """
    ui.info(f"Editing '{entry.name}' (press Enter to keep current value)")

    new_username = ui.prompt("Username", entry.username)
    new_url = ui.prompt("URL", entry.url)
    new_notes = ui.prompt("Notes", entry.notes)

    # Handle category change
    current_category = entry.category or Config.DEFAULT_CATEGORY
    if ui.confirm(f"Change category? (current: {current_category})", default=False):
        new_category = select_category(
            vault,
            f"Select new category (current: {current_category})",
            include_new=True,
        )
        if not new_category:
            new_category = current_category
    else:
        new_category = current_category

    # Handle password change
    if ui.confirm("Change password?", default=False):
        if ui.confirm("Generate new password?", default=True):
            new_password = prompt_and_generate_password()
            if new_password is None:
                new_password = entry.password
        else:
            new_password = questionary.password(
                "New password:", style=ui.select_style
            ).ask()
            if new_password is None:
                new_password = entry.password  # Keep old password if cancelled
    else:
        new_password = entry.password

    updated_entry = entry.copy_with_updates(
        username=new_username,
        password=new_password,
        url=new_url,
        notes=new_notes,
        category=new_category,
    )
    vault.add(updated_entry)
    ui.success(f"Updated entry '{entry.name}'")

    # Return refreshed entry
    return vault.get(entry.name, track_access=False)


def core_edit_entry(vault: Vault) -> None:
    """Edit entry."""
    entry = select_entry(vault, "Select entry to edit", track_access=False)
    if not entry:
        return

    edit_existing_entry(vault, entry)


def core_delete_entry(vault: Vault) -> None:
    """Delete entry."""
    entry = select_entry(vault, "Select entry to delete")
    if not entry:
        return

    # Confirm deletion
    if not ui.confirm(f"Delete '{entry.name}'?", default=False):
        ui.info(Message.CANCELLED.value)
        return

    vault.remove(entry.name)
    ui.success(f"Deleted entry '{entry.name}'")


def core_list_entries(vault: Vault) -> None:
    """List entries."""
    entries = vault.get_all()
    ui.show_entries_table(entries)


def core_browse_category(
    vault: Vault, category: Optional[str] = None
) -> Optional[PasswordEntry]:
    """Browse entries by category."""
    # Step 1: Select a category if not provided
    if category is None:
        categories = vault.get_all_categories()
        if not categories:
            ui.info(Message.NO_ENTRIES.value)
            return None

        # Build category choices with counts
        entries_by_cat = vault.get_entries_by_category()
        category_choices = []
        for cat in categories:
            count = len(entries_by_cat.get(cat, []))
            category_choices.append(f"{cat} ({count})")

        category_choices.insert(0, UIPrompt.VIEW_ALL_CATEGORIES.value)

        selected_category = questionary.select(
            "Select category to browse:",
            choices=category_choices,
            style=select_style,
        ).ask()

        if selected_category is None:
            return None

        if selected_category.startswith("All categories"):
            category = None  # View all
        else:
            # Extract category name (remove count)
            category = selected_category.rsplit(" (", 1)[0]

    # Step 2: Show entries in selected category
    if category is None:
        # Show all entries in table format
        core_list_entries(vault)
        entry = select_entry(vault, "Select entry to view")
    else:
        # Show entries in specific category
        category_entries = vault.get_by_category(category)

        if category_entries:
            from rich.panel import Panel
            from rich.table import Table

            # Create table for category entries
            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column("Name", style="white", no_wrap=False)
            table.add_column("Username", style="dim", no_wrap=False)
            table.add_column("URL", style="blue dim", no_wrap=False)

            for e in sorted(category_entries, key=lambda x: x.name.lower()):
                prefix = "★ " if e.favorite else ""
                name = f"{prefix}{e.name}"
                url = e.url if e.url else ""
                if url and len(url) > Config.MAX_URL_DISPLAY_LENGTH:
                    url = url[: Config.MAX_URL_DISPLAY_LENGTH - 3] + "..."
                table.add_row(name, e.username, url)

            panel = Panel(
                table,
                title=f"[bold cyan]{category}[/bold cyan] [dim]({len(category_entries)} entries)[/dim]",
                border_style="cyan",
                padding=(1, 2),
            )
            ui.console.print()
            ui.console.print(panel)

            # Let user select entry from this category (filtered)
            entry = select_entry(
                vault, f"Select entry from {category}", entries=category_entries
            )
        else:
            entry = None

    return entry


def core_list_categories(vault: Vault) -> None:
    """List categories."""
    from rich.panel import Panel
    from rich.table import Table

    categories = vault.get_all_categories()
    if not categories:
        ui.info(Message.NO_CATEGORIES.value)
        return

    entries_by_cat = vault.get_entries_by_category()

    # Create categories table
    table = Table(show_header=True, box=None, padding=(0, 2))
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Entries", style="dim", justify="right")

    for cat in categories:
        count = len(entries_by_cat.get(cat, []))
        table.add_row(cat, str(count))

    panel = Panel(
        table,
        title=f"[bold cyan]Categories[/bold cyan] [dim]({len(categories)} total)[/dim]",
        border_style="cyan",
        padding=(1, 2),
    )
    ui.console.print()
    ui.console.print(panel)


def core_rename_category(vault: Vault) -> None:
    """Rename category."""
    categories = vault.get_all_categories()
    if not categories:
        ui.info(Message.NO_CATEGORIES.value)
        return

    # Remove Uncategorized from choices
    selectable = [c for c in categories if c != Config.DEFAULT_CATEGORY]
    if not selectable:
        ui.info("No categories to rename")
        return

    old_name = questionary.select(
        "Select category to rename:",
        choices=selectable,
        style=select_style,
    ).ask()

    if not old_name:
        return

    # Check if category exists
    entries = vault.get_by_category(old_name)
    if not entries:
        ui.error(f"Category '{old_name}' not found or is empty")
        return

    # Prompt for new name
    new_name = ui.prompt(f"New name for '{old_name}'")
    if not new_name:
        ui.info(Message.CANCELLED.value)
        return

    # Check if new name already exists
    if new_name in vault.get_all_categories():
        ui.error(f"Category '{new_name}' already exists")
        return

    # Update all entries in the category
    for entry in entries:
        updated_entry = entry.copy_with_updates(category=new_name)
        vault.add(updated_entry, update_timestamp=False)

    ui.success(
        f"Renamed category '{old_name}' → '{new_name}' ({len(entries)} entries updated)"
    )


def core_move_entries_to_category(vault: Vault) -> None:
    """Move entries between categories."""
    categories = vault.get_all_categories()
    if not categories:
        ui.info(Message.NO_CATEGORIES.value)
        return

    # Select source category
    from_category = questionary.select(
        "Move entries FROM category:",
        choices=categories,
        style=select_style,
    ).ask()

    if not from_category:
        return

    # Get entries in source category
    entries = vault.get_by_category(from_category)
    if not entries:
        ui.error(f"Category '{from_category}' not found or is empty")
        return

    # Select destination category
    # Build choices (exclude source category)
    dest_choices = [c for c in categories if c != from_category]
    dest_choices.insert(0, UIPrompt.CREATE_CATEGORY.value)

    selected = questionary.select(
        f"Move {len(entries)} entries TO category:",
        choices=dest_choices,
        style=select_style,
    ).ask()

    if not selected:
        return

    if selected == UIPrompt.CREATE_CATEGORY.value:
        to_category = ui.prompt("New category name")
        if not to_category:
            ui.info(Message.CANCELLED.value)
            return
    else:
        to_category = selected

    # Confirm the move
    if not ui.confirm(
        f"Move {len(entries)} entries from '{from_category}' to '{to_category}'?",
        default=True,
    ):
        ui.info(Message.CANCELLED.value)
        return

    # Move all entries
    for entry in entries:
        updated_entry = entry.copy_with_updates(category=to_category)
        vault.add(updated_entry, update_timestamp=False)

    ui.success(
        f"Moved {len(entries)} entries from '{from_category}' to '{to_category}'"
    )

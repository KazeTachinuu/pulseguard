"""Core operations for CLI commands."""

from getpass import getpass
from typing import Optional

import questionary
from rich.prompt import Confirm

from . import ui
from .cli_helpers import (
    Message,
    QuickAction,
    UIPrompt,
    prompt_and_generate_password,
)
from .config import Config
from .models import PasswordEntry
from .passwordgen import copy_to_clipboard
from .ui import select_category, select_entry, select_style
from .vault import Vault


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
    if Confirm.ask("Generate password?", default=True):
        password = prompt_and_generate_password()
        if not password:
            return  # User cancelled
    else:
        password = getpass("Password: ")

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
                copied = copy_to_clipboard(entry.password)
                if copied:
                    ui.success("Password copied to clipboard")
                else:
                    ui.warning("Clipboard unavailable")

            elif action == QuickAction.COPY_USERNAME.value:
                copied = copy_to_clipboard(entry.username)
                if copied:
                    ui.success("Username copied to clipboard")
                else:
                    ui.warning("Clipboard unavailable")

            elif action == QuickAction.COPY_URL.value:
                copied = copy_to_clipboard(entry.url)
                if copied:
                    ui.success("URL copied to clipboard")
                else:
                    ui.warning("Clipboard unavailable")

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
                if Confirm.ask(f"Delete '{entry.name}'?", default=False):
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
    copied = copy_to_clipboard(entry.password)
    if copied:
        ui.success("Password copied to clipboard")
    else:
        ui.warning("Clipboard unavailable")

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
    if Confirm.ask(f"Change category? (current: {current_category})", default=False):
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
    if Confirm.ask("Change password?", default=False):
        if Confirm.ask("Generate new password?", default=True):
            new_password = prompt_and_generate_password()
            if new_password is None:
                new_password = entry.password
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
        category=new_category,
        tags=entry.tags,
        favorite=entry.favorite,
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
    if not Confirm.ask(f"Delete '{entry.name}'?", default=False):
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
            ui.console.print(
                f"\n[cyan]{category}[/cyan] [dim]({len(category_entries)})[/dim]"
            )
            for e in sorted(category_entries, key=lambda x: x.name.lower()):
                prefix = "★ " if e.favorite else ""
                parts = [f"{prefix}{e.name}", f"[dim]{e.username}[/dim]"]
                if e.url:
                    url = e.url if len(e.url) <= 35 else e.url[:32] + "..."
                    parts.append(f"[blue dim]{url}[/blue dim]")
                ui.console.print(f"  {' · '.join(parts)}")
            ui.console.print()

            # Let user select entry from this category (filtered)
            entry = select_entry(
                vault, f"Select entry from {category}", entries=category_entries
            )
        else:
            entry = None

    return entry


def core_list_categories(vault: Vault) -> None:
    """List categories."""
    categories = vault.get_all_categories()
    if not categories:
        ui.info(Message.NO_CATEGORIES.value)
        return

    entries_by_cat = vault.get_entries_by_category()

    ui.console.print("\n[bold cyan]Categories[/bold cyan]\n")

    for cat in categories:
        count = len(entries_by_cat.get(cat, []))
        ui.console.print(f"  {cat}: [dim]{count} entries[/dim]")

    ui.console.print(f"\n[dim]Total: {len(categories)} categories[/dim]\n")


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
        updated_entry = PasswordEntry(
            name=entry.name,
            username=entry.username,
            password=entry.password,
            url=entry.url,
            notes=entry.notes,
            category=new_name,
            tags=entry.tags,
            favorite=entry.favorite,
        )
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
    if not Confirm.ask(
        f"Move {len(entries)} entries from '{from_category}' to '{to_category}'?",
        default=True,
    ):
        ui.info(Message.CANCELLED.value)
        return

    # Move all entries
    for entry in entries:
        updated_entry = PasswordEntry(
            name=entry.name,
            username=entry.username,
            password=entry.password,
            url=entry.url,
            notes=entry.notes,
            category=to_category,
            tags=entry.tags,
            favorite=entry.favorite,
        )
        vault.add(updated_entry, update_timestamp=False)

    ui.success(
        f"Moved {len(entries)} entries from '{from_category}' to '{to_category}'"
    )

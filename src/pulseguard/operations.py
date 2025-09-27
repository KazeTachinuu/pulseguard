"""CLI operations for PulseGuard."""

from typing import List

from .messages import (
    DEMO_ENTRIES,
    ERROR_NOT_FOUND,
    ERROR_USAGE_ADD,
    ERROR_USAGE_DELETE,
    ERROR_USAGE_EDIT,
    ERROR_USAGE_GET,
    ERROR_USAGE_SEARCH,
    INFO_FOUND_COUNT,
    INFO_FOUND_MATCHING,
    INFO_NO_MATCHES,
    INFO_NO_ENTRIES,
    SUCCESS_ADDED,
    SUCCESS_DELETED,
)
from .models import PasswordEntry
from .vault import Vault, VaultError


def list_passwords(vault: Vault) -> None:
    """List all entries."""
    if not vault.entries:
        print(INFO_NO_ENTRIES)
        return

    print(INFO_FOUND_COUNT.format(count=len(vault.entries)))
    for i, entry in enumerate(vault.entries, 1):
        print(f"{i}. {entry.name} - {entry.username}")


def add_password(
    vault: Vault,
    name: str,
    username: str,
    password: str,
    url: str = "",
    notes: str = "",
) -> None:
    """Add a password."""
    try:
        entry = PasswordEntry(
            name=name, username=username, password=password, url=url, notes=notes
        )
        vault.add(entry)
        print(SUCCESS_ADDED.format(name=name))
    except VaultError as e:
        print(f"Error adding password: {e}")


def get_password(vault: Vault, name: str) -> None:
    """Get password details."""
    entry = vault.get(name)
    if entry:
        print(f"Password: {entry.name}")
        print(f"Username: {entry.username}")
        print(f"Password: {entry.password}")
        if entry.url:
            print(f"URL: {entry.url}")
        if entry.notes:
            print(f"Notes: {entry.notes}")
    else:
        print(ERROR_NOT_FOUND.format(name=name))


def edit_password(vault: Vault, name: str) -> None:
    """Edit password interactively."""
    entry = vault.get(name)
    if not entry:
        print(ERROR_NOT_FOUND.format(name=name))
        return

    print(f"Editing password '{name}'. Press Enter to keep current value.")

    # Edit username
    new_username = input(f"Username [{entry.username}]: ").strip()
    if new_username:
        entry.username = new_username

    # Edit password
    new_password = input("Password [***]: ").strip()
    if new_password:
        entry.password = new_password

    # Edit URL
    new_url = input(f"URL [{entry.url}]: ").strip()
    if new_url is not None:  # Allow empty string to clear URL
        entry.url = new_url

    # Edit notes
    new_notes = input(f"Notes [{entry.notes}]: ").strip()
    if new_notes is not None:  # Allow empty string to clear notes
        entry.notes = new_notes

    try:
        vault.add(entry)
        print(SUCCESS_ADDED.format(name=name))
    except VaultError as e:
        print(f"Error updating password: {e}")


def delete_password(vault: Vault, name: str) -> None:
    """Delete a password."""
    if vault.remove(name):
        print(SUCCESS_DELETED.format(name=name))
    else:
        print(ERROR_NOT_FOUND.format(name=name))


def search_passwords(vault: Vault, query: str) -> None:
    """Search passwords."""
    results = vault.search(query)
    if results:
        print(INFO_FOUND_MATCHING.format(count=len(results), query=query))
        for entry in results:
            print(f"  {entry.name} - {entry.username}")
    else:
        print(INFO_NO_MATCHES.format(query=query))


def run_demo(vault: Vault) -> None:
    """Run demo with sample data."""
    print("Running PulseGuard demo with sample data...")

    for entry_data in DEMO_ENTRIES:
        entry = PasswordEntry.from_dict(entry_data)
        vault.add(entry)
        print(f"Added: {entry.name}")

    print(f"\nDemo complete! Added {len(DEMO_ENTRIES)} sample passwords.")
    print(
        "Use 'pulseguard list' to see them or 'pulseguard' to start the interactive console."
    )

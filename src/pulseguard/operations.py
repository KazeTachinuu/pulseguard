"""CLI operations for PulseGuard."""

from .messages import (
    DEMO_ENTRIES,
    ERROR_MUTUALLY_EXCLUSIVE_GEN,
    ERROR_NOT_FOUND,
    INFO_FOUND_COUNT,
    INFO_FOUND_MATCHING,
    INFO_NO_ENTRIES,
    INFO_NO_MATCHES,
    SUCCESS_ADDED,
    SUCCESS_DELETED,
)
from .models import PasswordEntry
from .passwordgen import (
    DEFAULT_LEN,
    MAX_LEN,
    GenOptions,
    copy_to_clipboard,
    generate_password,
)
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
    gen: bool = False,
    length: int = DEFAULT_LEN,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = False,
) -> None:
    """Add a password."""
    try:
        if gen and password:
            print(ERROR_MUTUALLY_EXCLUSIVE_GEN)
            return
        if gen:
            opts = GenOptions(
                length=length, lower=lower, upper=upper, digits=digits, symbols=symbols
            )
            password = generate_password(opts)
            copied = copy_to_clipboard(password)

        entry = PasswordEntry(
            name=name, username=username, password=password, url=url, notes=notes
        )
        vault.add(entry)
        print(SUCCESS_ADDED.format(name=name))
        if gen:
            print(f"(length={len(password)}, max={MAX_LEN})")
            if copied:
                print("Generated password copied to clipboard.")
            else:
                print("! Clipboard unavailable, showing the new password below:")
                print(f"Password: {password}")
    except VaultError as e:
        print(f"Error adding password: {e}")
    except ValueError as e:
        print(f"Generation error: {e}")


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
    """Edit password interactively (with optional generator)."""
    entry = vault.get(name)
    if not entry:
        print(ERROR_NOT_FOUND.format(name=name))
        return

    print(f"Editing password '{name}'. Press Enter to keep current value.")

    # Edit username
    new_username = input(f"Username [{entry.username}]: ").strip()
    if new_username:
        entry.username = new_username

    # Propose generation
    use_generator = input("Generate a new password? (y/N): ").strip().lower() == "y"
    if use_generator:
        try:
            # flags
            try_len = input(f"Length [default {DEFAULT_LEN}, max {MAX_LEN}]: ").strip()
            length = int(try_len) if try_len else DEFAULT_LEN
            lower = input("Include lowercase? (Y/n): ").strip().lower() != "n"
            upper = input("Include UPPERCASE? (Y/n): ").strip().lower() != "n"
            digits = input("Include digits? (Y/n): ").strip().lower() != "n"
            symbols = input("Include symbols? (y/N): ").strip().lower() == "y"

            opts = GenOptions(
                length=length, lower=lower, upper=upper, digits=digits, symbols=symbols
            )
            new_password = generate_password(opts)
            entry.password = new_password

            if copy_to_clipboard(new_password):
                print("New password copied to clipboard.")
            else:
                print("! Clipboard unavailable, showing the new password below:")
                print(new_password)
        except Exception as e:
            print(f"Generation error: {e}")
            # ask for manual pass
            new_password = input("Password [***]: ").strip()
            if new_password:
                entry.password = new_password
    else:
        new_password = input("Password [***]: ").strip()
        if new_password:
            entry.password = new_password

    # Edit URL
    new_url = input(f"URL [{entry.url}]: ").strip()
    if new_url:  # Only update if non-empty
        entry.url = new_url

    # Edit notes
    new_notes = input(f"Notes [{entry.notes}]: ").strip()
    if new_notes:  # Only update if non-empty
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


def generate_password_command(
    vault: Vault,
    length: int = DEFAULT_LEN,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = False,
) -> None:
    """Generate a password according to flags and copy to clipboard."""
    try:
        opts = GenOptions(
            length=length, lower=lower, upper=upper, digits=digits, symbols=symbols
        )
        pwd = generate_password(opts)
        copied = copy_to_clipboard(pwd)
        print("Generated password:")
        if copied:
            print("Copied to clipboard.")
        else:
            print("! Clipboard unavailable, showing below:")
            print(pwd)
        print(f"(length={len(pwd)}, max={MAX_LEN})")
    except Exception as e:
        print(f"Generation error: {e}")


def run_demo(vault: Vault) -> None:
    """Run demo with sample data."""
    print("Running PulseGuard demo with sample data...")

    for entry_data in DEMO_ENTRIES:
        entry = PasswordEntry.from_dict(entry_data)
        vault.add(entry)
        print(f"Added: {entry.name}")

    print(f"\nDemo complete! Added {len(DEMO_ENTRIES)} sample passwords.")
    print(
        "Use 'pulseguard list' to see them or 'pulseguard' to start the "
        "interactive console."
    )

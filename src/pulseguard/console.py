"""Interactive console for PulseGuard."""

import cmd
from typing import List

from .commands import generate_console_help
from .config import config
from .messages import (
    CONSOLE_INTRO,
    CONSOLE_PROMPT,
    ERROR_NOT_FOUND,
    ERROR_USAGE_ADD,
    ERROR_USAGE_DELETE,
    ERROR_USAGE_EDIT,
    ERROR_USAGE_GET,
    ERROR_USAGE_SEARCH,
    INFO_FOUND_COUNT,
    INFO_FOUND_MATCHING,
    INFO_GOODBYE,
    INFO_NO_MATCHES,
    INFO_NO_ENTRIES,
    SUCCESS_ADDED,
    SUCCESS_DELETED,
)
from .models import PasswordEntry
from .vault import Vault, VaultError


class Console(cmd.Cmd):
    """Interactive console for password management.

    Provides a command-line interface for managing passwords.
    Type 'help' to see available commands.
    """

    def __init__(self, vault: Vault = None):
        """Initialize the console with a vault instance."""
        super().__init__()
        self.vault = vault or Vault()
        self.intro = CONSOLE_INTRO
        self.prompt = CONSOLE_PROMPT

    def do_list(self, args: str) -> None:
        """List all passwords.

        Usage: list
        """
        self._list_passwords()

    def do_add(self, args: str) -> None:
        """Add a new password.

        Usage: add <name> <username> <password> [--url URL] [--notes NOTES]
        """
        parts = args.split()
        if len(parts) < 3:
            print(ERROR_USAGE_ADD)
            return

        name, username, password = parts[0], parts[1], parts[2]
        url, notes = "", ""

        # Parse optional arguments
        i = 3
        while i < len(parts):
            if parts[i] == "--url" and i + 1 < len(parts):
                url = parts[i + 1]
                i += 2
            elif parts[i] == "--notes" and i + 1 < len(parts):
                notes = parts[i + 1]
                i += 2
            else:
                i += 1

        try:
            entry = PasswordEntry(
                name=name, username=username, password=password, url=url, notes=notes
            )
            self.vault.add(entry)
            print(SUCCESS_ADDED.format(name=name))
        except VaultError as e:
            print(f"Error adding password: {e}")

    def do_get(self, args: str) -> None:
        """Get password details.

        Usage: get <name>
        """
        if not args.strip():
            print(ERROR_USAGE_GET)
            return

        self._get_password(args.strip())

    def do_edit(self, args: str) -> None:
        """Edit password (interactive).

        Usage: edit <name>
        """
        if not args.strip():
            print(ERROR_USAGE_EDIT)
            return

        self._edit_password(args.strip())

    def do_delete(self, args: str) -> None:
        """Delete a password.

        Usage: delete <name>
        """
        if not args.strip():
            print(ERROR_USAGE_DELETE)
            return

        self._delete_password(args.strip())

    def do_search(self, args: str) -> None:
        """Search passwords.

        Usage: search <query>
        """
        if not args.strip():
            print(ERROR_USAGE_SEARCH)
            return

        self._search_passwords(args.strip())

    def do_help(self, args: str) -> None:
        """Show help information.

        Usage: help [command]
        """
        if args.strip():
            super().do_help(args)
        else:
            print(generate_console_help())

    def do_quit(self, args: str) -> bool:
        """Quit the console.

        Usage: quit
        """
        print(INFO_GOODBYE)
        return True

    def do_exit(self, args: str) -> bool:
        """Exit the console.

        Usage: exit
        """
        return self.do_quit(args)

    def emptyline(self) -> None:
        """Do nothing on empty input line."""
        pass

    def _list_passwords(self) -> None:
        """List all entries."""
        if not self.vault.entries:
            print(INFO_NO_ENTRIES)
            return

        print(INFO_FOUND_COUNT.format(count=len(self.vault.entries)))
        for i, entry in enumerate(self.vault.entries, 1):
            print(f"{i}. {entry.name} - {entry.username}")

    def _get_password(self, name: str) -> None:
        """Get password details."""
        entry = self.vault.get(name)
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

    def _edit_password(self, name: str) -> None:
        """Edit password interactively."""
        entry = self.vault.get(name)
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
            self.vault.add(entry)
            print(SUCCESS_ADDED.format(name=name))
        except VaultError as e:
            print(f"Error updating password: {e}")

    def _delete_password(self, name: str) -> None:
        """Delete a password."""
        if self.vault.remove(name):
            print(SUCCESS_DELETED.format(name=name))
        else:
            print(ERROR_NOT_FOUND.format(name=name))

    def _search_passwords(self, query: str) -> None:
        """Search passwords."""
        results = self.vault.search(query)
        if results:
            print(INFO_FOUND_MATCHING.format(count=len(results), query=query))
            for entry in results:
                print(f"  {entry.name} - {entry.username}")
        else:
            print(INFO_NO_MATCHES.format(query=query))

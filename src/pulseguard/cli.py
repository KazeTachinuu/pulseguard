"""PulseGuard - Simple password manager.

A minimal, secure password manager with CLI and interactive console.
Features:
- Add, list, get, delete, and search passwords
- JSON file persistence
- Interactive console mode
- Simple command-line interface
"""

import argparse
import cmd
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class PasswordEntry:
    """A password entry with metadata.
    
    Attributes:
        name: Unique identifier for the password entry
        username: Username or email for the account
        password: The password
        url: Optional URL for the service
        notes: Optional notes about the entry
        created_at: Timestamp when the entry was created
    """
    name: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: datetime = None

    def __post_init__(self):
        """Initialize created_at if not provided."""
        if self.created_at is None:
            self.created_at = datetime.now()


class Vault:
    """Simple password vault with JSON persistence.
    
    Manages password entries with automatic file persistence.
    All changes are immediately saved to disk.
    """
    
    def __init__(self, file_path: str = "~/.pulseguard/vault.json"):
        """Initialize vault with file path.
        
        Args:
            file_path: Path to the JSON file for persistence
        """
        self.file_path = os.path.expanduser(file_path)
        self.entries: List[PasswordEntry] = []
        self._load()
    
    def _load(self):
        """Load entries from JSON file."""
        if not os.path.exists(self.file_path):
            return
        
        try:
            with open(self.file_path, 'r') as f:
                data = json.load(f)
                for entry_data in data.get('entries', []):
                    # Handle datetime deserialization
                    if 'created_at' in entry_data and isinstance(entry_data['created_at'], str):
                        entry_data['created_at'] = datetime.fromisoformat(entry_data['created_at'])
                    self.entries.append(PasswordEntry(**entry_data))
        except (json.JSONDecodeError, KeyError, ValueError):
            # If file is corrupted, start fresh
            self.entries = []
    
    def _save(self):
        """Save entries to JSON file."""
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        data = {
            'entries': [
                {
                    'name': entry.name,
                    'username': entry.username,
                    'password': entry.password,
                    'url': entry.url,
                    'notes': entry.notes,
                    'created_at': entry.created_at.isoformat()
                }
                for entry in self.entries
            ]
        }
        with open(self.file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add(self, entry: PasswordEntry):
        """Add or update a password entry.
        
        Args:
            entry: The password entry to add
        """
        self.remove(entry.name)
        self.entries.append(entry)
        self._save()
    
    def remove(self, name: str):
        """Remove a password entry by name.
        
        Args:
            name: Name of the entry to remove
        """
        self.entries = [e for e in self.entries if e.name != name]
        self._save()
    
    def get(self, name: str) -> Optional[PasswordEntry]:
        """Get a password entry by name.
        
        Args:
            name: Name of the entry to retrieve
            
        Returns:
            PasswordEntry if found, None otherwise
        """
        return next((e for e in self.entries if e.name == name), None)
    
    def search(self, query: str) -> List[PasswordEntry]:
        """Search entries by name or username.
        
        Args:
            query: Search query (case-insensitive)
            
        Returns:
            List of matching entries
        """
        query_lower = query.lower()
        return [
            e for e in self.entries
            if query_lower in e.name.lower() or query_lower in e.username.lower()
        ]


class Console(cmd.Cmd):
    """Interactive console for password management.
    
    Provides a command-line interface for managing passwords.
    Type 'help' to see available commands.
    """
    
    intro = "PulseGuard Console. Type 'help' for commands or 'quit' to exit."
    prompt = "pulseguard> "
    
    def __init__(self):
        """Initialize the console with a vault instance."""
        super().__init__()
        self.vault = Vault()
    
    def do_list(self, args):
        """List all passwords.
        
        Usage: list
        """
        if not self.vault.entries:
            print("No passwords found.")
            return
        print(f"Found {len(self.vault.entries)} password(s):")
        for i, entry in enumerate(self.vault.entries, 1):
            print(f"{i}. {entry.name} - {entry.username}")
    
    def do_add(self, args):
        """Add a new password.
        
        Usage: add <name> <username> <password>
        """
        parts = args.split()
        if len(parts) < 3:
            print("Usage: add <name> <username> <password>")
            return
        name, username, password = parts[0], parts[1], parts[2]
        entry = PasswordEntry(name=name, username=username, password=password)
        self.vault.add(entry)
        print(f"Added password '{name}' successfully.")
    
    def do_get(self, args):
        """Get password details.
        
        Usage: get <name>
        """
        if not args.strip():
            print("Usage: get <name>")
            return
        entry = self.vault.get(args.strip())
        if entry:
            print(f"Password: {entry.name}")
            print(f"Username: {entry.username}")
            print(f"Password: {entry.password}")
            if entry.url:
                print(f"URL: {entry.url}")
            if entry.notes:
                print(f"Notes: {entry.notes}")
        else:
            print(f"Password '{args.strip()}' not found.")
    
    def do_delete(self, args):
        """Delete a password.
        
        Usage: delete <name>
        """
        if not args.strip():
            print("Usage: delete <name>")
            return
        name = args.strip()
        if self.vault.get(name):
            self.vault.remove(name)
            print(f"Deleted password '{name}' successfully.")
        else:
            print(f"Password '{name}' not found.")
    
    def do_search(self, args):
        """Search passwords.
        
        Usage: search <query>
        """
        if not args.strip():
            print("Usage: search <query>")
            return
        query = args.strip()
        results = self.vault.search(query)
        if results:
            print(f"Found {len(results)} password(s) matching '{query}':")
            for entry in results:
                print(f"  {entry.name} - {entry.username}")
        else:
            print(f"No passwords found matching '{query}'.")
    
    def do_quit(self, args):
        """Quit the console.
        
        Usage: quit
        """
        print("Goodbye!")
        return True
    
    def do_exit(self, args):
        """Exit the console.
        
        Usage: exit
        """
        return self.do_quit(args)
    
    def emptyline(self):
        """Do nothing on empty input line."""
        pass


def _list_passwords(vault: Vault):
    """List all passwords."""
    if not vault.entries:
        print("No passwords found.")
        return
    print(f"Found {len(vault.entries)} password(s):")
    for i, entry in enumerate(vault.entries, 1):
        print(f"{i}. {entry.name} - {entry.username}")


def _add_password(vault: Vault, name: str, username: str, password: str):
    """Add a password."""
    entry = PasswordEntry(name=name, username=username, password=password)
    vault.add(entry)
    print(f"Added password '{name}' successfully.")


def _get_password(vault: Vault, name: str):
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
        print(f"Password '{name}' not found.")


def _delete_password(vault: Vault, name: str):
    """Delete a password."""
    if vault.get(name):
        vault.remove(name)
        print(f"Deleted password '{name}' successfully.")
    else:
        print(f"Password '{name}' not found.")


def _search_passwords(vault: Vault, query: str):
    """Search passwords."""
    results = vault.search(query)
    if results:
        print(f"Found {len(results)} password(s) matching '{query}':")
        for entry in results:
            print(f"  {entry.name} - {entry.username}")
    else:
        print(f"No passwords found matching '{query}'.")


def main():
    """Main entry point for PulseGuard.
    
    Handles both CLI and interactive console modes.
    """
    parser = argparse.ArgumentParser(
        description="PulseGuard - Simple password manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pulseguard                    # Start interactive console
  pulseguard list               # List all passwords
  pulseguard add Gmail user@example.com password123
  pulseguard get Gmail          # Get password details
  pulseguard search gmail       # Search passwords
  pulseguard delete Gmail       # Delete password

For more information, visit: https://github.com/yourusername/pulseguard
        """
    )
    parser.add_argument("command", nargs="?", help="Command to run")
    parser.add_argument("args", nargs="*", help="Command arguments")

    try:
        args = parser.parse_args()

        if not args.command:
            # Start interactive console
            Console().cmdloop()
            return
        
        # CLI mode
        vault = Vault()
        
        if args.command == "list":
            _list_passwords(vault)
        elif args.command == "add":
            if len(args.args) < 3:
                print("Usage: pulseguard add <name> <username> <password>")
                sys.exit(1)
            _add_password(vault, args.args[0], args.args[1], args.args[2])
        elif args.command == "get":
            if not args.args:
                print("Usage: pulseguard get <name>")
                sys.exit(1)
            _get_password(vault, args.args[0])
        elif args.command == "delete":
            if not args.args:
                print("Usage: pulseguard delete <name>")
                sys.exit(1)
            _delete_password(vault, args.args[0])
        elif args.command == "search":
            if not args.args:
                print("Usage: pulseguard search <query>")
                sys.exit(1)
            _search_passwords(vault, args.args[0])
        else:
            print(f"Unknown command: {args.command}")
            print("Run 'pulseguard --help' for usage information.")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
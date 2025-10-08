"""Authentication utilities for secure master password handling."""

import getpass
import sys


def get_master_password(
    prompt: str = "Enter master password: ", confirm: bool = False
) -> str:
    """Securely prompt for master password without echo."""
    try:
        password = getpass.getpass(prompt)

        if confirm:
            password_confirm = getpass.getpass("Confirm master password: ")
            if password != password_confirm:
                raise ValueError("Passwords do not match")

        return password

    except (KeyboardInterrupt, EOFError):
        print("\nPassword prompt cancelled", file=sys.stderr)
        raise


def prompt_create_master_password() -> str:
    """Prompt user to create a new master password with confirmation."""
    print("\n═══════════════════════════════════════")
    print("  Creating New Encrypted Vault")
    print("═══════════════════════════════════════")
    print("\nChoose a strong master password.")
    print("IMPORTANT: If lost, your vault cannot be recovered.\n")
    return get_master_password(prompt="Create master password: ", confirm=True)


def prompt_unlock_vault() -> str:
    """Prompt user to unlock existing vault with master password."""
    return get_master_password(prompt="Enter master password to unlock vault: ")



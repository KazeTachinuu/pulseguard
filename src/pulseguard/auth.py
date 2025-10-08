"""Authentication utilities for secure master password handling."""

import getpass
import os
import sys
from typing import Optional


def get_master_password(
    prompt: str = "Enter master password: ", confirm: bool = False
) -> str:
    """Securely prompt for master password without echo."""
    env_password = os.getenv("PULSEGUARD_MASTER_PASSWORD")
    if env_password is not None:
        return env_password

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
    print("\nCreating encrypted vault - you will need a master password.")
    print(
        "IMPORTANT: Choose a strong password you will remember. "
        "If lost, vault cannot be recovered."
    )
    print()
    return get_master_password(prompt="Create master password: ", confirm=True)


def prompt_unlock_vault() -> str:
    """Prompt user to unlock existing vault with master password."""
    return get_master_password(prompt="Enter master password to unlock vault: ")


def should_encrypt_vault() -> bool:
    """Ask user if they want to encrypt the vault."""
    print("\nDo you want to encrypt this vault with a master password?")
    print("  [Y]es - Recommended. Passwords will be encrypted at rest.")
    print("  [N]o  - Passwords will be stored in PLAINTEXT (INSECURE).")
    print()

    while True:
        try:
            choice = input("Encrypt vault? [Y/n]: ").strip().lower()

            if not choice or choice in ["y", "yes"]:
                return True
            elif choice in ["n", "no"]:
                print(
                    "\nWARNING: Vault will NOT be encrypted. "
                    "Passwords stored in plaintext!"
                )
                return False
            else:
                print("Please enter 'y' or 'n'")

        except (KeyboardInterrupt, EOFError):
            print("\nDefaulting to encrypted vault (secure option)")
            return True


def get_master_password_with_retry(
    max_attempts: int = 3, for_unlock: bool = True
) -> Optional[str]:
    """Get master password with retry logic for incorrect passwords."""
    attempts = 0

    while attempts < max_attempts:
        try:
            if for_unlock:
                password = prompt_unlock_vault()
            else:
                password = prompt_create_master_password()

            return password

        except ValueError as e:
            attempts += 1
            remaining = max_attempts - attempts
            print(f"\nError: {e}", file=sys.stderr)

            if remaining > 0:
                print(
                    f"Please try again ({remaining} attempts remaining)\n",
                    file=sys.stderr,
                )
            else:
                print("Maximum attempts exceeded", file=sys.stderr)
                return None

        except (KeyboardInterrupt, EOFError):
            return None

    return None

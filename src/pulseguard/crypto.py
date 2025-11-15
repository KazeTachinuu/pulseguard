"""Cryptographic operations for secure vault encryption."""

import base64
import secrets
from typing import Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken

# Import HashingError at module level with fallback
try:
    from argon2.exceptions import HashingError
except ImportError:
    HashingError = type('HashingError', (Exception,), {})

# Argon2id parameters (OWASP recommendations for password storage)
ARGON2_TIME_COST = 2  # Number of iterations
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_PARALLELISM = 4  # Number of parallel threads
ARGON2_HASH_LENGTH = 32  # 32 bytes for Fernet key
ARGON2_SALT_LENGTH = 16  # 16 bytes salt

SALT_LENGTH = ARGON2_SALT_LENGTH
KEY_LENGTH = ARGON2_HASH_LENGTH


class CryptoError(Exception):
    """Base exception for cryptographic operations."""

    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails (wrong password or corrupted data)."""

    pass


class EncryptionError(CryptoError):
    """Raised when encryption fails."""

    pass


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(SALT_LENGTH)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive encryption key from master password using Argon2id."""
    try:
        from argon2.low_level import Type, hash_secret_raw

        password_bytes = master_password.encode("utf-8")

        # Use Argon2id for key derivation
        key = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LENGTH,
            type=Type.ID,  # Argon2id variant
        )

        return key
    except (ValueError, TypeError, ImportError, HashingError) as e:
        raise CryptoError(f"Key derivation failed: {e}") from e


def create_fernet(key: bytes) -> Fernet:
    """Create Fernet cipher from derived key."""
    try:
        fernet_key = base64.urlsafe_b64encode(key)
        return Fernet(fernet_key)
    except (ValueError, TypeError) as e:
        raise CryptoError(f"Fernet creation failed: {e}") from e


def encrypt_data(
    data: bytes, master_password: str, salt: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Encrypt data with master password."""
    try:
        if salt is None:
            salt = generate_salt()

        key = derive_key(master_password, salt)
        cipher = create_fernet(key)
        ciphertext = cipher.encrypt(data)

        return ciphertext, salt
    except CryptoError:
        raise
    except (ValueError, TypeError) as e:
        raise EncryptionError(f"Encryption failed: {e}") from e


def decrypt_data(ciphertext: bytes, master_password: str, salt: bytes) -> bytes:
    """Decrypt data with master password."""
    try:
        key = derive_key(master_password, salt)
        cipher = create_fernet(key)
        plaintext = cipher.decrypt(ciphertext)

        return plaintext
    except InvalidToken:
        raise DecryptionError(
            "Decryption failed - incorrect master password or corrupted vault"
        )
    except CryptoError:
        raise
    except (ValueError, TypeError) as e:
        raise DecryptionError(f"Decryption failed: {e}") from e

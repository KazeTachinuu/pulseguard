"""Cryptographic operations for secure vault encryption."""

import base64
import hashlib
import secrets
from typing import Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 32
KEY_LENGTH = 32


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
    """Derive encryption key from master password using PBKDF2-HMAC-SHA256."""
    try:
        password_bytes = master_password.encode('utf-8')

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )

        key = kdf.derive(password_bytes)
        return key
    except Exception as e:
        raise CryptoError(f"Key derivation failed: {e}") from e


def create_fernet(key: bytes) -> Fernet:
    """Create Fernet cipher from derived key."""
    try:
        fernet_key = base64.urlsafe_b64encode(key)
        return Fernet(fernet_key)
    except Exception as e:
        raise CryptoError(f"Fernet creation failed: {e}") from e


def encrypt_data(
    data: bytes, master_password: str, salt: bytes = None
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
    except Exception as e:
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
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e


def verify_password(master_password: str, salt: bytes, ciphertext: bytes) -> bool:
    """Verify master password without decrypting entire vault."""
    try:
        decrypt_data(ciphertext, master_password, salt)
        return True
    except DecryptionError:
        return False


def hash_for_storage(data: str) -> str:
    """Create SHA-256 hash for integrity checking (not encryption)."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

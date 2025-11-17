"""
Unit tests for cryptographic operations.

This module tests the core cryptographic primitives used in PulseGuard:
- Salt generation for key derivation
- Argon2id key derivation from passwords
- AES-128 (Fernet) encryption and decryption
- Security properties (timing safety, authentication, etc.)
"""

import pytest

from pulseguard.crypto import (
    DecryptionError,
    decrypt_data,
    derive_key,
    encrypt_data,
    generate_salt,
)


class TestSaltGeneration:
    """Test cryptographic salt generation for key derivation."""

    def test_generates_correct_length(self):
        """Salt must be exactly 16 bytes for Argon2 compatibility."""
        salt = generate_salt()
        assert len(salt) == 16

    def test_returns_bytes_type(self):
        """Salt must be bytes, not string or other type."""
        salt = generate_salt()
        assert isinstance(salt, bytes)

    def test_generates_unique_salts(self):
        """Each salt generation must produce unique random values."""
        salts = [generate_salt() for _ in range(100)]
        unique_salts = set(salts)
        assert len(unique_salts) == 100, "All 100 salts should be unique"

    def test_has_sufficient_entropy(self):
        """Salt should have high entropy, not be all zeros or repeating."""
        salt = generate_salt()
        assert salt != b"\x00" * 16, "Salt should not be all zeros"

        unique_bytes = len(set(salt))
        assert (
            unique_bytes >= 12
        ), f"Salt should have varied bytes, got {unique_bytes}/16"


class TestKeyDerivation:
    """Test Argon2id key derivation from passwords and salts."""

    def test_derives_correct_key_length(self, salt):
        """Derived key must be 32 bytes for AES-256."""
        key = derive_key("password", salt)
        assert len(key) == 32

    def test_is_deterministic(self, salt):
        """Same password + salt must always produce same key."""
        key1 = derive_key("password", salt)
        key2 = derive_key("password", salt)
        assert key1 == key2, "Key derivation must be deterministic"

    def test_different_passwords_produce_different_keys(self, salt):
        """Different passwords must produce different keys."""
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2, "Different passwords must yield different keys"

    def test_different_salts_produce_different_keys(self):
        """Same password with different salts must produce different keys."""
        password = "password"
        salt1 = generate_salt()
        salt2 = generate_salt()

        key1 = derive_key(password, salt1)
        key2 = derive_key(password, salt2)
        assert key1 != key2, "Different salts must yield different keys"

    def test_handles_empty_password(self, salt):
        """Empty password should still derive a valid key."""
        key = derive_key("", salt)
        assert len(key) == 32

    def test_handles_unicode_password(self, salt):
        """Unicode passwords (emoji, Chinese, etc.) should work."""
        password = "пароль密码🔒"
        key = derive_key(password, salt)
        assert len(key) == 32

    def test_handles_very_long_password(self, salt):
        """Very long passwords should be handled correctly."""
        password = "a" * 1000
        key = derive_key(password, salt)
        assert len(key) == 32


class TestEncryption:
    """Test data encryption with password-based key derivation."""

    def test_encryption_decryption_roundtrip(self):
        """Encrypted data should decrypt back to original."""
        data = b"Hello, World! This is secret data."
        password = "secure_password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data, "Decrypted data must match original"

    def test_produces_unique_ciphertext_each_time(self):
        """Same data+password should produce different ciphertext (random IV)."""
        data = b"Same data"
        password = "same_password"

        ciphertext1, salt1 = encrypt_data(data, password)
        ciphertext2, salt2 = encrypt_data(data, password)

        assert ciphertext1 != ciphertext2, "Ciphertext should differ due to random IV"
        assert salt1 != salt2, "Each encryption should use unique salt"

    def test_reuses_provided_salt(self, salt):
        """When salt is provided, it should be reused."""
        data = b"Test data"
        password = "password"

        ciphertext, returned_salt = encrypt_data(data, password, salt=salt)

        assert returned_salt == salt, "Provided salt should be returned"
        plaintext = decrypt_data(ciphertext, password, salt)
        assert plaintext == data

    def test_encrypts_empty_data(self):
        """Empty data should encrypt and decrypt correctly."""
        data = b""
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data

    def test_encrypts_large_data(self):
        """Large data (1MB) should encrypt and decrypt correctly."""
        data = b"X" * 1_000_000
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data

    def test_ciphertext_does_not_contain_plaintext(self):
        """Ciphertext should not contain any plaintext fragments."""
        data = b"SECRET_PASSWORD_123"
        password = "encryption_key"

        ciphertext, salt = encrypt_data(data, password)

        assert data not in ciphertext, "Plaintext should not appear in ciphertext"
        assert b"SECRET" not in ciphertext, "No plaintext fragments in ciphertext"


class TestDecryption:
    """Test decryption error handling and security."""

    def test_wrong_password_raises_error(self):
        """Decryption with wrong password should fail clearly."""
        data = b"Secret data"
        correct_password = "correct"
        wrong_password = "wrong"

        ciphertext, salt = encrypt_data(data, correct_password)

        with pytest.raises(DecryptionError) as exc:
            decrypt_data(ciphertext, wrong_password, salt)

        assert "incorrect master password" in str(exc.value).lower()

    def test_corrupted_ciphertext_raises_error(self):
        """Tampered ciphertext should be detected and rejected."""
        data = b"Secret data"
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        corrupted = ciphertext[:-10] + b"corrupted!"

        with pytest.raises(DecryptionError):
            decrypt_data(corrupted, password, salt)

    def test_wrong_salt_raises_error(self):
        """Decryption with wrong salt should fail."""
        data = b"Secret data"
        password = "password"

        ciphertext, correct_salt = encrypt_data(data, password)
        wrong_salt = generate_salt()

        with pytest.raises(DecryptionError):
            decrypt_data(ciphertext, password, wrong_salt)

    def test_truncated_ciphertext_raises_error(self):
        """Truncated ciphertext should be detected as invalid."""
        data = b"Secret data"
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        truncated = ciphertext[:10]

        with pytest.raises(DecryptionError):
            decrypt_data(truncated, password, salt)


class TestSecurityProperties:
    """Test cryptographic security guarantees."""

    def test_constant_time_password_verification(self):
        """Wrong passwords should take similar time to reject (timing attack resistance)."""
        data = b"Secret data"
        password = "correct_password"
        ciphertext, salt = encrypt_data(data, password)

        import time

        # Measure time for two different wrong passwords
        start1 = time.time()
        try:
            decrypt_data(ciphertext, "wrong", salt)
        except DecryptionError:
            pass
        time1 = time.time() - start1

        start2 = time.time()
        try:
            decrypt_data(ciphertext, "also_wrong", salt)
        except DecryptionError:
            pass
        time2 = time.time() - start2

        # Times should be similar (not 100x different)
        ratio = max(time1, time2) / max(min(time1, time2), 0.0001)
        assert ratio < 100, f"Timing ratio too high: {ratio:.1f}x"

    def test_salt_prevents_rainbow_table_attacks(self):
        """Same password with different salts produces different keys (defeats rainbow tables)."""
        password = "common_password"
        keys = []

        for _ in range(10):
            salt = generate_salt()
            key = derive_key(password, salt)
            keys.append(key)

        unique_keys = set(keys)
        assert len(unique_keys) == 10, "All keys should be unique despite same password"

    def test_authenticated_encryption_detects_tampering(self):
        """Fernet provides authenticated encryption - tampering should be detected."""
        data = b"Original data"
        password = "password"

        ciphertext, salt = encrypt_data(data, password)

        # Tamper with ciphertext (flip a bit)
        tampered = bytearray(ciphertext)
        tampered[len(tampered) // 2] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(DecryptionError):
            decrypt_data(tampered, password, salt)

    def test_no_key_reuse_across_encryptions(self):
        """Each encryption should use fresh random IV (no key stream reuse)."""
        data = b"Same data"
        password = "same_password"
        salt = generate_salt()  # Same salt

        ciphertext1, _ = encrypt_data(data, password, salt=salt)
        ciphertext2, _ = encrypt_data(data, password, salt=salt)

        assert ciphertext1 != ciphertext2, "Should use fresh IV each time"


class TestEdgeCases:
    """Test edge cases and unusual inputs."""

    def test_binary_data_roundtrip(self):
        """All byte values (0-255) should encrypt/decrypt correctly."""
        data = bytes(range(256))
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data

    def test_null_bytes_in_data(self):
        """Data containing null bytes should be handled correctly."""
        data = b"Hello\x00World\x00\x00Data"
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data

    def test_special_characters_in_password(self):
        """Passwords with special characters should work."""
        data = b"Test data"
        password = "p@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data

    def test_whitespace_matters_in_password(self):
        """Passwords with different whitespace are different."""
        salt = generate_salt()

        keys = [
            derive_key("password", salt),
            derive_key("pass word", salt),
            derive_key(" password", salt),
            derive_key("password ", salt),
        ]

        assert len(set(keys)) == 4, "All passwords should produce different keys"

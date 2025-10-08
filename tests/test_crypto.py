"""Comprehensive tests for cryptographic operations.

Why these tests:
- Verify encryption/decryption roundtrip works correctly
- Test key derivation produces consistent results
- Validate error handling for wrong passwords
- Check salt generation produces unique values
- Ensure encrypted data is not human-readable
- Test boundary conditions and edge cases
- Verify security properties (deterministic key derivation, etc.)

Security testing focus:
- Wrong password detection
- Data corruption detection
- Salt uniqueness
- Key derivation consistency
- No plaintext leakage
"""

import base64
import os
import secrets

import pytest

from pulseguard.crypto import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    create_fernet,
    decrypt_data,
    derive_key,
    encrypt_data,
    generate_salt,
    hash_for_storage,
    verify_password,
)


class TestSaltGeneration:
    """Tests for cryptographically secure salt generation."""

    def test_salt_generation_length(self):
        """Verify salt is 16 bytes (128 bits) as specified for Argon2."""
        salt = generate_salt()
        assert len(salt) == 16, "Salt must be 16 bytes for Argon2"

    def test_salt_generation_type(self):
        """Verify salt is returned as bytes."""
        salt = generate_salt()
        assert isinstance(salt, bytes), "Salt must be bytes type"

    def test_salt_uniqueness(self):
        """Verify each salt generation produces unique values (high probability)."""
        # Generate multiple salts and ensure they're all different
        salts = [generate_salt() for _ in range(100)]
        unique_salts = set(salts)

        # All salts should be unique (probability of collision is negligible)
        assert len(unique_salts) == 100, "Salts must be unique (cryptographic RNG)"

    def test_salt_entropy(self):
        """Verify salt has high entropy (not all zeros or predictable pattern)."""
        salt = generate_salt()

        # Salt should not be all zeros
        assert salt != b"\x00" * 16, "Salt must not be all zeros"

        # Salt should have good distribution of bytes
        # At least 12 unique byte values in 16 bytes (reasonable entropy check)
        unique_bytes = len(set(salt))
        assert unique_bytes >= 12, "Salt must have high entropy"


class TestKeyDerivation:
    """Tests for Argon2id-based key derivation from passwords."""

    def test_key_derivation_length(self):
        """Verify derived key is 32 bytes (256 bits) as specified."""
        password = "test_password"
        salt = generate_salt()
        key = derive_key(password, salt)

        assert len(key) == 32, "Derived key must be 32 bytes"

    def test_key_derivation_deterministic(self):
        """Verify same password + salt always produces same key (deterministic)."""
        password = "test_password"
        salt = generate_salt()

        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)

        assert key1 == key2, "Key derivation must be deterministic"

    def test_key_derivation_different_passwords(self):
        """Verify different passwords produce different keys."""
        salt = generate_salt()

        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)

        assert key1 != key2, "Different passwords must produce different keys"

    def test_key_derivation_different_salts(self):
        """Verify different salts produce different keys (same password)."""
        password = "test_password"

        salt1 = generate_salt()
        salt2 = generate_salt()

        key1 = derive_key(password, salt1)
        key2 = derive_key(password, salt2)

        assert key1 != key2, "Different salts must produce different keys"

    def test_key_derivation_empty_password(self):
        """Verify empty password is handled correctly (allowed but not recommended)."""
        password = ""
        salt = generate_salt()

        # Empty password should work (though not secure)
        key = derive_key(password, salt)
        assert len(key) == 32, "Empty password should still produce valid key"

    def test_key_derivation_unicode_password(self):
        """Verify Unicode passwords are handled correctly."""
        password = "пароль密码🔒"  # Russian, Chinese, emoji
        salt = generate_salt()

        # Unicode password should work via UTF-8 encoding
        key = derive_key(password, salt)
        assert len(key) == 32, "Unicode password should produce valid key"

    def test_key_derivation_long_password(self):
        """Verify very long passwords are handled correctly."""
        password = "a" * 1000  # 1000 character password
        salt = generate_salt()

        key = derive_key(password, salt)
        assert len(key) == 32, "Long password should produce valid key"


class TestEncryption:
    """Tests for data encryption with Fernet."""

    def test_encrypt_roundtrip(self):
        """Verify encryption/decryption roundtrip preserves data."""
        data = b"Hello, World! This is secret data."
        password = "my_secure_password"

        # Encrypt
        ciphertext, salt = encrypt_data(data, password)

        # Decrypt
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data, "Roundtrip must preserve original data"

    def test_encrypt_produces_different_ciphertext(self):
        """Verify same data + password produces different ciphertext (due to random IV)."""
        data = b"Same data"
        password = "same_password"

        # Encrypt twice with same password (will generate different salts)
        ciphertext1, salt1 = encrypt_data(data, password)
        ciphertext2, salt2 = encrypt_data(data, password)

        # Ciphertexts should differ (different salts and IVs)
        assert ciphertext1 != ciphertext2, "Ciphertext must be different (random IV)"
        assert salt1 != salt2, "Salts must be different"

    def test_encrypt_with_provided_salt(self):
        """Verify encryption works with provided salt (for re-encryption)."""
        data = b"Test data"
        password = "password"
        salt = generate_salt()

        # Encrypt with provided salt
        ciphertext, returned_salt = encrypt_data(data, password, salt=salt)

        assert returned_salt == salt, "Provided salt should be returned"

        # Decrypt with original salt
        plaintext = decrypt_data(ciphertext, password, salt)
        assert plaintext == data, "Decryption with provided salt must work"

    def test_encrypt_empty_data(self):
        """Verify empty data can be encrypted."""
        data = b""
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data, "Empty data roundtrip must work"

    def test_encrypt_large_data(self):
        """Verify large data can be encrypted."""
        data = b"X" * 1_000_000  # 1 MB
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data, "Large data roundtrip must work"

    def test_encrypted_data_not_plaintext(self):
        """Verify encrypted data doesn't contain plaintext."""
        data = b"SECRET_PASSWORD_123"
        password = "encryption_key"

        ciphertext, salt = encrypt_data(data, password)

        # Ciphertext should not contain plaintext
        assert data not in ciphertext, "Ciphertext must not contain plaintext"
        assert b"SECRET" not in ciphertext, "Ciphertext must not contain parts of plaintext"


class TestDecryption:
    """Tests for data decryption and error handling."""

    def test_decrypt_wrong_password(self):
        """Verify wrong password raises DecryptionError."""
        data = b"Secret data"
        password = "correct_password"

        ciphertext, salt = encrypt_data(data, password)

        # Try to decrypt with wrong password
        with pytest.raises(DecryptionError) as exc_info:
            decrypt_data(ciphertext, "wrong_password", salt)

        assert "incorrect master password" in str(exc_info.value).lower()

    def test_decrypt_corrupted_ciphertext(self):
        """Verify corrupted ciphertext raises DecryptionError."""
        data = b"Secret data"
        password = "password"

        ciphertext, salt = encrypt_data(data, password)

        # Corrupt the ciphertext
        corrupted = ciphertext[:-10] + b"corrupted!"

        # Try to decrypt corrupted data
        with pytest.raises(DecryptionError):
            decrypt_data(corrupted, password, salt)

    def test_decrypt_wrong_salt(self):
        """Verify wrong salt raises DecryptionError."""
        data = b"Secret data"
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        wrong_salt = generate_salt()  # Different salt

        # Try to decrypt with wrong salt
        with pytest.raises(DecryptionError):
            decrypt_data(ciphertext, password, wrong_salt)

    def test_decrypt_truncated_ciphertext(self):
        """Verify truncated ciphertext raises DecryptionError."""
        data = b"Secret data"
        password = "password"

        ciphertext, salt = encrypt_data(data, password)

        # Truncate ciphertext
        truncated = ciphertext[:10]

        # Try to decrypt truncated data
        with pytest.raises(DecryptionError):
            decrypt_data(truncated, password, salt)


class TestPasswordVerification:
    """Tests for password verification utility."""

    def test_verify_correct_password(self):
        """Verify correct password returns True."""
        data = b"Test data"
        password = "correct_password"

        ciphertext, salt = encrypt_data(data, password)

        assert verify_password(password, salt, ciphertext) is True

    def test_verify_wrong_password(self):
        """Verify wrong password returns False."""
        data = b"Test data"
        password = "correct_password"

        ciphertext, salt = encrypt_data(data, password)

        assert verify_password("wrong_password", salt, ciphertext) is False


class TestHashForStorage:
    """Tests for SHA-256 hashing utility."""

    def test_hash_consistency(self):
        """Verify same input produces same hash."""
        data = "test data"

        hash1 = hash_for_storage(data)
        hash2 = hash_for_storage(data)

        assert hash1 == hash2, "Hash must be consistent"

    def test_hash_different_inputs(self):
        """Verify different inputs produce different hashes."""
        hash1 = hash_for_storage("data1")
        hash2 = hash_for_storage("data2")

        assert hash1 != hash2, "Different inputs must produce different hashes"

    def test_hash_format(self):
        """Verify hash is hex-encoded string."""
        data = "test"
        hash_value = hash_for_storage(data)

        # SHA-256 produces 64 hex characters
        assert len(hash_value) == 64, "SHA-256 hash must be 64 hex characters"
        assert all(c in "0123456789abcdef" for c in hash_value), "Hash must be hex"


class TestSecurityProperties:
    """Tests for security properties and attack resistance."""

    def test_timing_attack_resistance(self):
        """Verify wrong password check doesn't leak timing information (basic check)."""
        # This is a basic test - true timing attack resistance needs more sophisticated testing
        data = b"Secret data"
        password = "correct_password"
        ciphertext, salt = encrypt_data(data, password)

        # Both wrong password attempts should take similar time (both fail MAC check)
        import time

        # Attempt 1: Completely wrong password
        start1 = time.time()
        try:
            decrypt_data(ciphertext, "wrong", salt)
        except DecryptionError:
            pass
        time1 = time.time() - start1

        # Attempt 2: Different wrong password
        start2 = time.time()
        try:
            decrypt_data(ciphertext, "also_wrong", salt)
        except DecryptionError:
            pass
        time2 = time.time() - start2

        # Times should be relatively similar (within 100x factor)
        # This is a weak check but catches obvious timing leaks
        ratio = max(time1, time2) / max(min(time1, time2), 0.0001)
        assert ratio < 100, "Timing should not leak information about password incorrectness"

    def test_salt_prevents_rainbow_tables(self):
        """Verify salt prevents rainbow table attacks (same password, different keys)."""
        password = "common_password"

        # Same password with different salts should produce different keys
        keys = []
        for _ in range(10):
            salt = generate_salt()
            key = derive_key(password, salt)
            keys.append(key)

        # All keys should be unique
        unique_keys = set(keys)
        assert len(unique_keys) == 10, "Salt must produce unique keys for same password"

    def test_fernet_provides_authentication(self):
        """Verify Fernet provides authentication (tamper detection)."""
        data = b"Original data"
        password = "password"

        ciphertext, salt = encrypt_data(data, password)

        # Modify one byte of ciphertext
        tampered = bytearray(ciphertext)
        tampered[len(tampered) // 2] ^= 0xFF  # Flip bits in middle
        tampered = bytes(tampered)

        # Decryption should fail (MAC verification)
        with pytest.raises(DecryptionError):
            decrypt_data(tampered, password, salt)

    def test_no_key_reuse_across_encryptions(self):
        """Verify each encryption uses different IV (even with same key)."""
        data = b"Same data"
        password = "same_password"
        salt = generate_salt()  # Use same salt

        # Encrypt twice with same password and salt
        ciphertext1, _ = encrypt_data(data, password, salt=salt)
        ciphertext2, _ = encrypt_data(data, password, salt=salt)

        # Ciphertexts should be different (different IV each time)
        assert ciphertext1 != ciphertext2, "Fernet must use different IV each time"


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_binary_data_roundtrip(self):
        """Verify binary data (all byte values) can be encrypted."""
        # Data with all possible byte values
        data = bytes(range(256))
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data, "Binary data roundtrip must work"

    def test_null_bytes_in_data(self):
        """Verify null bytes in data are handled correctly."""
        data = b"Hello\x00World\x00\x00Data"
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data, "Null bytes must be preserved"

    def test_special_characters_in_password(self):
        """Verify special characters in password work correctly."""
        data = b"Test data"
        password = "p@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)

        assert plaintext == data, "Special characters in password must work"

    def test_whitespace_in_password(self):
        """Verify whitespace in password is significant."""
        data = b"Test data"

        password1 = "password"
        password2 = "pass word"
        password3 = " password"
        password4 = "password "

        salt = generate_salt()

        # All should produce different keys
        key1 = derive_key(password1, salt)
        key2 = derive_key(password2, salt)
        key3 = derive_key(password3, salt)
        key4 = derive_key(password4, salt)

        assert len({key1, key2, key3, key4}) == 4, "Whitespace must be significant"


if __name__ == "__main__":
    # Run with: python -m pytest tests/test_crypto.py -v
    pytest.main([__file__, "-v"])

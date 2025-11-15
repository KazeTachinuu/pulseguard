"""Tests for cryptographic operations."""

import pytest

from pulseguard.crypto import (
    DecryptionError,
    decrypt_data,
    derive_key,
    encrypt_data,
    generate_salt,
)


class TestSaltGeneration:
    def test_salt_generation_length(self):
        salt = generate_salt()
        assert len(salt) == 16, "Salt must be 16 bytes for Argon2"

    def test_salt_generation_type(self):
        salt = generate_salt()
        assert isinstance(salt, bytes), "Salt must be bytes type"

    def test_salt_uniqueness(self):
        salts = [generate_salt() for _ in range(100)]
        unique_salts = set(salts)
        assert len(unique_salts) == 100

    def test_salt_entropy(self):
        salt = generate_salt()
        assert salt != b"\x00" * 16
        unique_bytes = len(set(salt))
        assert unique_bytes >= 12


class TestKeyDerivation:
    def test_key_derivation_length(self):
        password = "test_password"
        salt = generate_salt()
        key = derive_key(password, salt)
        assert len(key) == 32

    def test_key_derivation_deterministic(self):
        password = "test_password"
        salt = generate_salt()
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        assert key1 == key2

    def test_key_derivation_different_passwords(self):
        salt = generate_salt()
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2

    def test_key_derivation_different_salts(self):
        password = "test_password"
        salt1 = generate_salt()
        salt2 = generate_salt()
        key1 = derive_key(password, salt1)
        key2 = derive_key(password, salt2)
        assert key1 != key2

    def test_key_derivation_empty_password(self):
        password = ""
        salt = generate_salt()
        key = derive_key(password, salt)
        assert len(key) == 32

    def test_key_derivation_unicode_password(self):
        password = "пароль密码🔒"
        salt = generate_salt()
        key = derive_key(password, salt)
        assert len(key) == 32

    def test_key_derivation_long_password(self):
        password = "a" * 1000
        salt = generate_salt()
        key = derive_key(password, salt)
        assert len(key) == 32


class TestEncryption:
    def test_encrypt_roundtrip(self):
        data = b"Hello, World! This is secret data."
        password = "my_secure_password"
        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)
        assert plaintext == data

    def test_encrypt_produces_different_ciphertext(self):
        data = b"Same data"
        password = "same_password"
        ciphertext1, salt1 = encrypt_data(data, password)
        ciphertext2, salt2 = encrypt_data(data, password)
        assert ciphertext1 != ciphertext2
        assert salt1 != salt2

    def test_encrypt_with_provided_salt(self):
        data = b"Test data"
        password = "password"
        salt = generate_salt()
        ciphertext, returned_salt = encrypt_data(data, password, salt=salt)
        assert returned_salt == salt
        plaintext = decrypt_data(ciphertext, password, salt)
        assert plaintext == data

    def test_encrypt_empty_data(self):
        data = b""
        password = "password"
        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)
        assert plaintext == data

    def test_encrypt_large_data(self):
        data = b"X" * 1_000_000
        password = "password"
        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)
        assert plaintext == data

    def test_encrypted_data_not_plaintext(self):
        data = b"SECRET_PASSWORD_123"
        password = "encryption_key"
        ciphertext, salt = encrypt_data(data, password)
        assert data not in ciphertext
        assert b"SECRET" not in ciphertext


class TestDecryption:
    def test_decrypt_wrong_password(self):
        data = b"Secret data"
        password = "correct_password"
        ciphertext, salt = encrypt_data(data, password)
        with pytest.raises(DecryptionError) as exc_info:
            decrypt_data(ciphertext, "wrong_password", salt)
        assert "incorrect master password" in str(exc_info.value).lower()

    def test_decrypt_corrupted_ciphertext(self):
        data = b"Secret data"
        password = "password"
        ciphertext, salt = encrypt_data(data, password)
        corrupted = ciphertext[:-10] + b"corrupted!"
        with pytest.raises(DecryptionError):
            decrypt_data(corrupted, password, salt)

    def test_decrypt_wrong_salt(self):
        data = b"Secret data"
        password = "password"
        ciphertext, salt = encrypt_data(data, password)
        wrong_salt = generate_salt()
        with pytest.raises(DecryptionError):
            decrypt_data(ciphertext, password, wrong_salt)

    def test_decrypt_truncated_ciphertext(self):
        data = b"Secret data"
        password = "password"
        ciphertext, salt = encrypt_data(data, password)
        truncated = ciphertext[:10]
        with pytest.raises(DecryptionError):
            decrypt_data(truncated, password, salt)


class TestSecurityProperties:
    def test_timing_attack_resistance(self):
        data = b"Secret data"
        password = "correct_password"
        ciphertext, salt = encrypt_data(data, password)
        import time

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

        ratio = max(time1, time2) / max(min(time1, time2), 0.0001)
        assert ratio < 100

    def test_salt_prevents_rainbow_tables(self):
        password = "common_password"
        keys = []
        for _ in range(10):
            salt = generate_salt()
            key = derive_key(password, salt)
            keys.append(key)
        unique_keys = set(keys)
        assert len(unique_keys) == 10

    def test_fernet_provides_authentication(self):
        data = b"Original data"
        password = "password"
        ciphertext, salt = encrypt_data(data, password)
        tampered = bytearray(ciphertext)
        tampered[len(tampered) // 2] ^= 0xFF
        tampered = bytes(tampered)
        with pytest.raises(DecryptionError):
            decrypt_data(tampered, password, salt)

    def test_no_key_reuse_across_encryptions(self):
        data = b"Same data"
        password = "same_password"
        salt = generate_salt()
        ciphertext1, _ = encrypt_data(data, password, salt=salt)
        ciphertext2, _ = encrypt_data(data, password, salt=salt)
        assert ciphertext1 != ciphertext2


class TestEdgeCases:
    def test_binary_data_roundtrip(self):
        data = bytes(range(256))
        password = "password"

        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)
        assert plaintext == data

    def test_null_bytes_in_data(self):
        data = b"Hello\x00World\x00\x00Data"
        password = "password"
        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)
        assert plaintext == data

    def test_special_characters_in_password(self):
        data = b"Test data"
        password = "p@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?"
        ciphertext, salt = encrypt_data(data, password)
        plaintext = decrypt_data(ciphertext, password, salt)
        assert plaintext == data

    def test_whitespace_in_password(self):
        password1 = "password"
        password2 = "pass word"
        password3 = " password"
        password4 = "password "
        salt = generate_salt()
        key1 = derive_key(password1, salt)
        key2 = derive_key(password2, salt)
        key3 = derive_key(password3, salt)
        key4 = derive_key(password4, salt)
        assert len({key1, key2, key3, key4}) == 4

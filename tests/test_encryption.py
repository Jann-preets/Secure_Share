
import os

import pytest

from services.encryption import (
    decrypt_file,
    encrypt_file,
)


def test_encrypt_decrypt_round_trip():
    key = os.urandom(32)
    original = b"SecureShare encryption test"

    result = encrypt_file(original, key)

    assert result["ciphertext"] != original
    assert decrypt_file(
        result["ciphertext"],
        result["nonce"],
        key,
    ) == original


def test_wrong_key_is_rejected():
    original = b"Private file content"
    encrypted = encrypt_file(original, os.urandom(32))

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_file(
            encrypted["ciphertext"],
            encrypted["nonce"],
            os.urandom(32),
        )


def test_tampered_ciphertext_is_rejected():
    key = os.urandom(32)
    encrypted = encrypt_file(b"Integrity test", key)

    tampered = bytearray(encrypted["ciphertext"])
    tampered[0] ^= 1

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_file(
            bytes(tampered),
            encrypted["nonce"],
            key,
        )

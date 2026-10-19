
import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_master_key(encoded_key: str) -> bytes:
    """Decode and validate a 32-byte AES-256 key."""
    try:
        key = base64.urlsafe_b64decode(encoded_key.strip())
    except Exception as exc:
        raise ValueError("MASTER_KEY must be valid URL-safe Base64.") from exc

    if len(key) != 32:
        raise ValueError("MASTER_KEY must decode to exactly 32 bytes.")

    return key


def encrypt_file(file_data: bytes, master_key: bytes) -> dict:
    """Encrypt file bytes and return ciphertext metadata."""
    if len(master_key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = os.urandom(12)
    aesgcm = AESGCM(master_key)

    ciphertext = aesgcm.encrypt(nonce, file_data, None)

    return {
        "ciphertext": ciphertext,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "sha256": hashlib.sha256(file_data).hexdigest(),
        "size": len(file_data),
    }


def decrypt_file(
    ciphertext: bytes,
    nonce_b64: str,
    master_key: bytes,
) -> bytes:
    """Decrypt and authenticate ciphertext; reject tampered data."""
    if len(master_key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = base64.b64decode(nonce_b64, validate=True)

    if len(nonce) != 12:
        raise ValueError("Invalid AES-GCM nonce length.")

    try:
        return AESGCM(master_key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError(
            "File authentication failed: the data or key may be invalid."
        ) from exc

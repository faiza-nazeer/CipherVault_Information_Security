"""
DES (Data Encryption Standard) - Simplified implementation for benchmarking/comparison.
Uses Python's cryptography library for correctness.
"""
import os

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from cryptography.hazmat.backends import default_backend
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


def encrypt_des(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt using 3DES (Triple DES) for modern security comparison."""
    if not _CRYPTO_AVAILABLE:
        raise ImportError("cryptography package required: pip install cryptography")
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    # 3DES requires 16 or 24 byte key
    key = (key * 3)[:24]
    # PKCS7 padding
    pad_len = 8 - (len(plaintext) % 8)
    plaintext = plaintext + bytes([pad_len] * pad_len)
    iv = b'\x00' * 8
    cipher = Cipher(TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_des(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt using 3DES."""
    if not _CRYPTO_AVAILABLE:
        raise ImportError("cryptography package required: pip install cryptography")
    if isinstance(key, str):
        key = key.encode('utf-8')
    key = (key * 3)[:24]
    iv = b'\x00' * 8
    cipher = Cipher(TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]


def is_available() -> bool:
    return _CRYPTO_AVAILABLE

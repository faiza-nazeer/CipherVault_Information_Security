"""
RSA Digital Signatures for CipherVault
Handles key generation, signing, and verification.
"""
import hashlib
import json
import os
import base64

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


def generate_rsa_keypair(key_size: int = 2048):
    """Generate RSA key pair. Returns (private_key_pem, public_key_pem) as bytes."""
    if not _CRYPTO_AVAILABLE:
        raise ImportError("cryptography package required")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """Sign data with RSA private key. Returns signature bytes."""
    if not _CRYPTO_AVAILABLE:
        raise ImportError("cryptography package required")
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verify RSA signature. Returns True if valid."""
    if not _CRYPTO_AVAILABLE:
        return False
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem, backend=default_backend()
        )
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def compute_file_hash(data: bytes) -> str:
    """Compute SHA-256 hash of file data."""
    return hashlib.sha256(data).hexdigest()


def is_available() -> bool:
    return _CRYPTO_AVAILABLE

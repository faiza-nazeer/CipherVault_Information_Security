"""
Vault Storage Manager for CipherVault
Handles saving, loading, and managing encrypted files on disk.
"""
import base64
import json
import os
from datetime import datetime
from pathlib import Path

VAULT_DIR = Path(__file__).parent / "encrypted_files"


def get_vault_path(username: str) -> Path:
    path = VAULT_DIR / username
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_encrypted_file(
    username: str,
    original_name: str,
    encrypted_data: bytes,
    signature: bytes,
    public_key_pem: bytes,
    file_hash: str,
    algorithm: str = "AES-128"
) -> str:
    """
    Save an encrypted file to the vault.
    Returns the stored filename (vault_name).
    """
    vault_path = get_vault_path(username)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    vault_name = f"{timestamp}_{original_name}.enc"
    file_path = vault_path / vault_name

    package = {
        "original_name": original_name,
        "vault_name": vault_name,
        "algorithm": algorithm,
        "timestamp": datetime.now().isoformat(),
        "sha256": file_hash,
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "signature": base64.b64encode(signature).decode(),
        "public_key": public_key_pem.decode(),
    }

    with open(file_path, "w") as f:
        json.dump(package, f, indent=2)

    return vault_name


def load_encrypted_file(username: str, vault_name: str) -> dict | None:
    """Load and parse an encrypted file package from vault."""
    vault_path = get_vault_path(username)
    file_path = vault_path / vault_name
    if not file_path.exists():
        return None
    with open(file_path, "r") as f:
        package = json.load(f)
    # Decode base64 fields back to bytes
    package["encrypted_data"] = base64.b64decode(package["encrypted_data"])
    package["signature"] = base64.b64decode(package["signature"])
    package["public_key"] = package["public_key"].encode()
    return package


def list_user_files(username: str) -> list[dict]:
    """List all encrypted files for a user (metadata only)."""
    vault_path = get_vault_path(username)
    files = []
    for f in sorted(vault_path.glob("*.enc"), reverse=True):
        try:
            with open(f, "r") as fp:
                pkg = json.load(fp)
            files.append({
                "vault_name": pkg.get("vault_name", f.name),
                "original_name": pkg.get("original_name", f.name),
                "algorithm": pkg.get("algorithm", "Unknown"),
                "timestamp": pkg.get("timestamp", "Unknown"),
                "sha256": pkg.get("sha256", ""),
            })
        except Exception:
            continue
    return files


def delete_vault_file(username: str, vault_name: str) -> bool:
    """Delete an encrypted file from vault. Returns True if deleted."""
    vault_path = get_vault_path(username)
    file_path = vault_path / vault_name
    if file_path.exists():
        file_path.unlink()
        return True
    return False


def get_vault_stats(username: str) -> dict:
    """Get storage statistics for a user's vault."""
    vault_path = get_vault_path(username)
    files = list(vault_path.glob("*.enc"))
    total_size = sum(f.stat().st_size for f in files)
    return {
        "file_count": len(files),
        "total_size_kb": round(total_size / 1024, 2),
    }

"""
Authentication module for CipherVault
Handles user registration, login, and session management using JSON storage.
Uses PBKDF2 with SHA-256 for password hashing.
"""
import hashlib
import hmac
import json
import os
import secrets
import re
from pathlib import Path

AUTH_DB_PATH = Path(__file__).parent.parent / "vault" / "users.json"


def _load_users() -> dict:
    if AUTH_DB_PATH.exists():
        with open(AUTH_DB_PATH, "r") as f:
            return json.load(f)
    return {}


def _save_users(users: dict):
    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(AUTH_DB_PATH, "w") as f:
        json.dump(users, f, indent=2)


def _hash_password(password: str, salt: str) -> str:
    """PBKDF2-HMAC-SHA256 with 200,000 iterations."""
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=200_000
    )
    return dk.hex()


def check_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Returns (is_strong, list_of_issues).
    Strong password: 12+ chars, upper, lower, digit, special char.
    """
    issues = []
    if len(password) < 12:
        issues.append("At least 12 characters required")
    if not re.search(r'[A-Z]', password):
        issues.append("At least one uppercase letter required")
    if not re.search(r'[a-z]', password):
        issues.append("At least one lowercase letter required")
    if not re.search(r'\d', password):
        issues.append("At least one digit required")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        issues.append("At least one special character required")
    return len(issues) == 0, issues


def register_user(username: str, password: str) -> tuple[bool, str]:
    """Register a new user. Returns (success, message)."""
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters"
    users = _load_users()
    if username in users:
        return False, "Username already exists"
    strong, issues = check_password_strength(password)
    if not strong:
        return False, "Weak password: " + "; ".join(issues)
    salt = secrets.token_hex(32)
    hashed = _hash_password(password, salt)
    users[username] = {
        "salt": salt,
        "password_hash": hashed,
        "files": []
    }
    _save_users(users)
    return True, "Registration successful"


def login_user(username: str, password: str) -> tuple[bool, str]:
    """Authenticate user. Returns (success, message)."""
    users = _load_users()
    if username not in users:
        return False, "Invalid username or password"
    user = users[username]
    hashed = _hash_password(password, user["salt"])
    if not hmac.compare_digest(hashed, user["password_hash"]):
        return False, "Invalid username or password"
    return True, "Login successful"


def get_user_files(username: str) -> list:
    """Get list of file metadata for a user."""
    users = _load_users()
    if username not in users:
        return []
    return users[username].get("files", [])


def save_file_metadata(username: str, file_meta: dict):
    """Save encrypted file metadata to user's record."""
    users = _load_users()
    if username not in users:
        return
    if "files" not in users[username]:
        users[username]["files"] = []
    users[username]["files"].append(file_meta)
    _save_users(users)


def delete_file_metadata(username: str, filename: str):
    """Remove file metadata by filename."""
    users = _load_users()
    if username not in users:
        return
    users[username]["files"] = [
        f for f in users[username].get("files", [])
        if f.get("original_name") != filename
    ]
    _save_users(users)


def user_exists(username: str) -> bool:
    return username in _load_users()

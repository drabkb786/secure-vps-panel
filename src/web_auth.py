"""Root-owned web credentials. Passwords never leave the daemon as stored hashes."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from common import BASE_DIR, ValidationError, atomic_write_json, read_json, validate_password

AUTH_FILE = BASE_DIR / "web_admin.json"


def configure(params: dict) -> dict:
    username = str(params.get("username", "")).strip()
    if not username.isascii() or not username.replace("-", "").replace("_", "").isalnum() or not 3 <= len(username) <= 48:
        raise ValidationError("Admin username must be 3-48 ASCII letters, digits, - or _")
    password = validate_password(str(params.get("password", "")))
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()
    atomic_write_json(AUTH_FILE, {
        "username": username, "salt": salt.hex(), "hash": digest,
        "revision": secrets.token_hex(24),
    })
    return {"username": username, "message": "Web credentials saved; previous sessions revoked"}


def authenticate(params: dict) -> dict:
    data = read_json(AUTH_FILE, {})
    password = str(params.get("password", ""))
    if len(password) > 128:
        return {"authenticated": False}
    # A fixed dummy salt keeps the missing-account path similarly expensive.
    salt = bytes.fromhex(data.get("salt", "00" * 16))
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()
    valid = hmac.compare_digest(digest, data.get("hash", "0" * 64))
    valid &= hmac.compare_digest(str(params.get("username", "")).encode(), data.get("username", "").encode())
    return {"authenticated": bool(valid and data), "revision": data.get("revision", "") if valid else ""}


def revision() -> str:
    return str(read_json(AUTH_FILE, {}).get("revision", ""))

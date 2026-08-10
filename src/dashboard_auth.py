#!/usr/bin/env python3
"""Password hashing and stateless dashboard sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any

from common import ValidationError, validate_password

PBKDF2_ITERATIONS = 600_000
SESSION_SECONDS = 8 * 60 * 60
ADMIN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def validate_admin(value: str) -> str:
    username = str(value).strip()
    if not ADMIN_RE.fullmatch(username):
        raise ValidationError(
            "Dashboard username must be 3-32 letters, digits, dot, dash or underscore"
        )
    return username


def create_auth_config(username: str, password: str) -> dict[str, Any]:
    username = validate_admin(username)
    password = validate_password(password)
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return {
        "username": username,
        "password": {
            "algorithm": "pbkdf2-sha256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": _b64(salt),
            "digest": _b64(digest),
        },
        "session_secret": _b64(secrets.token_bytes(32)),
    }


def verify_password(config: dict[str, Any], username: str, password: str) -> bool:
    try:
        username_ok = hmac.compare_digest(str(config["username"]), str(username))
        data = config["password"]
        iterations = int(data["iterations"])
        if not 100_000 <= iterations <= 2_000_000:
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _unb64(data["salt"]), iterations
        )
        password_ok = hmac.compare_digest(actual, _unb64(data["digest"]))
        return username_ok and password_ok
    except (KeyError, TypeError, ValueError):
        return False


def issue_session(config: dict[str, Any], *, now: int | None = None) -> str:
    now = int(time.time()) if now is None else int(now)
    payload = {
        "sub": str(config["username"]),
        "iat": now,
        "exp": now + SESSION_SECONDS,
        "nonce": _b64(secrets.token_bytes(16)),
    }
    body = _b64(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signature = hmac.new(
        _unb64(str(config["session_secret"])), body.encode("ascii"), hashlib.sha256
    ).digest()
    return body + "." + _b64(signature)


def verify_session(
    config: dict[str, Any], token: str, *, now: int | None = None
) -> dict[str, Any] | None:
    now = int(time.time()) if now is None else int(now)
    try:
        body, encoded_signature = token.split(".", 1)
        expected = hmac.new(
            _unb64(str(config["session_secret"])), body.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, _unb64(encoded_signature)):
            return None
        payload = json.loads(_unb64(body).decode("utf-8"))
        if payload.get("sub") != config.get("username"):
            return None
        issued = int(payload["iat"])
        expires = int(payload["exp"])
        if issued > now + 60 or expires <= now or expires - issued > SESSION_SECONDS:
            return None
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def csrf_token(config: dict[str, Any], session_token: str) -> str:
    return _b64(
        hmac.new(
            _unb64(str(config["session_secret"])),
            ("csrf:" + session_token).encode("utf-8"),
            hashlib.sha256,
        ).digest()
    )


def verify_csrf(config: dict[str, Any], session_token: str, supplied: str) -> bool:
    return bool(supplied) and hmac.compare_digest(
        csrf_token(config, session_token), supplied
    )

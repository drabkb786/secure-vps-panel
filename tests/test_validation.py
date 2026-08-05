from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from common import (  # noqa: E402
    DEFAULT_SUPER_ADMIN_ID,
    PROJECT_GITHUB,
    PROJECT_OWNER,
    ValidationError,
    calculate_expiry,
    validate_bot_token,
    validate_days,
    validate_domain,
    validate_password,
    validate_quota,
    validate_sessions,
    validate_telegram_id,
    validate_username,
)


def test_valid_username() -> None:
    assert validate_username("vpn_user-1") == "vpn_user-1"


@pytest.mark.parametrize("value", ["Root", "bad user", "a;id", "../etc/passwd", "x" * 32, "root"])
def test_invalid_username(value: str) -> None:
    with pytest.raises(ValidationError):
        validate_username(value)


def test_password_rules() -> None:
    assert validate_password("correct horse battery staple")
    with pytest.raises(ValidationError):
        validate_password("short")
    with pytest.raises(ValidationError):
        validate_password("valid-length\nmalicious")


@pytest.mark.parametrize("value", ["vpn.example.com", "a-b.example.co.uk", "xn--bcher-kva.example"])
def test_valid_domain(value: str) -> None:
    assert validate_domain(value) == value


@pytest.mark.parametrize("value", ["example", "-bad.example.com", "bad_.example.com", "example.com;reboot", "http://example.com"])
def test_invalid_domain(value: str) -> None:
    with pytest.raises(ValidationError):
        validate_domain(value)


def test_numeric_limits() -> None:
    assert validate_days("30") == 30
    assert validate_sessions("2") == 2
    assert validate_quota("Unlimited") is None
    assert validate_quota("1.5") == 1.5
    with pytest.raises(ValidationError):
        validate_sessions("0")


def test_telegram_values() -> None:
    assert validate_telegram_id("123456789") == "123456789"
    assert validate_bot_token("123456789:" + "A" * 40)
    with pytest.raises(ValidationError):
        validate_telegram_id("@username")


def test_calculate_expiry_format() -> None:
    result = calculate_expiry(1)
    assert len(result) == 10
    assert result.count("-") == 2


def test_personalized_owner_metadata() -> None:
    assert PROJECT_OWNER == "Abdul Basit"
    assert PROJECT_GITHUB == "https://github.com/drabkb786/secure-vps-panel"
    assert DEFAULT_SUPER_ADMIN_ID == "6408975845"
    assert validate_telegram_id(DEFAULT_SUPER_ADMIN_ID) == "6408975845"

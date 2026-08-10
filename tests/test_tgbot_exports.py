from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tgbot import Bot, TelegramAPI  # noqa: E402


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self) -> bytes:
        return b'{"ok":true}'


def test_telegram_document_uses_safe_multipart(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update({"request": request, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = TelegramAPI("test-token").send_document(
        "123456", "alice-vless.xray.json", b'{"ok":true}\n'
    )
    request = captured["request"]
    assert result["ok"] is True
    assert request.full_url.endswith("/sendDocument")
    assert b"alice-vless.xray.json" in request.data
    assert b'{"ok":true}' in request.data
    assert request.headers["Content-type"].startswith("multipart/form-data; boundary=")


def test_telegram_document_rejects_unsafe_name() -> None:
    result = TelegramAPI("test-token").send_document("123456", "../shadow", b"x")
    assert result["ok"] is False


def test_bot_delivers_daemon_exports(monkeypatch: pytest.MonkeyPatch) -> None:
    bot = Bot("test-token")
    content = b"open profile"
    monkeypatch.setattr(
        bot,
        "panel",
        lambda command, **params: {
            "filename": params["filename"],
            "content_base64": base64.b64encode(content).decode("ascii"),
        },
    )
    sent = []
    monkeypatch.setattr(
        bot.api,
        "send_document",
        lambda chat_id, filename, data: (
            sent.append((chat_id, filename, data)) or {"ok": True}
        ),
    )
    assert bot.deliver_exports("123456", "alice", ["alice-vless.xray.json"]) == 1
    assert sent == [("123456", "alice-vless.xray.json", content)]

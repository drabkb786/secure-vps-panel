import pytest

from tgbot import Bot


@pytest.fixture
def bot(monkeypatch):
    monkeypatch.setattr(Bot, "load_offset", staticmethod(lambda: 0))
    obj = Bot("offline-fixture-only")
    obj.output = []
    obj.backend_calls = []
    monkeypatch.setattr(obj, "roles", lambda: ("123456789", {"123456789"}))
    monkeypatch.setattr(obj, "edit", lambda chat, msg, text, keyboard=None: obj.output.append((chat, text, keyboard)))
    monkeypatch.setattr(obj, "send", lambda chat, text, keyboard=None: obj.output.append((chat, text, keyboard)))
    monkeypatch.setattr(obj.api, "call", lambda *args, **kwargs: {"ok": True})
    def backend(command, **params):
        obj.backend_calls.append((command, params))
        if command == "xray_status":
            return {"accounts": [{"name": "basit", "active": True}]}
        return {"name": "basit", "links": {"vless": "vless://fixture?type=ws&security=tls", "trojan": "trojan://fixture?type=ws&security=tls"}, "readiness": {"warnings": ["Core offline"]}}
    monkeypatch.setattr(obj, "panel", backend)
    return obj


def callback(chat, data):
    return {"callback_query": {"id": "qa", "from": {"id": int(chat)}, "data": data, "message": {"message_id": 5, "chat": {"id": int(chat)}}}}


def test_authorized_admin_can_choose_profile_and_get_both_direct_links(bot):
    bot.process_update(callback("123456789", "menu_xray"))
    assert bot.output[-1][2]["inline_keyboard"][0][0]["callback_data"] == "xray_export:basit"
    bot.process_update(callback("123456789", "xray_export:basit"))
    text = bot.output[-1][1]
    assert "vless://fixture" in text and "trojan://fixture" in text
    assert "&amp;security=tls" in text and "Core offline" in text


def test_unauthorized_callback_cannot_export_links(bot):
    bot.process_update(callback("987654321", "xray_export:basit"))
    assert not bot.backend_calls and not bot.output


def test_find_by_name_sends_links_without_editing_the_users_message(bot):
    bot.process_update(callback("123456789", "xray_find"))
    bot.process_update({"message": {"message_id": 10, "chat": {"id": 123456789}, "text": "basit"}})
    assert bot.backend_calls[-1] == ("xray_export", {"name": "basit"})
    assert "trojan://fixture" in bot.output[-1][1]

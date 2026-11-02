#!/usr/bin/env python3
"""Unprivileged Telegram administration bot for Abdul Basit VPS Panel."""
from __future__ import annotations

import html
import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from common import ADMIN_IDS_FILE, BOT_TOKEN_FILE, DOMAIN_FILE, SUPER_ADMIN_FILE, read_text
from panel_client import request as panel_request

LOG = logging.getLogger("abdulbasit-bot")
STATE_TTL = 600
OFFSET_FILE = Path("/var/lib/abdulbasit-bot/offset")


class TelegramAPI:
    def __init__(self, token: str) -> None:
        self.token = token
        self.base = f"https://api.telegram.org/bot{token}/"

    def call(self, method: str, payload: dict[str, Any], timeout: int = 35) -> dict[str, Any]:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            self.base + method,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "Abdul Basit-SecureBot/2.1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
            if not result.get("ok"):
                LOG.warning("Telegram API %s failed: %s", method, result.get("description"))
            return result
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            LOG.warning("Telegram API %s error type=%s", method, type(exc).__name__)
            return {"ok": False, "description": "Telegram API request failed"}


class Bot:
    def __init__(self, token: str) -> None:
        self.api = TelegramAPI(token)
        self.states: dict[str, dict[str, Any]] = {}
        self.rate: dict[str, deque[float]] = defaultdict(deque)
        self.denied_notice: dict[str, float] = {}
        self.offset = self.load_offset()

    @staticmethod
    def load_offset() -> int:
        try:
            return int(OFFSET_FILE.read_text(encoding="utf-8").strip())
        except (FileNotFoundError, ValueError, OSError):
            return 0

    @staticmethod
    def save_offset(offset: int) -> None:
        OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = OFFSET_FILE.with_suffix(".tmp")
        tmp.write_text(f"{offset}\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, OFFSET_FILE)

    @staticmethod
    def roles() -> tuple[str, set[str]]:
        super_admin = read_text(SUPER_ADMIN_FILE)
        admins: set[str] = set()
        try:
            admins = {line.strip() for line in ADMIN_IDS_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}
        except OSError:
            pass
        if super_admin:
            admins.add(super_admin)
        return super_admin, admins

    def authorized(self, chat_id: str) -> bool:
        return chat_id in self.roles()[1]

    def is_super(self, chat_id: str) -> bool:
        return bool(chat_id) and chat_id == self.roles()[0]

    def rate_ok(self, chat_id: str) -> bool:
        now = time.monotonic()
        q = self.rate[chat_id]
        while q and now - q[0] > 10:
            q.popleft()
        if len(q) >= 15:
            return False
        q.append(now)
        return True


    def prune_ephemeral_data(self) -> None:
        now = time.monotonic()
        for chat_id, state in list(self.states.items()):
            if now - state.get("updated", 0) > STATE_TTL:
                self.states.pop(chat_id, None)
        for chat_id, queue in list(self.rate.items()):
            while queue and now - queue[0] > 10:
                queue.popleft()
            if not queue:
                self.rate.pop(chat_id, None)
        for chat_id, sent_at in list(self.denied_notice.items()):
            if now - sent_at > STATE_TTL:
                self.denied_notice.pop(chat_id, None)

    def state(self, chat_id: str) -> dict[str, Any]:
        state = self.states.get(chat_id, {})
        if state and time.monotonic() - state.get("updated", 0) > STATE_TTL:
            self.states.pop(chat_id, None)
            return {}
        return state

    def set_state(self, chat_id: str, step: str | None = None, **data: Any) -> None:
        if not step:
            self.states.pop(chat_id, None)
            return
        self.states[chat_id] = {"step": step, "updated": time.monotonic(), **data}

    @staticmethod
    def main_keyboard(super_admin: bool) -> dict[str, Any]:
        rows = [
            [{"text": "👤 Users", "callback_data": "menu_users"}, {"text": "📋 User List", "callback_data": "list_users"}],
            [{"text": "🟢 Sessions", "callback_data": "list_sessions"}, {"text": "📊 Service Status", "callback_data": "status"}],
            [{"text": "🔗 Xray Links", "callback_data": "menu_xray"}],
        ]
        if super_admin:
            rows.append([{"text": "🔐 Super Admin", "callback_data": "menu_super"}])
        return {"inline_keyboard": rows}

    @staticmethod
    def users_keyboard() -> dict[str, Any]:
        return {"inline_keyboard": [
            [{"text": "➕ Create", "callback_data": "create_start"}, {"text": "🗑 Delete", "callback_data": "delete_start"}],
            [{"text": "📅 Renew", "callback_data": "renew_start"}, {"text": "🔢 Session Limit", "callback_data": "sessions_start"}],
            [{"text": "📦 Quota Metadata", "callback_data": "quota_start"}],
            [{"text": "⬅️ Main", "callback_data": "menu_main"}],
        ]}

    @staticmethod
    def super_keyboard() -> dict[str, Any]:
        return {"inline_keyboard": [
            [{"text": "🌐 Set Domain", "callback_data": "domain_start"}, {"text": "🔒 Issue SSL", "callback_data": "ssl_issue"}],
            [{"text": "👮 Add Admin", "callback_data": "admin_add_start"}, {"text": "➖ Remove Admin", "callback_data": "admin_remove_start"}],
            [{"text": "📋 Admin List", "callback_data": "admin_list"}],
            [{"text": "🔄 Restart Nginx", "callback_data": "restart:nginx"}, {"text": "🔄 Restart WS", "callback_data": "restart:abdulbasit-ws"}],
            [{"text": "⬅️ Main", "callback_data": "menu_main"}],
        ]}

    def send(self, chat_id: str, text: str, keyboard: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text[:4096], "parse_mode": "HTML", "disable_web_page_preview": True}
        if keyboard:
            payload["reply_markup"] = keyboard
        self.api.call("sendMessage", payload)

    def edit(self, chat_id: str, message_id: int, text: str, keyboard: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"chat_id": chat_id, "message_id": message_id, "text": text[:4096], "parse_mode": "HTML", "disable_web_page_preview": True}
        if keyboard:
            payload["reply_markup"] = keyboard
        result = self.api.call("editMessageText", payload)
        if not result.get("ok"):
            self.send(chat_id, text, keyboard)

    def main_menu(self, chat_id: str, message_id: int | None = None, notice: str = "") -> None:
        self.set_state(chat_id)
        text = "<b>🛡 Abdul Basit Secure VPS Panel</b>\n" + (f"\n{notice}" if notice else "")
        keyboard = self.main_keyboard(self.is_super(chat_id))
        if message_id is None:
            self.send(chat_id, text, keyboard)
        else:
            self.edit(chat_id, message_id, text, keyboard)

    def panel(self, command: str, **params: Any) -> dict[str, Any]:
        return panel_request(command, **params)

    def callback(self, chat_id: str, message_id: int, callback_id: str, data: str) -> None:
        self.api.call("answerCallbackQuery", {"callback_query_id": callback_id})
        if data == "menu_main":
            self.main_menu(chat_id, message_id)
        elif data == "menu_users":
            self.set_state(chat_id)
            self.edit(chat_id, message_id, "<b>👤 User Management</b>\nSession limit means concurrent Dropbear sessions, not unique IP addresses.", self.users_keyboard())
        elif data == "menu_xray":
            self.show_xray_profiles(chat_id, message_id)
        elif data == "xray_find":
            self.set_state(chat_id, "xray_export_name")
            self.edit(chat_id, message_id, "Enter the Xray profile name to get its direct import links:")
        elif data.startswith("xray_export:"):
            self.show_xray_links(chat_id, message_id, data.split(":", 1)[1])
        elif data == "menu_super":
            if not self.is_super(chat_id):
                return
            self.set_state(chat_id)
            self.edit(chat_id, message_id, "<b>🔐 Super Admin Controls</b>", self.super_keyboard())
        elif data == "create_start":
            self.set_state(chat_id, "create_username")
            self.edit(chat_id, message_id, "Enter a new lowercase username:")
        elif data == "delete_start":
            self.set_state(chat_id, "delete_username")
            self.edit(chat_id, message_id, "Enter the managed username to delete:")
        elif data.startswith("delete_confirm:"):
            username = data.split(":", 1)[1]
            try:
                self.panel("delete_user", username=username)
                self.main_menu(chat_id, message_id, f"✅ User <code>{html.escape(username)}</code> deleted.")
            except RuntimeError as exc:
                self.main_menu(chat_id, message_id, f"❌ {html.escape(str(exc))}")
        elif data == "delete_cancel":
            self.main_menu(chat_id, message_id, "Deletion cancelled.")
        elif data == "renew_start":
            self.set_state(chat_id, "renew_username")
            self.edit(chat_id, message_id, "Enter the username to renew:")
        elif data == "sessions_start":
            self.set_state(chat_id, "sessions_username")
            self.edit(chat_id, message_id, "Enter the username whose concurrent session limit should change:")
        elif data == "quota_start":
            self.set_state(chat_id, "quota_username")
            self.edit(chat_id, message_id, "Enter the username whose quota metadata should change:\n\n<i>Note: quota enforcement is intentionally disabled until a reliable accounting backend is configured.</i>")
        elif data == "list_users":
            self.show_users(chat_id, message_id)
        elif data == "list_sessions":
            self.show_sessions(chat_id, message_id)
        elif data == "status":
            self.show_status(chat_id, message_id)
        elif data == "domain_start" and self.is_super(chat_id):
            self.set_state(chat_id, "domain")
            self.edit(chat_id, message_id, "Enter a domain such as <code>vpn.example.com</code>:")
        elif data == "ssl_issue" and self.is_super(chat_id):
            domain = read_text(DOMAIN_FILE)
            self.edit(chat_id, message_id, f"Issuing/renewing SSL for <code>{html.escape(domain or 'not set')}</code>…")
            try:
                result = self.panel("issue_cert", domain=domain)
                self.edit(chat_id, message_id, f"✅ SSL active for <code>{html.escape(result['domain'])}</code>.", self.super_keyboard())
            except RuntimeError as exc:
                self.edit(chat_id, message_id, f"❌ SSL failed: {html.escape(str(exc))}", self.super_keyboard())
        elif data == "admin_add_start" and self.is_super(chat_id):
            self.set_state(chat_id, "admin_add")
            self.edit(chat_id, message_id, "Enter the numeric Telegram user ID to authorize:")
        elif data == "admin_remove_start" and self.is_super(chat_id):
            self.set_state(chat_id, "admin_remove")
            self.edit(chat_id, message_id, "Enter the numeric Telegram admin ID to remove:")
        elif data == "admin_list" and self.is_super(chat_id):
            self.show_admins(chat_id, message_id)
        elif data.startswith("restart:") and self.is_super(chat_id):
            service = data.split(":", 1)[1]
            try:
                self.panel("restart_service", service=service)
                self.edit(chat_id, message_id, f"✅ <code>{html.escape(service)}</code> restarted.", self.super_keyboard())
            except RuntimeError as exc:
                self.edit(chat_id, message_id, f"❌ {html.escape(str(exc))}", self.super_keyboard())

    def show_xray_profiles(self, chat_id: str, message_id: int) -> None:
        self.set_state(chat_id)
        try:
            rows = self.panel("xray_status").get("accounts", [])
            active_rows = [row for row in rows if row.get("active")]
            keyboard = {"inline_keyboard": [
                [{"text": row["name"], "callback_data": f"xray_export:{row['name']}"}] for row in active_rows[:20]
            ] + [[{"text": "🔎 Find by name", "callback_data": "xray_find"}], [{"text": "⬅️ Main", "callback_data": "menu_main"}]]}
            self.edit(chat_id, message_id, "<b>🔗 Xray import links</b>\nSelect a profile to get its VLESS, VMess and/or Trojan links.\nCreate profiles from the dashboard or CLI.\n" + (f"\nShowing {min(20, len(active_rows))} of {len(active_rows)} eligible profiles." if active_rows else "\nNo eligible Xray profiles found."), keyboard)
        except RuntimeError as exc:
            self.edit(chat_id, message_id, f"❌ {html.escape(str(exc))}", self.main_keyboard(self.is_super(chat_id)))

    def show_xray_links(self, chat_id: str, message_id: int | None, name: str) -> None:
        self.set_state(chat_id)
        def display(text: str, keyboard: dict) -> None:
            if message_id is None:
                self.send(chat_id, text, keyboard)
            else:
                self.edit(chat_id, message_id, text, keyboard)
        try:
            result = self.panel("xray_export", name=name)
            lines = [f"<b>🔗 {html.escape(result['name'])}</b>", "Treat import links as account passwords."]
            for protocol, link in result["links"].items():
                lines.append(f"\n<b>{html.escape(protocol.upper())}</b>\n<code>{html.escape(link)}</code>")
            lines.extend(f"\n⚠️ {html.escape(w)}" for w in result.get("readiness", {}).get("warnings", []))
            display("\n".join(lines), {"inline_keyboard": [[{"text": "⬅️ Xray profiles", "callback_data": "menu_xray"}]]})
        except RuntimeError as exc:
            display(f"❌ {html.escape(str(exc))}", self.main_keyboard(self.is_super(chat_id)))

    def show_users(self, chat_id: str, message_id: int) -> None:
        try:
            users = self.panel("list_users").get("users", [])
            if not users:
                text = "No managed users found."
            else:
                lines = ["<b>📋 Managed Users</b>"]
                for user in users[:60]:
                    quota = user.get("quota_gb")
                    quota_text = "Unlimited" if quota is None else f"{quota} GB (metadata)"
                    lines.append(
                        f"\n👤 <code>{html.escape(str(user.get('username')))}</code>"
                        f"\nExpiry: {html.escape(str(user.get('expiry')))} | Sessions: {html.escape(str(user.get('max_sessions')))}"
                        f"\nQuota: {html.escape(quota_text)} | System account: {'yes' if user.get('exists') else 'missing'}"
                    )
                text = "\n".join(lines)
            self.edit(chat_id, message_id, text, self.main_keyboard(self.is_super(chat_id)))
        except RuntimeError as exc:
            self.edit(chat_id, message_id, f"❌ {html.escape(str(exc))}", self.main_keyboard(self.is_super(chat_id)))

    def show_sessions(self, chat_id: str, message_id: int) -> None:
        try:
            sessions = self.panel("list_sessions").get("sessions", [])
            text = "No active managed Dropbear sessions." if not sessions else "<b>🟢 Active Sessions</b>\n\n" + "\n".join(
                f"<code>{html.escape(item['username'])}</code>: {item['count']}" for item in sessions
            )
            self.edit(chat_id, message_id, text, self.main_keyboard(self.is_super(chat_id)))
        except RuntimeError as exc:
            self.edit(chat_id, message_id, f"❌ {html.escape(str(exc))}", self.main_keyboard(self.is_super(chat_id)))

    def show_status(self, chat_id: str, message_id: int) -> None:
        try:
            result = self.panel("service_status")
            lines = [f"<b>📊 Service Status</b>\nDomain: <code>{html.escape(result.get('domain', 'Not set'))}</code>"]
            for name, status in result.get("services", {}).items():
                icon = "🟢" if status == "active" else "🔴"
                lines.append(f"{icon} {html.escape(name)}: <code>{html.escape(status)}</code>")
            self.edit(chat_id, message_id, "\n".join(lines), self.main_keyboard(self.is_super(chat_id)))
        except RuntimeError as exc:
            self.edit(chat_id, message_id, f"❌ {html.escape(str(exc))}", self.main_keyboard(self.is_super(chat_id)))

    def show_admins(self, chat_id: str, message_id: int) -> None:
        try:
            result = self.panel("list_admins")
            lines = [f"👑 Super Admin: <code>{html.escape(result.get('super_admin', ''))}</code>", "", "Authorized admins:"]
            lines.extend(f"• <code>{html.escape(item)}</code>" for item in result.get("admins", []))
            self.edit(chat_id, message_id, "\n".join(lines), self.super_keyboard())
        except RuntimeError as exc:
            self.edit(chat_id, message_id, f"❌ {html.escape(str(exc))}", self.super_keyboard())

    def text(self, chat_id: str, message_id: int, text: str) -> None:
        if text == "/start" or text == "/cancel":
            self.main_menu(chat_id)
            return
        state = self.state(chat_id)
        step = state.get("step")
        if not step:
            self.main_menu(chat_id)
            return
        value = text.strip()
        try:
            if step == "xray_export_name":
                self.show_xray_links(chat_id, None, value)
            elif step == "create_username":
                self.set_state(chat_id, "create_password", username=value)
                self.send(chat_id, "Send a strong password (minimum 12 characters). The bot will delete that password message after reading it.")
            elif step == "create_password":
                self.api.call("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
                self.set_state(chat_id, "create_days", username=state["username"], password=text)
                self.send(chat_id, "Enter validity in days (1-3650):")
            elif step == "create_days":
                self.set_state(chat_id, "create_sessions", username=state["username"], password=state["password"], days=value)
                self.send(chat_id, "Enter maximum concurrent sessions (1-20):")
            elif step == "create_sessions":
                self.set_state(chat_id, "create_quota", username=state["username"], password=state["password"], days=state["days"], max_sessions=value)
                self.send(chat_id, "Enter quota metadata in GB, or <code>Unlimited</code>. Accurate quota enforcement is disabled.")
            elif step == "create_quota":
                result = self.panel(
                    "create_user",
                    username=state["username"], password=state["password"], days=state["days"],
                    max_sessions=state["max_sessions"], quota_gb=value,
                )
                self.set_state(chat_id)
                user = result["user"]
                self.send(
                    chat_id,
                    "✅ <b>Account created</b>\n"
                    f"Domain: <code>{html.escape(read_text(DOMAIN_FILE, 'Not set'))}</code>\n"
                    f"Username: <code>{html.escape(user['username'])}</code>\n"
                    f"Expiry: <code>{html.escape(user['expiry'])}</code>\n"
                    f"Concurrent sessions: <code>{user['max_sessions']}</code>\n"
                    "Ports: <code>22, 109, 447, 80, 443</code>\n\n"
                    "The password is not repeated or stored by the panel.",
                    self.users_keyboard(),
                )
            elif step == "delete_username":
                self.set_state(chat_id)
                self.send(chat_id, f"Delete managed user <code>{html.escape(value)}</code>?", {"inline_keyboard": [[
                    {"text": "✅ Confirm delete", "callback_data": f"delete_confirm:{value}"},
                    {"text": "Cancel", "callback_data": "delete_cancel"},
                ]]})
            elif step == "renew_username":
                self.set_state(chat_id, "renew_days", username=value)
                self.send(chat_id, "Enter days to add (1-3650):")
            elif step == "renew_days":
                result = self.panel("renew_user", username=state["username"], days=value)
                self.set_state(chat_id)
                self.send(chat_id, f"✅ <code>{html.escape(result['username'])}</code> renewed until <code>{result['expiry']}</code>.", self.users_keyboard())
            elif step == "sessions_username":
                self.set_state(chat_id, "sessions_value", username=value)
                self.send(chat_id, "Enter the new concurrent session limit (1-20):")
            elif step == "sessions_value":
                result = self.panel("set_sessions", username=state["username"], max_sessions=value)
                self.set_state(chat_id)
                self.send(chat_id, f"✅ Session limit for <code>{html.escape(result['username'])}</code> is now {result['max_sessions']}.", self.users_keyboard())
            elif step == "quota_username":
                self.set_state(chat_id, "quota_value", username=value)
                self.send(chat_id, "Enter GB value or <code>Unlimited</code>:")
            elif step == "quota_value":
                result = self.panel("set_quota", username=state["username"], quota_gb=value)
                self.set_state(chat_id)
                shown = "Unlimited" if result["quota_gb"] is None else f"{result['quota_gb']} GB"
                self.send(chat_id, f"✅ Quota metadata for <code>{html.escape(result['username'])}</code>: {html.escape(shown)}. Enforcement remains disabled.", self.users_keyboard())
            elif step == "domain" and self.is_super(chat_id):
                result = self.panel("set_domain", domain=value)
                self.set_state(chat_id)
                self.send(chat_id, f"✅ Domain set to <code>{html.escape(result['domain'])}</code>. TLS active: {result['tls']}", self.super_keyboard())
            elif step == "admin_add" and self.is_super(chat_id):
                result = self.panel("add_admin", admin_id=value)
                self.set_state(chat_id)
                self.send(chat_id, f"✅ Admin <code>{html.escape(value)}</code> added.", self.super_keyboard())
            elif step == "admin_remove" and self.is_super(chat_id):
                result = self.panel("remove_admin", admin_id=value)
                self.set_state(chat_id)
                self.send(chat_id, f"✅ Admin <code>{html.escape(value)}</code> removed.", self.super_keyboard())
        except RuntimeError as exc:
            self.set_state(chat_id)
            self.send(chat_id, f"❌ {html.escape(str(exc))}", self.main_keyboard(self.is_super(chat_id)))

    def process_update(self, update: dict[str, Any]) -> None:
        if "callback_query" in update:
            cb = update["callback_query"]
            message = cb.get("message", {})
            chat_id = str(message.get("chat", {}).get("id", ""))
            if not self.authorized(chat_id) or not self.rate_ok(chat_id):
                return
            self.callback(chat_id, int(message.get("message_id", 0)), str(cb.get("id", "")), str(cb.get("data", "")))
            return
        message = update.get("message", {})
        if "text" not in message:
            return
        chat_id = str(message.get("chat", {}).get("id", ""))
        if not self.rate_ok(chat_id):
            return
        if not self.authorized(chat_id):
            now = time.monotonic()
            if now - self.denied_notice.get(chat_id, 0) > STATE_TTL:
                self.denied_notice[chat_id] = now
                self.send(chat_id, f"⛔ Access denied. Your Telegram ID is <code>{html.escape(chat_id)}</code>.")
            return
        self.text(chat_id, int(message.get("message_id", 0)), str(message.get("text", "")))

    def run(self) -> None:
        backoff = 1
        while True:
            self.prune_ephemeral_data()
            result = self.api.call("getUpdates", {
                "offset": self.offset,
                "timeout": 25,
                "allowed_updates": ["message", "callback_query"],
            }, timeout=35)
            if not result.get("ok"):
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue
            backoff = 1
            for update in result.get("result", []):
                self.offset = int(update["update_id"]) + 1
                try:
                    self.process_update(update)
                except Exception:
                    LOG.exception("Failed to process Telegram update")
                self.save_offset(self.offset)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    token = read_text(BOT_TOKEN_FILE)
    if not token:
        raise SystemExit("Bot token is not configured")
    Bot(token).run()


if __name__ == "__main__":
    main()

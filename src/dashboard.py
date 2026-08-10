#!/usr/bin/env python3
"""Loopback-only authenticated web dashboard."""

from __future__ import annotations

import base64
import json
import logging
import mimetypes
import os
import threading
import time
from collections import defaultdict, deque
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from common import DASHBOARD_AUTH_FILE, read_json
from dashboard_auth import (
    csrf_token,
    issue_session,
    verify_csrf,
    verify_password,
    verify_session,
)
from panel_client import request as panel_request

LOG = logging.getLogger("abdulbasit-dashboard")
LISTEN = ("127.0.0.1", 9080)
MAX_BODY = 64 * 1024
STATIC_DIR = Path(
    os.environ.get(
        "ABDULBASIT_DASHBOARD_STATIC", "/usr/local/share/abdulbasit-dashboard"
    )
)
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
LOGIN_LOCK = threading.Lock()
MAX_TRACKED_LOGIN_IPS = 4096


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "AbdulBasitDashboard/3.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info("client=%s %s", self.client_ip(), fmt % args)

    def client_ip(self) -> str:
        if self.client_address[0] in {"127.0.0.1", "::1"}:
            return (
                self.headers.get("X-Real-IP", self.client_address[0])
                .split(",", 1)[0]
                .strip()[:64]
            )
        return self.client_address[0]

    def security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )

    def json_response(
        self, status: int, data: dict[str, Any], *, cookie: str = ""
    ) -> None:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        self.send_response(status)
        self.security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(payload)

    def read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if not 0 < length <= MAX_BODY:
            raise ValueError("Request body must be between 1 byte and 64 KiB")
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ValueError("Content-Type must be application/json")
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    @staticmethod
    def auth_config() -> dict[str, Any]:
        data = read_json(DASHBOARD_AUTH_FILE, {})
        return data if isinstance(data, dict) else {}

    def session_token(self) -> str:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            return cookie["ab_session"].value if "ab_session" in cookie else ""
        except Exception:
            return ""

    def require_auth(self, *, csrf: bool = False) -> tuple[dict[str, Any], str] | None:
        config = self.auth_config()
        token = self.session_token()
        if not config or verify_session(config, token) is None:
            self.json_response(
                HTTPStatus.UNAUTHORIZED,
                {"ok": False, "error": "Authentication required"},
            )
            return None
        if csrf and not verify_csrf(
            config, token, self.headers.get("X-CSRF-Token", "")
        ):
            self.json_response(
                HTTPStatus.FORBIDDEN, {"ok": False, "error": "Invalid CSRF token"}
            )
            return None
        return config, token

    def serve_static(self, name: str) -> None:
        allowed = {"index.html", "app.js", "styles.css"}
        if name not in allowed:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        path = STATIC_DIR / name
        try:
            data = path.read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.security_headers()
        self.send_header(
            "Content-Type", mimetypes.guess_type(name)[0] or "application/octet-stream"
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def login_allowed(self) -> bool:
        now = time.monotonic()
        address = self.client_ip()
        with LOGIN_LOCK:
            if (
                address not in LOGIN_ATTEMPTS
                and len(LOGIN_ATTEMPTS) >= MAX_TRACKED_LOGIN_IPS
            ):
                LOGIN_ATTEMPTS.pop(next(iter(LOGIN_ATTEMPTS)), None)
            attempts = LOGIN_ATTEMPTS[address]
            while attempts and now - attempts[0] > 300:
                attempts.popleft()
            return len(attempts) < 5

    def record_login_failure(self) -> None:
        with LOGIN_LOCK:
            LOGIN_ATTEMPTS[self.client_ip()].append(time.monotonic())

    def clear_login_failures(self) -> None:
        with LOGIN_LOCK:
            LOGIN_ATTEMPTS.pop(self.client_ip(), None)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self.serve_static("index.html")
            return
        if parsed.path in {"/app.js", "/styles.css"}:
            self.serve_static(parsed.path.lstrip("/"))
            return
        if parsed.path == "/api/session":
            auth = self.require_auth()
            if not auth:
                return
            config, token = auth
            self.json_response(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "username": config["username"],
                    "csrf": csrf_token(config, token),
                },
            )
            return
        auth = self.require_auth()
        if not auth:
            return
        try:
            if parsed.path == "/api/status":
                result = panel_request("service_status")
            elif parsed.path == "/api/users":
                result = panel_request("list_users")
            elif parsed.path == "/api/cdn":
                result = panel_request("list_cdn")
            elif parsed.path == "/api/dnstt":
                result = panel_request("list_dnstt")
            elif parsed.path == "/api/exports":
                username = parse_qs(parsed.query).get("username", [""])[0]
                result = panel_request("list_exports", username=username)
            elif parsed.path.startswith("/api/exports/"):
                parts = parsed.path.split("/", 4)
                if len(parts) != 5:
                    raise RuntimeError("Invalid export path")
                result = panel_request(
                    "get_export", username=unquote(parts[3]), filename=unquote(parts[4])
                )
                raw = base64.b64decode(result["content_base64"], validate=True)
                self.send_response(HTTPStatus.OK)
                self.security_headers()
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename={json.dumps(result['filename'])}",
                )
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            else:
                self.json_response(
                    HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"}
                )
                return
            self.json_response(HTTPStatus.OK, {"ok": True, **result})
        except (RuntimeError, ValueError) as exc:
            self.json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            if not self.login_allowed():
                self.json_response(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"ok": False, "error": "Too many login attempts"},
                )
                return
            try:
                data = self.read_json_body()
                config = self.auth_config()
                if not config or not verify_password(
                    config, str(data.get("username", "")), str(data.get("password", ""))
                ):
                    self.record_login_failure()
                    time.sleep(0.25)
                    self.json_response(
                        HTTPStatus.UNAUTHORIZED,
                        {"ok": False, "error": "Invalid credentials"},
                    )
                    return
                self.clear_login_failures()
                token = issue_session(config)
                cookie = f"ab_session={token}; Path=/panel/; Max-Age=28800; HttpOnly; Secure; SameSite=Strict"
                self.json_response(
                    HTTPStatus.OK,
                    {"ok": True, "csrf": csrf_token(config, token)},
                    cookie=cookie,
                )
            except (ValueError, json.JSONDecodeError) as exc:
                self.json_response(
                    HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}
                )
            return

        auth = self.require_auth(csrf=True)
        if not auth:
            return
        if parsed.path == "/api/logout":
            self.json_response(
                HTTPStatus.OK,
                {"ok": True},
                cookie="ab_session=; Path=/panel/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
            )
            return
        try:
            data = self.read_json_body()
            parts = parsed.path.strip("/").split("/")
            if parsed.path == "/api/users":
                result = panel_request(
                    "create_user",
                    username=data.get("username"),
                    password=data.get("password"),
                    days=data.get("days"),
                    max_sessions=data.get("max_sessions"),
                    quota_gb=data.get("quota_gb", "Unlimited"),
                    protocols=data.get("protocols", ["ssh"]),
                )
            elif parsed.path == "/api/cdn":
                result = panel_request(
                    "configure_cdn",
                    provider=data.get("provider"),
                    endpoint=data.get("endpoint"),
                    origin=data.get("origin", ""),
                    origin_secret=data.get("origin_secret", ""),
                )
            elif parsed.path == "/api/dnstt":
                result = panel_request(
                    "configure_dnstt",
                    zone=data.get("zone"),
                    nameserver=data.get("nameserver"),
                    listen_ip=data.get("listen_ip"),
                    target_port=data.get("target_port", 109),
                    rotate_keys=bool(data.get("rotate_keys", False)),
                )
            elif (
                len(parts) == 4
                and parts[:2] == ["api", "users"]
                and parts[3] == "renew"
            ):
                result = panel_request(
                    "renew_user", username=unquote(parts[2]), days=data.get("days")
                )
            elif (
                len(parts) == 4
                and parts[:2] == ["api", "users"]
                and parts[3] == "quota"
            ):
                result = panel_request(
                    "set_quota",
                    username=unquote(parts[2]),
                    quota_gb=data.get("quota_gb"),
                )
            elif (
                len(parts) == 4
                and parts[:2] == ["api", "users"]
                and parts[3] == "sessions"
            ):
                result = panel_request(
                    "set_sessions",
                    username=unquote(parts[2]),
                    max_sessions=data.get("max_sessions"),
                )
            elif (
                len(parts) == 5
                and parts[:2] == ["api", "users"]
                and parts[3] == "protocols"
                and parts[4] == "enable"
            ):
                result = panel_request(
                    "enable_protocol",
                    username=unquote(parts[2]),
                    protocols=data.get("protocols"),
                )
            elif (
                len(parts) == 5
                and parts[:2] == ["api", "users"]
                and parts[3] == "protocols"
                and parts[4] == "disable"
            ):
                result = panel_request(
                    "disable_protocol",
                    username=unquote(parts[2]),
                    protocol=data.get("protocol"),
                )
            elif (
                len(parts) == 5
                and parts[:2] == ["api", "users"]
                and parts[3] == "protocols"
                and parts[4] == "rotate"
            ):
                result = panel_request(
                    "rotate_protocol",
                    username=unquote(parts[2]),
                    protocol=data.get("protocol"),
                )
            elif (
                len(parts) == 5
                and parts[:2] == ["api", "users"]
                and parts[3:] == ["usage", "reset"]
            ):
                result = panel_request("reset_usage", username=unquote(parts[2]))
            elif (
                len(parts) == 4
                and parts[:2] == ["api", "users"]
                and parts[3] == "exports"
            ):
                result = panel_request(
                    "generate_exports",
                    username=unquote(parts[2]),
                    protocol=data.get("protocol"),
                    provider=data.get("provider", "direct"),
                )
            elif (
                len(parts) == 4
                and parts[:2] == ["api", "users"]
                and parts[3] == "dnstt-export"
            ):
                result = panel_request("export_dnstt", username=unquote(parts[2]))
            else:
                self.json_response(
                    HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"}
                )
                return
            self.json_response(HTTPStatus.OK, {"ok": True, **result})
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            self.json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})

    def do_DELETE(self) -> None:  # noqa: N802
        if not self.require_auth(csrf=True):
            return
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        try:
            if len(parts) == 3 and parts[:2] == ["api", "users"]:
                result = panel_request("delete_user", username=unquote(parts[2]))
            elif len(parts) == 3 and parts[:2] == ["api", "cdn"]:
                result = panel_request("remove_cdn", provider=unquote(parts[2]))
            elif parts == ["api", "dnstt"]:
                result = panel_request("disable_dnstt")
            elif len(parts) == 4 and parts[:2] == ["api", "exports"]:
                result = panel_request(
                    "delete_export",
                    username=unquote(parts[2]),
                    filename=unquote(parts[3]),
                )
            else:
                self.json_response(
                    HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"}
                )
                return
            self.json_response(HTTPStatus.OK, {"ok": True, **result})
        except RuntimeError as exc:
            self.json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    if not DASHBOARD_AUTH_FILE.is_file():
        raise SystemExit(
            "Dashboard is not configured; run: abdulbasit-panelctl configure-dashboard"
        )
    server = ThreadingHTTPServer(LISTEN, DashboardHandler)
    server.daemon_threads = True
    LOG.info("Dashboard listening on http://%s:%d", *LISTEN)
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()

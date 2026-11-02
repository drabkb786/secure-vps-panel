#!/usr/bin/env python3
"""Loopback web app; Nginx supplies public TLS. No third-party runtime dependencies."""
from __future__ import annotations

import hmac
import io
import json
import logging
import secrets
import threading
import time
import zipfile
import re
from datetime import datetime
from collections import OrderedDict, deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from panel_client import request

LOG = logging.getLogger("abdulbasit-web")
ASSETS = Path(__file__).resolve().parent / "web"
COOKIE = "noway_session"
MAX_BODY = 16 * 1024
SESSION_TTL = 8 * 3600
IDLE_TTL = 30 * 60
COMMANDS = {"cloudfront_configure", "cloudfront_check",
    "create_user", "delete_user", "renew_user", "set_sessions", "set_quota",
    "set_domain", "issue_cert", "restart_service", "dns_lookup", "dns_set",
    "xray_configure", "xray_create", "xray_update", "subscription_rotate", "subscription_revoke",
    "set_user_lock", "traffic_sample", "live_connections", "packet_test", "live_logs", "doctor", "restart_managed", "config_view", "banner_get", "banner_set", "memory_report", "slowdns_status", "slowdns_configure", "slowdns_check",
}


class Store:
    def __init__(self):
        self.lock = threading.RLock()
        self.sessions: OrderedDict[str, dict] = OrderedDict()
        self.attempts: OrderedDict[str, deque] = OrderedDict()
        self.public_attempts: OrderedDict[str, deque] = OrderedDict()
        self.public_total = deque()

    def public_allowed(self, ip: str) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.public_attempts.setdefault(ip, deque())
            self.public_attempts.move_to_end(ip)
            while len(self.public_attempts) > 2048:
                self.public_attempts.popitem(last=False)
            for bucket in (q, self.public_total):
                while bucket and now - bucket[0] > 60:
                    bucket.popleft()
            if len(q) >= 120 or len(self.public_total) >= 300:
                return False
            q.append(now); self.public_total.append(now)
            return True

    def login_allowed(self, ip: str) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.attempts.setdefault(ip, deque())
            while q and now - q[0] > 300:
                q.popleft()
            if len(q) >= 8:
                return False
            q.append(now)
            self.attempts.move_to_end(ip)
            while len(self.attempts) > 2048:
                self.attempts.popitem(last=False)
            return True

    def add(self, username: str, revision: str) -> tuple[str, dict]:
        now = time.monotonic()
        session = {"username": username, "revision": revision, "csrf": secrets.token_urlsafe(32), "created": now, "seen": now}
        token = secrets.token_urlsafe(48)
        with self.lock:
            for old, item in list(self.sessions.items()):
                if now - item["created"] > SESSION_TTL or now - item["seen"] > IDLE_TTL:
                    self.sessions.pop(old, None)
            self.sessions[token] = session
            while len(self.sessions) > 256:
                self.sessions.popitem(last=False)
        return token, session

    def get(self, token: str) -> dict | None:
        with self.lock:
            session = self.sessions.get(token)
            now = time.monotonic()
            if not session:
                return None
            if now - session["created"] > SESSION_TTL or now - session["seen"] > IDLE_TTL:
                self.sessions.pop(token, None)
                return None
            session["seen"] = now
            return dict(session)

    def delete(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)


STORE = Store()


class Handler(BaseHTTPRequestHandler):
    server_version = "NOWAY"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, fmt, *args):
        # Do not log URLs, account exports, request bodies or credentials.
        LOG.info("HTTP peer=%s", self.client_address[0])

    def reply(self, status: int, body: bytes, content_type="application/json; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def json(self, status: int, data: dict, headers=None):
        self.reply(status, json.dumps(data, ensure_ascii=False).encode(), headers=headers)

    def token(self) -> str:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            return cookie[COOKIE].value if COOKIE in cookie else ""
        except Exception:
            return ""

    def trusted_transport(self) -> bool:
        # A missing forwarded header means direct loopback / SSH forwarding.
        # Nginx always overwrites this header with $scheme on public requests.
        return self.headers.get("X-Forwarded-Proto") in (None, "https")

    def same_origin(self) -> bool:
        scheme = "https" if self.headers.get("X-Forwarded-Proto") == "https" else "http"
        host = self.headers.get("Host", "")
        try:
            parsed = urlsplit(f"{scheme}://{host}")
            if not host or parsed.netloc != host or parsed.path or parsed.username or not parsed.hostname:
                return False
            if self.headers.get("X-Forwarded-Proto") is None and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                return False
        except ValueError:
            return False
        return self.headers.get("Origin") == f"{scheme}://{host}"

    def session(self, *, csrf=False) -> dict | None:
        if not self.trusted_transport():
            self.json(426, {"error": "Use HTTPS, or an SSH tunnel to the loopback dashboard"})
            return None
        session = STORE.get(self.token())
        if session and request("web_revision")["revision"] != session["revision"]:
            STORE.delete(self.token())
            session = None
        if not session:
            self.json(401, {"error": "Sign in to continue"})
            return None
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
            self.json(403, {"error": "Invalid CSRF token; reload this page"})
            return None
        return session

    def do_GET(self):
        try:
            self.get()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except RuntimeError as exc:
            self.json(400, {"error": str(exc)})
        except (OSError, ValueError, KeyError):
            LOG.exception("Web read failed")
            self.json(503, {"error": "Panel daemon unavailable; check its service"})

    def get(self):
        url = urlsplit(self.path)
        if url.path.startswith("/panel/sub/"):
            self.subscription(url)
            return
        if url.path in {"/", "/panel"}:
            self.reply(302, b"", headers={"Location": "/panel/"})
            return
        assets = {"/panel/": ("index.html", "text/html; charset=utf-8"), "/panel/app.js": ("app.js", "text/javascript; charset=utf-8"), "/panel/qr.js": ("qr.js", "text/javascript; charset=utf-8"), "/panel/style.css": ("style.css", "text/css; charset=utf-8")}
        if url.path in assets:
            name, mime = assets[url.path]
            self.reply(200, (ASSETS / name).read_bytes(), mime)
            return
        if url.path == "/panel/api/health":
            self.json(200, {"ok": True})
            return
        if url.path not in {"/panel/api/session", "/panel/api/state", "/panel/api/diagnostics", "/panel/api/export", "/panel/api/backup", "/panel/api/cloudfront-setup"}:
            self.json(404, {"error": "Not found"})
            return
        session = self.session()
        if not session:
            return
        if url.path == "/panel/api/session":
            self.json(200, {"username": session["username"], "csrf": session["csrf"]})
        elif url.path == "/panel/api/state":
            self.json(200, request("dashboard_status", _web_revision=session["revision"]))
        elif url.path == "/panel/api/diagnostics":
            self.json(200, request("diagnostics", _web_revision=session["revision"]))
        elif url.path == "/panel/api/cloudfront-setup":
            result = request("cloudfront_setup", _web_revision=session["revision"])
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, content in result["files"].items():
                    archive.writestr(name, content)
            self.reply(200, stream.getvalue(), "application/zip", {"Content-Disposition": 'attachment; filename="NOWAY-cloudfront-private.zip"'})
        elif url.path == "/panel/api/backup":
            data = request("backup_export", _web_revision=session["revision"])["backup"]
            self.reply(200, (json.dumps(data, indent=2) + "\n").encode(), headers={"Content-Disposition": 'attachment; filename="NOWAY-xray-backup.json"'})
        else:
            query = parse_qs(url.query)
            if any(len(values) != 1 for values in query.values()):
                self.json(400, {"error": "Duplicate export parameters are not supported"})
                return
            format_name = query.get("format", ["json"])[0]
            if format_name not in {"json", "zip", "link"}:
                self.json(400, {"error": "Choose json, zip or link export format"})
                return
            result = request("xray_export", name=query.get("name", [""])[0], route=query.get("route", ["direct"])[0], _web_revision=session["revision"])
            if format_name == "link":
                protocol = query.get("protocol", [""])[0]
                if protocol not in {"vless", "vmess", "trojan", "vless-xhttp"} or protocol not in result["links"]:
                    self.json(400, {"error": "Selected protocol is not enabled for this account"})
                    return
                self.reply(200, (result["links"][protocol] + "\n").encode(), "text/plain; charset=utf-8",
                           {"Content-Disposition": f'attachment; filename="{result["name"]}-{protocol}.txt"'})
            elif format_name == "zip":
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name, content in result["files"].items():
                        archive.writestr(name, content)
                self.reply(200, stream.getvalue(), "application/zip", {"Content-Disposition": f'attachment; filename="NOWAY-{result["name"]}.zip"'})
            else:
                self.json(200, result)

    def subscription(self, url):
        if not self.trusted_transport():
            self.json(426, {"error": "Use HTTPS for subscriptions"})
            return
        token = url.path[len("/panel/sub/"):].rstrip("/")
        query = parse_qs(url.query)
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token) or any(len(v) != 1 for v in query.values()):
            self.json(404, {"error": "Subscription unavailable"})
            return
        ip = self.headers.get("X-Real-IP", self.client_address[0]) if self.headers.get("X-Forwarded-Proto") else self.client_address[0]
        if not STORE.public_allowed(ip):
            self.json(429, {"error": "Try again later"}, {"Retry-After": "60"})
            return
        agent = self.headers.get("User-Agent", "").lower()
        default = "clash" if "clash" in agent or "mihomo" in agent else "singbox" if "sing-box" in agent or "singbox" in agent else "base64"
        format_name = query.get("format", [default])[0]
        try:
            result = request("subscription_get", token=token, format=format_name, route=query.get("route", ["direct"])[0])
        except RuntimeError:
            self.json(404, {"error": "Subscription unavailable"})
            return
        expiry = int(datetime.fromisoformat(result.get("expires_at") or result["expiry"]).timestamp())
        usage = "".join(f"{key}={int(result['traffic'][key])}; " for key in ("upload", "download", "total")) if result.get("traffic") else ""
        self.reply(200, result["content"].encode(), result["content_type"],
                   {"profile-update-interval": "6", "subscription-userinfo": usage + f"expire={expiry}", "Vary": "User-Agent"})

    def do_POST(self):
        try:
            self.post()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except RuntimeError as exc:
            self.json(400, {"error": str(exc)})
        except (ValueError, TypeError, KeyError):
            self.json(400, {"error": "Invalid request"})
        except OSError:
            self.json(503, {"error": "Panel daemon unavailable; check its service"})

    def post(self):
        if not self.trusted_transport() or not self.same_origin():
            self.json(403, {"error": "HTTPS and a same-origin browser request are required (or use localhost through SSH)"})
            return
        if self.headers.get("Transfer-Encoding") or self.headers.get_content_type() != "application/json":
            self.json(415, {"error": "Send a JSON request without transfer encoding"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= MAX_BODY:
            self.json(413, {"error": "Invalid body size"})
            return
        data = json.loads(self.rfile.read(length))
        if not isinstance(data, dict):
            raise ValueError("Object required")
        path = urlsplit(self.path).path
        if path == "/panel/api/login":
            ip = self.headers.get("X-Real-IP", self.client_address[0]) if self.headers.get("X-Forwarded-Proto") else self.client_address[0]
            if not STORE.login_allowed(ip):
                self.json(429, {"error": "Too many login attempts; wait 5 minutes"})
                return
            result = request("web_auth", username=str(data.get("username", "")), password=str(data.get("password", "")))
            if not result["authenticated"]:
                self.json(401, {"error": "Invalid username or password"})
                return
            STORE.delete(self.token())
            token, session = STORE.add(str(data["username"]), result["revision"])
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
            self.json(200, {"username": session["username"], "csrf": session["csrf"]},
                      {"Set-Cookie": f"{COOKIE}={token}; Path=/panel/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}{secure}"})
            return
        session = self.session(csrf=True)
        if not session:
            return
        if path == "/panel/api/logout":
            STORE.delete(self.token())
            self.json(200, {"ok": True}, {"Set-Cookie": f"{COOKIE}=; Path=/panel/; Max-Age=0; HttpOnly; SameSite=Strict"})
        elif path == "/panel/api/command":
            command, params = data.get("command"), data.get("params", {})
            if command not in COMMANDS or not isinstance(params, dict):
                self.json(403, {"error": "Command unavailable"})
                return
            params["_web_revision"] = session["revision"]
            self.json(200, request(command, **params))
        else:
            self.json(404, {"error": "Not found"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request_socket, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request_socket)
            return
        try:
            super().process_request(request_socket, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request_socket, client_address):
        try:
            super().process_request_thread(request_socket, client_address)
        finally:
            self.slots.release()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with Server(("127.0.0.1", 9090), Handler) as server:
        LOG.info("Dashboard on 127.0.0.1:9090")
        server.serve_forever()

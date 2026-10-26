from __future__ import annotations

import http.client
import io
import json
import threading
import zipfile

import pytest

import web_auth
import web_server as web


@pytest.fixture
def client(monkeypatch):
    calls = []
    def backend(command, **params):
        calls.append((command, params))
        if command == "web_auth":
            return {"authenticated": params == {"username": "noway", "password": "correct-password"}, "revision": "revision1"}
        if command == "web_revision":
            return {"revision": "revision1"}
        if command == "xray_export":
            return {"name": "basit", "links": {"vless": "secret-link"}, "files": {"basit-vless.json": '{"outbounds":[]}', "links.txt": "secret-link"}}
        return {"ok": True, "test_result": command}
    monkeypatch.setattr(web, "request", backend)
    monkeypatch.setattr(web, "STORE", web.Store())
    server = web.Server(("127.0.0.1", 0), web.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    host = f"127.0.0.1:{server.server_port}"
    def call(path, data=None, *, cookie="", csrf="", origin=None, forwarded=None):
        conn = http.client.HTTPConnection(host, timeout=5)
        headers = {"Origin": origin or "http://" + host, "Content-Type": "application/json"}
        if cookie: headers["Cookie"] = cookie
        if csrf: headers["X-CSRF-Token"] = csrf
        if forwarded: headers["X-Forwarded-Proto"] = forwarded
        conn.request("GET" if data is None else "POST", "/panel/" + path, body=None if data is None else json.dumps(data), headers=headers)
        response = conn.getresponse(); body = response.read(); response_headers = dict(response.getheaders()); code = response.status; conn.close()
        return code, body, response_headers
    call.calls = calls
    yield call
    server.shutdown(); server.server_close(); thread.join(timeout=3)


def login(client):
    code, body, headers = client("api/login", {"username": "noway", "password": "correct-password"})
    assert code == 200
    return headers["Set-Cookie"].split(";", 1)[0], json.loads(body)["csrf"]


def test_unauthenticated_reads_and_exports_are_denied(client):
    for path in ("api/state", "api/diagnostics", "api/export?name=basit&format=zip"):
        code, body, _ = client(path)
        assert code == 401
        assert b"secret-link" not in body
    assert all(command != "xray_export" for command, _ in client.calls)


def test_csrf_same_origin_and_command_allowlist(client):
    cookie, csrf = login(client)
    data = {"command": "xray_create", "params": {"name": "basit", "days": 30}}
    assert client("api/command", data, cookie=cookie)[0] == 403
    assert client("api/command", data, cookie=cookie, csrf=csrf, origin="https://attacker.example")[0] == 403
    assert client("api/command", {"command": "configure_web"}, cookie=cookie, csrf=csrf)[0] == 403
    assert client("api/command", data, cookie=cookie, csrf=csrf)[0] == 200
    assert client.calls[-1] == ("xray_create", {"name": "basit", "days": 30, "_web_revision": "revision1"})


def test_logout_revokes_session_and_private_zip_needs_session(client):
    cookie, csrf = login(client)
    code, body, headers = client("api/export?name=basit&format=zip", cookie=cookie)
    assert code == 200 and headers["Cache-Control"] == "no-store"
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        assert archive.read("links.txt") == b"secret-link"
    assert client("api/logout", {}, cookie=cookie, csrf=csrf)[0] == 200
    assert client("api/state", cookie=cookie)[0] == 401


def test_public_plain_http_login_is_blocked(client):
    assert client("api/login", {"username": "noway", "password": "correct-password"}, forwarded="http")[0] == 403
    assert not client.calls


def test_login_rate_limit_and_cookie_flags(client):
    for _ in range(8):
        assert client("api/login", {"username": "noway", "password": "wrong"})[0] == 401
    assert client("api/login", {"username": "noway", "password": "wrong"})[0] == 429
    assert len(client.calls) == 8


def test_cookie_http_only_and_no_untrusted_asset_paths(client):
    _, _, headers = client("api/login", {"username": "noway", "password": "correct-password"})
    assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    assert client("../src/web_auth.py")[0] == 404
    code, body, headers = client("")
    assert code == 200 and b"NOWAY" in body
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_credential_hashing_and_rotation(tmp_path, monkeypatch):
    monkeypatch.setattr(web_auth, "AUTH_FILE", tmp_path / "auth.json")
    web_auth.configure({"username": "noway", "password": "correct-password"})
    before = web_auth.revision()
    assert "correct-password" not in web_auth.AUTH_FILE.read_text()
    assert web_auth.authenticate({"username": "noway", "password": "correct-password"})["authenticated"]
    assert not web_auth.authenticate({"username": "noway", "password": "wrong"})["authenticated"]
    web_auth.configure({"username": "noway", "password": "changed-password"})
    assert web_auth.revision() != before
    assert not web_auth.authenticate({"username": "noway", "password": "correct-password"})["authenticated"]


def test_session_idle_expiry(monkeypatch):
    clock = [1000]
    monkeypatch.setattr(web.time, "monotonic", lambda: clock[0])
    store = web.Store(); token, _ = store.add("noway", "revision")
    clock[0] += web.IDLE_TTL + 1
    assert store.get(token) is None

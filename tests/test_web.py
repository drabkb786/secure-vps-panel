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
            return {"name": "basit", "links": {"vless": "secret-link", "trojan": "trojan://fixture-password@vpn.example.com:443?type=ws&security=tls&path=%2Ftrojan"}, "files": {"basit-vless.json": '{"outbounds":[]}', "links.txt": "secret-link"}}
        if command == "ssh_export":
            return {"name": "basit", "links": {"ssh": "ssh://basit@vpn.example.com:109", "wss": "wss://cdn.example.com/bunny/ssh/ws"}, "files": {"ssh-ws-client.py": "fixture adapter", "basit-ssh.json": '{"username":"basit"}'}}
        if command == "subscription_get":
            if params.get("token") != "A" * 43:
                raise RuntimeError("Subscription unavailable")
            return {"name": "basit", "expiry": "2099-01-01", "content": "fixture-subscription", "content_type": "text/plain; charset=utf-8"}
        if command == "cloudfront_setup":
            return {"files": {"parameters.private.json": "private-origin-fixture"}}
        if command == "bunny_setup":
            return {"files": {"bunny-setup.private.txt": "private-bunny-fixture"}}
        if command == "backup_export":
            return {"backup": {"schema": "noway-xray-backup-v1", "accounts": []}}
        return {"ok": True, "test_result": command}
    monkeypatch.setattr(web, "request", backend)
    monkeypatch.setattr(web, "STORE", web.Store())
    server = web.Server(("127.0.0.1", 0), web.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    host = f"127.0.0.1:{server.server_port}"
    def call(path, data=None, *, cookie="", csrf="", origin=None, forwarded=None, user_agent=None, gateway=False, real_ip=None):
        conn = http.client.HTTPConnection(host, timeout=5)
        headers = {"Origin": origin or "http://" + host, "Content-Type": "application/json"}
        if cookie: headers["Cookie"] = cookie
        if csrf: headers["X-CSRF-Token"] = csrf
        if forwarded: headers["X-Forwarded-Proto"] = forwarded
        if gateway:
            import gateway_identity
            headers[gateway_identity.header_name()] = "1"
        if real_ip: headers["X-Real-IP"] = real_ip
        if user_agent: headers["User-Agent"] = user_agent
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
    for path in ("api/state", "api/diagnostics", "api/export?name=basit&format=zip", "api/export?name=basit&format=link&protocol=trojan"):
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


def test_ssh_forward_cannot_forge_https_or_rotate_viewer_rate_key(client):
    data = {"username": "noway", "password": "correct-password"}
    assert client("api/login", data, forwarded="https", origin="https://attacker.example", real_ip="203.0.113.5")[0] == 403
    assert not client.calls


def test_gateway_marker_verifies_https_and_viewer_identity(client):
    # Use a bare handler to verify the same marker Nginx overwrites on requests.
    from email.message import Message
    import gateway_identity
    handler = object.__new__(web.Handler)
    handler.headers = Message(); handler.client_address = ("127.0.0.1", 12345)
    handler.headers["X-Forwarded-Proto"] = "https"
    handler.headers["X-Real-IP"] = "198.51.100.42"
    assert not handler.trusted_transport() and handler.viewer_ip() == "127.0.0.1"
    handler.headers[gateway_identity.header_name()] = "1"
    assert handler.trusted_transport() and handler.viewer_ip() == "198.51.100.42"


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


def test_direct_trojan_txt_is_private_plain_text_without_json_wrapper(client):
    cookie, _ = login(client)
    code, body, headers = client("api/export?name=basit&format=link&protocol=trojan", cookie=cookie)
    assert code == 200
    assert body.startswith(b"trojan://") and body.endswith(b"\n")
    assert headers["Content-Type"] == "text/plain; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert 'filename="basit-trojan.txt"' in headers["Content-Disposition"]


@pytest.mark.parametrize("query", ["format=other", "format=link&protocol=ss", "format=link&protocol=vmess", "format=link&protocol=vless&protocol=trojan"])
def test_invalid_export_format_or_unavailable_protocol_returns_actionable_error(client, query):
    cookie, _ = login(client)
    code, body, _ = client("api/export?name=basit&" + query, cookie=cookie)
    assert code == 400 and "error" in json.loads(body)


def test_live_subscription_requires_bearer_token_but_not_an_admin_cookie(client):
    code, body, headers = client("sub/" + "A" * 43)
    assert code == 200 and body == b"fixture-subscription"
    assert headers["Cache-Control"] == "no-store" and headers["profile-update-interval"] == "6"
    assert "expire=" in headers["subscription-userinfo"]
    assert client.calls[-1] == ("subscription_get", {"token": "A" * 43, "format": "base64", "route": "direct"})
    assert client("sub/" + "B" * 43)[0] == 404
    assert client("sub/short")[0] == 404
    assert client("sub/" + "A" * 43, forwarded="http")[0] == 426


@pytest.mark.parametrize("agent,format_name", [("Clash.Meta", "clash"), ("sing-box", "singbox"), ("v2rayNG", "base64")])
def test_subscription_selects_compatible_format_from_user_agent(client, agent, format_name):
    assert client("sub/" + "A" * 43, user_agent=agent)[0] == 200
    assert client.calls[-1][1]["format"] == format_name


def test_backup_download_is_authenticated_and_not_cached(client):
    assert client("api/backup")[0] == 401
    cookie, _ = login(client)
    code, body, headers = client("api/backup", cookie=cookie)
    assert code == 200 and json.loads(body)["schema"] == "noway-xray-backup-v1"
    assert headers["Cache-Control"] == "no-store" and "attachment" in headers["Content-Disposition"]
    assert client("api/command", {"command": "backup_restore", "params": {}}, cookie=cookie, csrf="wrong")[0] == 403


def test_public_subscription_rate_limit_is_bounded_and_recovers_after_window(monkeypatch):
    clock = [1000]
    monkeypatch.setattr(web.time, "monotonic", lambda: clock[0])
    store = web.Store()
    assert all(store.public_allowed("client") for _ in range(120))
    assert not store.public_allowed("client")
    clock[0] += 61
    assert store.public_allowed("client")


def test_new_ip_entries_remain_bounded_after_global_public_rate_limit():
    store = web.Store()
    for i in range(3000):
        store.public_allowed(f"fixture-{i}")
    assert len(store.public_attempts) <= 2048 and len(store.public_total) == 300


def test_cloudfront_private_setup_and_route_dispatch(client):
    assert client("api/cloudfront-setup")[0] == 401
    cookie, csrf = login(client)
    code, body, headers = client("api/cloudfront-setup", cookie=cookie)
    assert code == 200 and headers["Cache-Control"] == "no-store"
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        assert archive.read("parameters.private.json") == b"private-origin-fixture"
    assert client.calls[-1] == ("cloudfront_setup", {"_web_revision": "revision1"})
    assert client("api/export?name=basit&route=cloudfront", cookie=cookie)[0] == 200
    assert client.calls[-1][1]["route"] == "cloudfront"

    assert client("sub/" + "A" * 43 + "?route=cloudfront")[0] == 200
    assert client.calls[-1][1]["route"] == "cloudfront"
    assert client("api/command", {"command": "cloudfront_configure", "params": {"enabled": True}}, cookie=cookie)[0] == 403
    assert client("api/command", {"command": "cloudfront_setup"}, cookie=cookie, csrf=csrf)[0] == 403


def test_ssh_and_bunny_private_downloads_require_login(client):
    assert client("api/bunny-setup")[0] == 401
    assert client("api/export?kind=ssh&name=basit&route=bunny&format=zip")[0] == 401
    cookie, _ = login(client)
    code, body, _ = client("api/export?kind=ssh&name=basit&route=bunny&format=zip", cookie=cookie)
    assert code == 200
    assert client.calls[-1] == ("ssh_export", {"username": "basit", "route": "bunny", "_web_revision": "revision1"})
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        assert archive.read("ssh-ws-client.py") == b"fixture adapter"
    code, body, _ = client("api/bunny-setup", cookie=cookie)
    assert code == 200
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        assert archive.read("bunny-setup.private.txt") == b"private-bunny-fixture"

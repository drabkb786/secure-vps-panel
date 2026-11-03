import base64
import json
from urllib.parse import parse_qs, urlsplit

import pytest

import cdn_manager as cdn
import paneld
import web_server
import xray_manager as xray
from common import ValidationError, atomic_write_json


@pytest.fixture
def cloudfront(manager, tmp_path, monkeypatch):
    monkeypatch.setattr(cdn, "CONFIG_FILE", tmp_path / "cloudfront.json")
    monkeypatch.setattr(cdn, "DOMAIN_FILE", xray.DOMAIN_FILE)
    monkeypatch.setattr(cdn, "CERT_ROOT", xray.CERT_ROOT)
    installs = []
    obj = cdn.Manager(lambda domain: installs.append(domain))
    obj.installs = installs
    return obj


def test_prepare_attach_disable_and_private_setup(cloudfront):
    assert cloudfront.status()["stage"] == "disabled"
    prepared = cloudfront.configure({"enabled": True})
    secret = cdn.settings()["secret"]
    assert prepared["stage"] == "prepared" and secret not in json.dumps(prepared)
    assert cdn.CONFIG_FILE.stat().st_mode & 0o777 == 0o600
    files = cloudfront.setup()["files"]
    params = {row["ParameterKey"]: row["ParameterValue"] for row in json.loads(files["parameters.private.json"])}
    assert params["OriginSecret"] == secret
    assert secret not in files["cloudfront.json"]
    cloudfront.configure({"enabled": True, "endpoint": "d123example.cloudfront.net"})
    assert cloudfront.status()["stage"] == "attached" and cdn.settings()["secret"] == secret
    assert cdn.delivery("cloudfront", "vpn.example.com") == ("d123example.cloudfront.net", "/cloudfront")
    cloudfront.configure({"enabled": False})
    with pytest.raises(ValidationError): cdn.delivery("cloudfront", "vpn.example.com")
    assert cloudfront.status()["ssh_url"] == ""
    assert len(cloudfront.installs) == 3


def test_bad_reload_rolls_back_and_sanitizes_error(cloudfront):
    cloudfront.configure({"enabled": True})
    before = cdn.CONFIG_FILE.read_bytes()
    def broken(_): raise RuntimeError(cdn.settings()["secret"])
    cloudfront.install_nginx = broken
    with pytest.raises(RuntimeError, match="rolled back") as error:
        cloudfront.configure({"enabled": True, "endpoint": "d123example.cloudfront.net"})
    assert cdn.CONFIG_FILE.read_bytes() == before
    assert cdn.settings()["secret"] not in str(error.value)


@pytest.mark.parametrize("host", ["https://d123example.cloudfront.net", "d123example.cloudfront.net/", "d123example.cloudfront.net.evil.test", "127.0.0.1", "cloudfront.net", "d123example.cloudfront.net\n", "d123example.cloudfront.net:443", None, True])
def test_invalid_distribution_rejected(cloudfront, host):
    with pytest.raises(ValidationError): cloudfront.configure({"enabled": True, "endpoint": host})
    assert not cdn.CONFIG_FILE.exists()


def test_private_dns_never_connected(monkeypatch):
    monkeypatch.setattr(cdn.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    monkeypatch.setattr(cdn.socket, "socket", lambda *a: pytest.fail("Connected to private address"))
    assert not cdn.probe("d123example.cloudfront.net", cdn.PATHS["health"], False)["ok"]


def test_route_exports_preserve_credentials_and_include_routed_xhttp(cloudfront, manager):
    cloudfront.configure({"enabled": True, "endpoint": "d123example.cloudfront.net"})
    manager.configure({"enabled": True, "xhttp_enabled": True})
    manager.create({"name": "edgeuser", "days": 3})
    direct = manager.export({"name": "edgeuser"})
    export = manager.export({"name": "edgeuser", "route": "cloudfront"})
    assert "vless-xhttp" in direct["links"] and "vless-xhttp" in export["links"]
    assert cdn.settings()["secret"] not in json.dumps(export)
    for protocol, link in export["links"].items():
        stream = json.loads(export["files"][f"edgeuser-{protocol}.json"])["outbounds"][0]["streamSettings"]
        assert stream["tlsSettings"]["allowInsecure"] is False
        assert stream["tlsSettings"]["serverName"] == "d123example.cloudfront.net"
        path = cdn.PATHS["xhttp" if protocol == "vless-xhttp" else protocol]
        assert stream["xhttpSettings" if protocol == "vless-xhttp" else "wsSettings"]["path"] == path
        if protocol == "vmess":
            data = json.loads(base64.b64decode(link[8:]))
            assert data["path"] == cdn.PATHS[protocol] and data["add"] == "d123example.cloudfront.net"
        else:
            parsed = urlsplit(link)
            assert parsed.username == urlsplit(direct["links"][protocol]).username
            assert parsed.hostname == "d123example.cloudfront.net" and parse_qs(parsed.query)["path"] == [path]
    for format_name in ("singbox", "clash"):
        content = export["files"]["edgeuser-" + ("singbox.json" if format_name == "singbox" else "clash.yaml")]
        assert "/cloudfront/vless" in content and "vpn.example.com" not in content
    sub = manager.subscription_rotate({"name": "edgeuser"})
    token = sub["url"].rsplit("/", 1)[1]
    for format_name in ("plain", "base64", "xray", "singbox", "clash"):
        result = manager.subscription_get({"token": token, "format": format_name, "route": "cloudfront"})["content"]
        if format_name == "base64": result = base64.b64decode(result).decode()
        assert "cloudfront" in result and cdn.settings()["secret"] not in result
    manager.subscription_revoke({"name": "edgeuser"})
    with pytest.raises(ValidationError): manager.subscription_get({"token": token, "route": "cloudfront"})


def test_template_protects_origin_and_keeps_admin_out():
    tpl = cdn.template()
    assert tpl["Parameters"]["OriginSecret"]["NoEcho"] is True
    assert "Default" not in tpl["Parameters"]["OriginSecret"]
    dist = tpl["Resources"]["Distribution"]["Properties"]["DistributionConfig"]
    origin = dist["Origins"][0]
    assert origin["CustomOriginConfig"]["OriginProtocolPolicy"] == "https-only"
    behavior = dist["DefaultCacheBehavior"]
    assert behavior["CachePolicyId"] == "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    assert behavior["ViewerProtocolPolicy"] == "https-only"
    policy = tpl["Resources"]["OriginPolicy"]["Properties"]["OriginRequestPolicyConfig"]
    assert "Host" not in policy["HeadersConfig"]["Headers"] and policy["CookiesConfig"]["CookieBehavior"] == "none"
    assert {"Referer", "Content-Type", "X-Padding"} <= set(policy["HeadersConfig"]["Headers"])
    assert "cloudfront_setup" in paneld.WEB_COMMANDS and "cloudfront_setup" not in web_server.COMMANDS


def test_origin_domain_change_is_blocked(cloudfront, monkeypatch):
    cloudfront.configure({"enabled": True})
    monkeypatch.setattr(paneld, "DOMAIN_FILE", xray.DOMAIN_FILE)
    monkeypatch.setattr(paneld, "domain_conflicts", lambda _: [])
    monkeypatch.setattr(paneld, "ACME_ROOT", xray.CERT_ROOT)
    with pytest.raises(ValidationError, match="Disable CloudFront"):
        paneld.set_domain({"domain": "other.example.com"})


def test_endpoint_check_is_scoped_and_clear_on_update(cloudfront, monkeypatch):
    cloudfront.configure({"enabled": True, "endpoint": "d123example.cloudfront.net"})
    seen = []
    def probe(host, path, websocket):
        seen.append((host, path, websocket))
        return {"ok": path != cdn.PATHS["trojan"]}
    monkeypatch.setattr(cdn, "probe", probe)
    result = cloudfront.check()
    assert len(seen) == 5 and not result["ok"] and "speed not tested" in result["scope"]
    assert cloudfront.status()["last_check"] == result
    cloudfront.configure({"enabled": True, "endpoint": "d456example.cloudfront.net"})
    assert cloudfront.status()["last_check"] is None

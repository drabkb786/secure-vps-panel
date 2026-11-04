"""Explicit Bunny delivery with an origin secret and edge-derived viewer identity."""
import json
import re
import secrets
from common import BASE_DIR, DOMAIN_FILE, ValidationError, atomic_write, atomic_write_json, read_json, read_text, validate_domain
import cdn_manager

CONFIG_FILE = BASE_DIR / "bunny.json"
PREFIX = "/bunny"
PATHS = {name: path.replace("/cloudfront", PREFIX) for name, path in cdn_manager.PATHS.items()}


def settings():
    cfg = read_json(CONFIG_FILE, {})
    if not isinstance(cfg, dict):
        raise ValidationError("Bunny settings are invalid")
    cfg = {"enabled": False, "endpoint": "", **cfg}
    if cfg["enabled"]:
        validate_domain(cfg.get("origin", ""))
        validate_domain(cfg.get("endpoint", ""))
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", cfg.get("secret", "")):
            raise ValidationError("Bunny origin secret is invalid")
    return cfg


def translate(text):
    return (text.replace("/cloudfront", PREFIX).replace("noway_cf", "noway_bunny")
            .replace("x_noway_origin_verify", "x_noway_bunny_verify")
            .replace("X-Noway-Origin-Verify", "X-Noway-Bunny-Verify")
            .replace("x_noway_viewer_ip", "x_noway_bunny_viewer_ip")
            .replace("X-Noway-CloudFront-Health", "X-Noway-Bunny-Health")
            .replace("noway-cloudfront-origin-v1", "noway-bunny-origin-v1"))


def nginx_maps(cfg):
    return translate(cdn_manager.nginx_maps(cfg))


def nginx_locations(cfg, secure):
    return translate(cdn_manager.nginx_locations(cfg, secure))


class Manager:
    def __init__(self, install_nginx):
        self.install_nginx = install_nginx

    def status(self, _=None):
        cfg = settings()
        return {key: cfg.get(key) for key in ("enabled", "endpoint", "origin", "last_check")} | {
            "paths": PATHS, "notice": "Configure both origin request headers from private setup. Bunny charges apply; client transfer testing is still required."}

    def configure(self, params):
        if not isinstance(params.get("enabled"), bool):
            raise ValidationError("enabled must be a boolean")
        cfg = settings()
        domain = validate_domain(read_text(DOMAIN_FILE))
        cfg["enabled"] = params["enabled"]
        if cfg["enabled"]:
            if not all((cdn_manager.CERT_ROOT / domain / name).is_file() for name in ("fullchain.pem", "privkey.pem")):
                raise ValidationError("Issue the origin TLS certificate first")
            host = validate_domain(str(params.get("endpoint", cfg["endpoint"])))
            if host == domain:
                raise ValidationError("Use a separate CDN hostname; keep the origin DNS-only")
            cfg.update(origin=domain, endpoint=host)
            cfg.setdefault("secret", secrets.token_urlsafe(32))
        cfg.pop("last_check", None)
        old = CONFIG_FILE.read_text() if CONFIG_FILE.exists() else None
        atomic_write_json(CONFIG_FILE, cfg)
        try:
            self.install_nginx(domain)
        except Exception:
            if old is None:
                CONFIG_FILE.unlink(missing_ok=True)
            else:
                atomic_write(CONFIG_FILE, old)
            raise RuntimeError("Bunny change rolled back: Nginx validation or reload failed") from None
        return self.status()

    def setup(self, _=None):
        cfg = settings()
        if not cfg["enabled"]:
            raise ValidationError("Enable Bunny delivery first")
        text = (f"Origin URL: https://{cfg['origin']}\nOrigin Host: {cfg['origin']}\n"
                "Enable WebSockets and verify origin SSL. Forward Host: off.\n"
                "For /bunny/*, override cache time to 0, disable caching/optimizer, and set these ORIGIN REQUEST headers (overwrite incoming values):\n"
                f"X-Noway-Bunny-Verify: {cfg['secret']}\n"
                "X-Noway-Bunny-Viewer-IP: %{User.IP}\n"
                "Never set the secret as a response header or include it in client files.\n"
                f"Client Host/SNI: {cfg['endpoint']}\nSSH WSS path: /bunny/ssh/ws\n"
                "SSH requires a framing-capable client or the provided ssh-ws-client.py adapter.\n"
                "XHTTP uses /bunny/xhttp/ with GET/POST, request buffering off and no cache.\n"
                "Keep DNS CNAME, CDN TLS certificate and transport tests separate from origin readiness.\n"
                "Docs: https://docs.bunny.net/docs/edge-rules-variable-expansion\n")
        return {"files": {"bunny-setup.private.txt": text}}

    def check(self, _=None):
        cfg = settings()
        if not cfg["enabled"]:
            raise ValidationError("Enable Bunny delivery first")
        checks = cdn_manager.probe_paths(cfg["endpoint"], PATHS, provider="bunny")
        report = {"checks": checks, "ok": all(x["ok"] for x in checks.values()),
                  "scope": "TLS, Bunny edge, origin health and WS handshake only; SSH login, XHTTP and sustained transfer require real clients"}
        cfg["last_check"] = report
        atomic_write_json(CONFIG_FILE, cfg)
        return report

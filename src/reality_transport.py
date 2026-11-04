"""Private identities for opt-in VLESS REALITY and non-TLS VLESS Encryption."""
import re
import secrets
from urllib.parse import urlencode, quote
from common import BASE_DIR, ValidationError, atomic_write_json, read_json, validate_domain

KEY_FILE = BASE_DIR / "reality-keys.json"


class vless_encryption:
    """Use the pinned core's matching X25519 VLESS Encryption pair."""
    KEY_FILE = BASE_DIR / 'vless-non-tls-keys.json'
    PORT = 10005
    SERVER = r'mlkem768x25519plus\.native\.600s\.[A-Za-z0-9_-]{43}'
    CLIENT = r'mlkem768x25519plus\.native\.0rtt\.[A-Za-z0-9_-]{43}'

    @classmethod
    def keys(cls):
        if cls.KEY_FILE.is_symlink():
            raise ValidationError('Symlinked VLESS Encryption identity is not allowed')
        data = read_json(cls.KEY_FILE, {})
        if (not isinstance(data, dict) or not re.fullmatch(cls.SERVER, str(data.get('decryption', '')))
                or not re.fullmatch(cls.CLIENT, str(data.get('encryption', '')))):
            raise ValidationError('VLESS Encryption identity missing/invalid; enable the non-TLS route first')
        return data

    @classmethod
    def initialize(cls, run, binary):
        if cls.KEY_FILE.is_symlink() or cls.KEY_FILE.parent.is_symlink():
            raise ValidationError('Unsafe VLESS Encryption identity path')
        if cls.KEY_FILE.exists():
            cls.keys()
            return
        output = run([str(binary), 'vlessenc'], timeout=10).stdout
        # Upstream prints distinct X25519 and ML-KEM authentication pairs.
        # Select the complete X25519 pair; never mix the two methods.
        server = re.findall(r'"decryption":\s*"(' + cls.SERVER + r')"', output)
        client = re.findall(r'"encryption":\s*"(' + cls.CLIENT + r')"', output)
        if len(server) != 1 or len(client) != 1:
            raise RuntimeError('Unexpected official Xray vlessenc output; no identity was saved')
        atomic_write_json(cls.KEY_FILE, {'decryption': server[0], 'encryption': client[0]})
        cls.keys()


def port(value):
    try:
        value = int(str(value))
    except (ValueError, TypeError):
        raise ValidationError("REALITY port must be an integer")
    if not 1024 <= value <= 65535 or value in {2082, 9090, 10001, 10002, 10003, 10004, 10005}:
        raise ValidationError("Choose a free public port >=1024, excluding internal listeners")
    return value


def keys():
    data = read_json(KEY_FILE, {})
    if not isinstance(data, dict) or any(not re.fullmatch(r"[A-Za-z0-9_-]{43}", data.get(k, "")) for k in ("private", "public")) or not re.fullmatch(r"[a-f0-9]{16}", data.get("short_id", "")):
        raise ValidationError("REALITY keys missing/invalid; enable REALITY from the root CLI")
    return data


def initialize(run, binary):
    if KEY_FILE.exists():
        keys(); return
    output = run([str(binary), "x25519"], timeout=10).stdout
    fields = dict(re.findall(r"^(PrivateKey|Private key|Password|PublicKey|Public key)(?: \(PublicKey\))?:[ \t]*(\S+)[ \t]*$", output, re.M))
    private = fields.get("PrivateKey", fields.get("Private key", ""))
    public = fields.get("Password", fields.get("PublicKey", fields.get("Public key", "")))
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", private) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", public):
        raise RuntimeError("Unexpected official Xray X25519 output")
    atomic_write_json(KEY_FILE, {"private": private, "public": public, "short_id": secrets.token_hex(8)})


def inbound(config, clients, domain):
    key = keys()
    return {"tag": "noway-reality", "listen": "0.0.0.0", "port": port(config.get("reality_port", 8443)),
            "protocol": "vless", "settings": {"decryption": "none", "clients": clients},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "show": False, "target": "127.0.0.1:443", "xver": 0,
                "serverNames": [validate_domain(domain)], "privateKey": key["private"], "shortIds": [key["short_id"]]}}}


def client(row, domain, number):
    key = keys()
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": domain, "port": number,
                "users": [{"id": row["uuid"], "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
                "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                    "serverName": domain, "fingerprint": "chrome", "password": key["public"], "shortId": key["short_id"]}}}]}


def link(row, domain, number):
    key = keys()
    query = {"security": "reality", "type": "tcp", "flow": "xtls-rprx-vision", "encryption": "none",
             "sni": domain, "fp": "chrome", "pbk": key["public"], "sid": key["short_id"]}
    return f"vless://{row['uuid']}@{domain}:{number}?{urlencode(query)}#{quote('NOWAY-' + row['name'] + '-REALITY')}"

"""Managed tunnel backend only. The machine's administrative sshd is separate."""
from pathlib import Path
import re
from common import BASE_DIR, read_text

BACKEND_FILE = BASE_DIR / "ssh-backend"
OPENSSH_UNIT = "abdulbasit-sshd"
GROUP = "abdulbasit-tunnel"
GATEWAY_FILE = BASE_DIR / "gateway-backend"
HAPROXY_SECRET_FILE = BASE_DIR / "haproxy-verify"
DROPBEAR_BINARY = Path("/usr/local/lib/abdulbasit/dropbear")
DROPBEAR_VERSION = "2026.94"
HAPROXY_UNIT = "abdulbasit-haproxy"


def native_dropbear():
    return read_text(BACKEND_FILE) == "dropbear-2026"


def group_required():
    return name() == "openssh" or native_dropbear()


def dropbear_binary():
    return str(DROPBEAR_BINARY) if native_dropbear() else "/usr/sbin/dropbear"


def haproxy_enabled():
    return read_text(GATEWAY_FILE) == "haproxy"


def haproxy_secret():
    secret = read_text(HAPROXY_SECRET_FILE)
    if not re.fullmatch(r"[a-f0-9]{64}", secret):
        raise RuntimeError("HAProxy verification identity is missing/invalid; run the gateway migration")
    return secret


def haproxy_config(secret, *, public_ports=(80, 443), http_port=8080, tls_port=8081, ipv6=False):
    if not re.fullmatch(r"[a-f0-9]{64}", secret):
        raise ValueError("Invalid private HAProxy identity")
    if any(type(p) is not int or not 1 <= p <= 65535 for p in (*public_ports, http_port, tls_port)):
        raise ValueError("Invalid gateway port")
    ports = (*public_ports, http_port, tls_port)
    if not public_ports or len(set(ports)) != len(ports):
        raise ValueError("Gateway needs a public port and distinct public, HTTP and TLS listener ports")
    binds = "\n".join(f"    bind 0.0.0.0:{p}" + (f"\n    bind [::]:{p} v6only" if ipv6 else "") for p in public_ports)
    return f'''# Managed by NOWAY. TLS terminates at loopback Nginx.
global
    log stdout format raw local0
    user haproxy
    group haproxy
    maxconn 4096
defaults
    log global
    mode tcp
    option tcplog
    option clitcpka
    option srvtcpka
    timeout connect 5s
    timeout client 1h
    timeout server 1h
    timeout client-fin 10s
    timeout server-fin 10s
frontend noway_public
{binds}
    unique-id-format {secret}
    tcp-request inspect-delay 5s
    tcp-request content accept if {{ req.ssl_hello_type 1 }}
    tcp-request content accept if {{ req.len ge 1 }} !{{ req.payload(0,1) -m bin 16 }}
    use_backend noway_tls if {{ req.ssl_hello_type 1 }}
    default_backend noway_http
backend noway_http
    server nginx_http 127.0.0.1:{http_port} send-proxy-v2 proxy-v2-options unique-id
backend noway_tls
    server nginx_tls 127.0.0.1:{tls_port} send-proxy-v2 proxy-v2-options unique-id
'''


def name():
    # Older installations have no marker and must remain attributable until migrated.
    return "openssh" if read_text(BACKEND_FILE) == "openssh" else "dropbear"


def unit():
    return OPENSSH_UNIT if name() == "openssh" else "dropbear"


def config(ports=(109, 447), directory="/etc/abdulbasit-sshd", legacy_crypto=False):
    """OpenSSH 8.9+ compatible; no remote shell or remote/listening forwards."""
    return "\n".join([
        *(f"Port {port}" for port in ports),
        f"HostKey {directory}/ssh_host_ed25519_key",
        f"HostKey {directory}/ssh_host_rsa_key",
        "PidFile /run/abdulbasit-sshd/sshd.pid",
        "SyslogFacility AUTH", "LogLevel VERBOSE", "UsePAM yes",
        f"AllowGroups {GROUP}", "PermitRootLogin no", "StrictModes yes",
        "PasswordAuthentication yes", "PubkeyAuthentication yes",
        "AuthorizedKeysFile .ssh/authorized_keys", "PermitEmptyPasswords no",
        "KbdInteractiveAuthentication no", "AuthenticationMethods any",
        "AllowTcpForwarding local", "PermitOpen any", "AllowStreamLocalForwarding no",
        "GatewayPorts no", "PermitTunnel no", "AllowAgentForwarding no",
        "X11Forwarding no", "PermitTTY yes", "PermitUserRC no",
        "PermitUserEnvironment no", "MaxSessions 10", "MaxAuthTries 3",
        "ForceCommand /usr/local/lib/abdulbasit/tunnel-shell",
        "LoginGraceTime 30", "MaxStartups 20:30:100",
        "ClientAliveInterval 30", "ClientAliveCountMax 3", "TCPKeepAlive yes",
        "UseDNS no", "Compression no", "PrintMotd no", "PrintLastLog no",
        "Banner /etc/abdulbasit/ssh-banner.txt",
        *(["HostKeyAlgorithms +ssh-rsa", "PubkeyAcceptedAlgorithms +ssh-rsa",
           "KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"]
          if legacy_crypto else []), "",
    ])


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--legacy-crypto', action='store_true', help='Explicit compatibility mode for clients lacking modern SSH algorithms')
    args = parser.parse_args()
    print(config(legacy_crypto=args.legacy_crypto), end="")

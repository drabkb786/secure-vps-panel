"""Managed tunnel backend only. The machine's administrative sshd is separate."""
from pathlib import Path
from common import BASE_DIR, read_text

BACKEND_FILE = BASE_DIR / "ssh-backend"
OPENSSH_UNIT = "abdulbasit-sshd"
GROUP = "abdulbasit-tunnel"


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

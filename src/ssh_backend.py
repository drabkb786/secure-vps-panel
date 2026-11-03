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


def config(ports=(109, 447), directory="/etc/abdulbasit-sshd"):
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
        "X11Forwarding no", "PermitTTY no", "PermitUserRC no",
        "PermitUserEnvironment no", "MaxSessions 0", "MaxAuthTries 3",
        "LoginGraceTime 30", "MaxStartups 20:30:100",
        "ClientAliveInterval 30", "ClientAliveCountMax 3", "TCPKeepAlive yes",
        "UseDNS no", "Compression no", "PrintMotd no", "PrintLastLog no",
        "Banner /etc/abdulbasit/ssh-banner.txt", "",
    ])


if __name__ == "__main__":
    print(config(), end="")

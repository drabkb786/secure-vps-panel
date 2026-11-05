"""SSH sharing with root-private saved passwords and two simple copy values."""
import json
import re
from datetime import date
from urllib.parse import quote
from common import SSH_UPGRADE_PATHS, DOMAIN_FILE, ValidationError, read_text, validate_domain, validate_ssh_password, validate_username
import cdn_manager
import slowdns
import ssh_secrets


def export(params, lookup):
    user = validate_username(str(params.get("username", "")))
    account = lookup(user)
    if account.get("username", user) != user:
        raise ValidationError("SSH account identity does not match")
    account = {**account, "username": user}
    if not account.get("enabled", True) or date.fromisoformat(account["expiry"]) <= date.today():
        raise ValidationError("Renew/unlock this SSH account before exporting")
    domain = validate_domain(read_text(DOMAIN_FILE))
    route = params.get("route", "direct")
    host, prefix = cdn_manager.delivery(route, domain)
    port = params.get("port", 80 if route == "direct" else 443)
    if type(port) is not int or port not in ({80, 443} if route == "direct" else {443}):
        raise ValidationError("Choose port 80 or 443 for direct; CDN routes use 443")
    alias = params.get("path", "/cdn-cgi")
    if alias not in (SSH_UPGRADE_PATHS if route == "direct" else ("/cdn-cgi",)):
        raise ValidationError("Choose a supported direct SSH path; CDN exports use the provider alias")
    share_path = prefix + alias
    password = params.get("password")
    if password is not None:
        password = validate_ssh_password(password)
        if params.get("remember_password") is True:
            ssh_secrets.save(account, password)
    else:
        password = ssh_secrets.load(account)
    payload = f"GET {share_path} HTTP/1.1[crlf]Host: {host}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
    share = {"credentials": f"{host}:{port}@{user}:{password or ''}", "payload": payload}
    share_notes = []
    if password is None:
        share_notes.append("This account predates saved sharing passwords, or its OS password changed. Save its current password once; hashes cannot be reversed.")
    if route != "direct":
        share_notes.append("CDN SSH requires actual binary WebSocket mode. A raw payload alone does not provide framing. This alias also needs the updated origin/provider route configuration.")
    elif port == 443:
        share_notes.append(f"TLS mode: enable certificate verification and use SNI {host}.")
    summary = {"name": user, "share": share, "password_available": password is not None,
               "share_warnings": share_notes}
    if params.get("simple") is True:
        return summary
    credential = quote(user, safe="") + (":" + quote(password, safe="") if password is not None else "")
    path = share_path
    profile = {"schema": "noway-ssh-v1", "username": user, "host": host, "port": 443,
               "transport": "websocket", "path": path, "tls": True, "server_name": host,
               "verify_certificate": True, "http_host": host, "requires_rfc6455": True,
               "route": route, "max_sessions": account["max_sessions"],
               "max_ips": account.get("max_ips", 0), "expiry": account["expiry"]}
    if password is not None:
        profile["password"] = password
    links = {"ssh": f"ssh://{credential}@{domain}:109", "wss": f"wss://{host}{path}"}
    command = f'ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o "ProxyCommand=python3 ssh-ws-client.py --host {host} --path {path}" -p 109 -N -D 127.0.0.1:10888 {user}@{domain}'
    notes = ["The ssh:// URI is direct SSH on 109. App support for SSH URIs varies.",
             "The wss:// URL identifies a transport, not a complete SSH login/import URI.",
             "For WSS use the supplied adapter as OpenSSH ProxyCommand; a raw HTTP payload alone cannot encode WebSocket frames.",
             "On Windows use python instead of python3 if appropriate, and put the adapter in the current directory.",
             "Verify the SSH host-key fingerprint against your server before accepting it.",
             "SSH usernames/passwords are separate from VLESS/VMess UUIDs and Trojan credentials."]
    files = {f"{user}-ssh.json": json.dumps(profile, indent=2) + "\n",
             "links.txt": "\n".join(links.values()) + "\n",
             "connect.txt": f"Direct:\nssh -N -D 127.0.0.1:10888 -p 109 {user}@{domain}\n\nWSS:\n{command}\n"}
    # Never fabricate a proprietary .nm/.ehi format.
    if route == "direct":
        direct = {"schema": "noway-ssh-direct-v1", "username": user, "host": domain,
                  "port": 109, "tls": False, "transport": "ssh", "proxy_type": "none"}
        if password is not None: direct["password"] = password
        files[f"{user}-direct.json"] = json.dumps(direct, indent=2) + "\n"
        files[f"{user}-direct-alt.json"] = json.dumps({**direct, "port": 447}, indent=2) + "\n"
        plain_ws = {**profile, "port": 80, "tls": False}
        for field in ("server_name", "verify_certificate"): plain_ws.pop(field, None)
        files[f"{user}-ws-non-tls.json"] = json.dumps(plain_ws, indent=2) + "\n"
        links["ws"] = f"ws://{domain}{share_path}"
        files["links.txt"] = "\n".join(links.values()) + "\n"
        files["connect.txt"] += (f'\nWS non-TLS:\nssh -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o "ProxyCommand=python3 ssh-ws-client.py --host {domain} --no-tls" -p 109 -N -D 127.0.0.1:10888 {user}@{domain}\n'
                                 f'\nClient route probes (run on the client, not the VPS):\npython3 ssh-ws-client.py --host {domain} --no-tls --path /ssh/raw --probe --raw\n'
                                 f'python3 ssh-ws-client.py --host {domain} --path /ssh/raw --probe --raw\n'
                                 f'python3 ssh-ws-client.py --host {domain} --no-tls --probe\n'
                                 f'python3 ssh-ws-client.py --host {domain} --probe\n')
        files["legacy-raw-payload.txt"] = payload + "\n"
        notes.append("legacy-raw-payload.txt is for direct origin port 80 (or TLS 443) and raw-upgrade SSH clients only; it is not a CDN WSS profile.")
        raw = {"schema": "noway-ssh-raw-v1", "username": user, "host": domain,
               "port": 80, "tls": False, "transport": "http-upgrade-raw",
               "path": share_path, "http_host": domain, "proxy_type": "none",
               "requires_rfc6455": False, "payload": files["legacy-raw-payload.txt"].strip()}
        if password is not None:
            raw["password"] = password
        files[f"{user}-raw-http.json"] = json.dumps(raw, indent=2) + "\n"
        raw_tls = {**raw, "port": 443, "tls": True, "server_name": domain, "verify_certificate": True}
        files[f"{user}-raw-tls.json"] = json.dumps(raw_tls, indent=2) + "\n"
        files["client-settings.txt"] = (
            f"SSH username: {user}\nPassword: use this account's current password\n\n"
            f"Direct SSH: {domain}:109 or :447; TLS none; payload empty; proxy none.\n"
            f"Raw HTTP Upgrade: {domain}:80; TLS none; proxy none.\n"
            f"Raw TLS Upgrade: {domain}:443; TLS on; verify certificate; SNI {domain}; proxy none.\n"
            f"Payload for either raw mode:\n{raw['payload']}\n"
            "Raw mode must omit Sec-WebSocket-Key and Sec-WebSocket-Version.\n\n"
            f"Binary WS non-TLS: {domain}:80; TLS none; Host {domain}; path {share_path}.\n"
            f"Binary WSS: {host}:443; TLS on; SNI/Host {host}; path {path}.\n"
            "Use actual RFC6455 binary framing for WSS; a raw payload is not a framed WSS client.\n"
            "These JSON/TXT files document settings; they are not proprietary .nm/.ehi import files.\n"
            "A local pre-request 200 message is not the remote server's HTTP response.\n"
            "No client/mobile reachability or SSH authentication was tested by exporting these files.\n")
    else:
        files["client-settings.txt"] = (
            f"SSH username: {user}\nPassword: use this account's current password\n"
            f"Authorized {route} WSS endpoint: {host}:443\nTLS: on; verify certificate\n"
            f"SNI/Host: {host}\nWebSocket path: {path}\nProxy type: none\n"
            "Requires RFC6455 binary WebSocket framing, not raw HTTP payload mode.\n"
            "Configure both private edge-origin headers using the provider setup export.\n"
            "No client/mobile reachability or SSH authentication was tested by exporting these files.\n")
    tunnel = slowdns.settings()
    if tunnel["enabled"]:
        key = read_text(slowdns.PUBLIC_KEY)
        if account.get("max_ips", 0):
            notes.append("This account has an IP limit and cannot use SlowDNS, whose viewer IP is unavailable. Set its IP cap to 0 first.")
        elif not re.fullmatch(r"[a-fA-F0-9]{64}", key):
            notes.append("SlowDNS is enabled but its public key is invalid; no unusable dnstt profile was exported.")
        else:
            zone, ns_host = validate_domain(tunnel["zone"]), validate_domain(tunnel["ns_host"])
            dns_profile = {"schema": "noway-ssh-dnstt-v1", "transport": "dnstt", "username": user,
                           "zone": zone, "nameserver": ns_host, "public_key": key,
                           "resolver": "YOUR_DNS_RESOLVER:53", "server_udp_port": tunnel["port"],
                           "local_host": "127.0.0.1", "local_port": 7000, "ssh_upstream": "127.0.0.1:109"}
            if password is not None: dns_profile["password"] = password
            files[f"{user}-dnstt.json"] = json.dumps(dns_profile, indent=2) + "\n"
            files["slowdns.txt"] = (f"dnstt-client -udp YOUR_DNS_RESOLVER:53 -pubkey {key} {zone} 127.0.0.1:7000\n"
                                    f"ssh -o HostKeyAlias={domain} -o ServerAliveInterval=30 -N -D 127.0.0.1:10888 -p 7000 {user}@127.0.0.1\n\n"
                                    "Keep dnstt-client running in one terminal, then run SSH in another.\n"
                                    "YOUR_DNS_RESOLVER is a reachable recursive resolver, separate from the tunnel zone and authoritative nameserver.\n"
                                    "DNS delegation/listener checks do not prove an external DNS tunnel connection.\n")
    from pathlib import Path
    adapter = Path(__file__).with_name("ssh_ws_client.py")
    if adapter.is_file():
        files["ssh-ws-client.py"] = adapter.read_text()
    if password is not None and "client-settings.txt" in files:
        files["client-settings.txt"] = files["client-settings.txt"].replace("Password: use this account's current password", "Password: " + password)
    files["README.txt"] = "\n".join(notes) + "\nInstall adapter dependency: python -m pip install 'wsproto==1.3.2' 'h11==0.16.0'\nPassword is prompted by SSH unless explicitly embedded in this private export.\n"
    return {**summary, "links": links, "files": files, "profile": profile,
            "readiness": {"public_reachability": "not_checked", "warnings": notes}}

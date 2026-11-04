"""Small, original adapters for officially documented WS/TLS client schemas."""
from __future__ import annotations

PATHS = {"vless": "/vless", "vmess": "/vmess", "trojan": "/trojan"}


def singbox_config(row: dict, domain: str, prefix: str = "") -> dict:
    proxies = []
    for protocol in row["protocols"]:
        proxy = {"type": protocol, "tag": f"NOWAY-{row['name']}-{protocol}",
                 "server": domain, "server_port": 443,
                 "tls": {"enabled": True, "server_name": domain, "insecure": False, "alpn": ["http/1.1"]},
                 "transport": {"type": "ws", "path": prefix + PATHS[protocol], "headers": {"Host": domain}}}
        if protocol == "trojan":
            proxy["password"] = row["trojan_password"]
        else:
            proxy["uuid"] = row["uuid"]
        if protocol == "vmess":
            proxy.update({"security": "auto", "alter_id": 0})
        proxies.append(proxy)
    return {"log": {"level": "warn"},
            "inbounds": [{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": 10808}],
            "outbounds": [{"type": "selector", "tag": "NOWAY", "outbounds": [p["tag"] for p in proxies]}] + proxies,
            "route": {"final": "NOWAY"}}


def clash_config(row: dict, domain: str, prefix: str = "") -> dict:
    """Returned JSON is also valid YAML, accepted by Mihomo/Clash.Meta."""
    proxies = []
    for protocol in row["protocols"]:
        proxy = {"name": f"NOWAY-{row['name']}-{protocol}", "type": protocol,
                 "server": domain, "port": 443, "tls": True, "skip-cert-verify": False,
                 "network": "ws", "udp": True, "alpn": ["http/1.1"],
                 "ws-opts": {"path": prefix + PATHS[protocol], "headers": {"Host": domain}}}
        proxy["sni" if protocol == "trojan" else "servername"] = domain
        if protocol == "trojan":
            proxy["password"] = row["trojan_password"]
        else:
            proxy["uuid"] = row["uuid"]
        if protocol == "vmess":
            proxy.update({"alterId": 0, "cipher": "auto"})
        proxies.append(proxy)
    return {"mixed-port": 10808, "allow-lan": False, "mode": "rule", "log-level": "warning",
            "proxies": proxies, "proxy-groups": [{"name": "NOWAY", "type": "select", "proxies": [p["name"] for p in proxies]}],
            "rules": ["MATCH,NOWAY"]}

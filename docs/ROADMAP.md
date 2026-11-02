# NOWAY VPS Control Room — implementation sequence

## Implemented in v3

1. **Repair the existing base.** Fix free-port detection (`ss -H`), restart services on upgrades, avoid saving a domain when Nginx rejects it, restart Telegram after token changes, align session expiry with the OS expiry date, allow shadow-utils to create their lock/temp files, register a tunnel-only shell, migrate only managed `/bin/false` accounts, and buffer partial writes in the SSH upgrade relay.
2. **Browser dashboard.** Responsive navy/emerald NOWAY design, overview, server metrics, service status/restart, SSH creation/renewal/deletion, Xray profiles, DNS/SSL and diagnostics. Root daemon remains behind a UNIX socket; the HTTP worker is unprivileged and loopback-only.
3. **Admin access.** Root CLI credential setup, salted scrypt hashes, server-side sessions, password-reset revocation, HttpOnly/SameSite cookies, Secure cookies through TLS, same-origin POST checks, CSRF tokens, bounded login attempts and HTTP workers. No shipped default password.
4. **DNS and TLS.** Xray resolver configuration (IPs and HTTPS DoH), IPv4/IPv6 strategy, A/AAAA lookup, certificate issuance through the existing ACME webroot and certificate/clock diagnostics.
5. **Xray engine.** Optional, checksum-verified official binary, isolated systemd service and loopback VLESS/VMess/Trojan WS inbounds. TLS terminates at Nginx. Add/renew/disable/delete accounts with rollback after a failed config test or restart. Expiry is enforced by a one-minute timer.
6. **Client delivery.** Per-protocol import links and Xray client JSON, individual TXT files, base64 subscription text, private ZIP download and CLI export. `xray-link` prints a plain VLESS/VMess/Trojan URI; Telegram admins can retrieve links through **Xray Links**.
7. **Regression coverage.** Authentication, CSRF, IPC permissions, failed updates, expiry, exports and optional real-Xray TLS/WebSocket transport tests. Retain Telegram administration; browser and CLI are the new profile-management interfaces.

## Deployment gate — requires the actual VPS

- Back up the existing installation, then install v3.2 on Ubuntu/Debian.
- Verify the public domain's A/AAAA records, ACME issuance and provider firewall.
- Run diagnostics and import each profile into the user's actual client/device.
- Check browser login, reconnect after restart, renewal and certificate renewal on that host.
- Investigate any host/network-specific failure using its real logs; local tests cannot establish universal reachability.

## Implemented in v3.1 after GitHub comparison

1. **Live subscriptions:** profile-specific private URLs, token hashing, rotation/revoke,
   expiry/disable enforcement, bounded requests and sensitive-route log suppression.
2. **Client formats and QR:** local QR generation, sing-box JSON and Mihomo/Clash.Meta
   configuration alongside Xray/URI/ZIP exports. The two new client adapters use WS/TLS.
3. **Recovery:** scoped Xray backup download and root-only restore with strict validation,
   recovery copies and rollback. Corrupt JSON metadata can be recovered from a valid backup.
4. **VLESS XHTTP:** an opt-in variant with Nginx HTTP/2, TLS and a loopback listener;
   verified by importing the generated URI into real Xray and sending traffic.

The bounded comparison and adoption decisions are in [PANEL_RESEARCH.md](PANEL_RESEARCH.md).

## Follow-up phases (not implemented in this release)

- REALITY presets, additional transport choices and live gRPC config application.
  Current Xray emits deprecation notices for legacy WS, VMess and Trojan; those
  requested compatibility protocols still work in the tested pinned core.
- Validated per-account SSH byte accounting and exact packet-level quota cutoff;
  v3.2 already provides Xray sampled payload accounting/quotas and activity IPs.
- DNS-provider API record editing and a general authoritative DNS service.
  v3.2 already provides an optional dnstt tunnel and delegation checks; resolver
  settings remain distinct from DNS provider records.
- Xray profile creation inside Telegram, multi-role web accounts, multi-node management,
  first-use expiry, signed updates and encrypted full-system backup workflows.
  Existing profile export and scoped Xray recovery are implemented.

These follow-ups must preserve working credentials, profiles and SSH administration.

## Implemented in v3.2 from the reference menu

Exact 24-hour Xray trials, sampled payload quotas/reset, authenticated recent IPs,
SSH/Xray locks, UDP policy, official dnstt SlowDNS integration, operations/logs/
packet tests, SSH banner editing and explicit root maintenance are implemented.
See [OPERATIONS.md](OPERATIONS.md) for the complete 20-control mapping and precise
scope. Multi-node, REALITY and exact SSH byte quotas are not claimed.

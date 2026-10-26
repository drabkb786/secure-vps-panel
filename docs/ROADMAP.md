# NOWAY VPS Control Room — implementation sequence

## Implemented in v3

1. **Repair the existing base.** Fix free-port detection (`ss -H`), restart services on upgrades, avoid saving a domain when Nginx rejects it, restart Telegram after token changes, align session expiry with the OS expiry date, allow shadow-utils to create their lock/temp files, register a tunnel-only shell, migrate only managed `/bin/false` accounts, and buffer partial writes in the SSH upgrade relay.
2. **Browser dashboard.** Responsive navy/emerald NOWAY design, overview, server metrics, service status/restart, SSH creation/renewal/deletion, Xray profiles, DNS/SSL and diagnostics. Root daemon remains behind a UNIX socket; the HTTP worker is unprivileged and loopback-only.
3. **Admin access.** Root CLI credential setup, salted scrypt hashes, server-side sessions, password-reset revocation, HttpOnly/SameSite cookies, Secure cookies through TLS, same-origin POST checks, CSRF tokens, bounded login attempts and HTTP workers. No shipped default password.
4. **DNS and TLS.** Xray resolver configuration (IPs and HTTPS DoH), IPv4/IPv6 strategy, A/AAAA lookup, certificate issuance through the existing ACME webroot and certificate/clock diagnostics.
5. **Xray engine.** Optional, checksum-verified official binary, isolated systemd service and loopback VLESS/VMess/Trojan WS inbounds. TLS terminates at Nginx. Add/renew/disable/delete accounts with rollback after a failed config test or restart. Expiry is enforced by a one-minute timer.
6. **Client delivery.** Per-protocol import links and Xray client JSON, base64 subscription text, private ZIP download and CLI export.
7. **Regression coverage.** Authentication, CSRF, IPC permissions, failed updates, expiry, exports and optional real-Xray TLS/WebSocket transport tests. Retain Telegram administration; browser and CLI are the new profile-management interfaces.

## Deployment gate — requires the actual VPS

- Back up the existing installation, then install v3 on Ubuntu/Debian.
- Verify the public domain's A/AAAA records, ACME issuance and provider firewall.
- Run diagnostics and import each profile into the user's actual client/device.
- Check browser login, reconnect after restart, renewal and certificate renewal on that host.
- Investigate any host/network-specific failure using its real logs; local tests cannot establish universal reachability.

## Follow-up phases (not implemented in this release)

- VLESS XHTTP / REALITY presets and transport selection. Current Xray emits deprecation notices for legacy WS, VMess and Trojan; those requested compatibility protocols still work in the tested pinned core.
- Enforced bandwidth quotas and live traffic accounting through the Xray statistics API; existing SSH quotas remain metadata.
- DNS-provider API record editing, authoritative DNS or a SlowDNS transport, if specifically requested. The v3 DNS page configures resolvers and checks records; it is not a public DNS server.
- Xray profile creation/export inside Telegram, multi-role web accounts and a signed update/backup workflow.

These follow-ups must preserve working credentials, profiles and SSH administration.

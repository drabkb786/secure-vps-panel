# Security Policy

## Supported release

Security fixes are made against the current v3 branch. Older generated scripts and legacy `raretriccks-*` services are not supported.

## Secrets that must never be committed

- Telegram bot tokens
- VPS/user passwords
- SSH or DNSTT private keys
- CloudFront origin-verification secrets
- Certificate private keys
- Production files copied from `/etc/abdulbasit`
- Generated user exports

Deleting a secret from the latest commit does not delete Git history. Rotate any exposed credential before doing anything else.

## Trust boundaries

Public traffic terminates at Nginx, with optional DNSTT on a dedicated UDP/53 address. Xray, its Stats API, the web dashboard, and the SSH WebSocket bridge bind only to loopback.

The Internet-facing Telegram bot and dashboard run as separate unprivileged users. They communicate with the root daemon over `/run/abdulbasit/paneld.sock`. The daemon:

- verifies the UNIX peer UID;
- exposes its socket only to the dedicated `abdulbasit-clients` group (bot and dashboard, not Xray/DNSTT);
- separates root, bot and dashboard command allow-lists;
- restricts bot service-restart and certificate parameters at the privileged boundary;
- caps requests at 16 KiB and responses at 1 MiB;
- accepts only registered JSON operations;
- validates every user-controlled parameter at the privileged boundary;
- invokes subprocesses with argument arrays and no shell;
- changes/deletes only accounts with safe panel-owned metadata;
- uses an inter-process state lock and atomic file replacement;
- validates Xray/Nginx candidates and rolls back failed deployment.

The bot cannot configure CDN origin secrets, configure the DNSTT server, configure dashboard authentication or replace bot credentials through its socket role. The dashboard cannot manage Telegram admins, bot credentials, certificates/domains or service restarts.

## Secret isolation

- `/etc/abdulbasit/cdn.json` is `0600 root:root`.
- The generated Nginx file is `0600 root:root` because it may contain the CloudFront origin secret.
- Dashboard authentication is `0640 root:abdulbasit-dashboard`.
- DNSTT private state is restricted to the DNSTT group.
- Xray credentials and generated client files are root-only.
- Public API/status responses redact the CDN origin secret and Xray credentials.

## Dashboard controls

- PBKDF2-SHA256 password hashing with 600,000 iterations and a random salt
- Signed eight-hour stateless sessions
- `Secure`, `HttpOnly`, `SameSite=Strict` cookie
- CSRF token on every mutation
- login failure throttling
- strict CSP, frame denial, no-store and MIME-sniffing protection
- 64 KiB request limit
- loopback bind plus systemd IP restrictions
- Nginx TLS-only `/panel/` route

## Network controls

- TLS is mandatory for public VMess/VLESS/Trojan exports.
- Plain HTTP does not expose Xray protocol paths.
- CloudFront uses a custom HTTPS origin header checked only on dedicated `/cloudfront/*` routes.
- Requests carrying that CloudFront origin header are rejected on direct protocol, dashboard and legacy SSH routes.
- Xray blocks private/reserved destinations and BitTorrent.
- Nginx overwrites forwarded source headers rather than trusting viewer-supplied values.
- DNSTT forwards only to loopback Dropbear and runs unprivileged with `CAP_NET_BIND_SERVICE` only.

## Limits and accounting

Xray statistics provide per-user uplink/downlink bytes. A one-minute timer resets and persists counters, aggregates VMess/VLESS/Trojan under the user's statistics identity, and removes expired or over-quota users from Xray. Once written, an idempotent root-only pending journal replays interrupted persistence without applying the same collection transaction twice.

SSH/DNSTT byte usage is not part of this counter. SSH and DNSTT are still controlled by Linux expiry and Dropbear concurrent-session limits. This distinction is intentional; process I/O is not presented as network bandwidth.

## Supply-chain controls

- Xray v26.3.27 stable archives are pinned to per-architecture SHA-256 values.
- DNSTT is pinned to upstream commit `0c5c52a57d899c05428c116898941761a2ed83c2` (`v1.20260501.0`).
- The temporary Go 1.26.5 toolchain is pinned to official per-architecture SHA-256 values.
- Go module checksums are verified by the Go module system.
- Installed files are copied into root-owned paths; runtime service users cannot modify application code.

## Known limitations

- A root daemon remains necessary for Linux account, Nginx, Certbot and systemd administration.
- The root daemon's systemd unit must permit `/etc` writes because shadow/account tools create transient lock files there; `/usr` and `/boot` remain protected, while daemon command/parameter validation is the main `/etc` mutation boundary.
- A fully compromised bot process can invoke the bot role's finite command set. Telegram Super Admin separation is implemented in bot logic, not as a separate OS process.
- A fully compromised authenticated dashboard session can perform the dashboard's user/CDN/DNSTT operations.
- Telegram password-message deletion is best effort. Use temporary strong passwords and rotate them when appropriate.
- VMess, Trojan and WebSocket are deprecated upstream in Xray v26 but remain available because the project explicitly supports them. VLESS is recommended.
- CloudFront and public DNS behavior depend on external provider configuration. Repository tests cannot create or validate a distribution without the operator's AWS account.
- Proprietary locked NetMod/DarkTunnel formats are not generated; exports are open, inspectable JSON.

## Verification

```bash
python3 scripts/static-audit.py
pytest -q
cfn-lint infra/cloudfront-websocket.yml
abdulbasit-security-check
xray run -test -config /etc/abdulbasit/xray/config.json
nginx -t
systemd-analyze security abdulbasit-paneld.service
systemd-analyze security abdulbasit-dashboard.service
systemd-analyze security abdulbasit-xray.service
systemd-analyze security abdulbasit-dnstt.service
```

A passing check or systemd exposure score is evidence, not a formal proof of security.

## Reporting a vulnerability

Do not open a public issue containing live tokens, passwords, private keys, origin secrets, server credentials or exploit details against a production VPS. Revoke/rotate affected secrets first, preserve minimal logs, and share a sanitized reproduction with the maintainer.

## Owner bootstrap

The repository contains Abdul Basit's numeric Telegram user ID `6408975845` as the default Super Admin identifier. A numeric user ID is not an authentication secret by itself. A locally configured bot token is still required.

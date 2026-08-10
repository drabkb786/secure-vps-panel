# Changelog

## 3.0.0 — Multi-protocol, CDN and dashboard release

### CloudFront and Cloudflare

- Added a `cfn-lint`-validated CloudFront WebSocket distribution template.
- Added dedicated `/cloudfront/vmess`, `/cloudfront/vless` and `/cloudfront/trojan` routes.
- Added a root-only origin-verification secret shared by CloudFormation and Nginx.
- Restricted CloudFront-origin requests to `/cloudfront/*` routes (plus `/healthz`) and required the CDN origin to match an installed panel TLS certificate.
- Added direct and Cloudflare profile generation with TLS hostname validation.

### Protocols, files and limits

- Added pinned Xray v26 with VMess, VLESS and Trojan loopback WebSocket inbounds.
- Added stable-compatible Xray client JSON with a loopback SOCKS5 listener and standard share links.
- Added Xray Stats API JSON/legacy collection, verified filter/reset flags and real aggregate per-user byte limits.
- Added an idempotent crash-replay journal so a partially persisted Stats API collection is not counted twice on retry.
- Added time-limit enforcement across SSH and Xray plus existing SSH session limits.
- Added open NetMod/DarkTunnel JSON, Xray JSON, link and payload bundles.
- Added atomic credential enable/disable/rotation and rollback-safe Xray deployment.

### Dashboard and Telegram

- Added a TLS-only dashboard for users, limits, protocols, CDN, DNSTT and file download/deletion.
- Added isolated dashboard authentication, signed sessions, CSRF, CSP and login throttling.
- Added direct Telegram upload of generated files.
- Added per-service daemon command allow-lists for root, bot and dashboard peers.
- Isolated the panel socket in a client-only OS group and restricted bot restart/certificate parameters at the privileged boundary.

### DNSTT

- Added DNSTT + SSH configuration, DNS record generation and client exports.
- Pinned upstream `v1.20260501.0`, including the send-loop reliability fix.
- Added checksum-verified Go toolchain builds and an unprivileged capability-limited service.
- Made key rotation transactional, restoring the previous DNSTT keypair and config if service restart fails.

### Verification

- Added protocol/CDN/export/dashboard/DNSTT/usage/permission tests.
- Validated generated server/client JSON with the pinned real Xray binary.
- Completed live VMess, VLESS and Trojan WebSocket/SOCKS data-path tests.
- Completed a live encrypted DNSTT client/server echo test.
- Expanded static, Bash, JavaScript, CloudFormation and runtime security checks.

## 2.1.0 — Abdul Basit personalized release

- Rebranded all user-facing text and internal service identifiers to Abdul Basit.
- Set canonical GitHub target to `drabkb786/secure-vps-panel`.
- Preconfigured Telegram Super Admin ID `6408975845` without embedding a bot token.
- Added owner and maintainer metadata plus GitHub CODEOWNERS for `@drabkb786`.
- Added installer checks that reject symlinked protected paths and unsafe Super Admin config nodes.
- Added safe GitHub CLI publishing helpers targeting `drabkb786/secure-vps-panel` with private visibility by default.


## 2.0.0-secure

### Security architecture

- Replaced generated runtime scripts with reviewable source files.
- Added privileged local `paneld` API and unprivileged Telegram bot.
- Added UNIX peer credential validation and request-size limits.
- Added root-owned immutable installation paths and strict config permissions.
- Added systemd service hardening.

### Input and command safety

- Removed `shell=True` password creation vulnerability.
- Added strict validation for all privileged inputs.
- Added atomic JSON metadata writes.
- Added service restart allow-list.
- Added HTML escaping for Telegram output.
- Added Telegram rate limiting, state expiry, and safe offset persistence.

### Network and TLS

- Changed internal proxy from `0.0.0.0:2082` to `127.0.0.1:2082`.
- Added bounded header parsing, timeouts, connection cap, HTTP Upgrade checks, and proper `Sec-WebSocket-Accept` when a key is provided.
- Added rollback-safe Nginx generation and `nginx -t` validation.
- Replaced stop-Nginx standalone certificate flow with Certbot webroot.
- Replaced custom cron duplication with Certbot timer/deploy hook behavior.

### Account enforcement

- Renamed misleading IP limit to concurrent session limit.
- Excess sessions are terminated instead of locking the entire user.
- Removed inaccurate `/proc/PID/io` network quota enforcement.
- Quota is retained as non-enforced metadata and clearly labeled.

### Operations

- Removed unattended full system upgrade.
- Avoided modifying OpenSSH configuration.
- Added tests, CI checks, Dependabot configuration, security check script, and documentation.

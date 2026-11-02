# Changelog

## 3.3.0 — Dropbear transport and verified sessions

- Consolidate the v3.2 panel and both Actions v7 dependency PRs on `main`;
  preserve the older CDN draft branch as a documented future port.
- Add real RFC 6455 binary SSH transport at `/ssh/ws` using the maintained
  wsproto parser, retaining legacy raw Upgrade at `/` and `/ssh/raw`.
- Bound threads before dispatch, enforce an absolute header deadline, reject
  ambiguous handshakes and handle framing/close/backpressure without data loss.
- Attribute older root-owned forwarding sessions from trusted final auth
  journal records and modern sessions from verified process UIDs. Pin kernel
  identities with pidfds before enforcement; keep the oldest connections.
- Add explicit Dropbear listener/version/session diagnostics, reverse-forward
  denial, three authentication tries, a 128-KiB receive window, loopback-safe
  Fail2ban configuration and installer defaults rollback.
- Add independent WebSocket regressions and opt-in official Dropbear/Nginx
  integration checks for auth, host keys, TCP forwarding and tunnel-only policy.

## 3.2.0 — operations desk and measured usage

- Map the reference screenshot's 20 controls to original NOWAY browser/terminal
  workflows; add profile filters, daily-action cards and dedicated operations screens.
- Add exact 24-hour Xray trial timestamps, measured per-profile traffic, sampled
  GB quota enforcement, reset baselines and credential-preserving lock/unlock.
- Add a private UNIX-socket StatsService and persistent authoritative counters,
  authenticated recent IPs and separately labelled gateway peers. Overwrite and
  test forwarded headers through the real Nginx gateway.
- Add SSH lock/expiry enforcement, preserve manual locks during renewals, and
  provide transactional Dropbear banners and redacted configuration viewing.
- Add bounded logs, packet-loss/latency checks, doctor inspection/repair and
  config-checked managed gateway restarts.
- Add authenticated Xray UDP policy and optional official dnstt DNS tunnelling,
  pinned/checksum-verified build tooling, an isolated service, delegation/port
  checks and private key handling. Existing DNS services are not overwritten.
- Add root-terminal cache/journal maintenance, checkpointed reinstall and scoped
  uninstall with typed confirmation. Destructive maintenance is absent from HTTP APIs.
- Extend private Xray recovery to quotas, trials, usage and damaged counter-state
  recovery. Test real UDP traffic, native statistics/IPs and official dnstt TCP round trips.

## 3.1.0 — subscriptions, client formats and recovery

- Compared 10 relevant GitHub panels/installers and two upstream references;
  recorded feature decisions, source snapshots and license metadata in `docs/PANEL_RESEARCH.md`.
- Added per-profile live subscription URLs with hashed tokens, one-time display,
  rotation/revocation, expiry/disable enforcement, format selection and bounded public requests.
- Added browser-local QR generation and WS/TLS sing-box and Mihomo/Clash.Meta exports.
- Added scoped private Xray backups and root-only transactional restore, including
  pre-restore recovery copies and recovery from corrupt metadata.
- Added optional VLESS XHTTP with streaming Nginx proxying, HTTP/2 and explicit
  ALPN; existing WS profiles and credentials are retained.
- Fail closed on unreadable/invalid JSON stores instead of silently replacing
  existing accounts/settings with defaults.
- Validate imported XHTTP links through real Xray/Nginx, native client parsers,
  QR decoding and subscription/recovery regressions. See `docs/VALIDATION.md`.

## Direct-link audit — v3 follow-up

- Added plain `xray-link` and `xray-export --links` output, protocol TXT exports,
  explicit protocol copy buttons, copy-all and Telegram retrieval of existing profiles.
- Return import links immediately when creating a profile; report offline-core
  warnings separately from credential validity and public network reachability.
- Fix explicit re-enable of stopped services, verify core listeners after startup,
  preserve marker permissions on rollback, and retain successful account creation
  when a subsequent dashboard refresh fails.
- Test the generated URIs by independently importing them and using real Xray
  TLS/WebSocket connections. Local validation: 70 Python tests + 2 JavaScript tests.

## 3.0.0 — NOWAY VPS Control Room

- Added an authenticated, responsive browser dashboard, DNS/SSL controls and diagnostics.
- Added isolated Xray VLESS, VMess and Trojan WS/TLS profiles, account expiry timer,
  transactional updates, import links, JSON files and authenticated ZIP exports.
- Added checksum-verified pinned Xray installation, CLI/menu commands and upgrade support.
- Fixed port-header false conflicts, Nginx/domain save order, stale services on upgrade,
  bot token restart, shadow-utils lock files, tunnel-account shells, expiry boundaries,
  and SSH relay partial writes/backpressure.
- Added authentication/CSRF/IPC/rollback regressions and optional real-core transport checks.
- See `docs/WEB_XRAY.md` for setup and `docs/ROADMAP.md` for remaining phases.

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

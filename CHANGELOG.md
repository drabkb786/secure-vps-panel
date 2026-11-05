# Changelog

## 4.6.1 — Simple SSH sharing and origin aliases

- Show only credentials in `server:port@username:password` form and a complete
  single-request payload in SSH web/bot sharing; retain full CLI ZIP exports.
- Add `/cdn-cgi` origin and guarded provider aliases while preserving old routes
  and strict HTTP parsing. CDN framing and provider-deployment requirements are
  explicitly labelled; a path change does not prove carrier zero-rating.
- Encrypt newly created SSH sharing passwords in a root-private AES-256-GCM/
  RSA-OAEP vault. Verify old passwords once with libcrypt; invalidate saved
  secrets after external password changes and remove records on deletion.
- Update both backend and bot through the application updater. Exercise native
  HTTP/TLS/framed alias transfers, encrypted storage and actual dialog controls.

## 4.6.0 — Account management, per-IP access and measured payload

- Add the sketch's account rows with upload, download, total/quota, IP cap,
  access status and expandable/paginated per-IP traffic and Block/Allow controls.
- Add canonical account-scoped IP policies for SSH and every Xray protocol,
  keeping unrelated accounts behind the same NAT address usable.
- Add explicitly labelled modified builds of pinned Dropbear 2026.94 and Xray
  v26.10.31. Count authenticated SSH channel payload and Xray dispatch payload
  per account/source; keep absolute-counter baselines across reconnect/reset.
- Add a SO_PEERCRED/executable/socket-verified SSH collector and metered SSH
  GB/GiB quotas. Preserve unenforced legacy SSH quota notes as informational.
- Add POST-only optional-password SSH exports, visible server/client settings,
  complete Host payloads, direct SSH links, private ZIP and existing QR/configs.
- Keep byte counters as integers and return exact decimal strings. New runtimes
  require explicit activation; pre-activation per-IP usage cannot be invented.
  Limits are sampled, can overshoot, and exclude provider transport overhead.
- Keep expensive IP queries lazy and paginated. Native meter builds and actual
  byte/authentication/IP-block acceptance run in a dedicated Linux CI job.

## 4.5.0 — Explicit HAProxy / Dropbear 2026 migration

- Add a backed-up migration to official checksum-pinned Dropbear 2026.94 on
  managed ports 109/447 and a separate HAProxy service on public 80/443.
- Move Nginx to loopback 8080/8081, keeping TLS termination, dashboard, Xray,
  SSH raw/WS routes and authenticated CDN guards. Carry client addresses using
  PROXYv2 plus a root-private identity; reject forged local proxy metadata.
- Keep administrative SSH, existing account passwords, expiry, host keys and
  DNS tunnel settings. Validate candidate files before switching, recover on
  failure and support explicit rollback. Refuse unrelated port owners/sites.
- Reuse the small Dropbear build on repeat runs; never build the private SDK
  during migration. Support fast application updates with either SSH backend
  and preserve the selected pinned backend on subsequent full installations.
  Install newly introduced modules on older deployments; remove them again
  when recovering an interrupted/failed application update.
- Add disposable-systemd acceptance for real password authentication, byte
  forwarding over direct/raw/WS/TLS, accurate IP/session enforcement, failed
  activation recovery, repeat migration and explicit rollback.

## 4.4.1 — Modern Xray-compatible non-TLS VLESS

- Real-core validation found that the pinned Xray refuses unencrypted VLESS
  client configurations for public hosts. Generate a matching pair with official
  `xray vlessenc` and use a separate loopback VLESS Encryption listener on 10005.
- Preserve existing TLS UUIDs/profiles and aggregate non-TLS usage under the
  same VLESS account identity. Never export the server decryption identity.
- Export the non-TLS URI/JSON for compatible Xray clients; keep sing-box/Mihomo
  exports on supported TLS profiles rather than emitting incompatible entries.

## 4.4.0 — Explicit dual transports and client-side SSH probes

- Add opt-in direct VLESS WS on port 80 alongside verified TLS on 443. Preserve
  UUIDs, quota counters and encrypted VMess/Trojan/CDN routes; roll back Xray
  settings if the Nginx change fails. Expose the switch in CLI and dashboard.
- Export separate non-TLS VLESS URI/JSON, sing-box/Mihomo and live subscription
  entries with an explicit unencrypted-transport notice.
- Add non-TLS WS to the SSH adapter and real client-route probes for both raw
  HTTP Upgrade and framed WS over HTTP/TLS, reporting HTTP rejection and EOF.
- Include direct SSH 109/447, raw HTTP/TLS, WS/WSS and eligible dnstt settings
  in private SSH bundles. Validate public DNS keys and omit unusable IP-limited
  dnstt profiles. Use the managed SSH port for exported host-key lookup.
- Update affected modules and web assets from one committed snapshot through
  the fast compatibility updater, with backups and no runtime compilation.

## 4.3.2 — Wait for the daemon before reporting update success

- Confirm the daemon's UNIX socket with a bounded read-only RPC after restart;
  systemd's active state alone does not mean a Type=simple service is ready.
- Briefly retry missing/refused socket connections before sending a command.
  Never replay a command after connection, send, timeout or reply failure.
- Include the IPC client in the fast update and its recovery/source snapshot;
  no package installation or runtime compilation is required.

## 4.3.1 — Committed updates and explicit client/transport checks

- Stage one Git commit for fast SSH updates; optionally back up and synchronize
  only the affected working-copy modules instead of installing manual edits.
- Add bounded HTTP/TLS-to-SSH diagnostics that retain split/coalesced banners
  and distinguish local transport readiness from real client authentication.
- Export separate raw HTTP/TLS settings and readable client setup alongside
  WSS profiles, preserving transient-password and authenticated CDN behavior.

## 4.3.0 — Direct SSH transport compatibility and reversible MSS tuning

- Select raw or RFC6455 framing using a valid WebSocket key on direct SSH
  routes; accept supported legacy methods/HTTP versions and preserve split data.
- Add explicit Nginx direct SSH locations and upstream socket keepalive while
  preserving panel routing, bounded parsing and authenticated CDN origin routes.
- Allow ten managed SSH session channels and PTYs behind the forced tunnel-only
  command. Offer old-client crypto only through an explicit migration option.
- Add optional tagged PMTU MSS rules, boot reapplication, MSS-only mode and
  transactional rollback that preserves existing firewall rules and sysctls.

## 4.2.5 — Reuse completed builds with the staged Fail2ban interpreter link

- Validate the extracted package's relative fail2ban-python binding against
  the OS interpreter already used by the managed wrappers. No package files
  are rewritten and no compilation is needed for completed-build activation.
- Continue rejecting unexpected dangling links and writable interpreter targets.

## 4.2.4 — Faster CI and protected completed builds

- Cancel superseded workflow runs and avoid duplicate feature-push builds.
- Run Python 3.15 compatibility checks without compiling the private runtime;
  compile the full stack when build inputs change or a full run is requested.
- Remove inherited group/other write access before a fresh runtime is marked
  ready. Completed builds retain strict ownership and permission validation.

## 3.4.0 — CloudFront WS delivery and bridge tuning

- Add guarded TLS CloudFront origin routes for VLESS, VMess, Trojan and binary WebSocket Dropbear, with a private CloudFormation setup export and restricted edge paths.
- Add dashboard/CLI lifecycle, public endpoint handshake checks, Direct/CloudFront URI, QR, JSON, TXT, ZIP, sing-box, Mihomo and subscription routing.
- Preserve direct access, credentials, quotas and existing subscription tokens; keep XHTTP direct.
- Reduce bridge overhead with 64 KiB reads and TCP_NODELAY, retaining memory/connection bounds and authentication; include a reproducible comparison benchmark.
- Add real Nginx guard tests and native Xray/Dropbear two-hop TLS simulations. AWS live deployment remains a separate operator check.
- Document external GitHub/AWS sources, deployment costs, origin secret handling and measured-performance limits.

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

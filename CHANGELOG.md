# Changelog

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

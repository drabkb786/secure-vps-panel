# Security Audit and Remediation Report

This report summarizes the review of the original uploaded `menu.sh` / `tgbot.py` project and the changes implemented in the secure v2 rewrite.

## Executive summary

The original project had multiple high-impact weaknesses because Internet-facing Telegram input reached root-level operating-system commands with weak validation. It also exposed an internal proxy publicly, stored workflow secrets on disk, used inaccurate accounting as if it were network bandwidth, and rewrote critical server configuration without reliable rollback.

The secure rewrite changes the architecture instead of applying only cosmetic patches. The Telegram process is unprivileged, privileged actions cross a local UNIX socket with peer-credential checks, every operation is allow-listed, and every parameter is validated again at the root boundary.

## Findings and fixes

| Severity | Original issue | Risk | Secure v2 remediation |
|---|---|---|---|
| Critical | `subprocess.run(..., shell=True)` built a `chpasswd` command from Telegram username/password | Command injection and full root compromise | Removed all shell execution; `chpasswd` receives validated data through stdin with an argument-array subprocess |
| Critical | Telegram bot ran as root and could restart services, create/delete Linux users, and edit Nginx | A bot parser/library flaw became direct root compromise | Bot runs as dedicated `abdulbasit-bot`; a narrow root daemon accepts only allow-listed JSON commands |
| High | Usernames, domains, limits, Telegram IDs, and service values were not strictly validated | Path traversal, command/config injection, destructive account operations | Central validation functions enforce format, length, range, reserved-name, and allow-list rules |
| High | Password was written into JSON state files under `/etc/abdulbasit/bot_states` | Plaintext credential disclosure from disk/backups | Bot state is memory-only, expires after 10 minutes, and is periodically pruned; password messages are deleted best-effort |
| High | Internal WebSocket proxy listened on `0.0.0.0:2082` | Direct bypass of Nginx/TLS controls and unnecessary attack surface | Proxy binds only to `127.0.0.1:2082`; runtime check verifies it is not public |
| High | Old “IP limit” counted processes/sessions rather than unique client IPs | False enforcement claims and account denial of service | Renamed to concurrent session limit; only excess/newest sessions are terminated |
| High | Session overage permanently locked the account | One extra connection could deny service until manual unlock | No permanent lock on transient overage; expiry and limits are handled separately |
| High | `/proc/PID/io` was presented as Internet bandwidth | Incorrect usage data and wrongful quota lockouts | Removed inaccurate enforcement; quota remains clearly labeled metadata only |
| High | Nginx configuration was overwritten and restarted without validation/rollback | Bad domain/config could take the service offline | Generate to an atomic file, run `nginx -t`, reload only on success, restore previous config on failure |
| High | Certbot standalone flow stopped Nginx and could leave it stopped after failure | Remote outage and failed renewals | Uses webroot challenge while Nginx remains active; deploy hook reloads only after successful renewal |
| High | Bot/admin/domain/token files had weak or inconsistent permissions | Secret disclosure to local users | Root-owned configuration directories; secrets `0640` or stricter; user metadata `0600` |
| High | Bot token was entered with visible terminal echo | Shoulder-surfing and terminal-history exposure | `getpass`/hidden input through `abdulbasit-panelctl configure-bot` |
| High | Existing system users could be targeted by delete/update operations | Accidental deletion of administrators or service users | Only panel-managed users with safe regular JSON metadata can be changed/deleted |
| Medium | Telegram-rendered values were inserted into HTML without escaping | Message formatting injection and misleading admin output | All user-controlled Telegram output is HTML-escaped |
| Medium | All Telegram admins could control domain, SSL, services, and admin membership | Excess privilege and larger blast radius | Role separation in bot UI: ordinary admins manage users/status; Super Admin controls infrastructure/admin list |
| Medium | No callback confirmation for destructive deletion | Accidental user deletion | Explicit confirmation callback before deletion |
| Medium | WebSocket parser accepted arbitrary/unbounded initial data | Memory/thread exhaustion and malformed-request abuse | 16 KiB header cap, 10-second header timeout, upgrade validation, connection semaphore, idle timeout |
| Medium | Unlimited thread creation | Resource exhaustion | Maximum 200 concurrent proxy handlers plus Nginx per-IP connection/rate limits |
| Medium | Trusted forwarded IP values without a strong boundary | Spoofed source attribution | Listener is loopback-only and Nginx overwrites `X-Forwarded-For` / `X-Real-IP` |
| Medium | Broad exception suppression hid failures | Silent broken security controls | Structured journald logging and user-visible sanitized errors; no blanket `except: pass` in control paths |
| Medium | `apt upgrade -y` ran during installation | Unplanned package changes/reboots and harder rollback | Installer updates package index and installs only required packages |
| Medium | OpenSSH configuration was rewritten | Risk of locking out the VPS administrator | OpenSSH port 22/config is left unchanged; Dropbear uses separate ports 109/447 |
| Medium | Root login protection was not explicit for Dropbear | Password brute-force against root | Dropbear starts with `-w` to reject root logins; Fail2ban protects direct ports when filter is available |
| Medium | Duplicated custom Certbot cron entries | Repeated jobs and unnecessary Nginx downtime | Uses distribution Certbot timer and a deploy hook; legacy cron line is removed after backup |
| Medium | Legacy obfuscated/generated scripts remained executable | Hard-to-audit code continued running after upgrade | Legacy services are disabled; scripts/config are quarantined root-only; plaintext bot state is removed |
| Low | Telegram API failures could log exception text containing sensitive URL material | Potential bot token leakage into journal | API errors log only method and exception type; token is never printed |
| Low | Temporary state/rate maps could grow indefinitely | Long-running memory growth | Periodic TTL pruning and one denied-access notice per chat per TTL |
| Low | PID reuse race during session termination | Very small chance of signaling an unrelated process | Re-check PID owner and process name immediately before TERM/KILL |

## Residual risks

1. A privileged daemon is still required to administer Linux users, Nginx, Certbot, and services. Keep the VPS patched and restrict root access.
2. A compromised Telegram bot process can request the finite set of operations exposed by the daemon. It cannot run arbitrary shell commands, but those operations are still powerful.
3. Telegram is not a secret manager. Password messages are deleted best-effort and never stored by the panel, but administrators should use strong temporary passwords.
4. Accurate per-user network quota enforcement is not implemented. Adding it requires a separately tested accounting design rather than process-I/O guessing.
5. Systemd sandbox compatibility can vary slightly across older distributions. The included units target supported Ubuntu/Debian systemd releases and are verified syntactically.

## Verification completed on the build

- Bash syntax checks for installer, menu, and security script
- Python bytecode compilation for all source files
- 22 unit tests
- Dependency-free AST/static security audit
- `systemd-analyze verify` for all service units
- Real `nginx -t` against generated HTTP configuration
- Secret-pattern and unsafe subprocess scans

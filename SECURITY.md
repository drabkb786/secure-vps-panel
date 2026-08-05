# Security Policy

## Secret handling

Never commit:

- Telegram bot tokens
- VPS passwords or private keys
- `/etc/abdulbasit/*` production configuration
- user account passwords
- certificate private keys

If a token or credential was exposed in an older copy, rotate it before deployment. Deleting a secret from the latest commit does not remove it from Git history.

## Trust boundary

The Telegram bot is considered Internet-facing and potentially compromiseable. It runs as `abdulbasit-bot`, has no Linux capabilities, and communicates with a root daemon through `/run/abdulbasit/paneld.sock`.

The root daemon:

- accepts only local UNIX-socket clients with UID `0` or the dedicated bot UID;
- accepts one JSON request with a 16 KiB cap;
- uses an explicit command allow-list;
- validates every parameter again at the privileged boundary;
- invokes subprocesses with argument arrays and `shell=False`;
- permits user deletion only when panel-owned metadata exists.

## Known limitations

- Telegram itself is not a password manager. The bot deletes password messages on a best-effort basis and does not echo/store passwords, but administrators should still use temporary strong passwords and rotate when appropriate.
- The WebSocket component is a raw HTTP Upgrade tunnel intended for compatible SSH tunnel clients. It is not a general browser WebSocket-to-SSH gateway.
- GB quota is metadata only; inaccurate automatic enforcement was intentionally removed.
- A root daemon remains necessary for Linux account, certificate, Nginx, and service administration. Keep the VPS and Python runtime patched.

## Verification

Run:

```bash
abdulbasit-security-check
systemd-analyze security abdulbasit-paneld.service
systemd-analyze security abdulbasit-ws.service
systemd-analyze security abdulbasit-bot.service
```

A systemd exposure score is a review aid, not proof of security.

## Reporting

Do not open a public issue containing active tokens, passwords, private keys, server IP credentials, or exploit details against a live server. Revoke/rotate secrets first, then provide a minimal reproducible report without production data.

## Personalized owner bootstrap

This repository contains Abdul Basit's numeric Telegram user ID `6408975845` as the default Super Admin identifier. A numeric user ID is not an authentication secret by itself. The Telegram bot token remains mandatory and must be configured locally with hidden input; it must never be committed.

# Abdul Basit Secure VPS Panel v2.1.0

**Owner and Maintainer:** Abdul Basit

**GitHub:** `drabkb786`

**Repository:** `https://github.com/drabkb786/secure-vps-panel`

**Default Telegram Super Admin ID:** `6408975845`

A security-focused rewrite of the original VPS panel for **fresh Ubuntu/Debian VPS servers**. It manages Dropbear tunnel accounts, Nginx HTTP/TLS upgrade proxying, concurrent session limits, Let's Encrypt certificates, and an optional Telegram admin bot.

> Use this only on servers and networks you own or are authorized to administer.

## What changed

The original single `menu.sh` ran nearly everything as root and generated additional Python programs at runtime. This version separates privileges:

- `abdulbasit-paneld`: narrow root daemon; accepts only validated, allow-listed commands over a local UNIX socket.
- `abdulbasit-bot`: unprivileged Telegram process; it cannot execute arbitrary shell commands.
- `abdulbasit-ws`: unprivileged loopback-only HTTP Upgrade proxy.
- `abdulbasit-session-enforcer`: enforces **concurrent Dropbear sessions**, not a misleading “unique IP” claim.
- `menu`: root terminal UI backed by the same validated command API.

## Main security fixes

- Removed every `shell=True` and shell-built password command.
- Passwords are passed to `chpasswd` through standard input and are never written to panel files.
- Telegram workflow keeps temporary state only in memory and tries to delete the password message immediately.
- Bot token input is hidden; secret/config files are `0640` or stricter.
- Username, password, domain, Telegram ID, days, quota, session limit, service name, and callback values are validated.
- Telegram administrators cannot change domain/SSL/services/admin list; those actions are Super Admin only.
- Internal port `2082` binds only to `127.0.0.1`.
- Nginx config is tested before reload and automatically rolled back on failure.
- Certbot uses `webroot`, so Nginx does not need to be stopped for routine certificate issuance/renewal.
- Certbot deploy hook reloads Nginx only after a successful renewal.
- Destructive user deletion requires confirmation and can delete only users created/registered by this panel.
- Session overage terminates excess sessions; it does not permanently lock the whole account.
- Root services and unprivileged services include systemd sandboxing directives.
- No unattended `apt upgrade -y` is performed.
- OpenSSH port 22 and its configuration are not rewritten, reducing lockout risk.
- Fail2ban is enabled for direct Dropbear ports 109/447 when the distribution filter is available.
- Nginx applies per-IP connection and handshake rate limits.

## Important quota correction

The old script treated `/proc/<pid>/io` as Internet bandwidth. That measures process I/O and is not reliable per-user network accounting. Therefore:

- `quota_gb` is retained as **metadata only** for compatibility and planning.
- Automatic GB lock/kill enforcement is disabled.
- The UI clearly marks this instead of providing false usage numbers.

A proper future implementation should use a tested accounting backend designed for per-user network traffic.

## Requirements

- Fresh Ubuntu/Debian VPS with Python 3.10+ (for example Ubuntu 22.04/24.04 or Debian 12+)
- Root access
- Public IPv4/IPv6 as appropriate
- Optional domain/subdomain with its DNS A/AAAA record pointing to the VPS
- Provider firewall ports: `22`, `80`, `443`, `109`, `447` TCP
- Do **not** expose TCP `2082`; it is internal loopback only

## Install from the ZIP/repository

```bash
sudo -i
cd /path/to/secure-vps-panel
bash install.sh
```

Non-interactive example:

```bash
sudo bash install.sh \
  --domain vpn.example.com \
  --email admin@example.com \
  --non-interactive
```

Open the panel:

```bash
menu
```

## Publish to Abdul Basit GitHub account

From Windows PowerShell, after installing GitHub CLI and signing in:

```powershell
.\PUBLISH_TO_GITHUB.ps1
```

The helper targets `drabkb786/secure-vps-panel` and creates it as a private repository by default. Use `-Visibility public` only when the owner intentionally wants the source public.

## Telegram setup

1. Create a bot with BotFather.
2. Run `menu`.
3. Open **Telegram bot** → **Configure token and Super Admin**.
4. Token input is hidden.
5. Send `/start` to the bot from the configured Super Admin account.

Rotate any token that was previously committed, shared, logged, or used in the older panel.

## Useful commands

```bash
abdulbasit-panelctl status
abdulbasit-panelctl list-users
abdulbasit-panelctl list-sessions
abdulbasit-security-check
journalctl -u abdulbasit-paneld -u abdulbasit-ws -u abdulbasit-session-enforcer -u abdulbasit-bot
```

Create a user without opening the menu:

```bash
abdulbasit-panelctl create-user alice --days 30 --sessions 2 --quota Unlimited
```

The password is prompted without echo.

## Services

```text
abdulbasit-paneld.service
abdulbasit-ws.service
abdulbasit-session-enforcer.service
abdulbasit-bot.service
```

## Migration notes

The secure rewrite uses JSON metadata in `/etc/abdulbasit/users/*.json`. Old `*.conf` files are not trusted or automatically executed. Migrate account metadata manually after verifying each username and system account.

## Removal

No automatic package purge is included. To remove the panel safely:

```bash
systemctl disable --now abdulbasit-bot abdulbasit-session-enforcer abdulbasit-ws abdulbasit-paneld
rm -f /etc/systemd/system/abdulbasit-*.service
systemctl daemon-reload
rm -rf /usr/local/lib/abdulbasit
rm -f /usr/local/sbin/abdulbasit-panelctl /usr/local/sbin/abdulbasit-menu /usr/local/sbin/abdulbasit-security-check
rm -f /usr/local/bin/menu /usr/bin/menu
rm -f /etc/nginx/conf.d/abdulbasit-vpn.conf
nginx -t && systemctl reload nginx
```

Review `/etc/abdulbasit`, managed Linux users, Dropbear backup files, and certificates before deleting them.

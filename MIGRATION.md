# Migration from the original panel

## Before migration

1. Take a VPS snapshot.
2. Rotate any Telegram token that appeared in files, screenshots, logs, chat messages, or Git history.
3. Keep an active root SSH session on port 22 while testing.
4. Verify provider firewall access for 22, 80, 443, 109, and 447 TCP.

## Recommended method

Deploy v3 on a fresh VPS. Create each account again through `menu`, the TLS dashboard, or `abdulbasit-panelctl`, using a new temporary password.

For an existing secure v2 installation, back up `/etc/abdulbasit`, run the v3 installer, and enable Xray protocols per user. Existing SSH users remain SSH users; the panel does not invent or recover their passwords.

## Why old metadata is not auto-imported

Old files used shell-style `KEY=value` content and could contain malformed or attacker-controlled values. The secure version uses validated JSON and never sources old files.

## Existing Linux users

The secure daemon refuses to claim an existing Linux username automatically. This prevents accidental control or deletion of administrators and system service accounts.

To migrate an existing tunnel user, verify the account manually, remove it only after backup, then recreate it through the secure panel.

## Migration from the earlier legacy secure build

The Abdul Basit installer detects and disables the older `raretriccks-*` services, backs up their local systemd/Nginx files, removes conflicting old Nginx configuration, and does **not** import old Telegram tokens. The old `/etc/raretriccks` directory is retained root-only for manual review because production secrets may exist there.

After confirming the new panel works, manually delete the old directory only after preserving any non-secret account records you genuinely need:

Remove old directories only after a separate manual review and backup; do not paste a broad recursive deletion command from documentation into a production server.

Do not copy `bot_token.conf`, private keys, passwords, or unknown legacy scripts into the new installation.

# NOWAY VPS Control Room v4.6.1

[SSH two-value sharing, `/cdn-cgi` aliases and automatic encrypted password retrieval](docs/SSH_SIMPLE_SHARE_4_6_1.md).

> Browser dashboard, managed OpenSSH (Dropbear fallback), VLESS/VMess/Trojan, optional XHTTP/REALITY, live subscriptions, QR, client configs and private recovery for Ubuntu/Debian VPS servers.

**4.0 upgrade:** [OpenSSH migration, SSH links/adapter, Bunny, Xray runtime updates and validation](docs/UPGRADE_4.md).
**4.1 runtime upgrade:** [Pinned Nginx, Python/OpenSSL, Certbot and Fail2ban with rollback](docs/RUNTIME_UPGRADE.md).
**Changing #1 / #2:** [Implementation decisions and upstream sources](docs/CHANGING_1_2.md).

**4.6 account dashboard:** [Per-IP controls, payload metering and activation](docs/ACCOUNT_DASHBOARD_4_6.md).

## Project information

| Item | Value |
|---|---|
| Owner and Maintainer | **Abdul Basit** |
| GitHub Account | `drabkb786` |
| Repository | `drabkb786/secure-vps-panel` |
| Version | `4.6.0` |
| Default Telegram Super Admin ID | `6408975845` |
| Supported OS | Ubuntu 22.04/24.04 and Debian 12+ |
| Required Python | Python 3.10 or newer |

> **Authorized use only:** Is panel ko sirf apne VPS, apne network, ya us server par use karein jahan aapko proper permission hasil ho. Yeh project telecom billing bypass, unauthorized access, credential theft, ya kisi third-party service ko abuse karne ke liye nahi hai.

---

## Panel kya karta hai?

Yeh browser aur terminal dono se khulta hai. Naya NOWAY dashboard `https://YOUR-DOMAIN/panel/` par milta hai; purana `menu` aur Telegram workflow bhi available hai. Browser access ke liye `abdulbasit-panelctl configure-web` se apna admin login set karein.

**v3.2 setup, migration, Xray exports aur limitations:** [Web + Xray guide](docs/WEB_XRAY.md).
**Implementation sequence aur next phases:** [Roadmap](docs/ROADMAP.md).
**Verification evidence:** [Validation](docs/VALIDATION.md).
**Exact byte units, unique-IP caps, migration and limitations:** [Accuracy guide](docs/ACCURACY.md).
**CloudFront setup, direct/CDN links and performance scope:** [CloudFront guide](docs/CLOUDFRONT.md).
**External GitHub/AWS comparison:** [CloudFront research](docs/CLOUDFRONT_RESEARCH.md).
**Dropbear fixes, standard WebSocket and session attribution:** [SSH transport guide](docs/DROPBEAR.md).
**Screenshot ke 20 controls, traffic, SlowDNS aur maintenance:** [Operations guide](docs/OPERATIONS.md).
**10 GitHub panels + 2 upstream references ka comparison:** [Research and upgrade decisions](docs/PANEL_RESEARCH.md).

v3.1 mein profile-wise live subscription URL (rotation/revoke), local QR codes,
sing-box JSON, Mihomo/Clash.Meta YAML, private Xray backup/root-CLI restore aur
optional VLESS XHTTP add hain. XHTTP, Xray/URI exports mein hai; sing-box/Mihomo
exports WS/TLS use karte hain. Backup sirf Xray accounts/settings ka hai; SSH OS
users, certificate private keys aur admin/bot credentials ismein shamil nahi.

**v3.2:** naya operations dashboard aur terminal menu, exact 24-hour Xray trials,
measured Xray GB limits/reset, authenticated recent IPs, SSH/Xray lock/unlock,
UDP policy, optional official dnstt SlowDNS, doctor/repair, bounded error logs,
packet-loss test, custom Dropbear banner aur root-only maintenance. Xray quotas
ab five-second target checks par enforce hote hain (plus processing time);
SSH byte metering unavailable hai aur finite SSH quotas reject hote hain. Public
SlowDNS ko actual NS delegation/UDP firewall setup chahiye. Details aur complete
20-option mapping operations guide mein hain.

**v3.3:** standard binary WebSocket SSH `/ssh/ws`, existing legacy `/` and
`/ssh/raw` routes, bounded bridge workers/queues, stricter handshake validation,
old/new Dropbear session attribution and pidfd-safe enforcement. Installer adds
`python3-wsproto`, disables reverse forwarding, limits auth retries and rolls back
Dropbear defaults if either managed listener fails. Detailed limits, source
research and native test scope are in the SSH transport guide.

**v3.5:** restart-fenced integer counters, explicit GB/GiB units, unique source-IP caps,
private loopback gateway identity and trusted CloudFront viewer IPs. IP caps are
polled, not device limits; quotas can overshoot. Existing CloudFront stacks must
be updated before the VPS upgrade. See the accuracy guide above.

Panel automatically:

- Dropbear SSH ko ports `109` aur `447` par configure karta hai.
- Existing OpenSSH administration access ko normally port `22` par untouched rakhta hai.
- Nginx par HTTP WebSocket port `80` configure karta hai.
- Valid SSL certificate milne ke baad WSS/TLS port `443` configure karta hai.
- Internal WebSocket proxy ko sirf `127.0.0.1:2082` par bind karta hai.
- Linux tunnel users create, renew aur delete karta hai.
- Per-user concurrent Dropbear session limit enforce karta hai.
- Let's Encrypt SSL issue aur renew karta hai.
- Optional Telegram bot ke through users aur services manage karta hai.
- Fail2ban ke through direct Dropbear login brute-force protection enable karne ki koshish karta hai.
- Nginx configuration ko apply karne se pehle test karta hai aur failure par rollback karta hai.

## Architecture

```text
Internet client
   |
   |-- Direct SSH/Dropbear: VPS-IP:109 or VPS-IP:447
   |
   |-- HTTP WebSocket: domain:80
   |        |
   |        v
   |      Nginx
   |        |
   |        v
   |   127.0.0.1:2082
   |        |
   |        v
   |   Dropbear 127.0.0.1:109
   |
   `-- TLS WebSocket/WSS: domain:443
            |
            v
          Nginx SSL
            |
            v
       127.0.0.1:2082
            |
            v
       Dropbear 127.0.0.1:109
```

Internal port `2082` public internet par open nahi hona chahiye.

---

# 1. VPS requirements

## Recommended VPS

- Fresh Ubuntu `22.04` ya `24.04`
- Ya Debian `12` or newer
- Minimum `1 CPU`, `512 MB RAM`, `5 GB` storage
- Public IPv4 recommended
- Root ya sudo access
- Clean/fresh VPS strongly recommended

Purane production server, shared hosting, cPanel server, ya important website wale VPS par direct install na karein. Installer Nginx aur Dropbear configuration manage karta hai.

## Required public ports

Provider firewall/security group mein yeh TCP ports allow hon:

| Port | Purpose |
|---:|---|
| `22` | Normal OpenSSH server administration |
| `80` | HTTP WebSocket and Let's Encrypt verification |
| `443` | TLS WebSocket/WSS |
| `109` | Direct Dropbear SSH |
| `447` | Alternate direct Dropbear SSH |
| `2082` | **Publicly open na karein**; loopback-only internal service |

Agar aapke VPS ka normal SSH port `22` nahi hai, apne real administration port ko firewall mein open rakhein. Installer OpenSSH configuration ko intentionally rewrite nahi karta.

---

# 2. Domain aur DNS setup

Domain optional hai, lekin port `443` par valid TLS/WSS use karne ke liye domain zaroori hai.

Example:

```text
vpn.example.com
```

DNS provider mein A record banayein:

```text
Type: A
Name/Host: vpn
Value/Target: YOUR_VPS_PUBLIC_IP
TTL: Auto or 300
```

Agar IPv6 properly configured hai to optional AAAA record bhi add kiya ja sakta hai.

## DNS verify karein

Apne computer ya VPS se:

```bash
getent ahostsv4 vpn.example.com
```

Ya:

```bash
nslookup vpn.example.com
```

Result mein VPS ka public IP aana chahiye.

### Cloudflare users

Initial SSL installation ke waqt record ko **DNS only** rakhna easiest hai. Pehle certificate issue aur direct connection verify karein. Kisi proxy/CDN ki terms aur traffic policies ko follow karna aapki responsibility hai.

---

# 3. VPS se connect hona

Windows PowerShell, Windows Terminal, Linux ya macOS terminal se:

```bash
ssh root@YOUR_VPS_IP
```

Example:

```bash
ssh root@203.0.113.10
```

Agar VPS root login ke bajaye sudo user deta hai:

```bash
ssh ubuntu@YOUR_VPS_IP
sudo -i
```

Installation start karne se pehle confirm karein:

```bash
whoami
```

Expected result:

```text
root
```

---

# 4. GitHub repository clone karna

Repository private ho to authenticated GitHub access required hoga.

## Method A — GitHub CLI, recommended for private repository

GitHub CLI install karein:

```bash
apt-get update
apt-get install -y git gh
```

Login:

```bash
gh auth login
```

Prompts mein:

```text
GitHub.com
HTTPS
Login with an SSH client (legacy example)
```

Phir repository clone karein:

```bash
cd /root
gh repo clone drabkb786/secure-vps-panel
cd secure-vps-panel
```

## Method B — normal Git clone

Public repository ke liye:

```bash
apt-get update
apt-get install -y git
git clone https://github.com/drabkb786/secure-vps-panel.git
cd secure-vps-panel
```

Private repository mein GitHub password accept nahi hota. Password prompt par Personal Access Token ya authenticated credential manager required hoga. Token ko command, README, screenshot, Telegram, ya source file mein paste/commit na karein.

## Files verify karein

Installation se pehle:

```bash
ls -la
```

Kam az kam yeh items hone chahiye:

```text
install.sh
menu.sh
src/
systemd/
scripts/
tests/
README.md
SECURITY.md
```

Agar sirf `README.md` nazar aaye aur `install.sh` na ho, full source abhi repository mein upload nahi hua. Us state mein installation run nahi ho sakti.

---

# 5. Pre-install checks

Project folder ke andar:

```bash
cd /root/secure-vps-panel
```

Installer syntax check:

```bash
bash -n install.sh
```

Python files compile test:

```bash
python3 -m py_compile src/*.py
```

Optional automated tests:

```bash
python3 -m unittest discover -s tests -v
```

Installer permissions:

```bash
chmod +x install.sh menu.sh scripts/*.sh
```

---

# 6. Installation methods

## Method 1 — Interactive installation

Recommended for first installation:

```bash
sudo bash install.sh
```

Installer poochega:

```text
Domain: vpn.example.com
Certbot email: your-email@example.com
```

Domain abhi ready na ho to blank Enter kar sakte hain. Baad mein `menu` se domain configure ho jayega.

## Method 2 — Non-interactive installation with domain

```bash
sudo bash install.sh \
  --domain vpn.example.com \
  --email admin@example.com \
  --non-interactive
```

Apna real domain aur email use karein.

## Method 3 — Install now, domain later

```bash
sudo bash install.sh --non-interactive
```

Installation ke baad:

```bash
menu
```

Phir option:

```text
2) Set/change domain
3) Issue/renew SSL
```

## Installer kya install/change karega?

Packages:

```text
ca-certificates
nginx
dropbear
certbot
python3
procps
passwd
iproute2
fail2ban
```

Installer:

- Unattended full `apt upgrade -y` nahi chalata.
- OpenSSH port `22` ko intentionally change nahi karta.
- Dropbear ko `109` aur `447` par configure karta hai.
- Purane insecure panel services ko disable/quarantine karta hai.
- Secure services install karta hai.
- Default Telegram Super Admin ID `6408975845` save karta hai.
- Bot token khud generate nahi karta; aapko BotFather token manually configure karna hota hai.

---

# 7. Installation verify karna

Installation complete hone ke baad:

```bash
menu
```

Panel open na ho to:

```bash
/usr/local/sbin/abdulbasit-menu
```

## Service status

```bash
abdulbasit-panelctl status
```

Ya individually:

```bash
systemctl status dropbear --no-pager
systemctl status nginx --no-pager
systemctl status abdulbasit-paneld --no-pager
systemctl status abdulbasit-ws --no-pager
systemctl status abdulbasit-session-enforcer --no-pager
```

Telegram token configure hone ke baad:

```bash
systemctl status abdulbasit-bot --no-pager
```

## Listening ports verify karein

```bash
ss -lntp | grep -E ':(22|80|109|443|447|2082)\b'
```

Expected:

- `109` and `447` Dropbear
- `80` Nginx
- `443` Nginx, only after SSL certificate/config is available
- `2082` only on `127.0.0.1`

Security requirement:

```text
127.0.0.1:2082   correct
0.0.0.0:2082     wrong/insecure
[::]:2082        wrong/insecure
```

## Built-in security check

```bash
abdulbasit-security-check
```

Successful checks normally show `PASS`.

## Nginx check

```bash
nginx -t
```

## Fail2ban check

```bash
systemctl status fail2ban --no-pager
fail2ban-client status dropbear
```

---

# 8. Panel menu use karna

Root shell mein:

```bash
menu
```

Main menu:

```text
1) User management
2) Set/change domain
3) Issue/renew SSL
4) Telegram bot
5) Service status
6) Restart core services
7) View recent logs
8) Exit
```

---

# 9. SSH/Dropbear user create karna

## Menu method

```bash
menu
```

Choose:

```text
1) User management
1) Create user
```

Required fields:

```text
Username: lowercase username
Validity days: 1 to 3650
Concurrent sessions: 1 to 20
Unique IP cap: 0 (Unlimited) or 1 to 20; SSH GB metering unavailable
Password: minimum 12 characters
```

Example:

```text
Username: testuser
Validity days: 30
Concurrent sessions: 2
Unique IP cap: 0 (Unlimited)
Password: use-a-strong-private-password
```

## CLI method

```bash
abdulbasit-panelctl create-user testuser \
  --days 30 \
  --sessions 2 \
  --quota Unlimited
```

Password terminal mein hidden prompt par enter hoga. Password source file ya shell command argument mein nahi jata.

## User list

```bash
abdulbasit-panelctl list-users
```

## Active sessions

```bash
abdulbasit-panelctl list-sessions
```

## Renew user

30 days add karne ke liye:

```bash
abdulbasit-panelctl renew-user testuser --days 30
```

## Concurrent session limit change

```bash
abdulbasit-panelctl set-sessions testuser --sessions 3
```

Allowed range `1` to `20` hai.

## Clear an old SSH quota note

Finite SSH GB quotas are rejected because this backend cannot measure them.
To clear a legacy metadata-only value:

```bash
abdulbasit-panelctl set-quota testuser --quota Unlimited
```

> SSH GB metering unavailable hai. Xray profiles ke GB/GiB limits measured hain; SSH process I/O ko network traffic nahi samjha jata.

## User delete karna

Menu recommended hai, kyun ke confirmation mangta hai:

```bash
menu
```

```text
User management → Delete managed user
Type DELETE to confirm
```

CLI:

```bash
abdulbasit-panelctl delete-user testuser
```

Sirf panel ke managed/registered users delete kiye ja sakte hain.

---

# 10. Domain configure/change karna

Menu:

```bash
menu
```

```text
2) Set/change domain
```

CLI:

```bash
abdulbasit-panelctl set-domain vpn.example.com
```

Panel:

- Domain format validate karega.
- Existing Nginx server-name conflicts check karega.
- Managed Nginx configuration write karega.
- `nginx -t` run karega.
- Error par old configuration restore karega.

---

# 11. SSL certificate issue/renew karna

Pehle ensure karein:

- DNS domain VPS IP par point karta ho.
- Port `80` provider firewall mein open ho.
- Nginx running ho.

Menu:

```text
3) Issue/renew SSL
```

CLI:

```bash
abdulbasit-panelctl issue-cert --domain vpn.example.com
```

Agar domain pehle configured hai:

```bash
abdulbasit-panelctl issue-cert
```

Certificate verify:

```bash
certbot certificates
```

Renewal test:

```bash
certbot renew --dry-run
```

Certbot timer:

```bash
systemctl status certbot.timer --no-pager
```

## Common SSL failure causes

- DNS wrong IP par point kar raha hai.
- DNS propagation complete nahi hui.
- Port `80` blocked hai.
- Same domain kisi aur Nginx config mein configured hai.
- Domain ke A aur AAAA records different servers par point karte hain.
- Provider ya local firewall incoming HTTP block kar raha hai.

Logs:

```bash
journalctl -u nginx -n 100 --no-pager
ls -la /var/log/letsencrypt/
tail -n 100 /var/log/letsencrypt/letsencrypt.log
```

---

# 12. Client connection information

Created user ke liye basic credentials:

```text
Host: your VPS IP or configured domain
Username: panel-created username
Password: account password
```

## Direct Dropbear SSH

```text
Host: VPS IP or domain
Port: 109
Protocol: SSH
```

Alternate:

```text
Host: VPS IP or domain
Port: 447
Protocol: SSH
```

## HTTP WebSocket

```text
Host/SNI: vpn.example.com
Port: 80
TLS/SSL: Off
WebSocket path: /
SSH username/password: panel-created credentials
```

## TLS WebSocket / WSS

Valid SSL issue hone ke baad:

```text
Host/SNI: vpn.example.com
Port: 443
TLS/SSL: On
WebSocket path: /
SSH username/password: panel-created credentials
```

Generic WebSocket upgrade request structure:

```http
GET / HTTP/1.1
Host: vpn.example.com
Upgrade: websocket
Connection: Upgrade

```

Apna real authorized domain use karein. Kisi third-party host, zero-rated service, billing bypass host, ya unauthorized payload ko use na karein.

---

# 13. Telegram bot setup

## Bot create karna

Telegram mein official `@BotFather` open karein:

```text
/newbot
```

Bot name aur username select karein. BotFather aapko token dega.

Token example format:

```text
BOT_TOKEN_FROM_BOTFATHER
```

Real token ko GitHub, chat screenshot, public message, README, ya source code mein share na karein.

## Panel mein bot configure karna

```bash
menu
```

Choose:

```text
4) Telegram bot
1) Configure token and Super Admin
```

Enter:

```text
Bot token: hidden input
Super Admin ID: 6408975845
```

CLI alternative:

```bash
abdulbasit-panelctl configure-bot
```

Bot token hidden prompt mein enter hoga. Default Super Admin ID already:

```text
6408975845
```

Telegram mein bot ko open karke:

```text
/start
```

bhejein.

## Bot service check

```bash
systemctl status abdulbasit-bot --no-pager
```

Logs:

```bash
journalctl -u abdulbasit-bot -n 100 --no-pager
```

Live logs:

```bash
journalctl -u abdulbasit-bot -f
```

## Extra Telegram admin add karna

```bash
abdulbasit-panelctl add-admin TELEGRAM_NUMERIC_ID
```

Example:

```bash
abdulbasit-panelctl add-admin 123456789
```

Admin list:

```bash
abdulbasit-panelctl list-admins
```

Admin remove:

```bash
abdulbasit-panelctl remove-admin 123456789
```

Super Admin ID remove nahi ki ja sakti.

## Token leak ho jaye to

BotFather mein token revoke/regenerate karein aur panel mein new token configure karein:

```bash
abdulbasit-panelctl configure-bot
```

---

# 14. Services and logs

## Service names

```text
dropbear.service
nginx.service
fail2ban.service
abdulbasit-paneld.service
abdulbasit-ws.service
abdulbasit-session-enforcer.service
abdulbasit-bot.service
```

## Restart allowed services

```bash
abdulbasit-panelctl restart nginx
abdulbasit-panelctl restart dropbear
abdulbasit-panelctl restart abdulbasit-ws
abdulbasit-panelctl restart abdulbasit-session-enforcer
abdulbasit-panelctl restart abdulbasit-bot
```

Panel daemon apne API ke through khud ko restart nahi karta. Direct systemd command use karein:

```bash
systemctl restart abdulbasit-paneld
```

## Combined logs

```bash
journalctl --no-pager -n 200 \
  -u abdulbasit-paneld \
  -u abdulbasit-ws \
  -u abdulbasit-session-enforcer \
  -u abdulbasit-bot
```

## Live WebSocket logs

```bash
journalctl -u abdulbasit-ws -f
```

## Dropbear logs

```bash
journalctl -u dropbear -n 100 --no-pager
```

## Nginx logs

```bash
tail -n 100 /var/log/nginx/error.log
tail -n 100 /var/log/nginx/access.log
```

---

# 15. Troubleshooting

## `menu: command not found`

```bash
ls -l /usr/local/bin/menu /usr/bin/menu
/usr/local/sbin/abdulbasit-menu
```

Reinstall files:

```bash
cd /root/secure-vps-panel
sudo bash install.sh --non-interactive
```

## Panel daemon socket error

```bash
systemctl status abdulbasit-paneld --no-pager
journalctl -u abdulbasit-paneld -n 100 --no-pager
ls -la /run/abdulbasit/
```

Restart:

```bash
systemctl restart abdulbasit-paneld
```

## Port already occupied

```bash
ss -lntp | grep -E ':(80|109|443|447|2082)\b'
```

Conflicting service identify karke carefully resolve karein. Existing production service ko blindly stop/delete na karein.

## WebSocket port 80 works, 443 does not

```bash
certbot certificates
nginx -t
ss -lntp | grep ':443'
```

Phir:

```bash
abdulbasit-panelctl issue-cert
```

## Direct SSH works but WebSocket fails

```bash
systemctl status nginx abdulbasit-ws dropbear --no-pager
curl -i -H 'Upgrade: websocket' -H 'Connection: Upgrade' http://vpn.example.com/
```

Expected response normally `101 Switching Protocols` ho sakta hai. A simple curl connection tunnel mode mein open reh sakti hai; `Ctrl+C` se close karein.

## Telegram bot not responding

```bash
systemctl status abdulbasit-bot --no-pager
journalctl -u abdulbasit-bot -n 150 --no-pager
```

Check:

- Token correct hai.
- Bot ko `/start` bheja gaya hai.
- Telegram ID numeric aur correct hai.
- VPS outbound HTTPS access block nahi hai.
- `/etc/abdulbasit/bot_token.conf` exists and secure hai.

Permissions:

```bash
stat -c '%a %U %G %n' \
  /etc/abdulbasit/bot_token.conf \
  /etc/abdulbasit/super_admin.conf
```

Expected mode usually `640`, owner `root`, group `abdulbasit`.

## User login fails

```bash
getent passwd USERNAME
chage -l USERNAME
systemctl status dropbear --no-pager
journalctl -u dropbear -n 100 --no-pager
```

Password minimum `12` characters hona chahiye at account creation.

## Too many sessions disconnect ho rahi hain

Current session limit dekhein:

```bash
abdulbasit-panelctl list-users
abdulbasit-panelctl list-sessions
```

Limit increase:

```bash
abdulbasit-panelctl set-sessions USERNAME --sessions 3
```

---

# 16. Firewall example

Provider firewall/security group pehle configure karein. Local UFW use karte waqt SSH lockout se bachne ke liye current administration port confirm karein.

Current SSH listeners:

```bash
ss -lntp | grep sshd
```

UFW installed ho aur normal SSH port `22` ho to example:

```bash
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 109/tcp
ufw allow 447/tcp
ufw deny 2082/tcp
ufw enable
ufw status verbose
```

Agar SSH custom port par hai, `22/tcp` ki jagah real port allow karein **before** enabling UFW.

---

# 17. Configuration files

| Path | Purpose |
|---|---|
| `/etc/abdulbasit/domain.conf` | Active domain |
| `/etc/abdulbasit/certbot_email.conf` | Certbot email |
| `/etc/abdulbasit/super_admin.conf` | Telegram Super Admin ID |
| `/etc/abdulbasit/admin_ids.conf` | Additional Telegram admins |
| `/etc/abdulbasit/bot_token.conf` | Telegram bot token; secret |
| `/etc/abdulbasit/users/*.json` | Managed user metadata |
| `/etc/abdulbasit/backups/` | Installer-created legacy/config backups |
| `/etc/nginx/conf.d/abdulbasit-vpn.conf` | Managed Nginx config |
| `/usr/local/lib/abdulbasit/` | Installed Python source |
| `/run/abdulbasit/paneld.sock` | Local privileged daemon socket |

Do not manually make secret files world-readable.

---

# 18. Backup

## Panel metadata/config backup

```bash
tar -C / -czf /root/abdulbasit-panel-backup-$(date +%F).tar.gz \
  etc/abdulbasit \
  etc/nginx/conf.d/abdulbasit-vpn.conf
```

Certificates include karne ke liye optional:

```bash
tar -C / -czf /root/abdulbasit-panel-full-config-$(date +%F).tar.gz \
  etc/abdulbasit \
  etc/nginx/conf.d/abdulbasit-vpn.conf \
  etc/letsencrypt
```

Backup permissions secure karein:

```bash
chmod 600 /root/abdulbasit-panel-*.tar.gz
```

> Managed Linux accounts ka complete restore sirf metadata tar se nahi hota. Reliable disaster recovery ke liye VPS provider snapshot/image recommended hai. `/etc/shadow` ko manually copy/share na karein.

---

# 19. Update panel from GitHub

Repository folder:

```bash
cd /root/secure-vps-panel
```

Current changes check:

```bash
git status
```

Update:

```bash
git pull --ff-only origin main
```

Tests:

```bash
bash -n install.sh
python3 -m py_compile src/*.py
python3 -m unittest discover -s tests -v
```

Re-run installer to deploy updated files:

```bash
sudo bash install.sh --non-interactive
```

Agar current domain/email preserve karna ho, files `/etc/abdulbasit/` mein rehti hain. Update se pehle VPS snapshot aur `/etc/abdulbasit` backup recommended hai.

---

# 20. Migration from old RareTriccks panel

Secure installer old services/scripts detect karke quarantine karne ki koshish karta hai. Old Telegram state files plaintext passwords contain kar sakti thi, isliye trusted import nahi hota.

Important:

- Old bot token rotate karein.
- Old `/etc/raretriccks` ko automatically trust/import na karein.
- Old users ko verify karke manually migrate karein.
- Production server snapshot pehle banayein.
- Detailed notes ke liye `MIGRATION.md` read karein.

---

# 21. Uninstall

Pehle optional backup lein.

Services stop/disable:

```bash
systemctl disable --now \
  abdulbasit-bot \
  abdulbasit-session-enforcer \
  abdulbasit-ws \
  abdulbasit-paneld
```

Unit files remove:

```bash
rm -f /etc/systemd/system/abdulbasit-*.service
systemctl daemon-reload
```

Installed program remove:

```bash
rm -rf /usr/local/lib/abdulbasit
rm -f /usr/local/sbin/abdulbasit-panelctl
rm -f /usr/local/sbin/abdulbasit-menu
rm -f /usr/local/sbin/abdulbasit-security-check
rm -f /usr/local/bin/menu /usr/bin/menu
```

Nginx managed configuration remove:

```bash
rm -f /etc/nginx/conf.d/abdulbasit-vpn.conf
nginx -t && systemctl reload nginx
```

Optional Certbot deploy hook remove:

```bash
rm -f /etc/letsencrypt/renewal-hooks/deploy/abdulbasit-nginx-reload
```

`/etc/abdulbasit`, certificates, Dropbear configuration aur panel-created Linux users ko blindly delete na karein. Pehle contents review aur backup karein.

---

# 22. Security notes

- Bot token kabhi GitHub par commit na karein.
- Passwords screenshots ya Telegram groups mein share na karein.
- Root SSH ke liye SSH keys preferred hain.
- VPS OS security updates regularly apply karein.
- Provider firewall mein sirf required ports expose karein.
- Port `2082` public expose na karein.
- Unknown scripts ko root par execute na karein.
- `nginx -t` ke baghair manual Nginx reload na karein.
- Bot token leak ho to immediately revoke/rotate karein.
- GitHub Personal Access Token ko repository files mein save na karein.
- Panel ka use sirf authorized systems par karein.

Full security model aur known limitations ke liye:

```text
SECURITY.md
AUDIT.md
```

---

# Quick command reference

```bash
# Open panel
menu

# Service summary
abdulbasit-panelctl status

# Users
abdulbasit-panelctl list-users
abdulbasit-panelctl list-sessions

# Create user
abdulbasit-panelctl create-user USERNAME --days 30 --sessions 2 --quota Unlimited

# Renew user
abdulbasit-panelctl renew-user USERNAME --days 30

# Set domain and issue SSL
abdulbasit-panelctl set-domain vpn.example.com
abdulbasit-panelctl issue-cert

# Configure Telegram bot
abdulbasit-panelctl configure-bot

# Security verification
abdulbasit-security-check
nginx -t

# Logs
journalctl -u abdulbasit-paneld -u abdulbasit-ws -u abdulbasit-session-enforcer -u abdulbasit-bot -n 200 --no-pager
```

---

## License and responsibility

The server owner is responsible for:

- local laws and provider terms,
- user authorization,
- server billing,
- domain/DNS ownership,
- account security,
- traffic and abuse handling,
- backups and incident response.

**Maintainer:** Abdul Basit  
**GitHub:** `drabkb786`  
**Telegram Super Admin ID:** `6408975845`

### Comparing a completed download

Account traffic cells show decimal MB/GB, binary MiB/GiB and exact bytes. Quota units do not change traffic display units. A downloader may label 157,286,400 bytes as “150 MB”, which is 150 MiB and 157.2864 decimal MB.

Use the account's **Download check** action. Pause downloads on that account for five seconds, save its starting counter, perform the download, and wait five seconds after traffic stops before comparing. Enter the actual byte size or select the completed local file to read its size without uploading its contents. The comparison uses only the download counter, keeps existing quota totals, and rejects usage resets or recreated accounts.

These counters measure the account's tunnel payload. HTTP/TLS bytes inside that payload are included. A completed file's size and the account's total download increase are different measurements. Comparing them requires an exact starting byte count and the same account/measurement interval.

### SSH and Xray over DNS

The Transports page supports **SSH**, **Xray VLESS**, and **SSH + Xray together**. Existing configurations default to SSH. Both mode preserves the original SSH zone/key and requires a second, disjoint zone for Xray, for example `xdns.example.com`. Delegate both zones to the same DNS-only nameserver hostname pointing to this VPS. One public UDP port (normally 53) dispatches by delegated zone to two private DNSTT instances. Private UDP ports 53530/53531 and VLESS TCP 10006 bind only on loopback.

After installing the official core, enable the managed Xray core and configure both tunnels:

```bash
sudo abdulbasit-panelctl slowdns-enable --mode both --zone tunnel.example.com --xray-zone xdns.example.com --ns-host ns1.example.com
sudo abdulbasit-panelctl slowdns-check
sudo abdulbasit-panelctl xray-export ACCOUNT --route dns --zip ACCOUNT-dns.zip
```

The DNS export uses the existing VLESS account UUID and its normal byte quota, expiry and lock. IP cap must be 0 and the account IP block list empty. DNS resolvers hide the viewer address, so the panel excludes restricted accounts and labels DNS source usage unknown. It never counts a resolver/loopback address as the client. DNS bytes remain part of the same account total across reconnects and reset with that account.

On the client, start one of the exported DNSTT commands (UDP, DoH or DoT) on local port 7001, then import the provided VLESS link/JSON. For concurrent SSH use the original SSH DNSTT zone on local port 7000. An ordinary Xray client requires a separate DNSTT client. Public resolver/carrier access and speed need a real client test.

The uploaded switching script was used as a reference for DNSTT-to-VLESS topology. This integration keeps the system resolver, uses the panel's pinned DNSTT build, and authenticates against managed accounts. It does not execute the uploaded script or create an unrelated shared UUID.

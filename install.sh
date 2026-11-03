#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/lib/abdulbasit"
CONFIG_DIR="/etc/abdulbasit"
BACKUP_DIR="$CONFIG_DIR/backups"
LEGACY_CONFIG_DIR="/etc/raretriccks"
DOMAIN=""
EMAIL=""
NON_INTERACTIVE=0
WITH_XRAY=0
WITH_DNSTT=0
XRAY_VERSION=""
DEFAULT_SUPER_ADMIN_ID="6408975845"

log() { printf '\033[0;34m[INFO]\033[0m %s\n' "$*"; }
ok() { printf '\033[0;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die() { printf '\033[0;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "Installation failed near line $LINENO. Existing SSH port 22 was not intentionally modified."' ERR

usage() {
  cat <<'EOF'
Usage: sudo bash install.sh [--domain vpn.example.com] [--email admin@example.com]
                           [--with-xray] [--with-dnstt] [--xray-version vX.Y.Z] [--non-interactive]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --with-xray) WITH_XRAY=1; shift ;;
    --with-dnstt) WITH_DNSTT=1; shift ;;
    --xray-version) XRAY_VERSION="${2:-}"; WITH_XRAY=1; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root: sudo -i"
[[ -r /etc/os-release ]] || die "Unsupported operating system"
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) die "Supported systems: Ubuntu and Debian" ;;
esac

if [[ -z "$DOMAIN" && $NON_INTERACTIVE -eq 0 ]]; then
  read -r -p "Domain (example: vpn.example.com, leave blank to configure later): " DOMAIN
fi
if [[ -z "$EMAIL" && $NON_INTERACTIVE -eq 0 ]]; then
  read -r -p "Certbot email (recommended; blank is allowed): " EMAIL
fi
if [[ $NON_INTERACTIVE -eq 1 && -z "$DOMAIN" ]]; then
  warn "No domain supplied; Nginx VPN site and SSL will be configured later."
fi
if [[ -n "$EMAIL" && ! "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  die "Invalid email format"
fi

log "Installing required packages without performing an unattended full system upgrade"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates nginx dropbear certbot python3 python3-wsproto procps passwd iproute2 iputils-ping fail2ban curl dnsutils openssl
python3 - <<'PY' || die "Python 3.10 or newer is required (use Ubuntu 22.04+/Debian 12+ or install a supported Python)"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY

for protected_path in "$CONFIG_DIR" "$INSTALL_DIR"; do
  if [[ -L "$protected_path" ]]; then
    die "Refusing to use symlinked protected path: $protected_path"
  fi
done

log "Creating dedicated group and unprivileged Telegram bot account"
getent group abdulbasit >/dev/null || groupadd --system abdulbasit
if ! id abdulbasit-bot >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid abdulbasit abdulbasit-bot
fi
if ! id abdulbasit-web >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid abdulbasit abdulbasit-web
fi
getent group abdulbasit-xray >/dev/null || groupadd --system abdulbasit-xray
getent group abdulbasit-gateway >/dev/null || groupadd --system abdulbasit-gateway
getent group abdulbasit-dnstt >/dev/null || groupadd --system abdulbasit-dnstt
if ! id abdulbasit-dnstt >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid abdulbasit-dnstt abdulbasit-dnstt
fi
if ! id abdulbasit-xray >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid abdulbasit-xray abdulbasit-xray
fi

install -d -m 0750 -o root -g abdulbasit "$CONFIG_DIR" "$CONFIG_DIR/users"
install -d -m 0700 -o root -g root "$BACKUP_DIR"
install -d -m 0755 -o root -g root "$INSTALL_DIR" /var/www/letsencrypt
# systemd resolves mandatory ReadWritePaths before starting paneld. Certbot may
# not create its work/log directories until the first certificate request.
install -d -m 0700 -o root -g root /var/lib/letsencrypt /var/log/letsencrypt
install -d -m 0750 -o root -g abdulbasit-xray /etc/abdulbasit-xray
install -d -m 0755 -o root -g root "$INSTALL_DIR/web"
if [[ -f "$INSTALL_DIR/paneld.py" ]]; then
  cp -a "$INSTALL_DIR" "$BACKUP_DIR/app.$(date -u +%Y%m%dT%H%M%SZ)"
fi

# Personalized owner bootstrap. The numeric Telegram ID is not a bot token or password.
if [[ -L "$CONFIG_DIR/super_admin.conf" || ( -e "$CONFIG_DIR/super_admin.conf" && ! -f "$CONFIG_DIR/super_admin.conf" ) ]]; then
  die "Unsafe Super Admin configuration path detected"
fi
if [[ ! -s "$CONFIG_DIR/super_admin.conf" ]]; then
  printf '%s\n' "$DEFAULT_SUPER_ADMIN_ID" > "$CONFIG_DIR/super_admin.conf"
fi
chown root:abdulbasit "$CONFIG_DIR/super_admin.conf"
chmod 0640 "$CONFIG_DIR/super_admin.conf"

log "Quarantining legacy root scripts/services from older panel releases, if present"
for legacy_unit in ws-proxy autokill tgbot raretriccks-paneld raretriccks-ws raretriccks-session-enforcer raretriccks-bot; do
  if systemctl cat "$legacy_unit.service" >/dev/null 2>&1; then
    systemctl disable --now "$legacy_unit.service" >/dev/null 2>&1 || true
    [[ -f "/etc/systemd/system/$legacy_unit.service" ]] && cp -a "/etc/systemd/system/$legacy_unit.service" "$BACKUP_DIR/$legacy_unit.service.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
done
for legacy_file in /usr/local/bin/ws-proxy.py /usr/local/bin/autokill.py /usr/local/bin/tgbot.py \
  /usr/local/sbin/raretriccks-panelctl /usr/local/sbin/raretriccks-menu /usr/local/sbin/raretriccks-security-check; do
  if [[ -f "$legacy_file" ]]; then
    mv "$legacy_file" "$BACKUP_DIR/$(basename "$legacy_file").legacy.$(date -u +%Y%m%dT%H%M%SZ)"
    chmod 0600 "$BACKUP_DIR"/*.legacy.* 2>/dev/null || true
  fi
done
for legacy_cfg in "$CONFIG_DIR" "$LEGACY_CONFIG_DIR"; do
  if [[ -d "$legacy_cfg/bot_states" ]]; then
    warn "Removing legacy Telegram state files because they may contain plaintext passwords: $legacy_cfg/bot_states"
    find "$legacy_cfg/bot_states" -type f -exec rm -f -- {} +
    rmdir "$legacy_cfg/bot_states" 2>/dev/null || true
  fi
  if [[ -f "$legacy_cfg/bot.conf" ]]; then
    chmod 0600 "$legacy_cfg/bot.conf"
    warn "Legacy bot.conf was found in $legacy_cfg. Rotate the old Telegram token; do not import it."
  fi
done
if [[ -d "$LEGACY_CONFIG_DIR" ]]; then
  warn "Older /etc/raretriccks configuration was detected. It is left root-only for manual review and is not trusted or imported."
  find "$LEGACY_CONFIG_DIR" -type f -exec chmod go-rwx {} + 2>/dev/null || true
fi
for legacy_nginx in /etc/nginx/conf.d/vpn.conf /etc/nginx/conf.d/raretriccks-vpn.conf; do
  if [[ -f "$legacy_nginx" ]]; then
    cp -a "$legacy_nginx" "$BACKUP_DIR/$(basename "$legacy_nginx").legacy.$(date -u +%Y%m%dT%H%M%SZ)"
    rm -f "$legacy_nginx"
  fi
done
if command -v crontab >/dev/null 2>&1; then
  old_cron="$(crontab -l 2>/dev/null || true)"
  if [[ -n "$old_cron" ]]; then
    printf '%s\n' "$old_cron" > "$BACKUP_DIR/root.crontab.$(date -u +%Y%m%dT%H%M%SZ)"
    printf '%s\n' "$old_cron" | grep -v "certbot renew --quiet --pre-hook.*systemctl stop nginx" | crontab - || true
  fi
fi
find "$CONFIG_DIR" -type f -exec chmod go-rwx {} + 2>/dev/null || true
chown root:abdulbasit "$CONFIG_DIR/super_admin.conf"
chmod 0640 "$CONFIG_DIR/super_admin.conf"
install -m 0755 -o root -g root "$PROJECT_DIR/src/common.py" "$INSTALL_DIR/common.py"
install -m 0755 -o root -g root "$PROJECT_DIR/src/panel_client.py" "$INSTALL_DIR/panel_client.py"
install -m 0755 -o root -g root "$PROJECT_DIR/src/paneld.py" "$INSTALL_DIR/paneld.py"
install -m 0755 -o root -g root "$PROJECT_DIR/src/panelctl.py" "$INSTALL_DIR/panelctl.py"
install -m 0755 -o root -g root "$PROJECT_DIR/src/tgbot.py" "$INSTALL_DIR/tgbot.py"
install -m 0755 -o root -g root "$PROJECT_DIR/src/ws_proxy.py" "$INSTALL_DIR/ws_proxy.py"
install -m 0755 -o root -g root "$PROJECT_DIR/src/session_enforcer.py" "$INSTALL_DIR/session_enforcer.py"
install -m 0755 -o root -g root "$PROJECT_DIR/src/dropbear_sessions.py" "$INSTALL_DIR/dropbear_sessions.py"
install -m 0755 -o root -g root "$PROJECT_DIR/scripts/tunnel-shell" "$INSTALL_DIR/tunnel-shell"
if ! grep -Fxq "$INSTALL_DIR/tunnel-shell" /etc/shells; then
  printf '\n%s\n' "$INSTALL_DIR/tunnel-shell" >> /etc/shells
fi
PYTHONPATH="$INSTALL_DIR" python3 - <<'PY'
import pwd, subprocess
from common import USERS_DIR, ValidationError, read_json, validate_username
for path in USERS_DIR.glob('*.json'):
    data = read_json(path, {})
    try:
        name = validate_username(str(data.get('username', path.stem)))
        account = pwd.getpwnam(name)
    except (ValidationError, KeyError):
        continue
    if account.pw_shell == '/bin/false' and account.pw_uid != 0:
        subprocess.run(['/usr/sbin/usermod', '--shell', '/usr/local/lib/abdulbasit/tunnel-shell', name], check=True)
PY
for module in web_auth web_server xray_manager diagnostics client_formats cdn_manager profile_backup operations traffic slowdns maintenance terminal_ui gateway_identity ssh_identity; do
  install -m 0755 -o root -g root "$PROJECT_DIR/src/$module.py" "$INSTALL_DIR/$module.py"
done
python3 "$INSTALL_DIR/gateway_identity.py"
install -m 0755 -o root -g root "$PROJECT_DIR/scripts/install-dnstt.sh" "$INSTALL_DIR/install-dnstt.sh"
install -m 0644 -o root -g root "$PROJECT_DIR/src/web/"* "$INSTALL_DIR/web/"
if [[ $WITH_XRAY -eq 1 ]]; then
  bash "$PROJECT_DIR/scripts/install-xray.sh" "$XRAY_VERSION"
fi
if [[ $WITH_DNSTT -eq 1 ]]; then
  bash "$PROJECT_DIR/scripts/install-dnstt.sh"
fi
install -m 0755 -o root -g root "$PROJECT_DIR/menu.sh" /usr/local/sbin/abdulbasit-menu
ln -sfn /usr/local/sbin/abdulbasit-menu /usr/local/bin/menu
ln -sfn /usr/local/sbin/abdulbasit-menu /usr/bin/menu
cat > /usr/local/sbin/abdulbasit-panelctl <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /usr/local/lib/abdulbasit/panelctl.py "$@"
EOF
chmod 0755 /usr/local/sbin/abdulbasit-panelctl
install -m 0755 -o root -g root "$PROJECT_DIR/scripts/security-check.sh" /usr/local/sbin/abdulbasit-security-check

if [[ -n "$EMAIL" ]]; then
  printf '%s\n' "$EMAIL" > "$CONFIG_DIR/certbot_email.conf"
  chown root:abdulbasit "$CONFIG_DIR/certbot_email.conf"
  chmod 0640 "$CONFIG_DIR/certbot_email.conf"
fi

log "Backing up and configuring Dropbear on ports 109 and 447"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
dropbear_was_active=0
systemctl is-active --quiet dropbear && dropbear_was_active=1
dropbear_previous="$BACKUP_DIR/dropbear.default.$timestamp"
if [[ -f /etc/default/dropbear ]]; then
  cp -a /etc/default/dropbear "$dropbear_previous"
fi
for port in 109 447; do
  conflict="$(ss -H -ltnp "sport = :$port" 2>/dev/null || true)"
  if [[ -n "$conflict" ]] && printf '%s\n' "$conflict" | grep -qv '"dropbear"'; then
    die "Port $port is already occupied by another service"
  fi
done
cat > /etc/default/dropbear <<'EOF'
# Managed by Abdul Basit Secure VPS Panel
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 447 -b /etc/abdulbasit/ssh-banner.txt -w -k -T 3 -K 30 -I 1800 -W 131072"
DROPBEAR_BANNER=""
EOF
chmod 0644 /etc/default/dropbear
if [[ ! -f "$CONFIG_DIR/ssh-banner.txt" ]]; then
  printf '%s\n' 'NOWAY / Private VPS access' 'Authorized accounts only.' > "$CONFIG_DIR/ssh-banner.txt"
fi
chmod 0644 "$CONFIG_DIR/ssh-banner.txt"
dropbear_ready() {
  systemctl is-active --quiet dropbear || return 1
  local port
  for port in 109 447; do
    ss -H -ltnp "sport = :$port" | grep -q '"dropbear"' || return 1
  done
}
if ! systemctl restart dropbear || ! dropbear_ready; then
  warn "Dropbear configuration failed; restoring previous defaults"
  if [[ -f "$dropbear_previous" ]]; then
    cp -a "$dropbear_previous" /etc/default/dropbear
  else
    rm -f /etc/default/dropbear
  fi
  if [[ "$dropbear_was_active" == 1 ]]; then
    systemctl restart dropbear || warn "Previous Dropbear service could not be restored; normal OpenSSH is unchanged"
  else
    systemctl stop dropbear || true
  fi
  die "Dropbear did not open both managed ports; previous configuration restored"
fi
systemctl enable dropbear

if [[ -f /etc/fail2ban/filter.d/dropbear.conf ]]; then
  log "Enabling Fail2ban protection for direct Dropbear ports"
  cat > /etc/fail2ban/jail.d/abdulbasit-dropbear.local <<'EOF'
[dropbear]
enabled = true
port = 109,447
backend = systemd
ignoreip = 127.0.0.1/8 ::1
maxretry = 5
findtime = 10m
bantime = 1h
EOF
  if systemctl enable --now fail2ban; then
    fail2ban-client reload || warn "Fail2ban reload failed; inspect: journalctl -u fail2ban"
  else
    warn "Fail2ban could not start; continue installation and inspect: journalctl -u fail2ban"
  fi
else
  warn "Dropbear Fail2ban filter was not found; direct-port brute-force jail was not enabled"
fi

for old_unit_file in /etc/systemd/system/raretriccks-*.service; do
  [[ -e "$old_unit_file" ]] || continue
  cp -a "$old_unit_file" "$BACKUP_DIR/$(basename "$old_unit_file").legacy.$(date -u +%Y%m%dT%H%M%SZ)"
  rm -f "$old_unit_file"
done
rm -f /etc/letsencrypt/renewal-hooks/deploy/raretriccks-nginx-reload
rm -f /etc/fail2ban/jail.d/raretriccks-dropbear.local
systemctl daemon-reload

log "Installing hardened systemd services"
for unit in "$PROJECT_DIR"/systemd/*.service "$PROJECT_DIR"/systemd/*.timer; do
  install -m 0644 -o root -g root "$unit" "/etc/systemd/system/$(basename "$unit")"
done
systemctl daemon-reload
systemctl enable abdulbasit-paneld abdulbasit-ws abdulbasit-session-enforcer abdulbasit-web abdulbasit-xray
systemctl restart abdulbasit-paneld abdulbasit-ws abdulbasit-session-enforcer abdulbasit-web
for attempt in {1..30}; do
  [[ -S /run/abdulbasit/paneld.sock ]] && break
  sleep 0.2
done
[[ -S /run/abdulbasit/paneld.sock ]] || die "Panel daemon socket not ready; inspect journalctl -u abdulbasit-paneld"
systemctl enable --now abdulbasit-xray-expiry.timer
systemctl restart abdulbasit-xray-expiry.timer
if [[ -f /etc/abdulbasit-dnstt/config.json ]]; then
  if "$INSTALL_DIR/panelctl.py" slowdns-status | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("enabled") else 1)'; then
    systemctl enable abdulbasit-dnstt
    systemctl restart abdulbasit-dnstt
    systemctl is-active --quiet abdulbasit-dnstt || die "Configured SlowDNS service failed to start"
  fi
fi
if [[ -f /etc/abdulbasit-xray/enabled ]]; then
  "$INSTALL_DIR/panelctl.py" xray-enable
fi

log "Installing Certbot deploy hook (reloads Nginx only after a successful renewal)"
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/abdulbasit-nginx-reload <<'EOF'
#!/usr/bin/env bash
set -e
/usr/sbin/nginx -t
/bin/systemctl reload nginx
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/abdulbasit-nginx-reload

if systemctl list-unit-files | grep -q '^certbot.timer'; then
  systemctl enable --now certbot.timer
fi

if [[ -z "$DOMAIN" && -s "$CONFIG_DIR/domain.conf" ]]; then
  DOMAIN="$(cat "$CONFIG_DIR/domain.conf")"
fi
if [[ -n "$DOMAIN" ]]; then
  log "Validating domain and writing rollback-safe Nginx configuration"
  "$INSTALL_DIR/panelctl.py" set-domain "$DOMAIN"
  log "Requesting Let's Encrypt certificate using the webroot method"
  if "$INSTALL_DIR/panelctl.py" issue-cert --domain "$DOMAIN"; then
    ok "TLS certificate installed"
  else
    warn "Certificate issuance failed. HTTP WebSocket remains configured; check DNS and run: menu → Issue/renew SSL"
  fi
fi

systemctl enable abdulbasit-bot >/dev/null 2>&1 || true
if [[ -s "$CONFIG_DIR/bot_token.conf" ]]; then
  systemctl restart abdulbasit-bot
fi

log "Running local syntax and security checks"
python3 -m py_compile "$INSTALL_DIR"/*.py
bash -n /usr/local/sbin/abdulbasit-menu
nginx -t
/usr/local/sbin/abdulbasit-security-check || warn "One or more runtime checks need attention; review the output above"

ok "Installation complete"
cat <<'EOF'

Open the panel with:
  menu

Create or reset your browser login (no default password):
  abdulbasit-panelctl configure-web

Browser dashboard:
  https://YOUR-DOMAIN/panel/

Install the optional Xray core with:
  bash install.sh --with-xray --domain YOUR-DOMAIN
After TLS succeeds, enable it from the dashboard or:
  abdulbasit-panelctl xray-enable

Public/provider firewall ports required:
  22/tcp (server administration), 80/tcp, 443/tcp, 109/tcp, 447/tcp

Internal ports 2082, 9090 and 10001-10003 must NOT be opened publicly.
Configure Telegram from: menu → Telegram bot → Configure token and Super Admin
EOF

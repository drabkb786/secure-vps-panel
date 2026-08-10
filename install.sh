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
INSTALL_DNSTT=1
DEFAULT_SUPER_ADMIN_ID="6408975845"

log() { printf '\033[0;34m[INFO]\033[0m %s\n' "$*"; }
ok() { printf '\033[0;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die() { printf '\033[0;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "Installation failed near line $LINENO. Existing SSH port 22 was not intentionally modified."' ERR

usage() {
  cat <<'EOF'
Usage: sudo bash install.sh [--domain vpn.example.com] [--email admin@example.com] [--non-interactive] [--skip-dnstt]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --skip-dnstt) INSTALL_DNSTT=0; shift ;;
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
apt-get install -y --no-install-recommends ca-certificates curl unzip git nginx dropbear certbot python3 procps passwd iproute2 fail2ban
python3 - <<'PY' || die "Python 3.10 or newer is required (use Ubuntu 22.04+/Debian 12+ or install a supported Python)"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY

for protected_path in "$CONFIG_DIR" "$INSTALL_DIR"; do
  if [[ -L "$protected_path" ]]; then
    die "Refusing to use symlinked protected path: $protected_path"
  fi
done

log "Creating isolated groups and unprivileged service accounts"
getent group abdulbasit >/dev/null || groupadd --system abdulbasit
getent group abdulbasit-clients >/dev/null || groupadd --system abdulbasit-clients
if ! id abdulbasit-bot >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid abdulbasit abdulbasit-bot
fi
getent group abdulbasit-dashboard >/dev/null || groupadd --system abdulbasit-dashboard
if ! id abdulbasit-dashboard >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid abdulbasit-dashboard abdulbasit-dashboard
fi
getent group abdulbasit-xray >/dev/null || groupadd --system abdulbasit-xray
if ! id abdulbasit-xray >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid abdulbasit-xray abdulbasit-xray
fi
getent group abdulbasit-dnstt >/dev/null || groupadd --system abdulbasit-dnstt
if ! id abdulbasit-dnstt >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid abdulbasit-dnstt abdulbasit-dnstt
fi
usermod -a -G abdulbasit-clients abdulbasit-bot
usermod -a -G abdulbasit-clients abdulbasit-dashboard
usermod -a -G abdulbasit abdulbasit-xray
usermod -a -G abdulbasit abdulbasit-dnstt
usermod -g abdulbasit-dashboard -a -G abdulbasit abdulbasit-dashboard

install -d -m 0750 -o root -g abdulbasit "$CONFIG_DIR" "$CONFIG_DIR/users"
install -d -m 0750 -o root -g abdulbasit-xray "$CONFIG_DIR/xray"
install -d -m 0750 -o root -g abdulbasit-dnstt "$CONFIG_DIR/dnstt"
install -d -m 0750 -o root -g abdulbasit "$CONFIG_DIR/exports"
install -d -m 0700 -o root -g root "$BACKUP_DIR"
install -d -m 0755 -o root -g root "$INSTALL_DIR" /var/www/letsencrypt
install -d -m 0755 -o root -g root /usr/local/share/abdulbasit-dashboard
if [[ -f "$CONFIG_DIR/dashboard_auth.json" && ! -L "$CONFIG_DIR/dashboard_auth.json" ]]; then
  chown root:abdulbasit-dashboard "$CONFIG_DIR/dashboard_auth.json"
  chmod 0640 "$CONFIG_DIR/dashboard_auth.json"
fi
if [[ -f "$CONFIG_DIR/cdn.json" && ! -L "$CONFIG_DIR/cdn.json" ]]; then
  chown root:root "$CONFIG_DIR/cdn.json"
  chmod 0600 "$CONFIG_DIR/cdn.json"
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
for shared_config in super_admin.conf domain.conf bot_token.conf admin_ids.conf certbot_email.conf; do
  if [[ -f "$CONFIG_DIR/$shared_config" && ! -L "$CONFIG_DIR/$shared_config" ]]; then
    chown root:abdulbasit "$CONFIG_DIR/$shared_config"
    chmod 0640 "$CONFIG_DIR/$shared_config"
  fi
done
if [[ -f "$CONFIG_DIR/dashboard_auth.json" && ! -L "$CONFIG_DIR/dashboard_auth.json" ]]; then
  chown root:abdulbasit-dashboard "$CONFIG_DIR/dashboard_auth.json"
  chmod 0640 "$CONFIG_DIR/dashboard_auth.json"
fi
if [[ -f "$CONFIG_DIR/dnstt.json" && ! -L "$CONFIG_DIR/dnstt.json" ]]; then
  chown root:abdulbasit-dnstt "$CONFIG_DIR/dnstt.json"
  chmod 0640 "$CONFIG_DIR/dnstt.json"
fi
for dnstt_key in "$CONFIG_DIR/dnstt/server.key" "$CONFIG_DIR/dnstt/server.pub"; do
  if [[ -f "$dnstt_key" && ! -L "$dnstt_key" ]]; then
    chown root:abdulbasit-dnstt "$dnstt_key"
    chmod 0640 "$dnstt_key"
  fi
done
if [[ -f "$CONFIG_DIR/cdn.json" && ! -L "$CONFIG_DIR/cdn.json" ]]; then
  chown root:root "$CONFIG_DIR/cdn.json"
  chmod 0600 "$CONFIG_DIR/cdn.json"
fi
for source_file in "$PROJECT_DIR"/src/*.py; do
  install -m 0755 -o root -g root "$source_file" "$INSTALL_DIR/$(basename "$source_file")"
done
for asset in "$PROJECT_DIR"/web/*; do
  install -m 0644 -o root -g root "$asset" "/usr/local/share/abdulbasit-dashboard/$(basename "$asset")"
done
install -m 0755 -o root -g root "$PROJECT_DIR/menu.sh" /usr/local/sbin/abdulbasit-menu
ln -sfn /usr/local/sbin/abdulbasit-menu /usr/local/bin/menu
ln -sfn /usr/local/sbin/abdulbasit-menu /usr/bin/menu
cat > /usr/local/sbin/abdulbasit-panelctl <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /usr/local/lib/abdulbasit/panelctl.py "$@"
EOF
chmod 0755 /usr/local/sbin/abdulbasit-panelctl
install -m 0755 -o root -g root "$PROJECT_DIR/scripts/security-check.sh" /usr/local/sbin/abdulbasit-security-check

log "Installing pinned, checksum-verified Xray core"
bash "$PROJECT_DIR/scripts/install-xray.sh"
if [[ $INSTALL_DNSTT -eq 1 ]]; then
  log "Building pinned DNSTT server source"
  bash "$PROJECT_DIR/scripts/install-dnstt.sh"
else
  warn "DNSTT binary installation skipped; run scripts/install-dnstt.sh before configuring DNSTT"
fi

PYTHONPATH="$INSTALL_DIR" /usr/bin/python3 - <<'PY'
from xray_runtime import deploy_config
deploy_config(restart=False)
PY
chown root:abdulbasit-xray "$CONFIG_DIR/xray/config.json"
chmod 0640 "$CONFIG_DIR/xray/config.json"

if [[ -n "$EMAIL" ]]; then
  printf '%s\n' "$EMAIL" > "$CONFIG_DIR/certbot_email.conf"
  chown root:abdulbasit "$CONFIG_DIR/certbot_email.conf"
  chmod 0640 "$CONFIG_DIR/certbot_email.conf"
fi

log "Backing up and configuring Dropbear on ports 109 and 447"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -f /etc/default/dropbear ]]; then
  cp -a /etc/default/dropbear "$BACKUP_DIR/dropbear.default.$timestamp"
fi
for port in 109 447; do
  conflict="$(ss -ltnp "sport = :$port" 2>/dev/null || true)"
  if [[ -n "$conflict" && "$conflict" != *dropbear* ]]; then
    die "Port $port is already occupied by another service"
  fi
done
cat > /etc/default/dropbear <<'EOF'
# Managed by Abdul Basit Secure VPS Panel
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 447 -b /etc/issue.net -w -K 30 -I 1800"
DROPBEAR_BANNER="/etc/issue.net"
EOF
chmod 0644 /etc/default/dropbear
: > /etc/issue.net
chmod 0644 /etc/issue.net
systemctl enable dropbear
systemctl restart dropbear
systemctl is-active --quiet dropbear || die "Dropbear failed to start; restore from $BACKUP_DIR if needed"

if [[ -f /etc/fail2ban/filter.d/dropbear.conf ]]; then
  log "Enabling Fail2ban protection for direct Dropbear ports"
  cat > /etc/fail2ban/jail.d/abdulbasit-dropbear.local <<'EOF'
[dropbear]
enabled = true
port = 109,447
backend = systemd
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
systemctl enable --now abdulbasit-paneld abdulbasit-ws abdulbasit-session-enforcer abdulbasit-xray
systemctl enable --now abdulbasit-usage.timer

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

systemctl enable abdulbasit-bot abdulbasit-dashboard abdulbasit-dnstt >/dev/null 2>&1 || true

log "Running local syntax and security checks"
python3 -m py_compile "$INSTALL_DIR"/*.py
bash -n /usr/local/sbin/abdulbasit-menu
nginx -t
/usr/local/sbin/abdulbasit-security-check || warn "One or more runtime checks need attention; review the output above"

ok "Installation complete"
cat <<'EOF'

Open the panel with:
  menu

Public/provider firewall ports required:
  22/tcp (server administration), 80/tcp, 443/tcp, 109/tcp, 447/tcp
  53/udp only when DNSTT is configured

Ports 2082, 9080, 21001-21003 and 21085 are loopback-only and must NOT be opened publicly.
Configure the TLS dashboard from: menu → Configure secure web dashboard
Configure Telegram from: menu → Telegram bot → Configure token and Super Admin
EOF

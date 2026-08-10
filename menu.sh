#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
CTL="/usr/local/sbin/abdulbasit-panelctl"

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo -e "${RED}Run as root: sudo -i${NC}"; exit 1; }
[[ -x "$CTL" ]] || { echo -e "${RED}Panel is not installed. Run install.sh first.${NC}"; exit 1; }

pause() { read -r -p "Press Enter to continue..." _; }
run_ctl() { "$CTL" "$@" || true; }

user_menu() {
  while true; do
    clear
    cat <<'EOF'
================ User Management ================
1) Create multi-protocol user
2) Delete managed user
3) Renew user
4) Set concurrent SSH session limit
5) Set Xray data limit
6) Reset Xray usage
7) List users
8) List active SSH sessions
9) Back
EOF
    read -r -p "Option [1-9]: " choice
    case "$choice" in
      1)
        read -r -p "Username: " username
        read -r -p "Validity days: " days
        read -r -p "Concurrent SSH sessions [1-20]: " sessions
        read -r -p "Xray data limit GB or Unlimited: " quota
        read -r -p "Protocols [ssh,vmess,vless,trojan]: " protocols
        run_ctl create-user "$username" --days "$days" --sessions "$sessions" --quota "$quota" --protocols "$protocols"; pause ;;
      2)
        read -r -p "Managed username to delete: " username
        read -r -p "Type DELETE to confirm: " confirm
        [[ "$confirm" == "DELETE" ]] && run_ctl delete-user "$username"
        pause ;;
      3) read -r -p "Username: " username; read -r -p "Days to add: " days; run_ctl renew-user "$username" --days "$days"; pause ;;
      4) read -r -p "Username: " username; read -r -p "New concurrent session limit: " sessions; run_ctl set-sessions "$username" --sessions "$sessions"; pause ;;
      5) read -r -p "Username: " username; read -r -p "GB or Unlimited: " quota; run_ctl set-quota "$username" --quota "$quota"; pause ;;
      6) read -r -p "Username: " username; run_ctl reset-usage "$username"; pause ;;
      7) run_ctl list-users; pause ;;
      8) run_ctl list-sessions; pause ;;
      9) return ;;
      *) sleep 1 ;;
    esac
  done
}

protocol_menu() {
  while true; do
    clear
    cat <<'EOF'
================ Protocols and Files =============
1) Enable protocol(s)
2) Disable protocol
3) Rotate VMess/VLESS/Trojan credential
4) Generate Xray/NetMod/DarkTunnel/payload files
5) List generated files
6) Delete generated file
7) Back
EOF
    read -r -p "Option [1-7]: " choice
    case "$choice" in
      1) read -r -p "Username: " username; read -r -p "Protocols: " protocols; run_ctl enable-protocol "$username" "$protocols"; pause ;;
      2) read -r -p "Username: " username; read -r -p "Protocol: " protocol; run_ctl disable-protocol "$username" "$protocol"; pause ;;
      3) read -r -p "Username: " username; read -r -p "Protocol: " protocol; run_ctl rotate-protocol "$username" "$protocol"; pause ;;
      4) read -r -p "Username: " username; read -r -p "Protocol [vmess/vless/trojan]: " protocol; read -r -p "Route [direct/cloudflare/cloudfront]: " provider; run_ctl generate-exports "$username" "$protocol" --provider "$provider"; pause ;;
      5) read -r -p "Username: " username; run_ctl list-exports "$username"; pause ;;
      6) read -r -p "Username: " username; read -r -p "Exact filename: " filename; run_ctl delete-export "$username" "$filename"; pause ;;
      7) return ;;
      *) sleep 1 ;;
    esac
  done
}

cdn_menu() {
  while true; do
    clear
    cat <<'EOF'
================ CDN Management ==================
1) Configure Amazon CloudFront
2) Configure Cloudflare
3) List CDN profiles
4) Disable CDN profile
5) Back
EOF
    read -r -p "Option [1-5]: " choice
    case "$choice" in
      1)
        read -r -p "CloudFront distribution domain: " endpoint
        read -r -p "VPS origin domain: " origin
        read -r -s -p "Origin secret (blank = generate): " secret
        echo
        if [[ -n "$secret" ]]; then
          run_ctl configure-cdn cloudfront --endpoint "$endpoint" --origin "$origin" --secret "$secret"
        else
          run_ctl configure-cdn cloudfront --endpoint "$endpoint" --origin "$origin"
        fi
        pause ;;
      2) read -r -p "Cloudflare-proxied hostname: " endpoint; read -r -p "VPS origin domain: " origin; run_ctl configure-cdn cloudflare --endpoint "$endpoint" --origin "$origin"; pause ;;
      3) run_ctl list-cdn; pause ;;
      4) read -r -p "Provider [cloudfront/cloudflare]: " provider; run_ctl remove-cdn "$provider"; pause ;;
      5) return ;;
      *) sleep 1 ;;
    esac
  done
}

dnstt_menu() {
  while true; do
    clear
    cat <<'EOF'
================ DNSTT + SSH =====================
1) Configure DNSTT
2) Show DNS records/status
3) Generate user DNSTT file
4) Disable DNSTT
5) Back
EOF
    read -r -p "Option [1-5]: " choice
    case "$choice" in
      1) read -r -p "Tunnel zone (t.example.com): " zone; read -r -p "Nameserver (tns.example.com): " nameserver; read -r -p "VPS public bind IP: " listen_ip; run_ctl configure-dnstt --zone "$zone" --nameserver "$nameserver" --listen-ip "$listen_ip"; pause ;;
      2) run_ctl list-dnstt; pause ;;
      3) read -r -p "Username: " username; run_ctl export-dnstt "$username"; pause ;;
      4) run_ctl disable-dnstt; pause ;;
      5) return ;;
      *) sleep 1 ;;
    esac
  done
}

bot_menu() {
  while true; do
    clear
    cat <<'EOF'
================ Telegram Bot ====================
1) Configure token and Super Admin
2) Add admin
3) Remove admin
4) List admins
5) Restart bot
6) Stop bot
7) Back
EOF
    read -r -p "Option [1-7]: " choice
    case "$choice" in
      1) run_ctl configure-bot; pause ;;
      2) read -r -p "Telegram numeric ID: " tid; run_ctl add-admin "$tid"; pause ;;
      3) read -r -p "Telegram numeric ID: " tid; run_ctl remove-admin "$tid"; pause ;;
      4) run_ctl list-admins; pause ;;
      5) systemctl restart abdulbasit-bot; systemctl --no-pager --full status abdulbasit-bot || true; pause ;;
      6) systemctl stop abdulbasit-bot; pause ;;
      7) return ;;
      *) sleep 1 ;;
    esac
  done
}

while true; do
  clear
  echo -e "${CYAN}====================================================${NC}"
  echo -e "${YELLOW}       Abdul Basit Secure VPS Panel v3.0.0${NC}"
  echo -e "${CYAN}====================================================${NC}"
  cat <<'EOF'
1) User management
2) Protocols and generated files
3) CloudFront / Cloudflare
4) Configure secure web dashboard
5) Set/change domain
6) Issue/renew SSL
7) DNSTT + SSH
8) Telegram bot
9) Service status
10) Restart core services
11) View recent logs
12) Exit
EOF
  read -r -p "Option [1-12]: " choice
  case "$choice" in
    1) user_menu ;;
    2) protocol_menu ;;
    3) cdn_menu ;;
    4) run_ctl configure-dashboard; pause ;;
    5) read -r -p "Domain (vpn.example.com): " domain; run_ctl set-domain "$domain"; pause ;;
    6) run_ctl issue-cert; pause ;;
    7) dnstt_menu ;;
    8) bot_menu ;;
    9) run_ctl status; pause ;;
    10)
      run_ctl restart dropbear
      run_ctl restart abdulbasit-ws
      run_ctl restart abdulbasit-xray
      run_ctl restart abdulbasit-dashboard
      run_ctl restart nginx
      pause ;;
    11) journalctl --no-pager -n 150 -u abdulbasit-paneld -u abdulbasit-ws -u abdulbasit-xray -u abdulbasit-dashboard -u abdulbasit-usage -u abdulbasit-dnstt -u abdulbasit-bot || true; pause ;;
    12) exit 0 ;;
    *) sleep 1 ;;
  esac
done

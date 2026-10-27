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
1) Create user
2) Delete managed user
3) Renew user
4) Set concurrent session limit
5) Set quota metadata (not enforced)
6) List users
7) List active sessions
8) Back
EOF
    read -r -p "Option [1-8]: " choice
    case "$choice" in
      1)
        read -r -p "Username: " username
        read -r -p "Validity days: " days
        read -r -p "Concurrent sessions [1-20]: " sessions
        read -r -p "Quota metadata in GB or Unlimited: " quota
        run_ctl create-user "$username" --days "$days" --sessions "$sessions" --quota "$quota"; pause ;;
      2)
        read -r -p "Managed username to delete: " username
        read -r -p "Type DELETE to confirm: " confirm
        [[ "$confirm" == "DELETE" ]] && run_ctl delete-user "$username"
        pause ;;
      3)
        read -r -p "Username: " username; read -r -p "Days to add: " days
        run_ctl renew-user "$username" --days "$days"; pause ;;
      4)
        read -r -p "Username: " username; read -r -p "New concurrent session limit: " sessions
        run_ctl set-sessions "$username" --sessions "$sessions"; pause ;;
      5)
        read -r -p "Username: " username; read -r -p "Quota metadata (GB or Unlimited): " quota
        run_ctl set-quota "$username" --quota "$quota"; pause ;;
      6) run_ctl list-users; pause ;;
      7) run_ctl list-sessions; pause ;;
      8) return ;;
      *) sleep 1 ;;
    esac
  done
}

bot_menu() {
  while true; do
    clear
    cat <<'EOF'
================ Telegram Bot ===================
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

network_menu() {
  while true; do
    clear
    cat <<'EOF'
NOWAY / DNS, TLS & WEB

1) Configure / reset web login
2) Domain DNS lookup
3) Set Xray DNS resolvers
4) Run diagnostics
5) Back
EOF
    read -r -p "Option [1-5]: " choice
    case "$choice" in
      1) run_ctl configure-web; pause ;;
      2) run_ctl dns-lookup; pause ;;
      3)
        read -r -p "Primary DNS IP / HTTPS DoH URL: " dns1
        read -r -p "Secondary DNS IP / HTTPS DoH URL: " dns2
        read -r -p "Strategy (UseIPv4 / UseIP / UseIPv6) [UseIPv4]: " strategy
        if [[ -n "$dns2" ]]; then
          run_ctl dns-set --server "$dns1" --server "$dns2" --strategy "${strategy:-UseIPv4}"
        else
          run_ctl dns-set --server "$dns1" --strategy "${strategy:-UseIPv4}"
        fi
        pause ;;
      4) run_ctl diagnostics; pause ;;
      5) return ;;
    esac
  done
}

xray_menu() {
  while true; do
    clear
    cat <<'EOF'
NOWAY / XRAY PROFILES

1) Status / profiles
2) Enable Xray (requires installed core + TLS)
3) Disable Xray
4) Create VLESS + VMess + Trojan profile
5) Renew profile
6) Delete profile
7) Direct VLESS / VMess / Trojan link
8) Export client ZIP
9) Back
EOF
    read -r -p "Option [1-9]: " choice
    case "$choice" in
      1) run_ctl xray-status; pause ;;
      2) run_ctl xray-enable; pause ;;
      3) run_ctl xray-disable; pause ;;
      4)
        read -r -p "Profile name: " name; read -r -p "Validity days: " days
        run_ctl xray-create "$name" --days "$days"; pause ;;
      5)
        read -r -p "Profile name: " name; read -r -p "Days to add: " days
        run_ctl xray-renew "$name" --days "$days"; pause ;;
      6)
        read -r -p "Profile name: " name; read -r -p "Type DELETE to confirm: " confirm
        [[ "$confirm" == "DELETE" ]] && run_ctl xray-delete "$name"
        pause ;;
      7)
        read -r -p "Profile name: " name; read -r -p "Protocol (vless/vmess/trojan) [vless]: " protocol
        run_ctl xray-link "$name" --protocol "${protocol:-vless}"; pause ;;
      8)
        read -r -p "Profile name: " name; read -r -p "Save ZIP to (new absolute path): " output
        run_ctl xray-export "$name" --zip "$output"; pause ;;
      9) return ;;
    esac
  done
}

while true; do
  clear
  echo -e "${CYAN}====================================================${NC}"
  echo -e "${GREEN}          NOWAY / VPS CONTROL ROOM v3.0${NC}"
  echo -e "${CYAN}                 by Abdul Basit${NC}"
  echo -e "${CYAN}====================================================${NC}"
  cat <<'EOF'
1) User management
2) Set/change domain
3) Issue/renew SSL
4) Telegram bot
5) Service status
6) Restart core services
7) View recent logs
8) Web dashboard / DNS / Diagnostics
9) Xray: VLESS / VMess / Trojan
0) Exit
EOF
  read -r -p "Option [0-9]: " choice
  case "$choice" in
    1) user_menu ;;
    2) read -r -p "Domain (vpn.example.com): " domain; run_ctl set-domain "$domain"; pause ;;
    3) run_ctl issue-cert; pause ;;
    4) bot_menu ;;
    5) run_ctl status; pause ;;
    6)
      run_ctl restart dropbear
      run_ctl restart abdulbasit-ws
      run_ctl restart abdulbasit-session-enforcer
      run_ctl restart nginx
      pause ;;
    7)
      journalctl --no-pager -n 100 -u abdulbasit-paneld -u abdulbasit-ws -u abdulbasit-session-enforcer -u abdulbasit-bot -u abdulbasit-web -u abdulbasit-xray || true
      pause ;;
    8) network_menu ;;
    9) xray_menu ;;
    0) exit 0 ;;
    *) sleep 1 ;;
  esac
done

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

while true; do
  clear
  echo -e "${CYAN}====================================================${NC}"
  echo -e "${YELLOW}       Abdul Basit Secure VPS Panel v2.1.0${NC}"
  echo -e "${CYAN}====================================================${NC}"
  cat <<'EOF'
1) User management
2) Set/change domain
3) Issue/renew SSL
4) Telegram bot
5) Service status
6) Restart core services
7) View recent logs
8) Exit
EOF
  read -r -p "Option [1-8]: " choice
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
      journalctl --no-pager -n 100 -u abdulbasit-paneld -u abdulbasit-ws -u abdulbasit-session-enforcer -u abdulbasit-bot || true
      pause ;;
    8) exit 0 ;;
    *) sleep 1 ;;
  esac
done

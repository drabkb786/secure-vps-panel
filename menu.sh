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
5) Clear legacy SSH quota note (GB metering unavailable)
6) List users
7) List active sessions
8) Export SSH links / adapter ZIP
9) Back
EOF
    read -r -p "Option [1-9]: " choice
    case "$choice" in
      1)
        read -r -p "Username: " username
        read -r -p "Validity days: " days
        read -r -p "Concurrent sessions [1-20]: " sessions
        read -r -p "Unique IP cap [0=Unlimited, 1-20]: " ips
        run_ctl create-user "$username" --days "$days" --sessions "$sessions" --quota Unlimited --ips "$ips"; pause ;;
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
        read -r -p "Unique IP cap [0=Unlimited, 1-20]: " ips
        run_ctl set-sessions "$username" --sessions "$sessions" --ips "$ips"; pause ;;
      5)
        read -r -p "Username: " username
        run_ctl set-quota "$username" --quota Unlimited; pause ;;
      6) run_ctl list-users; pause ;;
      7) run_ctl list-sessions; pause ;;
      8) read -r -p "Username: " username; read -r -p "Route (direct/bunny/cloudfront) [direct]: " route; read -r -p "Save private ZIP (new path, blank prints profiles): " output
         if [[ -n "$output" ]]; then run_ctl ssh-export "$username" --route "${route:-direct}" --zip "$output"; else run_ctl ssh-export "$username" --route "${route:-direct}"; fi; pause ;;
      9) return ;;
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
        read -r -p "Profile name: " name; read -r -p "Protocol (vless/vmess/trojan/vless-xhttp/vless-reality) [vless]: " protocol
        read -r -p "Route (direct/bunny/cloudfront) [direct]: " route
        run_ctl xray-link "$name" --protocol "${protocol:-vless}" --route "${route:-direct}"; pause ;;
      8)
        read -r -p "Profile name: " name; read -r -p "Save ZIP to (new absolute path): " output
        run_ctl xray-export "$name" --zip "$output"; pause ;;
      9) return ;;
    esac
  done
}

transport_menu() {
  while true; do
    clear
    echo 'NOWAY / TRANSPORT WORKBENCH'
    echo '1) UDP forwarding on  2) UDP forwarding off'
    echo '3) SlowDNS status     4) Configure / enable SlowDNS'
    echo '5) Check delegation   6) Disable SlowDNS'
    echo '7) Install official dnstt core  8) Enable direct REALITY  9) Disable REALITY'
    echo '10) Bunny delivery  11) CloudFront delivery  0) Back'
    read -r -p 'Choose: ' choice
    case "$choice" in
      1) run_ctl xray-udp on; pause ;;
      2) run_ctl xray-udp off; pause ;;
      3) run_ctl slowdns-status; pause ;;
      4) read -r -p 'DNS mode [ssh/xray/both, default ssh]: ' mode; read -r -p 'Xray zone (both mode only): ' xzone; read -r -p 'Tunnel zone: ' zone; read -r -p 'Nameserver host: ' ns; read -r -p 'UDP port [53]: ' port; read -r -p 'MTU [1232]: ' mtu; run_ctl slowdns-enable --zone "$zone" --ns-host "$ns" --port "${port:-53}" --mtu "${mtu:-1232}" --mode "${mode:-ssh}" --xray-zone "$xzone"; pause ;;
      5) run_ctl slowdns-check; pause ;;
      6) run_ctl slowdns-disable; pause ;;
      7) run_ctl slowdns-install; pause ;;
      8) read -r -p 'Direct REALITY port [8443]: ' port; run_ctl reality-enable --port "${port:-8443}"; echo 'Allow this TCP port in provider/UFW firewall after checking diagnostics.'; pause ;;
      9) run_ctl reality-disable; pause ;;
      10) read -r -p 'Bunny endpoint hostname: ' endpoint; run_ctl bunny-enable --endpoint "$endpoint"; read -r -p 'Private setup ZIP (new path): ' output; run_ctl bunny-setup --output "$output"; pause ;;
      11) read -r -p 'CloudFront distribution hostname (blank prepares origin): ' endpoint; run_ctl cloudfront-enable --endpoint "$endpoint"; read -r -p 'Private setup ZIP (new path): ' output; run_ctl cloudfront-setup --output "$output"; pause ;;
      0) return ;;
    esac
  done
}

while true; do
  clear
  /usr/local/lib/abdulbasit/python /usr/local/lib/abdulbasit/terminal_ui.py
  read -r -p 'Choose a control [00-23]: ' choice
  case "$choice" in
    1|01) read -r -p 'Profile name: ' name; read -r -p 'Days [30]: ' days; read -r -p 'GB limit / Unlimited [Unlimited]: ' quota; run_ctl xray-create "$name" --days "${days:-30}" --quota "${quota:-Unlimited}"; pause ;;
    2|02) read -r -p 'Trial profile name: ' name; read -r -p 'GB limit [1]: ' quota; run_ctl xray-trial "$name" --quota "${quota:-1}"; pause ;;
    3|03) run_ctl traffic; run_ctl connections; pause ;;
    4|04) bot_menu ;;
    5|05) read -r -p 'Xray profile: ' name; read -r -p 'Days to add: ' days; run_ctl xray-renew "$name" --days "$days"; read -r -p 'New GB limit / Unlimited (blank keeps it): ' quota; [[ -z "$quota" ]] || run_ctl xray-quota "$name" --quota "$quota"; pause ;;
    6|06) read -r -p 'Type (xray/ssh) [xray]: ' type; read -r -p 'Account name: ' name; if [[ "$type" == ssh ]]; then run_ctl lock-user "$name"; else run_ctl xray-lock "$name"; fi; pause ;;
    7|07) read -r -p 'Type (xray/ssh) [xray]: ' type; read -r -p 'Account name: ' name; if [[ "$type" == ssh ]]; then run_ctl unlock-user "$name"; else run_ctl xray-unlock "$name"; read -r -p 'Also reset measured usage? Type RESET: ' confirm; [[ "$confirm" != RESET ]] || run_ctl xray-reset-usage "$name"; fi; pause ;;
    8|08) read -r -p 'Type (xray/ssh) [xray]: ' type; read -r -p 'Account name: ' name; read -r -p 'Type DELETE: ' confirm; if [[ "$confirm" == DELETE ]]; then if [[ "$type" == ssh ]]; then run_ctl delete-user "$name"; else run_ctl xray-delete "$name"; fi; fi; pause ;;
    9|09) run_ctl config-view; pause ;;
    10) run_ctl xray-status; user_menu ;;
    11) run_ctl memory-report; echo '1) Inspect memory  2) Reclaim caches  3) System journal retention'; read -r -p 'Choose: ' action; case "$action" in 1) run_ctl maintenance memory ;; 2) run_ctl maintenance memory --reclaim ;; 3) run_ctl maintenance clean-logs ;; esac; pause ;;
    12) read -r -p 'Reconnect gateway clients? Type RESTART: ' confirm; [[ "$confirm" != RESTART ]] || run_ctl restart-managed; pause ;;
    13) run_ctl doctor; read -r -p 'Restart failed managed services? Type REPAIR: ' confirm; [[ "$confirm" != REPAIR ]] || run_ctl doctor --repair; pause ;;
    14) read -r -p 'Managed service [abdulbasit-xray]: ' service; run_ctl logs --service "${service:-abdulbasit-xray}"; pause ;;
    15) transport_menu ;;
    16) run_ctl packet-test; pause ;;
    17) echo '1) Set domain  2) Issue / renew SSL  3) DNS lookup'; read -r -p 'Choose: ' action; case "$action" in 1) read -r -p 'Domain: ' domain; run_ctl set-domain "$domain" ;; 2) run_ctl issue-cert ;; 3) run_ctl dns-lookup ;; esac; pause ;;
    18) run_ctl banner; read -r -p 'Plain-text banner file (blank keeps current): ' file; [[ -z "$file" ]] || run_ctl set-banner "$file"; pause ;;
    19) read -r -p 'Reviewed root-owned repository checkout: ' source; run_ctl maintenance reinstall --source "$source"; pause ;;
    20) if "$CTL" maintenance uninstall; then exit 0; else pause; fi ;;
    21) network_menu ;;
    22) xray_menu; read -r -p 'Subscription action (rotate/revoke/blank): ' action; if [[ "$action" == rotate || "$action" == revoke ]]; then read -r -p 'Profile: ' name; run_ctl "subscription-$action" "$name"; pause; fi ;;
    23) echo '1) Export private backup  2) Restore Xray snapshot'; read -r -p 'Choose: ' action; read -r -p 'JSON file path: ' file; case "$action" in 1) run_ctl backup --output "$file" ;; 2) run_ctl restore "$file" ;; esac; pause ;;
    0|00) exit 0 ;;
  esac
done

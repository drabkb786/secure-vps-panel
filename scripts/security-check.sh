#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

fail=0
check() { printf '%-55s' "$1"; shift; if "$@" >/dev/null 2>&1; then echo 'PASS'; else echo 'FAIL'; fail=1; fi; }

check 'Internal WS proxy is loopback-only' bash -c "ss -ltn | grep -Eq '127\\.0\\.0\\.1:2082'"
check 'Port 2082 is not listening on all interfaces' bash -c "! ss -ltn | grep -Eq '(^|[[:space:]])(0\\.0\\.0\\.0|\\*|\\[::\\]):2082'"
check 'Nginx configuration is valid' nginx -t
check 'Panel daemon is active' systemctl is-active --quiet abdulbasit-paneld
check 'WebSocket proxy is active' systemctl is-active --quiet abdulbasit-ws
check 'Session enforcer is active' systemctl is-active --quiet abdulbasit-session-enforcer
check 'Xray is active' systemctl is-active --quiet abdulbasit-xray
check 'Xray usage timer is active' systemctl is-active --quiet abdulbasit-usage.timer
check 'Fail2ban is active' systemctl is-active --quiet fail2ban
check 'Bot token is not world-readable' bash -c '[[ ! -e /etc/abdulbasit/bot_token.conf ]] || [[ $(stat -c "%a" /etc/abdulbasit/bot_token.conf) =~ ^(600|640)$ ]]'
check 'User metadata files are not world-readable' bash -c "! find /etc/abdulbasit/users -type f -perm /007 -print -quit | grep -q ."
check 'Generated client files are root-only' bash -c "! find /etc/abdulbasit/exports -type f -perm /077 -print -quit | grep -q ."
check 'Xray protocol listeners are loopback-only' bash -c "ss -ltn | grep -Eq '127\\.0\\.0\\.1:21001' && ss -ltn | grep -Eq '127\\.0\\.0\\.1:21002' && ss -ltn | grep -Eq '127\\.0\\.0\\.1:21003'"
check 'Xray Stats API is loopback-only' bash -c "ss -ltn | grep -Eq '127\\.0\\.0\\.1:21085' && ! ss -ltn | grep -Eq '(0\\.0\\.0\\.0|\\*|\\[::\\]):21085'"
check 'Nginx managed config protects CDN secret' bash -c '[[ ! -e /etc/nginx/conf.d/abdulbasit-vpn.conf ]] || [[ $(stat -c "%a" /etc/nginx/conf.d/abdulbasit-vpn.conf) == 600 ]]'
check 'CDN state is root-only' bash -c '[[ ! -e /etc/abdulbasit/cdn.json ]] || [[ $(stat -c "%a" /etc/abdulbasit/cdn.json) == 600 ]]'
if [[ -e /etc/abdulbasit/dashboard_auth.json ]]; then
  check 'Dashboard is active and loopback-only' bash -c "systemctl is-active --quiet abdulbasit-dashboard && ss -ltn | grep -Eq '127\\.0\\.0\\.1:9080' && ! ss -ltn | grep -Eq '(0\\.0\\.0\\.0|\\*|\\[::\\]):9080'"
  check 'Dashboard auth belongs to isolated group' bash -c '[[ $(stat -c "%a:%G" /etc/abdulbasit/dashboard_auth.json) == 640:abdulbasit-dashboard ]]'
fi
if python3 -c 'import json; raise SystemExit(0 if json.load(open("/etc/abdulbasit/dnstt.json")).get("enabled") else 1)' 2>/dev/null; then
  check 'DNSTT is active on UDP port 53' bash -c "systemctl is-active --quiet abdulbasit-dnstt && ss -lun | grep -Eq '(:|\\])53[[:space:]]'"
fi
check 'No shell=True remains in installed Python' bash -c "! grep -R --line-number 'shell[[:space:]]*=[[:space:]]*True' /usr/local/lib/abdulbasit"

exit "$fail"

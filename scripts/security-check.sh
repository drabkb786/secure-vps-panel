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
check 'Web dashboard is active' systemctl is-active --quiet abdulbasit-web
check 'Internal web listener is loopback-only' bash -c "ss -Hltn | grep -Eq '127\\.0\\.0\\.1:9090' && ! ss -Hltn | grep -Eq '(0\\.0\\.0\\.0|\\*|\\[::\\]):9090'"
if [[ -f /etc/abdulbasit-xray/enabled ]]; then
  check 'Xray is active' systemctl is-active --quiet abdulbasit-xray
  check 'Xray expiry timer is active' systemctl is-active --quiet abdulbasit-xray-expiry.timer
  check 'Xray configuration is valid' /usr/local/lib/abdulbasit/xray run -test -config /etc/abdulbasit-xray/config.json
  check 'Xray listeners are not public' bash -c "! ss -Hltn | grep -Eq '(0\\.0\\.0\\.0|\\*|\\[::\\]):1000[123]'"
fi
check 'Fail2ban is active' systemctl is-active --quiet fail2ban
check 'Bot token is not world-readable' bash -c '[[ ! -e /etc/abdulbasit/bot_token.conf ]] || [[ $(stat -c "%a" /etc/abdulbasit/bot_token.conf) =~ ^(600|640)$ ]]'
check 'User metadata files are not world-readable' bash -c "! find /etc/abdulbasit/users -type f -perm /007 -print -quit | grep -q ."
check 'No shell=True remains in installed Python' bash -c "! grep -R --line-number 'shell[[:space:]]*=[[:space:]]*True' /usr/local/lib/abdulbasit"

exit "$fail"

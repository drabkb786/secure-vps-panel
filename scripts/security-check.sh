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
check 'Fail2ban is active' systemctl is-active --quiet fail2ban
check 'Bot token is not world-readable' bash -c '[[ ! -e /etc/abdulbasit/bot_token.conf ]] || [[ $(stat -c "%a" /etc/abdulbasit/bot_token.conf) =~ ^(600|640)$ ]]'
check 'User metadata files are not world-readable' bash -c "! find /etc/abdulbasit/users -type f -perm /007 -print -quit | grep -q ."
check 'No shell=True remains in installed Python' bash -c "! grep -R --line-number 'shell[[:space:]]*=[[:space:]]*True' /usr/local/lib/abdulbasit"

exit "$fail"

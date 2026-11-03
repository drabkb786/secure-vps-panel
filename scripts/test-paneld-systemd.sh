#!/usr/bin/env bash
# Native CI regression: run the production unit, not an unsandboxed Python stub.
set -Eeuo pipefail
[[ ${GITHUB_ACTIONS:-} == true && $EUID -eq 0 ]] || {
  echo 'Run only as root on a disposable GitHub Actions runner.' >&2
  exit 1
}
[[ $(cat /proc/1/comm) == systemd ]] || exit 1
[[ $# -eq 1 && -x $1 ]] || { echo 'Supply the official dnstt-server test binary.' >&2; exit 1; }
unit=/etc/systemd/system/abdulbasit-paneld.service
dns_unit=/etc/systemd/system/abdulbasit-dnstt.service
[[ ! -e $unit && ! -e $dns_unit && ! -e /etc/abdulbasit && ! -e /etc/abdulbasit-dnstt && ! -e /usr/local/lib/abdulbasit/paneld.py ]] || {
  echo 'Refusing to replace an existing panel installation.' >&2
  exit 1
}
cleanup() {
  systemctl disable --now abdulbasit-dnstt.service || true
  systemctl stop abdulbasit-paneld.service || true
  rm -f -- "$unit" "$dns_unit"
  systemctl daemon-reload
}
trap cleanup EXIT
getent group abdulbasit >/dev/null || groupadd --system abdulbasit
install -d -m 0755 /usr/local/lib/abdulbasit /etc/abdulbasit/users /var/www/letsencrypt
install -d -m 0700 /var/lib/letsencrypt /var/log/letsencrypt
install -m 0755 src/*.py /usr/local/lib/abdulbasit/
install -m 0644 systemd/abdulbasit-paneld.service "$unit"
systemctl daemon-reload
systemctl start abdulbasit-paneld.service
for attempt in {1..50}; do
  [[ -S /run/abdulbasit/paneld.sock ]] && break
  sleep 0.2
done
if [[ ! -S /run/abdulbasit/paneld.sock ]] || ! systemctl is-active --quiet abdulbasit-paneld; then
  journalctl -u abdulbasit-paneld -n 50 --no-pager
  exit 1
fi
timeout 10s env PYTHONPATH=/usr/local/lib/abdulbasit /usr/bin/python3 - <<'PY'
import stat
from pathlib import Path
from panel_client import request
assert stat.S_IMODE(Path('/etc/abdulbasit').stat().st_mode) == 0o750
assert request('list_users') == {'ok': True, 'users': []}
print('Production systemd unit: startup, config chmod and socket request passed')
PY
getent group abdulbasit-dnstt >/dev/null || groupadd --system abdulbasit-dnstt
id abdulbasit-dnstt >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --gid abdulbasit-dnstt abdulbasit-dnstt
install -d -m 0700 /etc/letsencrypt
install -m 0755 "$1" /usr/local/lib/abdulbasit/dnstt-server
install -m 0644 systemd/abdulbasit-dnstt.service "$dns_unit"
systemctl daemon-reload
if ! timeout 40s env PYTHONPATH=/usr/local/lib/abdulbasit /usr/bin/python3 - <<'PY'
import socket
from panel_client import request
# Leave the runner's own DNS resolver untouched.
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
    probe.bind(('0.0.0.0', 0))
    port = probe.getsockname()[1]
result = request('slowdns_configure', enabled=True, zone='tunnel.example.com', ns_host='ns1.example.com', port=port)
assert result['enabled'] and len(result['public_key']) == 64, result
assert request('slowdns_status')['enabled']
print('Production SlowDNS systemd unit: enable, UDP listener and saved config passed')
PY
then
  journalctl -u abdulbasit-paneld -u abdulbasit-dnstt -n 80 --no-pager
  exit 1
fi

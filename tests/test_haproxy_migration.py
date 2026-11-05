"""Gateway boundaries and file/service recovery without touching the host OS."""
import importlib.util
from pathlib import Path
import subprocess

import pytest

import paneld
import ssh_backend
from common import read_text

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dropbear_gateway_migration', ROOT / 'scripts/migrate-dropbear-haproxy.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def test_mux_only_moves_nginx_listeners_and_preserves_route_guards(monkeypatch):
    monkeypatch.setattr(paneld, 'ipv6_enabled', lambda: True)
    site = paneld.nginx_text('vpn.example.com', True, multiplexed=True)
    assert 'listen 127.0.0.1:8080 proxy_protocol;' in site
    assert 'listen 127.0.0.1:8081 ssl http2 proxy_protocol;' in site
    assert 'listen 80;' not in site and 'listen 443 ' not in site and 'listen [::]' not in site
    assert 'real_ip_header proxy_protocol;' in site
    assert 'port_in_redirect off;' in site
    assert '$proxy_protocol_tlv_unique_id != "' + 'c' * 64 + '"' in site
    assert 'if ($noway_cf_forbidden) { return 403; }' in site
    assert 'if ($noway_bunny_forbidden) { return 403; }' in site
    assert 'proxy_pass http://127.0.0.1:2082;' in site
    assert 'location /panel/' in site and 'proxy_pass http://127.0.0.1:9090;' in site
    direct = paneld.nginx_text('vpn.example.com', True, multiplexed=False)
    assert 'listen 80;' in direct and 'listen 443 ssl http2;' in direct
    assert 'proxy_protocol' not in direct


def test_ha_tcp_mux_preserves_tls_and_uses_authenticated_proxy_metadata():
    cfg = ssh_backend.haproxy_config('a' * 64, ipv6=True)
    assert 'bind 0.0.0.0:80' in cfg and 'bind [::]:443 v6only' in cfg
    assert 'req.ssl_hello_type 1' in cfg
    assert '127.0.0.1:8080 send-proxy-v2 proxy-v2-options unique-id' in cfg
    assert '127.0.0.1:8081 send-proxy-v2 proxy-v2-options unique-id' in cfg
    assert 'unique-id-format ' + 'a' * 64 in cfg
    assert 'accept-proxy' not in cfg and 'ssl crt' not in cfg
    with pytest.raises(ValueError): ssh_backend.haproxy_config('injected\nconfig')
    with pytest.raises(ValueError): ssh_backend.haproxy_config('a' * 64, http_port=0)


def test_native_backend_group_requirement_and_binary(tmp_path, monkeypatch):
    path = tmp_path / 'backend'; monkeypatch.setattr(ssh_backend, 'BACKEND_FILE', path)
    path.write_text('dropbear-2026\n')
    assert ssh_backend.name() == 'dropbear' and ssh_backend.group_required()
    assert ssh_backend.dropbear_binary() == '/usr/local/lib/abdulbasit/dropbear'
    path.write_text('dropbear\n')
    assert not ssh_backend.group_required()
    assert ssh_backend.dropbear_binary() == '/usr/sbin/dropbear'


def test_private_gateway_identity_is_required(tmp_path, monkeypatch):
    monkeypatch.setattr(ssh_backend, 'HAPROXY_SECRET_FILE', tmp_path / 'missing')
    with pytest.raises(RuntimeError): paneld.nginx_text('vpn.example.com', True, multiplexed=True)


@pytest.fixture
def task(tmp_path):
    calls = []
    def runner(args, **kwargs):
        calls.append(tuple(str(x) for x in args))
        action = args[1] if len(args) > 1 else ''
        unit = args[2] if len(args) > 2 else ''
        if action == 'is-active': code, out = (0, 'active\n') if unit in ('nginx', 'abdulbasit-sshd') else (3, 'inactive\n')
        elif action == 'is-enabled': code, out = (0, 'enabled\n') if unit in ('nginx', 'abdulbasit-sshd') else (1, 'not-found\n')
        else: code, out = 0, ''
        return subprocess.CompletedProcess(args, code, out, '')
    obj = migration.Migration(root=tmp_path, runner=runner)
    obj.calls = calls
    for path in migration.FILES[:4]:
        target = obj.path(path); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('original:' + str(path)); target.chmod(0o640)
    return obj


def test_snapshot_restores_bytes_modes_and_service_selection(task):
    state = task.snapshot()
    for path in migration.FILES:
        target = task.path(path); target.parent.mkdir(parents=True, exist_ok=True); target.write_text('changed')
    task.rollback()
    for path in migration.FILES:
        target = task.path(path)
        if state['files'][str(path)]['exists']:
            assert read_text(target) == 'original:' + str(path)
            assert target.stat().st_mode & 0o777 == 0o640
        else: assert not target.exists()
    assert ('systemctl', 'start', 'abdulbasit-sshd') in task.calls
    assert ('systemctl', 'start', 'nginx') in task.calls
    assert ('systemctl', 'disable', 'abdulbasit-haproxy') in task.calls
    assert not any(call[:2] == ('systemctl', 'start') and call[-1] == 'dropbear' for call in task.calls)
    assert not any(call[-1] in ('ssh', 'sshd') for call in task.calls)


def test_pre_switch_recovery_does_not_interrupt_existing_services(task):
    task.snapshot(); task.calls.clear()
    task.rollback(restart=False)
    assert not any(call[0] == 'systemctl' and call[1] in ('stop', 'start') for call in task.calls)


def test_unsafe_recovery_and_foreign_listener_are_rejected(task):
    with pytest.raises(RuntimeError): task.rollback(task.root)
    def output(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, 'LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("haproxy",pid=77,fd=5))\n', '')
    task.run = output
    proc = task.path('/proc/77'); proc.mkdir(parents=True)
    (proc / 'cgroup').write_text('0::/system.slice/unrelated-haproxy.service\n')
    with pytest.raises(RuntimeError, match='unrelated service'): task.listeners(443, {'abdulbasit-haproxy'})
    (proc / 'cgroup').write_text('0::/system.slice/abdulbasit-haproxy.service\n')
    assert 'pid=77' in task.listeners(443, {'abdulbasit-haproxy'})


def test_snapshot_rejects_symlinked_ancestor(task):
    parent = task.path('/etc/abdulbasit-haproxy')
    other = task.root / 'other'; other.mkdir()
    parent.symlink_to(other, target_is_directory=True)
    with pytest.raises(RuntimeError, match='Unsafe migration path'): task.snapshot()


def test_new_units_keep_admin_ssh_separate_and_do_not_disable_forwarding():
    assert '-G abdulbasit-tunnel' in migration.DROPBEAR_UNIT
    assert '-w -k' in migration.DROPBEAR_UNIT and ' -j ' not in migration.DROPBEAR_UNIT
    assert '-p 109 -p 447' in migration.DROPBEAR_UNIT
    assert '-K 30' in migration.DROPBEAR_UNIT
    assert 'ProtectSystem=strict' in migration.DROPBEAR_UNIT
    assert 'Type=notify' in migration.HAPROXY_UNIT
    assert not any(name in ('ssh', 'sshd') for name in migration.UNITS)


def test_installer_retains_pinned_backend_and_normal_updates_do_not_build_runtime():
    source = (ROOT / 'install.sh').read_text()
    assert 'dropbear-2026) SSH_BACKEND=dropbear; PINNED_DROPBEAR=1' in source
    assert "printf '%s\\n' dropbear-2026" in source
    entry = (ROOT / 'scripts/migrate-dropbear-haproxy.sh').read_text()
    assert 'upgrade-runtime.py' not in entry
    assert 'update-ssh-compat.sh' in entry

def test_gateway_rejects_overlapping_public_and_private_listeners():
    import pytest
    import ssh_backend
    for options in ({"public_ports": (80, 80)}, {"http_port": 443}, {"tls_port": 8080}, {"public_ports": ()}):
        with pytest.raises(ValueError, match="listener ports"):
            ssh_backend.haproxy_config("a" * 64, **options)

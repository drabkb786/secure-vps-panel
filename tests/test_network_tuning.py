"""Transactional network tuning with an isolated kernel/firewall model."""
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

spec = importlib.util.spec_from_file_location('network_tuning', Path(__file__).resolve().parents[1] / 'scripts/tune-network.py')
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


@pytest.fixture
def kernel(tmp_path, monkeypatch):
    for name, filename in [('CONFIG', 'network.conf'), ('BACKUP', 'backup.json'),
                           ('UNIT', 'mss.service'), ('HELPER', 'helper.py')]:
        monkeypatch.setattr(network, name, tmp_path / filename)
    network.CONFIG.write_text('# original settings\n')
    values = {'net.core.default_qdisc': 'fq_codel', 'net.ipv4.tcp_congestion_control': 'cubic',
              'net.ipv4.tcp_available_congestion_control': 'reno cubic bbr'}
    rules, calls = set(), []
    state = {'values': values, 'rules': rules, 'calls': calls, 'fail': None}
    def run(*args):
        calls.append(args)
        if state['fail'] and state['fail'](args):
            raise subprocess.CalledProcessError(2, args)
        if args[0] == 'modprobe': return ''
        if args[0] == 'sysctl':
            if args[1] == '-n': return values[args[2]]
            key, value = args[2].split('=', 1); values[key] = value
            return ''
        if args[0] in ('iptables', 'ip6tables'):
            operation, chain = args[5:7]; key = (args[0], chain)
            if operation == '-C':
                if key not in rules: raise subprocess.CalledProcessError(1, args)
            elif operation == '-I': rules.add(key)
            elif operation == '-D': rules.remove(key)
            else: pytest.fail('Unexpected firewall operation')
            assert 'NOWAY managed PMTU MSS' in args
            return ''
        if args[0] == 'systemctl': return ''
        pytest.fail('Unexpected command: ' + repr(args))
    monkeypatch.setattr(network, 'run', run)
    monkeypatch.setattr(network.shutil, 'which', lambda name: '/usr/sbin/' + name)
    return state


def rollback():
    network.restore(json.loads(network.BACKUP.read_text()))
    network.BACKUP.unlink()


def test_mss_persistence_and_rollback_preserve_preexisting_rules(kernel):
    existing = ('iptables', 'FORWARD'); kernel['rules'].add(existing)
    network.apply(with_mss=True)
    assert len(kernel['rules']) == 4
    assert kernel['values']['net.ipv4.tcp_congestion_control'] == 'bbr'
    assert network.BACKUP.stat().st_mode & 0o777 == 0o600
    assert 'reapply-mss' in network.UNIT.read_text()
    assert network.HELPER.read_bytes() == Path(network.__file__).read_bytes()
    rollback()
    assert kernel['rules'] == {existing}
    assert kernel['values']['net.ipv4.tcp_congestion_control'] == 'cubic'
    assert network.CONFIG.read_text() == '# original settings\n'
    assert not network.UNIT.exists() and not network.HELPER.exists()


@pytest.mark.parametrize('failure', ['ipv6_insert', 'enable_service'])
def test_partial_failure_rolls_back_sysctls_rules_and_files(kernel, failure):
    def fail(args):
        return (args[0] == 'ip6tables' and '-I' in args) if failure == 'ipv6_insert' else args[:2] == ('systemctl', 'enable')
    kernel['fail'] = fail
    with pytest.raises(subprocess.CalledProcessError): network.apply(with_mss=True)
    assert not kernel['rules']
    assert kernel['values']['net.ipv4.tcp_congestion_control'] == 'cubic'
    assert network.CONFIG.read_text() == '# original settings\n'
    assert not network.BACKUP.exists() and not network.UNIT.exists() and not network.HELPER.exists()


def test_boot_reapply_is_idempotent_and_restores_lost_rules(kernel):
    network.apply(with_mss=True)
    kernel['rules'].clear()
    data = json.loads(network.BACKUP.read_text())
    network.apply_mss(data); network.apply_mss(data)
    assert len(kernel['rules']) == 4
    assert sum('-I' in call for call in kernel['calls']) == 8
    rollback(); assert not kernel['rules']


def test_bbr_unavailable_does_not_change_settings_or_rules(kernel):
    kernel['values']['net.ipv4.tcp_available_congestion_control'] = 'reno cubic'
    with pytest.raises(SystemExit, match='does not offer BBR'): network.apply(with_mss=True)
    assert not network.BACKUP.exists() and not kernel['rules']
    assert network.CONFIG.read_text() == '# original settings\n'


def test_bbr_only_and_old_receipts_do_not_touch_firewall(kernel):
    network.apply()
    rollback()
    assert not any(call[0] in ('iptables', 'ip6tables') for call in kernel['calls'])
    network.restore({'runtime': {'net.ipv4.tcp_congestion_control': 'cubic'}, 'config': None})
    assert not network.CONFIG.exists()


def test_foreign_persistence_files_are_preserved(kernel):
    network.UNIT.write_text('unrelated service')
    with pytest.raises(RuntimeError, match='already exists'): network.apply(with_mss=True)
    assert network.UNIT.read_text() == 'unrelated service'
    assert not network.BACKUP.exists() and not kernel['rules']


def test_mss_only_works_without_bbr_and_leaves_sysctls_unchanged(kernel):
    kernel['values']['net.ipv4.tcp_available_congestion_control'] = 'reno cubic'
    original = dict(kernel['values'])
    network.apply(with_mss=True, bbr=False)
    assert kernel['values'] == original
    assert network.CONFIG.read_text() == '# original settings\n'
    assert len(kernel['rules']) == 4
    rollback()
    assert kernel['values'] == original and not kernel['rules']


def test_bad_receipt_is_rejected_before_any_firewall_mutation(kernel):
    data = {'mss': [{'tool': 'iptables', 'chain': 'OUTPUT', 'owned': False},
                    {'tool': 'unexpected-command', 'chain': 'FORWARD', 'owned': False}]}
    with pytest.raises(RuntimeError, match='receipt'): network.apply_mss(data)
    assert not kernel['calls'] and not kernel['rules']

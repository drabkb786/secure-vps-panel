"""Opt-in real firewall/systemd acceptance on a disposable hosted runner."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('NOWAY_NETWORK_NATIVE') != '1' or
    os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0,
    reason='Requires explicit disposable root/systemd runner opt-in')


def test_actual_mss_rules_persist_reapply_and_rollback_without_changing_bbr():
    script = Path(__file__).resolve().parents[1] / 'scripts/tune-network.py'
    spec = importlib.util.spec_from_file_location('native_network', script)
    network = importlib.util.module_from_spec(spec); spec.loader.exec_module(network)
    assert not network.BACKUP.exists() and not network.UNIT.exists() and not network.HELPER.exists()
    tools = [tool for tool in ('iptables', 'ip6tables') if network.shutil.which(tool)]
    original = {tool: network.run(tool, '--wait', '5', '-t', 'mangle', '-S') for tool in tools}
    sysctls = {key: network.run('sysctl', '-n', key) for key in network.VALUES}
    def command(*args):
        result = subprocess.run([str(a) for a in args], text=True, capture_output=True, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
    try:
        command(sys.executable, script, 'apply', '--mss-only')
        data = json.loads(network.BACKUP.read_text())
        assert data['runtime'] == {} and len(data['mss']) == len(tools) * 2
        for entry in data['mss']:
            assert network.rule_present(entry['tool'], entry['chain'])
        # Simulate a firewall reload removing an owned rule, then execute the
        # installed boot helper through actual systemd and ensure idempotence.
        entry = data['mss'][0]
        network.run(entry['tool'], '--wait', '5', '-t', 'mangle', '-D', entry['chain'], *network.RULE)
        command('systemctl', 'start', network.UNIT.name)
        command('systemctl', 'restart', network.UNIT.name)
        for entry in data['mss']:
            assert network.rule_present(entry['tool'], entry['chain'])
            listing = network.run(entry['tool'], '--wait', '5', '-t', 'mangle', '-S', entry['chain'])
            assert listing.count('NOWAY managed PMTU MSS') == 1
        assert {key: network.run('sysctl', '-n', key) for key in network.VALUES} == sysctls
    finally:
        if network.BACKUP.exists(): command(sys.executable, script, 'rollback')
    assert not network.UNIT.exists() and not network.HELPER.exists()
    assert {tool: network.run(tool, '--wait', '5', '-t', 'mangle', '-S') for tool in tools} == original

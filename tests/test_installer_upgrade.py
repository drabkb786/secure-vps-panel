"""Exercise the real install transaction with all paths/downloads sandboxed."""
import hashlib
import os
import subprocess
import zipfile
from pathlib import Path

import pytest


@pytest.mark.parametrize("failure", ["", "restart", "checksum"])
def test_pinned_upgrade_and_rollback(tmp_path, failure):
    root = Path(__file__).resolve().parents[1]
    source = (root / "scripts/install-xray.sh").read_text()
    source = "\n".join(line for line in source.splitlines() if not line.startswith('[[ ${EUID:'))
    source = source.replace('/usr/local/lib/abdulbasit', str(tmp_path / 'app'))
    source = source.replace('/etc/abdulbasit/backups', str(tmp_path / 'backups'))
    source = source.replace('/etc/abdulbasit-xray', str(tmp_path / 'config'))
    source = source.replace('-o root -g root', '')
    scripts = tmp_path / 'scripts'; scripts.mkdir()
    installer = scripts / 'install.sh'; installer.write_text(source)
    (tmp_path / 'XRAY_VERSION').write_text('v26.10.31\n')
    app = tmp_path / 'app'; app.mkdir()
    binary = app / 'xray'; old = '#!/bin/sh\necho "Xray 26.10.21 fixture"\n'
    binary.write_text(old); binary.chmod(0o755)
    archive = tmp_path / 'release.zip'
    with zipfile.ZipFile(archive, 'w') as f:
        f.writestr('xray', '#!/bin/sh\nif [ "$1" = version ]; then echo "Xray 26.10.31 fixture"; fi\n')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest() if failure != 'checksum' else '0' * 64
    digest_path = tmp_path / 'release.dgst'; digest_path.write_text('SHA2-256= ' + digest)
    commands = tmp_path / 'commands'; commands.mkdir()
    curl = commands / 'curl'
    curl.write_text(f'''#!/usr/bin/env python3
import pathlib, sys
args = sys.argv[1:]
url = next(x for x in args if x.startswith('https://'))
src = pathlib.Path({str(digest_path)!r} if url.endswith('.dgst') else {str(archive)!r})
pathlib.Path(args[args.index('-o') + 1]).write_bytes(src.read_bytes())
'''); curl.chmod(0o755)
    systemctl = commands / 'systemctl'
    systemctl.write_text(f'''#!/bin/sh
if [ "$1" = restart ] && grep -q 26.10.31 {binary} && [ "{failure}" = restart ]; then exit 1; fi
exit 0
'''); systemctl.chmod(0o755)
    env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'])
    result = subprocess.run(['bash', str(installer)], capture_output=True, text=True, env=env, timeout=15)
    if failure:
        assert result.returncode != 0, result.stdout + result.stderr
        assert binary.read_text() == old
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert '26.10.31' in binary.read_text()
        curl.unlink()
        again = subprocess.run(['bash', str(installer)], capture_output=True, text=True, env=env, timeout=15)
        assert again.returncode == 0 and 'already installed' in again.stdout

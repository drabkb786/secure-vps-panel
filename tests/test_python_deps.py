import hashlib
import importlib.util
import os
from pathlib import Path
import zipfile

import pytest

spec = importlib.util.spec_from_file_location('python_deps', Path(__file__).resolve().parents[1] / 'scripts/install-python-deps.py')
deps = importlib.util.module_from_spec(spec); spec.loader.exec_module(deps)


def wheel(path, filename='package/__init__.py'):
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(filename, '# verified fixture\n')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_checksum_and_traversal_rejected(tmp_path):
    path = tmp_path / 'package.whl'; digest = wheel(path)
    with pytest.raises(ValueError, match='checksum'):
        deps.unpack(path, '0' * 64, tmp_path / 'output')
    deps.unpack(path, digest, tmp_path / 'output')
    assert (tmp_path / 'output/package/__init__.py').is_file()
    digest = wheel(path, '../escape.py')
    with pytest.raises(ValueError, match='Unsafe'):
        deps.unpack(path, digest, tmp_path / 'output')
    assert not (tmp_path / 'escape.py').exists()


def test_atomic_dependency_activation_and_failed_download(tmp_path, monkeypatch):
    fixture = tmp_path / 'fixture.whl'; digest = wheel(fixture)
    monkeypatch.setattr(deps, 'WHEELS', (('https://example.test/fixture.whl', digest),))
    def download(args, **kwargs): Path(args[args.index('--output') + 1]).write_bytes(fixture.read_bytes())
    monkeypatch.setattr(deps.subprocess, 'run', download)
    destination = tmp_path / 'install'
    previous_umask = os.umask(0o077)
    try:
        deps.install(destination)
    finally:
        os.umask(previous_umask)
    assert (destination / "deps").stat().st_mode & 0o777 == 0o755
    previous = (destination / 'vendor').resolve()
    assert (previous / 'package/__init__.py').is_file()
    assert previous.stat().st_mode & 0o777 == 0o755
    assert (previous / 'package').stat().st_mode & 0o777 == 0o755
    assert (previous / 'package/__init__.py').stat().st_mode & 0o777 == 0o644
    deps.install(destination)
    assert (destination / 'vendor').resolve() == previous
    monkeypatch.setattr(deps, 'WHEELS', (('https://example.test/new.whl', '0' * 64),))
    with pytest.raises(ValueError, match='checksum'):
        deps.install(destination)
    assert (destination / 'vendor').resolve() == previous

"""Committed source staging must never install manually edited working code."""
import importlib.util
from pathlib import Path
import subprocess

import pytest

spec = importlib.util.spec_from_file_location('source_snapshot', Path(__file__).resolve().parents[1] / 'scripts/source-snapshot.py')
source = importlib.util.module_from_spec(spec); spec.loader.exec_module(source)


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / 'repo'; root.mkdir(); (root / 'src').mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root / 'src/ws_proxy.py').write_text('STRICT = True\n')
    (root / 'src/paneld.py').write_text('ROUTE = "managed"\n')
    subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    '-c', 'commit.gpgsign=false', 'commit', '-qm', 'baseline'], check=True)
    return root


def test_dirty_or_invalid_working_copy_is_not_installed_or_erased(checkout, tmp_path):
    changed = checkout / 'src/ws_proxy.py'
    changed.write_text('invalid Python !!!\n')
    result = source.snapshot(checkout, tmp_path / 'stage', ['ws_proxy', 'paneld'])
    assert (tmp_path / 'stage/ws_proxy.py').read_text() == 'STRICT = True\n'
    assert changed.read_text() == 'invalid Python !!!\n'
    assert result['local_edits'] == ['src/ws_proxy.py']
    assert result['commit'] == source.git(checkout, 'rev-parse', 'HEAD').decode().strip()
    assert len(result['sha256']['ws_proxy']) == 64


@pytest.mark.parametrize('name', ['../outside', '/tmp/module', 'module.py', 'a/b', ''])
def test_module_names_cannot_escape_selected_source_directory(checkout, tmp_path, name):
    with pytest.raises(ValueError, match='selection'):
        source.snapshot(checkout, tmp_path / 'stage', [name])
    assert not (tmp_path / 'stage').exists()


def test_ancestor_repository_is_not_used_as_a_release(checkout, tmp_path):
    with pytest.raises(ValueError, match='ancestor'):
        source.snapshot(checkout / 'src', tmp_path / 'stage', ['ws_proxy'])


def test_missing_committed_module_does_not_leave_a_partial_stage(checkout, tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        source.snapshot(checkout, tmp_path / 'stage', ['ws_proxy', 'missing_module'])
    assert not (tmp_path / 'stage').exists()

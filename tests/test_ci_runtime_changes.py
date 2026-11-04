import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ci_runtime_changes', ROOT / 'scripts/ci-runtime-changes.py')
ci = importlib.util.module_from_spec(spec); spec.loader.exec_module(ci)
SOURCE = (ROOT / ci.UPGRADER).read_text()


def test_ui_docs_and_ci_updates_do_not_recompile_private_binaries():
    assert not ci.requires_build(['README.md', 'src/web/app.js', '.github/workflows/security.yml'], None, None)


def test_renewal_parser_and_cli_fixes_do_not_invalidate_the_build():
    after = SOURCE.replace('        if args.activate_built is not None:', '        if args.activate_built:')
    after = after.replace("plugin = value.strip()", "plugin = value.strip().lower()")
    assert not ci.requires_build([ci.UPGRADER], SOURCE, after)


def test_compiler_flags_dependencies_and_build_helpers_require_full_validation():
    for old, new in [("'--enable-experimental-jit=no'", "'--enable-experimental-jit=yes'"),
                     ("'gcc', 'g++'", "'gcc', 'clang'"),
                     ('BUILD_PROGRESS_SECONDS = 10', 'BUILD_PROGRESS_SECONDS = 5')]:
        assert old in SOURCE
        assert ci.requires_build([ci.UPGRADER], SOURCE, SOURCE.replace(old, new))
    for path in ['RUNTIME_VERSIONS.json', 'scripts/panel-python', 'install.sh', 'systemd/abdulbasit-web.service']:
        assert ci.requires_build([path], None, None)


def test_incomplete_comparisons_request_full_validation():
    assert ci.requires_build([ci.UPGRADER], None, SOURCE)
    assert ci.requires_build([ci.UPGRADER], SOURCE, 'invalid Python :')


def test_new_build_commands_in_main_request_full_validation():
    after = SOURCE.replace('            verify_toolchain()', "            run(['gcc', '--version'])\n            verify_toolchain()")
    assert after != SOURCE
    assert ci.requires_build([ci.UPGRADER], SOURCE, after)


@pytest.mark.parametrize('event,expected', [({'inputs': {'full_runtime': 'true'}}, 'true'),
                                           ({'inputs': {'full_runtime': 'false'}}, 'false')])
def test_manual_full_runtime_selection(tmp_path, monkeypatch, event, expected):
    payload = tmp_path / 'event.json'; payload.write_text(json.dumps(event))
    output = tmp_path / 'output'
    monkeypatch.setenv('GITHUB_EVENT_PATH', str(payload))
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'workflow_dispatch')
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    ci.main()
    assert output.read_text() == 'full_runtime=' + expected + '\n'

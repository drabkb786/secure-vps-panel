#!/usr/bin/env python3
"""Run expensive private compilation only when its recipe/dependencies change."""
import ast
import json
import os
from pathlib import Path
import re
import subprocess

UPGRADER = 'scripts/upgrade-runtime.py'
BUILD_FILES = {'RUNTIME_VERSIONS.json', 'XRAY_VERSION', 'scripts/install-xray.sh',
               'scripts/panel-python', 'install.sh'}
ACTIVATION_FUNCTIONS = {'check_renewal_plugins', 'completed_release', 'config_checks',
                        'active', 'switch_current', 'managed_files', 'snapshot',
                        'restore', 'activate', 'status', 'preflight'}
ACTIVATION_GLOBALS = {'UNITS', 'APP', 'PANEL_UNITS', 'UNITS_TO_RESTART', 'TOOLS', 'CONFIG_PATHS'}


def recipe(source):
    tree = ast.parse(source)
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in ACTIVATION_FUNCTIONS:
                continue
            if node.name == 'main':
                # Keep prerequisite/build calls, excluding CLI routing. A new
                # compiler command in main must also request full validation.
                selected.extend(item for item in ast.walk(node)
                                if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
                                and item.func.id in {'run', 'build', 'build_run', 'download',
                                                     'extract', 'verify_toolchain',
                                                     'seal_fresh_release', 'verify_versions'})
                continue
        if isinstance(node, ast.Assign) and all(isinstance(t, ast.Name) and t.id in ACTIVATION_GLOBALS for t in node.targets):
            continue
        if isinstance(node, (ast.If, ast.Expr)):
            continue  # Entry point and module documentation do not change binaries.
        selected.append(node)
    return '\n'.join(ast.dump(node, include_attributes=False) for node in selected)


def requires_build(changed, before, after):
    if any(path in BUILD_FILES or path.startswith('systemd/') for path in changed):
        return True
    if UPGRADER not in changed:
        return False
    if before is None or after is None:
        return True
    try:
        return recipe(before) != recipe(after)
    except (SyntaxError, ValueError):
        return True  # Conservative if the recipe cannot be compared.


def git(*args):
    return subprocess.check_output(['git', *args], text=True)


def main():
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    name = os.environ.get('GITHUB_EVENT_NAME')
    if name == 'workflow_dispatch':
        required = event.get('inputs', {}).get('full_runtime', False) in (True, 'true', '1')
    else:
        try:
            if name == 'pull_request':
                base, head = event['pull_request']['base']['sha'], event['pull_request']['head']['sha']
            else:
                base, head = event['before'], event['after']
            if not all(re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', ref) and set(ref) != {'0'} for ref in (base, head)):
                raise ValueError('Missing comparison commit')
            changed = git('diff', '--name-only', base, head).splitlines()
            before = after = None
            if UPGRADER in changed:
                before, after = git('show', base + ':' + UPGRADER), git('show', head + ':' + UPGRADER)
            required = requires_build(changed, before, after)
        except (KeyError, OSError, ValueError, subprocess.SubprocessError):
            required = True
    value = 'true' if required else 'false'
    print('Private runtime source build required: ' + value)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('full_runtime=' + value + '\n')


if __name__ == '__main__':
    main()

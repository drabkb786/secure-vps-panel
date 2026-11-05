#!/usr/bin/env python3
"""Stage one committed version of selected Python modules without executing edits."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess


def git(project, *args):
    return subprocess.check_output(['git', '-C', str(project), *args], timeout=10)


def snapshot(project, destination, modules, *, web_assets=False):
    project, destination = Path(project).resolve(), Path(destination)
    if not modules or any(not re.fullmatch(r'[a-z][a-z0-9_]*', name) for name in modules):
        raise ValueError('Invalid source module selection')
    top = Path(git(project, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
    if top != project:
        raise ValueError('Update requires the project Git checkout, not an ancestor repository')
    revision = git(project, 'rev-parse', '--verify', 'HEAD').decode().strip()
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', revision):
        raise ValueError('Invalid source commit')
    prepared, changed, hashes = {}, [], {}
    for name in modules:
        relative = 'src/' + name + '.py'
        content = git(project, 'show', revision + ':' + relative)
        ast.parse(content, filename=relative)
        prepared[name] = content
        hashes[name] = hashlib.sha256(content).hexdigest()
        source = project / relative
        if source.is_symlink() or not source.is_file() or source.read_bytes() != content:
            changed.append(relative)
    if web_assets:
        for asset in ('web/index.html', 'web/app.js', 'web/accounts.js', 'web/accounts.css'):
            relative = 'src/' + asset
            content = git(project, 'show', revision + ':' + relative)
            content.decode('utf-8')
            prepared[asset] = content
            hashes[asset] = hashlib.sha256(content).hexdigest()
            source = project / relative
            if source.is_symlink() or not source.is_file() or source.read_bytes() != content:
                changed.append(relative)
    destination.mkdir(mode=0o700)
    for name, content in prepared.items():
        path = destination / (name if name.startswith('web/') else name + '.py')
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(content); path.chmod(0o600)
    return {'commit': revision, 'local_edits': changed, 'sha256': hashes}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project'); parser.add_argument('destination')
    parser.add_argument('modules', nargs='+')
    parser.add_argument('--web-assets', action='store_true')
    args = parser.parse_args()
    print(json.dumps(snapshot(args.project, args.destination, args.modules, web_assets=args.web_assets), indent=2))

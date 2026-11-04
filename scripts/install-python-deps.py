#!/usr/bin/env python3
"""Install checksum-pinned pure Python wheels without modifying Ubuntu packages."""
import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
import zipfile

# Official PyPI wheel URLs and SHA-256 digests; licenses stay with each wheel.
WHEELS = (
    ('https://files.pythonhosted.org/packages/04/4b/29cac41a4d98d144bf5f6d33995617b185d14b22401f75ca86f384e87ff1/h11-0.16.0-py3-none-any.whl',
     '63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86'),
    ('https://files.pythonhosted.org/packages/a4/f5/10b68b7b1544245097b2a1b8238f66f2fc6dcaeb24ba5d917f52bd2eed4f/wsproto-1.3.2-py3-none-any.whl',
     '61eea322cdf56e8cc904bd3ad7573359a242ba65688716b0710a5eb12beab584'),
)


def unpack(wheel, expected, destination):
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != expected:
        raise ValueError('Dependency checksum mismatch: ' + wheel.name)
    with zipfile.ZipFile(wheel) as archive:
        members = archive.infolist()
        if sum(item.file_size for item in members) > 4 * 1024 * 1024:
            raise ValueError('Dependency exceeds extraction limit')
        for item in members:
            path = PurePosixPath(item.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename or (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Unsafe wheel member')
        archive.extractall(destination)


def install(destination):
    destination = destination.resolve()
    releases = destination / 'deps'
    releases.mkdir(mode=0o755, parents=True, exist_ok=True)
    releases.chmod(0o755)  # The main installer intentionally inherits umask 077.
    digest = hashlib.sha256(repr(WHEELS).encode()).hexdigest()[:20]
    release = releases / digest
    if not (release / '.complete').is_file():
        with tempfile.TemporaryDirectory(prefix='.build-', dir=releases) as work:
            stage = Path(work) / 'packages'; stage.mkdir(mode=0o755)
            stage.chmod(0o755)
            for url, expected in WHEELS:
                wheel = Path(work) / url.rsplit('/', 1)[-1]
                subprocess.run(['/usr/bin/curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2',
                                '--connect-timeout', '10', '--max-time', '90', '--retry', '2',
                                '--output', str(wheel), url], check=True, timeout=300)
                unpack(wheel, expected, stage)
            for path in stage.rglob('*'):
                path.chmod(0o755 if path.is_dir() else 0o644)
            (stage / '.complete').write_text(digest + '\n'); (stage / '.complete').chmod(0o644)
            # A failed download/extraction leaves the previous vendor untouched.
            if release.exists():
                raise ValueError('Incomplete dependency release exists: ' + str(release))
            stage.rename(release)
    release.chmod(0o755)
    temporary = destination / '.vendor-new'
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(release.relative_to(destination))
    os.replace(temporary, destination / 'vendor')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root')
    install(args.destination)


if __name__ == '__main__':
    main()

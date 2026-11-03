# Managed runtime upgrade (4.1)

The regular installer uses Ubuntu/Debian maintained packages. `--upgrade-runtime`
adds a pinned private stack, built and checked before activating it. It is an
explicit maintenance operation: restarting Nginx and the panel disconnects active
tunnels briefly. A source build can take 10–25 minutes on a small VPS; it needs
build tools, free disk space and access to the official download hosts/PyPI.

| Component | Selected version | Deployment |
|---|---|---|
| Nginx | 1.30.6 stable | Private binary; existing nginx.service and /etc/nginx |
| OpenSSL | 3.5.9 LTS | Private libraries actually linked by new Nginx and panel Python |
| Python | 3.15.2 | Private panel/CLI/bot/WS/SlowDNS interpreter; JIT disabled |
| Certbot / ACME | 5.9.0 | Private venv; existing certificates and certbot.timer |
| Fail2ban | 1.1.1 | Verified upstream DEB extracted privately; existing service/jails |
| Xray-core | 26.10.31 | Existing checksum-verified private core installer |

Stable Nginx and OpenSSL LTS are selected for maintenance continuity. Mainline
Nginx 1.31.8 and OpenSSL 4.1.0 are not needed for the panel's current protocols.
OS Python, OpenSSL, sshd and package-owned executables remain installed and are
still serviced by apt. Upstream version numbers alone do not describe Ubuntu
security backports. Run regular OS security updates separately.

## Apply on the VPS

```sh
cd /root/secure-vps-panel &&
git pull --ff-only origin main &&
bash install.sh --non-interactive --with-xray --ssh-backend openssh --upgrade-runtime --domain vpn.arm-29.tech
```

Inspect actual active and OS versions:

```sh
cd /root/secure-vps-panel
/usr/bin/python3 scripts/upgrade-runtime.py --status
abdulbasit-panelctl diagnostics
abdulbasit-security-check
```

For an already installed 4.1 panel, upgrade only the selected runtime:

```sh
cd /root/secure-vps-panel
/usr/bin/python3 scripts/upgrade-runtime.py --apply --jobs 2
```

The installer needs updated system Python with `tarfile.data_filter`. Full native
acceptance is exercised on Ubuntu 24.04; older OS releases may need additional
build dependencies or updated Python before this optional operation can run.

## Integrity, configuration and recovery

`RUNTIME_VERSIONS.json` records official URLs, exact versions and independently
retrieved SHA256 digests. Archives are verified before extraction/build. Private
Python package dependencies are resolved from PyPI; the installed package list
is saved in `python-packages.txt`. This is not a hash lock of every transitive
dependency, so future builds can resolve newer compatible dependencies.

Each build has an immutable directory under `/opt/noway/runtime/releases/`.
Failed work and build logs are retained under `/var/lib/noway-runtime/`. The
current symlink changes only after version/linkage checks, panel imports, Nginx
config validation and Fail2ban jail validation. Incompatible third-party Nginx
dynamic modules block activation; they are never silently removed.
Existing certificate lineages that require an additional DNS/Nginx Certbot
plugin also block activation until that plugin is installed in the private venv.

The upstream Fail2ban engine uses the OS Python so `python3-systemd` can read the
journal with its matching native ABI. Existing Fail2ban filters, jail overrides,
ban database, Nginx sites and Let's Encrypt lineage files are retained. Certbot's
existing systemd timer uses the new executable; no competing timer is installed.
Certbot renewals keep the panel's Nginx validation/reload deploy hook.

Root-only recovery snapshots include original wrapper/drop-in files and a
configuration/certificate archive. Activation failures restore the old symlink
and service commands and restart previously active services. Rollback does not
replace subsequently edited configuration or certificates with older copies.

The successful operation prints a rollback ID. Use that exact ID:

```sh
cd /root/secure-vps-panel
/usr/bin/python3 scripts/upgrade-runtime.py --rollback BACKUP_ID_FROM_OUTPUT
```

Check Nginx, Fail2ban, panel journals and application diagnostics after rollback.
The OS admin SSH listener is not restarted or reconfigured by this operation.

## Primary sources

- [Nginx downloads](https://nginx.org/en/download.html) and [build configuration](https://nginx.org/en/docs/configure.html)
- [Python 3.15.2 release and source digest](https://www.python.org/downloads/release/python-3152/)
- [OpenSSL supported releases](https://openssl-library.org/source/)
- [OpenSSL 3.5.9 official assets](https://github.com/openssl/openssl/releases/tag/openssl-3.5.9)
- [Certbot 5.9.0 official assets](https://github.com/certbot/certbot/releases/tag/v5.9.0)
- [Fail2ban 1.1.1 official package](https://github.com/fail2ban/fail2ban/releases/tag/1.1.1)

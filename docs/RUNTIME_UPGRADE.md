# Managed runtime upgrade (4.1)

The regular installer uses Ubuntu/Debian maintained packages. `--upgrade-runtime`
adds a pinned private stack, built and checked before activating it. It is an
explicit maintenance operation: restarting Nginx and the panel disconnects active
tunnels briefly. A source build can take 10–25 minutes on a small VPS; it needs
build tools, free disk space and access to the official download hosts/PyPI.
Each source-build command prints its log path, elapsed time and the latest log
line every 10 seconds, even if that command has not produced fresh output. This
is activity information, not a completion percentage. The full output remains
in the release's `build.log`; failures also show its tail in the terminal.
Keep the SSH session open until completion. Ctrl+C cancels the build and its
compiler/linker descendants, retains logs and prints a concise cancellation
message (exit 130). SIGHUP/terminal disconnect and SIGTERM use the same cleanup
path, with conventional exit codes 129/143. A later retry preserves incomplete
work and starts a fresh build.

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

## Compiler detection and retry

The runtime builder uses the distribution `/usr/bin/gcc` and `/usr/bin/g++` with
an explicit system PATH. Source builds ignore inherited cross-compiler prefixes,
compiler/linker flags and foreign library/config paths. A C and C++ compile,
link and execution probe runs before source downloads or activation. This catches
missing compilers, development headers, linker failures and execution restrictions
with their actual error, instead of only OpenSSL's generic detection failure.

After an interrupted/failed build, update the repository and retry only the runtime:

```sh
cd /root/secure-vps-panel &&
git pull --ff-only origin main &&
/usr/bin/python3 scripts/upgrade-runtime.py --apply --jobs 2
```

Verified downloads are reused. An incomplete build remains available for inspection
and a fresh build directory is used; the previously active runtime stays in place
until the candidate finishes verification. If the native compiler probe still
fails, its error includes the distribution toolchain repair command. A failed
compile/link/run probe must be resolved before continuing.

## Retry a completed build without compiling it again

If the log reached configuration validation after all build steps completed, the
release already has a `READY` receipt. Retry its activation with the 12-hex build
ID shown in the original log, after pulling the latest source:

```sh
cd /root/secure-vps-panel &&
git pull --ff-only origin main &&
/usr/bin/python3 scripts/upgrade-runtime.py --activate-built BUILD_ID_FROM_LOG
```

This explicit recovery action verifies the root-owned release tree, completion
receipt, exact selected manifest, actual binary versions/linkage and configuration
before activation. It does not download sources or run compilers. Incomplete,
writable, foreign-owned or mismatched builds are refused. Use `--apply` when you
intend to build a changed recipe instead of activating an existing candidate.

Certbot renewal files are read with ConfigObj, the parser Certbot itself uses.
Root-level settings, quoted values, comments, interpolation, list values and nested
`[[webroot_map]]` sections are preserved; configuration and certificate files are
not rewritten. Missing external renewal plugins still block activation.

## Integrity, configuration and recovery

`RUNTIME_VERSIONS.json` records official URLs, exact versions and independently
retrieved SHA256 digests. Archives are verified before extraction/build. Private
Python package dependencies are resolved from PyPI; the installed package list
is saved in `python-packages.txt`. This is not a hash lock of every transitive
dependency, so future builds can resolve newer compatible dependencies.

Each build has an immutable directory under `/opt/noway/runtime/releases/`.
Failed source builds and their logs stay beside the release under
`/opt/noway/runtime/releases/`; downloads and recovery state are retained under
`/var/lib/noway-runtime/`. The
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

## CI feedback

PRs and main receive ordinary unit/native checks plus a fast hosted-Python 3.15
compatibility suite. Superseded runs are cancelled and feature pushes do not
duplicate the PR workflow. Full private source compilation runs automatically
when build functions, prerequisites, the runtime manifest, installer/interpreter
selector or systemd units change. Parser, activation and CLI routing fixes do
not automatically rebuild the stack. A full build remains available through
workflow_dispatch with full_runtime enabled. Missing/invalid diff metadata
conservatively requests the full build.

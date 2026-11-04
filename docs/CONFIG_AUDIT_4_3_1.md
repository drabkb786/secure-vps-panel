# Configuration consistency and transport checks — 4.3.1

## What the tests establish

An HTTP 101 plus an SSH identification from 127.0.0.1 proves a local route.
The same test from an external client proves public reachability on that tested
network. Neither proves account authentication, successful SOCKS forwarding,
access from a different mobile network, UDP support or sustained throughput.
An app's local pre-request 200 message is not the remote server response.

Diagnostics now read both the HTTP header and the SSH line without discarding
coalesced data or assuming that a TCP read is a complete message. There are
separate loopback bridge, Nginx HTTP and verified Nginx TLS checks. Failure detail
distinguishes HTTP 200/403, premature EOF, invalid identification and TLS errors.
The public/mobile-network acceptance step stays explicitly separate.

## Updating manually edited installations

The fast updater stages all affected modules from one pinned Git HEAD. It does
not execute a modified working-copy Python module. Source edits are listed in
source-release.json inside the private recovery directory. Without --sync-source,
working files remain unchanged. With --sync-source, the selected working files
are backed up alongside installed files and restored to that commit. Other source
files, credentials, accounts, CDN secrets and network-tuning receipts are not edited.
A failed update restores the selected original files.

Run from a Git checkout, after pulling main:

```bash
bash scripts/update-ssh-compat.sh --sync-source
```

The operation does not invoke the runtime compiler, package installation or a
full OS upgrade. Do not run upgrade-runtime.py --apply to synchronize application
modules. Use --status for a read-only private-runtime report. Do not glob release
Python executables or mix one Python minor version with another version's
site-packages. Full developer tests require their declared QA dependencies;
missing node or websockets is not evidence that the live SSH daemon is broken.
Guard regressions caused by manual parser edits must not be suppressed.

## Client exports

SSH exports now include separate raw HTTP/TLS JSON settings and a readable
client-settings.txt, in addition to the existing WSS profile and adapter.

| Mode | Origin port | TLS | HTTP handling |
| --- | --- | --- | --- |
| Direct SSH | 109 / 447 | None | No HTTP payload |
| Raw Upgrade | 80 | None | /ssh/raw, Host, Upgrade and Connection headers |
| Raw Upgrade over TLS | 443 | Verify origin hostname | Same raw payload, no WS key/version |
| Binary WSS | 443 | Verify endpoint hostname | Real RFC6455 frames and generated handshake |
| Authorized CDN WSS | 443 | Verify CDN endpoint hostname | Provider route, framing and configured origin headers |

The generic JSON/TXT exports are documented settings, not fabricated proprietary
NetMod .nm/.ehi import files. Passwords remain transient and are only embedded in
private JSON exports when explicitly supplied. Export is not a live connection test.

## Preserve the routing boundaries

2082 remains loopback-only. Public Nginx reaches it locally; allowing that port
through the public firewall does not repair a domain or client configuration.
The panel's /panel/ route stays separate. Disabled CDN routes deliberately return
403 until the provider is configured and enabled. Enabled routes verify the
private edge-origin headers and viewer identity. Do not remove those checks or
force every ordinary browser request into an SSH tunnel.

Modern OpenSSH, XHTTP, REALITY, bounded streaming, keepalive, and reversible BBR/MSS
already exist in 4.3.0. No unmeasured framework rewrite, unlimited descriptors,
arbitrary MTU or guaranteed cipher speed multiplier is required for this update.

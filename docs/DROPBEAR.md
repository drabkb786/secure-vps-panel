# Dropbear and SSH transport — NOWAY v3.3

## What changed

The previous bridge returned a WebSocket handshake and then sent raw SSH bytes.
That works with some legacy HTTP Upgrade clients but is not RFC 6455 framing.
The new `/ssh/ws` endpoint translates binary WebSocket frames to the fixed local
Dropbear listener. Masking, fragmentation, ping/pong and close validation use the
maintained MIT-licensed `python-hyper/wsproto` library. Runtime installation uses
the distribution's `python3-wsproto` package; no third-party panel code is copied.

| Connection | Public endpoint | Framing |
|---|---|---|
| Direct SSH | VPS/domain port `109` or `447` | Normal SSH |
| Standard WebSocket | `wss://YOUR-DOMAIN/ssh/ws`, port `443` | RFC 6455 binary frames, version 13; optional `binary` subprotocol |
| Legacy HTTP Upgrade | `/` or `/ssh/raw`, port `80` or TLS `443` | Raw SSH after HTTP 101 |

As of 4.3.0, a valid WebSocket key selects RFC6455 on all three direct paths.
Legacy raw clients must omit WebSocket key/version headers. See
[current SSH compatibility](SSH_COMPATIBILITY.md) for the updated behavior.
Use `/ssh/ws` only when the client actually frames WebSocket data. Arbitrary paths
are rejected; migrate a previously custom legacy path to `/ssh/raw`. Plain `ws://`
on port 80 is supported, but WSS with a valid certificate is recommended. SSH
credentials and host-key verification are still required on every route.

The bridge binds only `127.0.0.1:2082` and forwards only to `127.0.0.1:109`.
It cannot select arbitrary destinations from request headers or URL parameters.
This step does not provision Bunny, CloudFront or their origin settings.

## Transport limits and failure handling

- 200 connections, acquired **before** a handler thread starts.
- Absolute 10-second HTTP header deadline and 16-KiB header cap. Duplicate
  headers, request bodies, invalid WebSocket keys/versions and malformed upgrade
  requests are rejected before opening Dropbear.
- Bounded output queues with backpressure, 8-MiB maximum binary message, and
  1-hour bridge inactivity timeout. Clients should split larger streams into
  messages. Keepalive ping/pong is supported; Dropbear also uses SSH keepalives.
- Text messages receive close 1003; invalid framing receives protocol close;
  oversized messages receive close 1009. HTTP errors are not injected after 101.
- Failed backend connections return 502; capacity overload returns 503.
- The systemd bridge is capped at 256 tasks, 256 MiB and 1,024 file descriptors.

## Session tracking

Older distribution builds such as Dropbear 2022.83 keep authenticated forwarding
processes as root. Newer upstream builds can drop to the account UID immediately
after authentication. Counting only `ps euid` missed the former.

NOWAY verifies the actual root-owned Dropbear executable, the parent/child
relationship and kernel process start time. Managed accounts must have UID at
least 1000 and the registered tunnel-only shell. Modern authenticated user-UID
children are counted directly. Root children require a successful final auth
record from the current boot's `dropbear.service` journal, with trusted kernel
`_PID`, `_UID` and `_EXE` fields. Partial multi-factor success, arbitrary process
names, foreign units and records predating a reused PID are ignored.

The enforcer retains older connections and removes excess newer connections on
its five-second cycle. It uses pidfds to pin the verified process before TERM
and KILL, so PID reuse cannot redirect a signal. It does not fall back to an
unverified numeric PID when the kernel refuses pidfds. Account lock/expiry also
use this attribution. v3.5 additionally limits unique verified source IPs;
multiple connections on one IP count once. Unknown sources (including SlowDNS)
are disconnected when an IP cap is set. SSH GB metering remains unavailable.
See [accuracy details](ACCURACY.md).

Journal limits are explicit: startup queries at most 10,000 matching auth records
from the current boot; verified live identities are cached in memory. Missing or
rotated auth records, unusual service wrappers that log through the parent's
stderr, or an orphaned connection after a parent disappears can leave sessions
uncounted. Diagnostics report journal failure/unattributed root connections;
pre-auth connections can also explain that count. No identity is guessed.

## Installation and diagnosis

Run the reviewed installer from the updated checkout to install the Python
dependency, modules, service limits and maintained OS Dropbear package:

```bash
sudo bash install.sh --non-interactive
```

Existing SSH accounts use their existing credentials and host keys. Production
Dropbear disallows root login (`-w`), disables remote/reverse forwarding (`-k`),
limits authentication to three tries (`-T 3`), uses a 30-second SSH keepalive,
30-minute SSH inactivity timeout, and a 128-KiB receive window. Local/SOCKS
forwarding remains available. Managed account shells reject interactive commands.
The installer preserves previous defaults and restores them if restart or either
managed listener fails. OpenSSH administration is not reconfigured.

```bash
sudo abdulbasit-panelctl diagnostics
```

```bash
sudo abdulbasit-panelctl list-sessions
```

```bash
sudo abdulbasit-panelctl logs --service dropbear --level all
```

Diagnostics now probe both actual SSH greetings and report session attribution.
Fail2ban protects direct Dropbear login attempts. Loopback is explicitly ignored:
SSH through the bridge reaches Dropbear from localhost, so this jail cannot
provide per-client bans for tunneled connections. Forwarded IP headers are only
advisory logs and are not trusted account identities.

## Research and verification

Reviewed primary projects:

- [mkj/dropbear](https://github.com/mkj/dropbear), upstream release
  [2026.94](https://github.com/mkj/dropbear/releases/tag/DROPBEAR_2026.94):
  runtime flags, public-key handling, privilege drop and auth logging.
- [2022.83 auth source](https://github.com/mkj/dropbear/blob/DROPBEAR_2022.83/svr-auth.c):
  older authenticated forwarding process behavior.
- [novnc/websockify](https://github.com/novnc/websockify): binary WebSocket-to-TCP
  translation and subprotocol compatibility; implementation was not copied.
- [erebe/wstunnel](https://github.com/erebe/wstunnel): explicit target restrictions
  and bounded tunnelling; its separate client wire protocol is not claimed compatible.
- [python-hyper/wsproto](https://github.com/python-hyper/wsproto): protocol parser
  used by this bridge; avoids a new handwritten masking/control-frame parser.

Regression tests use an independent `websockets` client, large concurrent streams,
malformed frames/handshakes, slow-header deadlines, worker saturation, legacy
compatibility, auth attribution and PID-reuse rejection. Native tests compile an
unmodified official Dropbear tarball with SHA256 verification in a test directory,
then exercise direct SSH, legacy Upgrade through Nginx and verified WSS through
the production Nginx route generator. They check host keys, wrong-key rejection,
authenticated forwarding of 4 MiB, remote-forward denial and command denial.

The native fixture uses temporary keys in a new private directory, with `-D`
pointing there; it does not alter system users or their authorized_keys. The test
server allows its current test UID, including root containers; production always
uses `-w`. This development container rejects Dropbear's required `initgroups`
operation, so the full native tests run on GitHub's Ubuntu runner. Privileged
installation/rollback and live provider connectivity still need a real VPS.

## Earlier pull-request consolidation

PRs [#4](https://github.com/drabkb786/secure-vps-panel/pull/4),
[#1](https://github.com/drabkb786/secure-vps-panel/pull/1) and
[#3](https://github.com/drabkb786/secure-vps-panel/pull/3) were merged into `main`.
The dependency conflict was resolved while retaining both Actions v7 updates.

The older parallel panel in [#2](https://github.com/drabkb786/secure-vps-panel/pull/2)
was closed as superseded; its branch and commit
`0e75a5e465e402717510c4449293dc98d9cc28a9` remain intact. Unique work to port in a
later phase includes CDN profiles/guarded routes/CloudFormation, Telegram document
delivery and DNSTT key rotation. Those features were not silently merged into an
incompatible daemon/data model or claimed as implemented in this Dropbear step.

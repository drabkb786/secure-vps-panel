# SSH transport compatibility — 4.3.0

The production Nginx template lives in `src/paneld.py`. `operations.py` calls
managed operations; it does not contain a second Nginx template. Bunny derives
its routes from the CloudFront generator, including socket keepalive settings.

## Direct origin connections

| Client | Port | TLS | Payload |
| --- | --- | --- | --- |
| Plain SSH | 109 or 447 | None | None |
| Raw HTTP Upgrade SSH | 80 | None | GET /ssh/raw plus Host, Upgrade and Connection headers |
| Raw HTTP Upgrade SSH over TLS | 443 | Verified origin hostname | Same raw payload |
| Binary WebSocket SSH | 443 | Verified origin hostname | Client generates an RFC6455 handshake and binary frames |

Direct `/`, `/ssh/raw` and `/ssh/ws` now choose framing using the presence of
`Sec-WebSocket-Key`. A valid key requires HTTP/1.1 GET, version 13, and real binary
WebSocket frames. A raw client must remove placeholder WebSocket key/version
headers. Without those headers, a valid Upgrade on these direct paths receives
101 followed by raw SSH bytes. Legacy methods GET, POST, CONNECT, HEAD and OPTIONS
and HTTP/1.0/1.1 are accepted by the loopback bridge. Public Nginx still applies
its own HTTP parser; this does not make malformed CONNECT targets valid.

TCP-split headers and SSH bytes coalesced after the header terminator are retained.
Bodies, duplicate/ambiguous headers, transfer encoding, absolute third-party URLs,
unknown paths and malformed pipelined request tricks remain rejected. The target
always stays loopback port 109. `/panel/` stays on the web worker. No catch-all
SNI/default server or additional public listeners are installed.

Authorized CDN SSH continues to use `/cloudfront/ssh/ws` or `/bunny/ssh/ws` with
valid origin verification and viewer identity. Keep both edge-origin headers
configured from the private CDN setup export. Removing a 403 check is not a
replacement for configuring those headers or enabling the route. CDN clients
still need real RFC6455 framing and a certificate valid for their hostname.

## Managed OpenSSH

The generated managed config has MaxSessions 10, PermitTTY yes and an explicit
ForceCommand pointing at the existing tunnel-only shell. Clients may allocate
session/PTY channels; arbitrary commands and interactive shells remain denied.
This does not alter administrative SSH or regenerate existing SSH host keys.
MaxSessions 0 previously allowed TCP forwarding; it was not proof of a
pre-authentication EOF. Modern clients keep the standard modern algorithm set.

For a confirmed old-client algorithm negotiation failure, the migration supports
an explicit `--legacy-crypto` option. That mode appends ssh-rsa and SHA-1 DH groups;
it is never enabled automatically. A normal installer/migration regenerates the
modern mode. Do not select legacy crypto to troubleshoot an HTTP/TLS error that
occurs before the SSH server banner.

## Fast update of an existing installation

Run `bash scripts/update-ssh-compat.sh` as root from an updated Git checkout. It
requires an already configured managed OpenSSH installation and origin domain.
It backs up the affected application/SSH/Nginx files, validates the candidate,
reloads the managed backend, restarts the bridge/daemon and checks a local 101
response followed by the actual OpenSSH banner through Nginx. A failure restores
the saved files. Recovery copies remain under `/etc/abdulbasit/backups/`.
From 4.3.2, it first waits for the UNIX socket and a successful read-only
`web_revision` reply, rather than relying on systemd's active state. The regular
CLI also tolerates a missing/refused startup socket for up to three seconds.
Only connection establishment is retried: a command sent to a connected daemon
is never automatically replayed, even if its reply is missing or times out.
This path does not install packages, build a runtime, change admin SSH or apply
network tuning. It accepts the same explicit `--legacy-crypto` option.
Modules are staged from one committed HEAD rather than manually edited source.
Add `--sync-source` to back up and reset just the affected working-copy modules
to that commit too. See [configuration consistency](CONFIG_AUDIT_4_3_1.md).

## Optional network tuning

BBR availability is checked before changing settings. The qdisc sysctl sets the
default for new interfaces; existing interface qdiscs are not replaced.
With `apply --mss-clamp`,
MSS rules are added to mangle OUTPUT (locally terminated SSH/proxy connections)
and FORWARD (routed traffic), for IPv4 and IPv6 when the tools are available.
PMTU determines MSS; the script does not hardcode an interface MTU or change DNS.

The exact rules carry a NOWAY comment. Existing matching rules are recorded as
preexisting and preserved by rollback. A root-only receipt tracks additions;
partial failures restore sysctls, the old config and owned firewall rules.
A managed helper/service reapplies MSS at boot. After a later firewall reload,
restart `noway-network-mss.service` to restore these rules. `apply --mss-only`
works even if the kernel does not expose BBR. Rollback understands older BBR-only
receipts and removes only files/rules created by this operation.

Use `python3 scripts/tune-network.py status`, `apply`, `apply --mss-clamp`,
`apply --mss-only` or `rollback`. If already applied, rollback first before choosing
a different mode. These are operator actions; regular installation does not
change congestion control or firewall policy. Measure sustained traffic on the
actual route before claiming a speed improvement.

## Sources and limits

- https://man.openbsd.org/sshd_config#MaxSessions
- https://man.openbsd.org/sshd_config#PermitTTY
- https://nginx.org/en/docs/http/websocket.html
- https://docs.kernel.org/networking/ip-sysctl.html
- https://www.netfilter.org/documentation/HOWTO/netfilter-extensions-HOWTO-4.html

Local tests cover protocol handling and transactional failure behavior. Hosted
opt-in acceptance uses the actual installed OpenSSH, real Nginx and a real
firewall/systemd MSS round trip. None of these establishes NetMod behavior,
public reachability, CDN performance or sustained speed on an untested VPS.

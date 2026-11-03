# NOWAY 4.0 — OpenSSH and transport stability

## Upgrade an existing node

Keep the current administrative SSH connection open during installation. Run in
the existing reviewed repository checkout:

```sh
git pull --ff-only origin main
bash install.sh --with-xray --ssh-backend openssh --domain vpn.arm-29.tech
```

The installer backs up the application, config and old Xray binary. Managed SSH
ports 109/447 move to `abdulbasit-sshd.service`; the administrative SSH daemon and
its port are not reconfigured. Existing managed users join `abdulbasit-tunnel`.
The migration tests config and both banners before saving the backend marker,
and restores the previous backend if startup fails. A transport migration can
disconnect tunnel clients; do it during a maintenance window.

OpenSSH has separate host keys from Dropbear. Verify the printed SHA256 host-key
fingerprint on the VPS, then update the matching saved entry in each client.
Never disable host-key checks to hide a changed key.

```sh
ssh-keygen -lf /etc/abdulbasit-sshd/ssh_host_ed25519_key.pub
abdulbasit-panelctl diagnostics
abdulbasit-panelctl status
```

For a deliberate rollback to the distribution's maintained Dropbear backend:

```sh
bash install.sh --ssh-backend dropbear --domain vpn.arm-29.tech
```

The primary backend uses maintained OpenSSH packages from Ubuntu/Debian. The
test-only Dropbear build script still verifies upstream 2026.94; it does not
silently replace the OS package. Do not replace system Python/OpenSSL to chase
their version numbers: Ubuntu backports fixes.

## SSH sharing and passwords

Managed SSH passwords accept 3–128 characters. Browser admin and Trojan backup
validation retain their separate stronger policy. No recoverable password store
was added; the SSH client prompts for the current password. A CLI export can
optionally embed a password entered at export time.

```sh
abdulbasit-panelctl ssh-export basit --zip /root/basit-direct.zip
abdulbasit-panelctl ssh-export basit --route bunny --with-password --zip /root/basit-bunny.zip
```

Web: SSH accounts → Export → choose route → links, QR, individual files or ZIP.
Telegram: User Management → SSH links. The `ssh://` link uses direct SSH port 109;
`wss://` identifies the framing transport and does not contain a complete SSH
login. A proprietary NetMod `.nm` file is not fabricated.

The ZIP includes `ssh-ws-client.py`, an RFC6455 ProxyCommand adapter using wsproto
1.2.0. It validates TLS, supports an optional edge address with the correct SNI,
answers ping frames, and sends binary frames with bounded buffers. Use a native
SSH-over-WebSocket client or this adapter; a manual raw payload is insufficient
for a CDN's standard WebSocket connection. `legacy-raw-payload.txt` is explicitly
for the direct origin's raw-upgrade route.

## Xray upgrade and interruption policy

The pin is v26.10.31. The installer now compares the installed version with the
pin, verifies the official SHA256, tests existing config before replacement, and
rolls back the binary if the restarted private API does not become ready.

Account additions and qualifying re-enables are applied with HandlerService
without a full core restart. The CLI success count is checked, including partial
failure with exit status zero. Persisted desired state is reconciled by restart
if the live API fails or the core instance changes. Metadata-only renewals do not
restart the core. Revocation, quota exhaustion, expiry and IP-limit removal still
restart when needed to terminate established connections; this is necessary for
the current enforcement guarantee. A future per-user connection-kill API could
remove that remaining interruption. Config/transport changes also restart.

Statistics retain integer payload bytes, explicit GB/GiB units, immutable user
identities, durable checkpoints and restart epochs. Five-second sampling can
overshoot a quota; an unexpected crash can lose uncheckpointed bytes. SSH finite
GB quotas remain rejected because no trustworthy SSH byte meter exists. No fake
100% accuracy or device counting is claimed.

## Bunny and CloudFront

Bunny is now an explicit delivery route, with private `/bunny/*` origin routes,
a private origin header and an edge-derived viewer IP. Download the private setup
and apply both **origin request** header rules in Bunny (overwrite incoming
values), including `%{User.IP}`. Never put an origin secret in a client profile or
response header. Enable WebSockets, validate origin TLS and disable caching for
tunnel paths. Keep the origin DNS-only.

```sh
abdulbasit-panelctl bunny-enable --endpoint cdn.arm-29.tech
abdulbasit-panelctl bunny-setup --output /root/bunny-setup-private.zip
abdulbasit-panelctl bunny-check
abdulbasit-panelctl xray-export basit --route bunny --zip /root/basit-xray-bunny.zip
```

CloudFront's updated template allows uncached XHTTP GET/POST under
`/cloudfront/xhttp/`. Deploy/update the AWS stack from the new setup ZIP before
using these exports. The viewer function rejects unrelated paths and methods.
The origin keeps authenticated viewer identity separate from untrusted headers.
CDN routes avoid applying a 40-user limit to the shared edge IP; per-account
limits use verified viewer sources. Existing direct public paths remain available.
Both CDNs require their own deployed TLS/DNS configuration and real client tests;
a local edge simulation or HTTP101 probe cannot prove production speed.

## Optional REALITY and SlowDNS

Direct VLESS REALITY uses a separate public port (8443 by default), the node's own
TLS origin as fallback, and local persistent X25519 keys. It does not pass through
Bunny/CloudFront. The exported direct VLESS link/JSON contains the public key,
short ID and Vision flow; private keys stay server-side. Open this extra port only
if enabling this feature. REALITY keys are retained locally across profile backup
restores and are included in whole-installation maintenance archives.

```sh
abdulbasit-panelctl reality-enable --port 8443
abdulbasit-panelctl xray-link basit --protocol vless-reality
```

SlowDNS now checks the parent's authoritative NS referrals instead of relying on
a recursive NS answer from the tunnel server. It reports nameserver addresses
and agreement separately from external UDP/client readiness. MTU is configurable
from 512–1400, default 1232; lower it only after testing a failing resolver/path.
Do not change your VPS interface MTU or replace its resolver blindly.

```sh
abdulbasit-panelctl slowdns-enable --zone tunnel.arm-29.tech --ns-host ns1.arm-29.tech --port 53 --mtu 1232
abdulbasit-panelctl slowdns-check
```

SlowDNS cannot recover the original viewer IP, so SSH accounts using it require
an unlimited IP cap (`0`). Session limits still apply. Xray already supports UDP
through its tested transports. SSH itself carries TCP; no unsupported UDPGW is
silently installed. The original `ambrop72/badvpn` upstream was archived and last
pushed in 2021, so importing that daemon by default would add an unmaintained
component rather than modernize the panel.

## Measured tuning and remaining deployment checks

The bridge already uses TCP_NODELAY, SO_KEEPALIVE, backpressure and 64 KiB reads.
`docs/v4-bridge-benchmark.json` records five alternating loopback rounds: median
49.2 MiB/s at 16 KiB/default Nagle and 168.19 MiB/s at the existing 64 KiB/NoDelay
settings. This is not a new WAN speed improvement; it supports preserving the
working path. It excludes encryption, TLS, CDN and mobile networks. An asyncio /
uvloop rewrite is not a drop-in replacement for this threaded server and was not
introduced without a demonstrated bottleneck.

The WS service raises its descriptor limit to 8192. Diagnostics avoid holding the
account writer lock during bounded ping, DNS and journal reads, and service
status uses one systemd query. The enforcer keeps a monotonic five-second target
without adding processing time to every sleep. Dashboard polling remains bounded,
visible-only and non-overlapping; unnecessary frontend/runtime rewrites were
avoided. Kernel BBR/fq tuning is opt-in and reversible:

```sh
python3 scripts/tune-network.py status
python3 scripts/tune-network.py apply
python3 scripts/tune-network.py rollback
```

No unconditional socket-buffer inflation, TCPMSS firewall rewrite, catch-all SNI,
malformed multi-request acceptance or certificate bypass is applied. Diagnose a
specific path first. Compare direct and CDN connections using the same client,
region, cipher, payload and time window, and measure a long transfer plus idle
recovery. The user's live VPS, AWS deployment and mobile/NetMod route remain
external acceptance steps; repository CI cannot access those signed-in sessions.

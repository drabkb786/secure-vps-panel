# HAProxy and Dropbear migration — 4.5.0

This is an explicit switch of the **managed tunnel backend**. It does not edit
the machine's administrative SSH configuration or service on port 22. Existing
managed connections reconnect during the short gateway/backend cutover.

| Listener | Owner | Destination |
| --- | --- | --- |
| Public TCP 80 / 443 | `abdulbasit-haproxy` | Inspect TLS ClientHello; forward TLS or HTTP |
| Loopback TCP 8080 | Nginx HTTP + PROXYv2 | Existing HTTP, raw SSH Upgrade, WS, ACME routes |
| Loopback TCP 8081 | Nginx TLS + PROXYv2 | Existing HTTPS, WSS, Xray, dashboard and CDN routes |
| Loopback TCP 2082 | Existing hybrid WS bridge | `127.0.0.1:109` |
| Public TCP 109 / 447 | Pinned Dropbear 2026.94 | Managed SSH authentication and local TCP forwarding |
| Configured UDP port, normally 53 | Existing dnstt | Existing SSH backend on `127.0.0.1:109` |

Outer HTTP/non-TLS SSH and TLS SSH stay available together. SSH encrypts its
own traffic in both cases. The existing optional VLESS non-TLS setting is not
changed; it retains VLESS Encryption on its separate loopback listener. Xray
UUIDs, counters, subscriptions, Bunny and CloudFront configuration remain in
place. No arbitrary-host routing, HTTP request smuggling or CDN guard removal
is introduced. HAProxy cannot make an unrelated CDN hostname route to this VPS
or guarantee mobile-network accessibility, carrier billing, speed or latency.

## Apply on an installed VPS

Keep the current administrative SSH session open. A working configured origin
domain and TLS certificate are required. On the VPS:

```bash
cd /root/secure-vps-panel &&
git pull --ff-only origin main &&
bash scripts/migrate-dropbear-haproxy.sh &&
abdulbasit-panelctl diagnostics
```

The script first applies the committed application snapshot with its existing
backup mechanism. It installs HAProxy from supported OS packages and compiles
only the small checksum-pinned upstream Dropbear when a trusted matching
binary is absent. The build prints progress and a log location. Repeated runs
reuse that binary; there is no Python/OpenSSL/Nginx runtime compilation.

The private binary is `/usr/local/lib/abdulbasit/dropbear`; the package-owned
`/usr/sbin/dropbear` remains available for rollback. A dedicated
`/etc/systemd/system/dropbear.service` selects the pinned binary. It restricts
login to managed tunnel-group accounts, disallows root and remote/listening
forwarding, and uses the existing forced tunnel shell. Existing Dropbear host
keys are reused; new keys are generated only if absent. Confirm the printed
public host-key fingerprint when changing from OpenSSH in a client.

Candidate Nginx and HAProxy configs are checked before the old services stop.
The script verifies listener ownership, loopback bindings, both Dropbear ports,
daemon RPC readiness and HTTP/TLS Upgrade plus the actual Dropbear banner.
An activation failure restores the saved config and previous active services.
The stock Nginx welcome-site link is disabled only when its target and package
conffile checksum match an unmodified distribution welcome site. Other sites
still binding 80/443 cause a refusal and recovery rather than being modified.

## Client IP and private listeners

HAProxy sends PROXYv2 addresses. Nginx consumes them only on loopback listeners
and requires a root-private unique-id TLV. This prevents an authenticated SSH
user forwarding to loopback 8080 from supplying a fake client source address.
HTTP `X-Forwarded-For` from the client does not override this identity. The
existing authenticated CDN viewer-IP rules still apply on CDN routes.

Do not open 8080/8081, 2082, 9090 or Xray loopback ports in provider/firewall
rules. Public 80/443 and, when direct SSH is wanted, 109/447 must be reachable.
Administrative SSH and UDP DNS rules remain as previously configured.

## Validate from the actual client network

```powershell
Test-NetConnection vpn.arm-29.tech -Port 80
Test-NetConnection vpn.arm-29.tech -Port 443
Test-NetConnection vpn.arm-29.tech -Port 109
```

Use the exported adapter probes from `TRANSPORTS_4_4.md` for raw HTTP/TLS and
framed WS/WSS. Then authenticate and perform a sustained transfer. Local 101
and an SSH banner alone do not establish a successful NetMod session.

## Recovery and later updates

The migration prints an exact `Recovery copy:` directory under
`/etc/abdulbasit/backups/dropbear-haproxy-*`. Restore that specific directory:

```bash
bash scripts/migrate-dropbear-haproxy.sh --rollback /etc/abdulbasit/backups/PASTE_THE_PRINTED_DIRECTORY
```

Rollback restores the layout captured by that migration. It preserves account
passwords and the updated application snapshot, which supports both backends.
The earlier source updater has its own separate recovery copy. The user/OS
data is never replaced by a repository upload.

Later application-only updates use the existing fast path:

```bash
cd /root/secure-vps-panel &&
git pull --ff-only origin main &&
bash scripts/update-ssh-compat.sh --sync-source &&
abdulbasit-panelctl diagnostics
```

The full installer also preserves an already selected `dropbear-2026` marker.
Do not request `--ssh-backend openssh` unless deliberately changing back.

## Primary references

- Official release archive: https://matt.ucc.asn.au/dropbear/releases/
- Upstream source/flags: https://github.com/mkj/dropbear/tree/DROPBEAR_2026.94
- HAProxy TCP inspection, `send-proxy-v2`, `unique-id-format` and
  `proxy-v2-options unique-id`: https://docs.haproxy.org/2.8/configuration.html
- Nginx PROXY TLVs: https://nginx.org/en/docs/http/ngx_http_core_module.html
- Nginx real IP handling: https://nginx.org/en/docs/http/ngx_http_realip_module.html

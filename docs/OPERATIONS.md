# NOWAY v3.2 operations guide

The supplied reference screenshot was used as a capability checklist. Its brand,
layout, endpoints and claims were not imported. NOWAY keeps its own dark
navy/emerald design and adds browser workflows alongside a rebuilt terminal menu.

## Reference-to-implementation map

| Reference control | NOWAY equivalent | Scope |
| --- | --- | --- |
| 01 Create VIP Account | New VIP Xray profile; separate SSH account creation | VLESS, VMess, Trojan and optional XHTTP; private links/files/QR |
| 02 Fast 24h Trial | Quick trial button / `xray-trial` | Exact UTC expiry timestamp; access removed at the next one-minute cycle |
| 03 Real GB & Live IPs | Traffic & connections | Xray payload counters and authenticated recent IPs; gateway peers are labelled separately |
| 04 Telegram Bot Menu | Existing Telegram menu, terminal bot menu, owner setup page | Tokens and Super Admin setup remain root-terminal operations |
| 05 Renew / Edit GB | Renew + Limits actions | Xray quota enforced by periodic core configuration; SSH GB remains metadata |
| 06 Lock User Account | Lock Xray or managed SSH | Xray removes credentials; SSH locks password and expires account, terminating verified sessions |
| 07 Unlock & Reset GB | Unlock + measured-usage reset | Existing credentials are retained; reset requires working stats baseline |
| 08 Delete User Acct | Delete managed profile/user | Explicit confirmation in the interface |
| 09 View Config File | Redacted configuration viewer | UUID/password fields removed; actual client secrets remain in private exports |
| 10 All Accounts List | Xray/SSH tables; terminal account directories | Search and active/locked/trial/quota filters for Xray |
| 11 Clean RAM/Logs | Memory report + root maintenance | Optional cache reclaim; explicit system-journal retention, never automatic |
| 12 Restart All | Restart managed gateway | Config check first; daemon/web and normal OpenSSH kept available |
| 13 Auto-Doctor Fix | Inspect + repair failed services | Reports what it changed; does not fabricate provider DNS/firewall fixes |
| 14 Live Error Test | Service journal viewer | Fixed service allow-list, 100 entries, private-link/token redaction |
| 15 Fix UDP/SlowDNS | UDP policy, optional dnstt setup and delegation checks | Authenticated Xray UDP; official DNS tunnel to local authenticated Dropbear |
| 16 15s Packet Test | Packet loss/latency test | 15 ICMP probes to a selected fixed resolver; not a bandwidth benchmark |
| 17 Domain/SSL Menu | DNS & SSL page and terminal menu | Existing A/AAAA checks, ACME issuance and TLS diagnostics |
| 18 SSH Banner Menu | Plain-text banner editor | Managed Dropbear only; config write/restart failure rollback |
| 19 Re-Install All | Root maintenance reinstall | Private installation archive, reviewed root-owned checkout, typed confirmation |
| 20 Clean Uninstall | Root maintenance uninstall | Active normal OpenSSH required; backup, managed unit/route removal and SSH account locks; retains private configuration/shared packages |

## Traffic and limits

Only **StatsService** is enabled on the private UNIX socket
`/run/abdulbasit-xray/stats.sock`, inside a mode-`0700` runtime directory owned by
the dedicated Xray service user. Root performs queries through the command daemon;
ordinary tunnel users and SSH TCP forwarding cannot reach the socket. No TCP
statistics port, Xray handler API or routing modification API is enabled. Per-protocol counters are combined into
the owning Xray profile. The persistent counter file is authoritative; metadata
is refreshed after it so a crash between writes does not count the same bytes
twice. Explicit core changes first sample usage and start a new counter epoch.
Systemd invocation IDs distinguish core restarts; a counter decrease is also
handled. Profile usage resets preserve the current baseline.

The timer samples every minute and removes credentials when their saved total
reaches the configured limit. This is **sampled quota enforcement**, not an exact
packet-by-packet cutoff: it can overshoot during an interval. An unexpected core
crash can lose bytes since the most recent successful sample. Unavailable APIs
are shown as unavailable and preserve previous totals. A displayed GB is
`1024³` bytes. SSH process I/O is never presented as network usage; SSH GB limits
remain metadata until a separately validated SSH accounting backend exists.

Nginx overwrites `X-Forwarded-For` and the internal `X-Noway-Gateway` header.
The core accepts forwarded addresses via this internal header on its loopback
listeners, matching the pinned core's actual header-based trust implementation.
Do not expose Xray's internal listeners or API. If a CDN is placed in front,
the observed address is its egress until the operator configures trusted real-IP
handling in Nginx. Authenticated IPs use Xray's recent-activity window; they are
not a concurrent-device limit. Gateway TCP peers alone do not prove authentication.

```bash
sudo abdulbasit-panelctl xray-trial basit_trial --quota 1
```

```bash
sudo abdulbasit-panelctl xray-quota basit --quota 20
```

```bash
sudo abdulbasit-panelctl traffic
```

```bash
sudo abdulbasit-panelctl xray-reset-usage basit
```

## UDP and optional SlowDNS

UDP forwarding travels inside an authenticated Xray connection. Disabling it
inserts an explicit UDP block in the core routing policy. Private/link-local
destination blocking remains in place. No open UDP relay is created.

```bash
sudo abdulbasit-panelctl xray-udp on
```

The optional dnstt installer builds **official dnstt v1.20260501.0** through
`proxy.golang.org` with `sum.golang.org` verification. It uses official Go 1.27.3
archives pinned by SHA256 for amd64/arm64. It does not expose a listener until
the operator enables a configured tunnel. Upgrade installation also supports
`install.sh --with-dnstt`.

```bash
sudo abdulbasit-panelctl slowdns-install
```

Create `ns1.example.com` A/AAAA records pointing to the actual VPS, then delegate
`tunnel.example.com` with an NS record to `ns1.example.com`. The NS host must not
be inside the delegated tunnel zone. Public delegation normally requires UDP 53;
a nonstandard local port needs an explicit external forwarding arrangement.
Existing DNS listeners are detected and are not stopped or overwritten.

```bash
sudo abdulbasit-panelctl slowdns-enable --zone tunnel.example.com --ns-host ns1.example.com --port 53
```

```bash
sudo abdulbasit-panelctl slowdns-check
```

The result contains the server's **public** key and example dnstt/SSH client
commands. The private key stays in `/etc/abdulbasit-dnstt/server.key`, readable
only by root/the dedicated service group. Traffic terminates at local Dropbear
`127.0.0.1:109`; a managed SSH account/password is still required. This is a DNS
tunnel, not a recursive DNS resolver or a guarantee of access on every carrier.

## System toolbox and owner maintenance

```bash
sudo abdulbasit-panelctl doctor --repair
```

```bash
sudo abdulbasit-panelctl logs --service abdulbasit-xray --level error
```

```bash
sudo abdulbasit-panelctl packet-test --target 1.1.1.1
```

The browser can inspect memory. Cache reclaim and archived-journal deletion
are root-terminal operations and require typed confirmation. Linux normally
reclaims file cache automatically; dropping it can temporarily reduce performance.
Journal cleanup affects the **system** archived journal (7-day / 256-MiB retention),
not only the panel, and permanently removes older entries.

```bash
sudo abdulbasit-panelctl maintenance memory --reclaim
```

```bash
sudo abdulbasit-panelctl maintenance clean-logs
```

Reinstall/uninstall are absent from the HTTP/Telegram command allow-lists.
They create mode-`0600` archives beneath `/etc/abdulbasit/backups/`, including
managed application/configuration files and the dnstt private key. Keep these
archives private. They are broader than the browser's scoped Xray JSON backup.
They are not an automatic full-OS restore image and omit Let's Encrypt keys.

```bash
sudo abdulbasit-panelctl maintenance reinstall --source /root/secure-vps-panel
```

```bash
sudo abdulbasit-panelctl maintenance uninstall
```

Uninstall requires active normal OpenSSH, removes managed panel units/code/routes,
locks managed SSH users, and retains configuration, backup archives, certificates
and shared Nginx/Dropbear packages. Use the source checkout to reinstall.

## Verification boundary

Real Xray/Nginx tests exercise TCP and UDP for VLESS/VMess/Trojan and XHTTP,
check actual statistics and authenticated forwarded addresses, and include forged
client header values that Nginx must overwrite. A separate test uses real official
dnstt server/client binaries to round-trip TCP through UDP DNS. It uses a local
echo fixture rather than changing real OS accounts or public DNS.

The complete privileged installer, account operations, systemd capabilities,
public UDP 53/delegation, certificate issuance, actual client devices and
reinstall/uninstall still require validation on the deployed VPS. Development
tests do not execute destructive maintenance. The UI screenshot contains
explicitly labelled example data and is not live server telemetry.

Primary references: [Xray StatsService](https://xtls.github.io/en/config/api.html),
[Xray statistics policy](https://xtls.github.io/en/config/policy.html),
[official dnstt module](https://pkg.go.dev/www.bamsoftware.com/git/dnstt.git),
[Go downloads](https://go.dev/dl/).

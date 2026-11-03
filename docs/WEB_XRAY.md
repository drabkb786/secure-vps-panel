# NOWAY v3.2 — browser, DNS and Xray setup

For the new trial/GB/IP/UDP/SlowDNS/system controls and the full reference-menu
mapping, see [OPERATIONS.md](OPERATIONS.md).

## Install or upgrade

Use a copy of this branch/release on the VPS. The installer requires root, systemd,
Python 3.10+, Ubuntu 22.04/24.04 or Debian 12+, and public ports 80/443. It does not
need a separate hosted website. `vpn.example.com` below is a placeholder.

```bash
sudo bash install.sh --domain vpn.example.com --email admin@example.com --with-xray
```

The Xray binary is pinned by `XRAY_VERSION` to the tested official release and
verified against its release SHA256 digest. To explicitly install another release:

```bash
sudo bash install.sh --domain vpn.example.com --with-xray --xray-version v26.10.21
```

An existing managed Xray binary is kept unless an explicit version is supplied.
The private binary is `/usr/local/lib/abdulbasit/xray`; an independently installed
`xray.service` and its configuration are not overwritten.

The installer keeps user metadata and makes a root-only backup of existing
application files. Upgrades regenerate the managed Nginx site even when the saved
domain is reused. Existing managed accounts using `/bin/false` move to a registered
tunnel-only shell. This allows Dropbear authentication while refusing interactive
commands; normal SSH forwarding channels work without opening a command shell.

## Create the browser login

There is no default password. Run this on the VPS as root; password entry is hidden.

```bash
sudo abdulbasit-panelctl configure-web
```

Open `https://vpn.example.com/panel/`. Changing the web password from this command
revokes existing sessions. Web credentials and SSH/Xray account credentials are
separate. Browser process restarts also end all browser sessions.

Before public TLS is ready, use a local SSH tunnel:

```bash
ssh -N -L 9090:127.0.0.1:9090 root@YOUR_VPS_IP
```

Then open `http://127.0.0.1:9090/panel/` on that same computer. Public plain-HTTP
login is rejected. Localhost HTTP through the SSH tunnel is intentionally supported.

## Domain and DNS

Create your domain's A record pointing to the VPS IPv4 address at the DNS provider.
Create an AAAA record only when that IPv6 address actually works. The dashboard's
**DNS & SSL** page saves the hostname, checks A/AAAA records and issues/renews TLS.
The ACME webroot is preserved and Nginx is not stopped for issuance.

**Resolver settings** affect Xray and exported client JSON only. They do not change
`/etc/resolv.conf`, create provider records or expose a public resolver on port 53.
Use 1–4 IPs or HTTPS DoH URLs. The default is IPv4 resolution. DoH hostnames still
need a working system resolver for bootstrap. Client import links do not carry
custom DNS; use the exported JSON or configure DNS in your client separately.

```bash
sudo abdulbasit-panelctl dns-set --server 1.1.1.1 --server 8.8.8.8 --strategy UseIPv4
```

```bash
sudo abdulbasit-panelctl dns-lookup
```

## Enable Xray and create profiles

Complete the domain and TLS setup before enabling Xray. In the browser, open
**Xray profiles → Enable Xray → New profile**. Choose protocols and validity.
Names are unique within the Xray account list. SSH accounts remain separate.

```bash
sudo abdulbasit-panelctl xray-enable
```

```bash
sudo abdulbasit-panelctl xray-create basit --days 30
```

| Protocol | Public endpoint | Internal listener |
| --- | --- | --- |
| VLESS | `wss://vpn.example.com:443/vless` | `127.0.0.1:10001` |
| VMess | `wss://vpn.example.com:443/vmess` | `127.0.0.1:10002` |
| Trojan | `wss://vpn.example.com:443/trojan` | `127.0.0.1:10003` |
| Optional VLESS XHTTP | `https://vpn.example.com:443/xhttp/` | `127.0.0.1:10004` |
| Browser | `https://vpn.example.com/panel/` | `127.0.0.1:9090` |
| Legacy SSH HTTP upgrade | existing path and 80/443 | `127.0.0.1:2082` |

Nginx terminates TLS for Xray; cleartext traffic between Nginx and the core stays on
loopback. Do not expose internal ports. Imported profiles verify TLS; there is no
`allowInsecure: true` in generated configs. UUID/password values are randomly
generated and stored root-only. Normal profile lists do not include them.

The older SSH proxy is an HTTP-upgrade raw TCP tunnel, not a general RFC 6455
WebSocket server. Existing compatible SSH tunnel clients can keep using it. The
Xray WS endpoints are actual WebSocket transports handled by Xray itself.

### Optional VLESS XHTTP

Enable **XHTTP** on the Xray page or run:

```bash
sudo abdulbasit-panelctl xray-enable --xhttp
```

This adds a separate VLESS variant for eligible VLESS profiles. It preserves their
WS links and credentials. Nginx accepts HTTP/2 over TLS and streams requests to the
loopback XHTTP listener; generated clients use `packet-up` mode and ALPN `h2`.
Use a client that supports Xray XHTTP. This preset has been tested through real
Nginx and Xray, but individual CDNs and mobile networks still need testing.

```bash
sudo abdulbasit-panelctl xray-link basit --protocol vless-xhttp
```

```bash
sudo abdulbasit-panelctl xray-enable --no-xhttp
```

## Export and import

Click **Export** beside a profile. Use **Copy VLESS link**, **Copy Trojan link**,
**Copy all links**, or **Link TXT** for the plain import URI. You can also download
Xray JSON, sing-box JSON, Mihomo/Clash.Meta YAML, or the ZIP with all selected
profiles, individual protocol TXT files, `links.txt`, and a base64
`subscription.txt`. The ZIP's subscription text is a static snapshot; live URLs
are described below. ZIPs and export APIs require an admin session and are not cached.
The QR button generates a code locally without sending the link to a QR service.

The sing-box and Mihomo adapters contain the selected **WS/TLS** profiles and a
loopback mixed listener on `10808`. The Mihomo file uses JSON syntax, which is
valid YAML. XHTTP is included in URI and Xray exports only. These adapters verify
TLS. Xray usage/quotas are enforced on the server through periodic sampling;
these client adapters do not implement a separate accounting backend.

Xray is the engine; VLESS, VMess and Trojan are the connection protocols.
The exported JSON starts a loopback SOCKS listener on `10808`. Run one client JSON
at a time or change that local port. Import-link compatibility depends on the
client supporting that protocol with WS+TLS.

These are direct **import URIs** (`vless://`, `trojan://`, `vmess://`). The configured
transport remains TLS + WebSocket on port 443; the word "direct" does not switch
the profile to a raw TCP transport. Import links are returned when creating a
profile and can be retrieved later without regenerating its credentials.

To print only one link with no JSON wrapper (replace `basit` with your profile name):

```bash
sudo abdulbasit-panelctl xray-link basit --protocol vless
```

```bash
sudo abdulbasit-panelctl xray-link basit --protocol trojan
```

```bash
sudo abdulbasit-panelctl xray-export basit --links
```

Warnings go to stderr so copied stdout remains importable. A missing protocol,
expired account or disabled account returns an error instead of an invented link.
If the core is offline, eligible profiles can still be exported with a clear warning;
core readiness and public reachability are separate. DNS, certificate and provider
firewall checks are still needed on the actual VPS. The Web UI shows that warning
beside its links. Its TXT/ZIP download endpoints require an admin session.

Telegram admins can open **Xray Links**, select a profile (or find it by name),
and copy its VLESS/VMess/Trojan URIs. This retrieves existing profiles; creation
continues through the dashboard/CLI. No real Telegram messages were sent during
the development tests; the bot tests use an offline API fixture.

```bash
sudo abdulbasit-panelctl xray-export basit --zip /root/basit-profiles.zip
```

```bash
sudo abdulbasit-panelctl xray-renew basit --days 30
```

```bash
sudo abdulbasit-panelctl xray-delete basit
```

Validity ends at the start of the expiry date in the VPS system timezone. The
expiry timer removes expired Xray credentials on the next five-second target check plus processing time. Config/account
changes restart the core and briefly reconnect existing clients. Failed tests or
restarts restore previous managed files; inspect the journal if rollback restart
also fails. Disabling Xray removes its boot-enable marker and stops its service.

Private/link-local destinations (including cloud metadata addresses) are blocked
by the generated server routing rules. This is an Internet proxy preset; private
LAN access is not enabled. Unique source-IP limits and explicit GB/GiB units are available in v3.5; they
are not device identification or packet-level hard quotas. REALITY and profile
creation inside Telegram remain deferred. SSH byte metering is unavailable;
finite SSH GB quotas are rejected. See [accuracy details](ACCURACY.md).

## Live subscription URLs

Choose **Subscription** beside a profile, then **Create / rotate URL**. Save the
private URL immediately: the full token is shown once and only its SHA256 digest
is stored. The CLI returns the same URL plus format-specific variants:

```bash
sudo abdulbasit-panelctl subscription-rotate basit
```

Supported `?format=` values are `base64`, `plain`, `xray`, `clash`, and `singbox`.
The default is base64 import links; recognized Mihomo/Clash and sing-box client
user agents select their native format. The Xray variant is a JSON array of
individual client configurations; it is not one directly runnable core config.
Use a downloaded individual JSON when invoking Xray directly.

Clients fetch the latest eligible configuration without an admin cookie. The
secret URL is the authorization, so treat it like a password. Public access
requires HTTPS. Requests are bounded, never cached, and excluded from the
managed Nginx access/error logs. An external CDN or reverse proxy may have its own
logging policy. Subscription headers include expiry and saved measured Xray
usage/limits. Values update on the next successful sample, not on every packet.

Rotation invalidates the old URL. **Revoke URL** stops future downloads:

```bash
sudo abdulbasit-panelctl subscription-revoke basit
```

Disabling/expiring/deleting the profile or disabling the engine blocks downloads.
Revocation and rotation do not change credentials already imported into a client;
disable/delete the profile to stop those connections. Token rotation itself does
not restart Xray.

## Private Xray backup and recovery

Open **Backup & recovery** to download a private JSON snapshot, or save it from
the root CLI. The CLI creates a new file with mode `0600` and refuses overwrite:

```bash
sudo abdulbasit-panelctl backup --output /root/noway-xray-backup.json
```

This versioned backup contains Xray account UUIDs/passwords, expiry, enabled flags,
subscription token digests and resolver/transport settings. It excludes OS SSH
accounts/passwords, TLS private keys, browser login and Telegram credentials. Keep
it private. A restored token digest makes a previously issued URL eligible again
when the domain and account are still valid; the token cannot be recovered from
the digest.

Restore runs only from the root CLI and replaces the managed Xray account list
and network settings. Install the managed core first. The existing server domain,
TLS keys, web login and bot configuration are preserved:

```bash
sudo abdulbasit-panelctl restore /root/noway-xray-backup.json
```

Review the prompt and type `RESTORE`. `--yes` is available for a deliberate scripted
restore. Validation happens before changes. A mode-`0600` recovery copy is written
under `/etc/abdulbasit/backups/` before applying; config validation, restart and
readiness failures roll the managed files back. Restores can reconnect clients.
If existing metadata is corrupt JSON, the recovery copy instead uses a separate
raw-file schema for inspection; it is not a valid import backup. A valid snapshot
can still restore the damaged store.

## Diagnose a deployed host

```bash
sudo abdulbasit-panelctl diagnostics
```

```bash
sudo journalctl --no-pager -n 100 -u abdulbasit-paneld -u abdulbasit-web -u abdulbasit-xray
```

```bash
sudo ss -ltnp
```

Check DNS A/AAAA, certificate validity, Nginx, core syntax, clock synchronization
and internal listeners. VMess needs an accurate clock. Provider firewall or carrier
restrictions must be tested from the actual client network; local diagnostics
cannot guarantee access from every network.

## Primary configuration references

- [Xray core and official releases](https://github.com/XTLS/Xray-core)
- [VLESS inbound](https://xtls.github.io/en/config/inbounds/vless.html)
- [VMess inbound](https://xtls.github.io/en/config/inbounds/vmess.html)
- [Trojan inbound](https://xtls.github.io/en/config/inbounds/trojan.html)
- [Built-in DNS](https://xtls.github.io/en/config/dns.html)
- [WebSocket transport](https://xtls.github.io/en/config/transports/websocket.html)
- [XHTTP transport](https://xtls.github.io/en/config/transports/splithttp.html)
- [Xray share-link proposal](https://github.com/XTLS/Xray-core/discussions/716)
- [XTLS libXray share-link implementation](https://github.com/XTLS/libXray/tree/main/share)

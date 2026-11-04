# Account dashboard and measured connections — 4.6.0

The Account management landing view follows the supplied dashboard sketch:

| Summary row | Expanded IP row |
| --- | --- |
| Account name and protocols | Canonical IPv4/IPv6 or explicit unknown source |
| Client upload / download | Per-source upload / download / total payload |
| Total usage / GB or GiB quota | Allowed / blocked, online / last seen |
| Unique IP count / cap, access status | Protocol tags and account-scoped Block/Allow |
| Limits, links/settings, lock and renew | Eight rows initially, Show more and subsequent pages |

SSH and Xray accounts remain separate credential identities, including when
their display names match. Blocking an address applies only to the selected
identity; it does not install a server-wide firewall ban. Xray policy changes
validate/restart its shared core, so existing Xray clients reconnect. SSH blocks
terminate matching verified sessions and reject subsequent metered admissions.

## Application update

```bash
cd /root/secure-vps-panel
git pull --ff-only origin main
bash scripts/update-ssh-compat.sh --sync-source
```

This installs the account screen, APIs, IP controls and sharing. Original Xray
builds still expose measured account totals; an unmodified backend cannot expose
new per-IP byte counters. The UI shows awaiting activation rather than zeros.

## Activate payload metering on the VPS

Keep an administrative SSH session open and allow time for the first Go build.
The host needs a working origin domain/certificate and enough memory/disk for
compilation (approximately 2 GB free RAM is recommended; two compiler workers).
The explicit activation migrates the managed tunnel service to the metered
Dropbear/HAProxy layout documented in HAPROXY_DROPBEAR_4_5.md.

```bash
cd /root/secure-vps-panel
bash scripts/activate-account-meters.sh
```

Only private managed binaries are replaced. The script uses the gateway's
backup/rollback migration and a separate Xray binary backup. A failed later
Xray build leaves the working SSH migration and original Xray in place. These
are separate, reported recovery scopes. Admin SSH and account passwords are
preserved. No private Python/OpenSSL/Nginx SDK rebuild is performed.

The modified builds are labelled `2026.94+noway-meter1` and
`noway-ip-meter-v1`. Upstream release/source identities are pinned and checked;
the reviewable additions are scripts/patch-dropbear-meter.py and
patches/xray/noway_meter.go. They are intentionally identified as modified
builds, rather than represented as official upstream binaries.

## Accuracy and enforcement

- Upload means client to target; download means target to client. Total is
  their sum. Metered bytes are authenticated channel/dispatch payload, excluding
  SSH/TLS/WS framing and provider IP/TCP overhead. A provider's bill can differ.
- SSH totals are generated inside authenticated Dropbear channel I/O. The root
  collector verifies kernel peer credentials, a root-owned executable, its
  managed listener ancestry and accepted TCP tuple. Gateway source mapping
  retains the existing private, live-inode verification. A supplied IP/username
  is never accepted as accounting identity.
- SSH absolute counters report once a second and at normal exit. The collector
  checkpoints atomically every two seconds and on disconnect. Repeated samples,
  collector reconnections and resets preserve their baselines. A process killed
  before its final report can lose its unreported interval; corrupt ledgers do
  not silently reset. Finite-quota sessions fail closed when metering fails.
- Xray per-source counters are collected with the existing restart-fenced
  account counters. Both regular Dispatch and DispatchLink paths are covered.
  The global per-IP counter registry is bounded; overflow marks IP attribution
  incomplete while account counters continue. Existing core-crash/checkpoint
  and polling limitations in ACCURACY.md still apply.
- Finite SSH quotas require the active, verified metered Dropbear build. Managed
  OpenSSH and old Dropbear remain compatible with unlimited SSH accounts but do
  not gain fictional byte counters. Old quota notes remain unenforced until
  the owner explicitly saves a new metered quota.
- GB = 1,000,000,000 bytes; GiB = 1,073,741,824 bytes. The API includes exact
  decimal byte strings. Quota/IP enforcement targets five-second checks plus
  processing time and can overshoot; it is not a packet-level hard cutoff.
- IP caps count unique network sources, not devices. Shared Wi-Fi/CGNAT can
  share an address. SlowDNS sources remain unknown after the resolver hop;
  an IP-limited SSH account cannot admit them. Unknown usage stays labelled.
- Traffic before activation cannot be reconstructed per IP. Existing account
  usage remains intact. SSH metering starts with the activated backend; the
  owner may reset an account's metered allowance explicitly.

## Sharing

The SSH export shows server, ports, username, direct URI and supported raw
HTTP/TLS payload containing Host. RFC6455 WS/WSS uses its real framed adapter,
not an invented proprietary client file. Optional password inclusion is sent
only through authenticated, CSRF-protected POST requests, retained transiently
in the export dialog and erased on close. It also applies to its private ZIP.
Stored password hashes cannot recover the current password; enter it to share.

VLESS/VMess/Trojan, XHTTP/REALITY where enabled, Direct/Bunny/CloudFront links,
QR codes and client JSON exports remain available through Links & settings.

## Performance and acceptance

Collapsed IP histories do not query the core. The active detail page is sampled
with bounded pages; history pagination does not truncate enforcement's IP set.
Added counters are local integer increments, not disk/process-I/O estimates.
New meters have a dedicated CI job using actual compiled cores, password SSH
authentication, echo transfers, exact per-IP byte assertions and account-scoped
IP denial. General integration and browser checks remain separate. No change
promises mobile-network speed or replaces a sustained test on the real route.

# Traffic and IP limits — v3.5

This release fixes counter continuity and adds explicit unique-source-IP limits.
It does **not** promise zero overshoot, device identification, or billing-grade
durability across an unexpected core crash. No live VPS/AWS deployment is implied
by a passing repository test.

| Control | What is measured / enforced | Boundary |
|---|---|---|
| Xray GB quota | Integer uplink + downlink bytes reported by the authenticated core, combined across VLESS, VMess, Trojan and XHTTP | Payload at the core's dispatch layer, not provider-billed IP/TCP/TLS bytes. Transport/mux framing may differ from application file size. |
| GB / GiB | GB = 1,000,000,000 bytes; GiB = 1,073,741,824 bytes | New accounts use GB. Existing untagged quotas keep their old binary capacity and are explicitly labelled GiB. Up to three decimal places; finer input is rejected, never silently rounded. |
| Xray unique IP cap | Union of canonical active source IPs across every protocol of the same account | Polling, not handshake admission. An over-limit profile is removed for 30 seconds, then automatically retried. Applying the shared core config reconnects other clients too. |
| SSH unique IP cap | Oldest admitted source IPs across authenticated Dropbear sessions | Multiple sessions on one IP count once. Excess/unknown-IP sessions are terminated at the next check. Session caps remain a separate setting. |
| SSH GB quota | Unavailable | Finite quotas are rejected before changing an OS account. Old quota notes do not grant enforcement. `/proc` disk I/O is never used as network usage. |
| SlowDNS IP identity | Unavailable after the resolver/dnstt hop | Use an SSH account with IP cap 0 (unlimited). An IP-limited account disconnects unattributable sources. |

The target check interval is **5 seconds after a completed cycle**, plus API,
scheduling, config validation and restart time. Traffic and short connections
between samples can exceed a limit. Increasing check frequency does not make this
a packet-level hard quota. An IP means a network source, not a device: shared
Wi-Fi/CGNAT can put many devices behind one address, and IPv6 privacy addresses
can make one device appear under several addresses.

## Counter correctness and recovery

- Queries do not reset Xray's counters. A repeated sample is idempotent.
- A valid systemd InvocationID is read before and after each sample. A restart
  race is retried once; an unidentified/unstable epoch is never guessed.
- Missing counters retain their baseline within the same epoch. Duplicate,
  negative, floating-point or malformed counters reject the entire sample.
- Counter identity is tied to the immutable account UUID. Recreating a name does
  not inherit an old user's statistics. Legacy email names are accepted during
  the upgrade's final sample.
- `traffic.json` is the authoritative checkpoint. Account metadata is hydrated
  from it even after a crash between the two writes. Atomic replacement fsyncs
  both the file and containing directory.
- Reset clears totals while preserving the current baseline. Failed reset/config
  operations roll back. Backups preserve quota units and IP caps and exclude
  transient online/cooldown flags.
- A counter decrease is recorded as a discontinuity; unobserved data before an
  external counter reset cannot be reconstructed. Core crashes and the gap between
  the final sample and a planned restart can lose uncheckpointed bytes.
- An unavailable meter blocks finite-quota profiles at the next enforcement
  cycle. An unavailable IP monitor blocks IP-limited profiles. A corrupt ledger
  stops the managed Xray service instead of resetting usage to zero. Restore a
  known-good profile backup from the root CLI and inspect the service journal.

The dashboard shows exact per-direction byte strings without JavaScript int64
rounding, explicit units, the last successful sample time, and monitor/cooldown
status. A stale sample is historical data, not live zero usage.

## Trusted client identity

Nginx overwrites forwarded addresses. The marker header and internal Xray paths
include a random secret stored in `/etc/abdulbasit-gateway/header.conf`; no client
export includes them. A normal SSH tunnel to loopback cannot bypass the public
gateway by forging the former public `X-Noway-Gateway` marker or public WS path.
Do not expose internal listeners or share the private server config.

CloudFront's viewer-request Function overwrites `X-Noway-Viewer-IP` using
`event.viewer.ip`; the origin request policy forwards this field. The origin
still requires its independent distribution secret. Missing viewer identity is
rejected with HTTP 503 instead of billing/counting an AWS edge as the user.

For SSH-over-WS, the bridge records its verified viewer IP against the live target
socket inode in a private DynamicUser runtime directory. The enforcer checks the
directory owner, file mode, live process descriptor and TCP tuple before using
the record. Stale/reused-port records fail closed. Direct SSH uses the kernel TCP
peer. Authentication identity remains separate: modern Dropbear drops UID;
older root forwarding processes require trusted current-boot journal auth records.
Missing/rotated journal records, unsupported wrappers and orphan processes can
still prevent attribution on older builds; see [Dropbear limitations](DROPBEAR.md).

## Upgrade and configure

For an existing CloudFront distribution, **update the AWS stack before upgrading
the VPS**. Generate the new public template from this checkout (no AWS secrets):

```bash
PYTHONPATH=src python3 -c 'import json, cdn_manager; print(json.dumps(cdn_manager.template(), indent=2))' > cloudfront-v35.json
```

Update the existing stack with this template, retaining its OriginDomain,
OriginSecret and PriceClass parameters. Wait for the distribution deployment.
The old origin tolerates the additional header; the new origin requires it.
Then rerun the normal installer from this checkout. The installer preserves the
gateway marker on later runs, installs the runtime permissions, updates Nginx/core
configuration and restarts the five-second timer. Existing public client URLs
and account credentials remain valid. AWS deployment and VPS installation are
operator actions, not performed by repository CI.

Set an Xray account to 20 decimal GB and two concurrent source IPs:

```bash
sudo abdulbasit-panelctl xray-limits basit --quota 20 --unit GB --ips 2
```

Keep a binary allowance explicitly:

```bash
sudo abdulbasit-panelctl xray-limits basit --quota 20 --unit GiB --ips 2
```

Set SSH session and IP caps independently:

```bash
sudo abdulbasit-panelctl set-sessions basit --sessions 6 --ips 2
```

Check authoritative counters and current source observations:

```bash
sudo abdulbasit-panelctl traffic
sudo abdulbasit-panelctl connections
sudo abdulbasit-panelctl list-sessions
```

## Source review

Implementation follows the pinned upstream's actual behavior, rather than
assuming a panel screenshot's IP/session/GB labels establish accuracy:

- [Xray v26.10.21 active IP reference counts](https://github.com/XTLS/Xray-core/blob/v26.10.21/app/stats/online_map.go)
- [Xray dispatcher counters and connection lifetime](https://github.com/XTLS/Xray-core/blob/v26.10.21/app/dispatcher/default.go)
- [Xray forwarded-header trust implementation](https://github.com/XTLS/Xray-core/blob/v26.10.21/common/protocol/http/headers.go)
- [Dropbear 2026.94 authentication and privilege drop](https://github.com/mkj/dropbear/blob/DROPBEAR_2026.94/src/svr-auth.c)
- [AWS true-client-IP Function example](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/example_cloudfront_functions_add_true_client_ip_header_section.html)
- [3x-ui client traffic/IP controls, reviewed for comparison](https://github.com/MHSanaei/3x-ui/blob/main/docs/content/docs/en/config/clients.mdx)

No global source-IP firewall ban was copied: an address can be shared by NAT or
by unrelated accounts. No third-party panel code was copied into this project.

# v3 Security and Reliability Review

## Result

The v3 change replaces the former SSH-only/metadata-quota behavior with a validated multi-protocol control plane. CloudFront was reviewed first, followed by Xray, quota enforcement, dashboard/file handling, DNSTT, Telegram and installer hardening.

No production credentials were used or committed. External AWS/Cloudflare deployment remains an operator action.

## Main controls reviewed

| Area | Risk addressed | v3 control |
|---|---|---|
| CloudFront origin | Distribution bypass or mismatched routes | Separate `/cloudfront/*` routes, a 24-128 character custom origin header, rejection of that header on non-CDN routes, and exact panel TLS-origin matching |
| CloudFront caching/headers | Cached tunnel handshakes or missing Upgrade headers | AWS managed `CachingDisabled` and `AllViewerExceptHostHeader` policies |
| CDN secret storage | Local disclosure | CDN state and generated Nginx file are `0600 root:root`; status output redacts the value |
| Plaintext Xray | VLESS/Trojan credential exposure | Xray paths exist only in the Nginx TLS server block |
| Xray exposure | Bypass of TLS/Nginx | Protocol inbounds and Stats API bind to `127.0.0.1` only |
| Xray config corruption | Service outage | Candidate config is validated by Xray, atomically installed and rolled back on restart failure |
| Client config drift | Parser-valid server but broken clients | Stable Xray `clients` plus `vnext`/`servers` schema, exercised through live SOCKS/WebSocket traffic |
| Quota accuracy | False or duplicate accounting after partial persistence | Current JSON and legacy StatsService parsing, real filter/reset CLI flags, plus an idempotent on-disk replay journal |
| Quota bypass | One protocol remains active | One statistics identity aggregates VMess/VLESS/Trojan; over-limit users are excluded from every inbound |
| Time expiry | SSH expires but Xray continues | Linux account expiry plus one-minute Xray expiry reconciliation |
| Dashboard compromise | Direct root HTTP service | Loopback-only unprivileged dashboard using a restricted UNIX-socket command role |
| Dashboard auth | Password/session/CSRF attacks | PBKDF2, signed expiry, secure cookie, CSRF, CSP and throttling |
| Export traversal | Arbitrary root file read/delete | Validated username/fixed export root/strict filename regex/safe regular-file checks |
| Proprietary app claims | Non-working fake files | Explicit open JSON exports; no claim of proprietary locking/encryption |
| DNSTT supply chain | Building old or mutable source | Fixed upstream reliability commit and checksum-pinned Go toolchain |
| DNSTT privilege | Root network daemon | Dedicated user with `CAP_NET_BIND_SERVICE` only |
| DNSTT target | Arbitrary internal pivot | Target host is fixed to `127.0.0.1`; target port is validated |
| UDP/53 conflict | Breaking the VPS resolver | Exact/wildcard listener conflict detection; unrelated loopback resolver is allowed |
| Telegram file flow | Bot reading arbitrary files | Bot receives only daemon-approved export names/content and validates multipart filenames again |
| Peer privilege | Network daemons or panel clients calling unintended root operations | Client-only socket group, `SO_PEERCRED`, separate command allow-lists, and bot parameter restrictions |
| Installer downloads | Mutable/unverified binaries | Pinned per-architecture SHA-256 for Xray and Go; fixed DNSTT commit |
| DNSTT key rotation | New config fails after old key is destroyed | Temporary key generation plus key/config rollback on restart failure |

## Runtime validation completed

- Python compilation for every source module
- Bash syntax for installer, menu and scripts
- JavaScript syntax for the dashboard
- Dependency-free AST/secret audit
- Full unit suite covering validation, protocol/CDN/export behavior, usage
  journaling, DNSTT rollback, dashboard routing and client permissions
- CloudFormation validation with `cfn-lint`
- systemd unit verification (the local checker reports only the expected missing installed Xray path before installation)
- Xray v26.3.27 stable server config validation
- Xray v26.3.27 stable VMess/VLESS/Trojan client config validation
- Live VMess WebSocket → SOCKS → HTTP request
- Live VLESS WebSocket → SOCKS → HTTP request
- Live Trojan WebSocket → SOCKS → HTTP request
- Live Xray Stats API query/reset
- DNSTT v1.20260501.0 server/client build and key generation
- Live encrypted DNSTT 8192-byte echo stream

The live Xray test also confirmed the production private-address protection. Its first loopback request was blocked by Xray's server-side Freedom safety policy; the test retry allowed only its exact temporary loopback target. Production keeps the private/reserved block enabled.

## Residual and environment-dependent risks

1. CloudFront deployment, AWS permissions, public DNS and CDN propagation require the operator's accounts and cannot be proven by offline repository tests.
2. A root daemon is necessary for account, Nginx, certificate and service administration.
   Its unit permits `/etc` writes because Linux shadow tools create transient sibling lock files; application allow-lists and validation remain the primary mutation boundary.
3. A fully compromised bot can invoke the finite bot command role; Telegram Super Admin checks live in bot logic.
4. SSH/DNSTT byte quotas are not implemented. Their expiry and SSH session limits are enforced, but only Xray bytes count toward the data limit.
5. VMess, Trojan and WebSocket are deprecated upstream. VLESS should be preferred for new profiles.
6. NetMod/DarkTunnel locked formats are proprietary. The project provides open profiles rather than pretending to produce undocumented encrypted files.

## Deployment acceptance checks

On the target VPS, complete these checks before distributing profiles:

```bash
nginx -t
xray run -test -config /etc/abdulbasit/xray/config.json
abdulbasit-security-check
abdulbasit-panelctl status
```

For CloudFront, additionally verify the distribution is deployed, `/healthz` works through its generated hostname, and an imported profile can reach an authorized test destination.

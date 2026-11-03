# CloudFront + Dropbear delivery — v3.4

CloudFront is an optional **AWS WebSocket delivery route** for the existing VPS.
It is not Cloudflare Workers, a replacement SSH server, or a universal speed boost.
The implementation was compared with public GitHub projects and AWS documentation;
see [research decisions](CLOUDFRONT_RESEARCH.md). AWS account access and usage charges
are the operator's responsibility. The panel does not receive AWS access keys.

## What is supported

| Transport | CloudFront path | Client exports |
|---|---|---|
| VLESS WS/TLS | `/cloudfront/vless` | URI, QR, Xray JSON, TXT, ZIP, sing-box, Mihomo, subscription |
| VMess WS/TLS | `/cloudfront/vmess` | Same formats |
| Trojan WS/TLS | `/cloudfront/trojan` | Same formats, including `trojan://` |
| Dropbear SSH over binary RFC6455 | `/cloudfront/ssh/ws` | WSS URL; your SSH client still authenticates and verifies the SSH host key |
| Origin health | `/cloudfront/health` | TLS/HTTP diagnostic |

Direct profiles and `/ssh/ws` remain available. Raw `/ssh/raw`, XHTTP, REALITY,
admin pages and subscriptions are not served through the distribution. Subscription
URLs stay on your origin domain; `?route=cloudfront` selects edge addresses inside
the returned profiles. Do not rewrite the subscription URL to the distribution.
This phase supports the AWS-generated `d….cloudfront.net` hostname, not custom
CloudFront aliases/ACM certificate management. Bunny is not part of this release.

## Setup from the dashboard

1. Install/update this repository normally. Set **DNS & SSL** to a public origin
   hostname whose A/AAAA records point directly to the VPS. Obtain a valid public
   certificate. Origin port 443 must be reachable by CloudFront; don't put another
   CDN in front of this origin hostname.
2. Enable Xray and create a profile for the protocols you need. Dropbear and the
   WS bridge must be running for SSH.
3. Open **CloudFront**, leave Distribution hostname blank, choose edge coverage,
   and **Prepare / save CloudFront**. This installs secret-guarded TLS routes.
4. Download **Private AWS setup ZIP**. It contains a CloudFormation template and
   `parameters.private.json` with a random origin secret. Keep the ZIP private,
   do not commit it, and restrict its permissions when unpacking. `NoEcho` masks
   the CloudFormation parameter; AWS principals allowed to read distribution
   configuration can still retrieve custom origin headers.
5. In a terminal with your own configured AWS CLI, create the stack using the
   template and parameters files. Use a short stack name (for example `noway-ws`)
   because CloudFront function names have a length limit.

```bash
umask 077
unzip NOWAY-cloudfront-private.zip -d noway-cloudfront
cd noway-cloudfront
aws cloudformation create-stack --stack-name noway-ws --template-body file://cloudfront.json --parameters file://parameters.private.json
aws cloudformation wait stack-create-complete --stack-name noway-ws
aws cloudformation describe-stacks --stack-name noway-ws --query 'Stacks[0].Outputs'
```

6. Wait for the distribution status to become **Deployed**. Paste its
   `DistributionDomain` output into the panel and save.
7. Run **Check TLS & WebSocket routes**. It verifies the public certificate,
   CloudFront response headers, origin health and four RFC6455 handshakes. A
   failure in any selected backend is reported, not silently counted as success.
   Even a passing check does **not** verify an account login, sustained traffic,
   quotas, UDP support in your client, or WAN speed.
8. Open a profile's **Export** dialog, select **CloudFront**, then import its link
   or JSON into a compatible client. Test an actual login and file transfer. Test
   the same destination through Direct and CloudFront from the same client before
   deciding which route is faster. Use application TLS/SSH for end-to-end privacy:
   AWS terminates viewer TLS and establishes a separate TLS connection to origin.

CloudFormation includes disabled caching, a narrow WebSocket header policy,
HTTPS on both hops, a path allowlist at the edge and no forwarding of viewer Host,
cookies or Authorization. CloudFront supplies the origin Host and secret header.
The origin is independently guarded, including denial of secret-bearing requests
to `/panel/` and other non-CDN paths. The direct routes are still intentionally
available, so this is not a claim that the VPS IP is hidden or inaccessible.

## CLI equivalents

```bash
sudo abdulbasit-panelctl cloudfront-enable
sudo abdulbasit-panelctl cloudfront-setup --output /root/NOWAY-cloudfront-private.zip
sudo abdulbasit-panelctl cloudfront-enable --endpoint d123example.cloudfront.net
sudo abdulbasit-panelctl cloudfront-check
sudo abdulbasit-panelctl xray-link YOUR_PROFILE --protocol trojan --route cloudfront
sudo abdulbasit-panelctl xray-export YOUR_PROFILE --route cloudfront --zip /root/client-private.zip
sudo abdulbasit-panelctl cloudfront-status
```

Replace `d123example.cloudfront.net` with your own distribution output, and the
profile name with an existing eligible account. The setup ZIP is created with
mode 0600 and exclusive creation; choose a new output path if it already exists.

Dropbear URL: `wss://YOUR_DISTRIBUTION/cloudfront/ssh/ws`. Use a client that speaks
standard binary RFC6455, not an arbitrary HTTP payload/legacy raw upgrade. The
bridge accepts the optional `binary` subprotocol. Enable SSH keepalives (about
25-30 seconds) and retain SSH host-key verification. Xray JSON exports include
25-second WS heartbeats; URI/client app keepalive support varies.

## Disable, update and recovery

```bash
sudo abdulbasit-panelctl cloudfront-disable
```

This disables origin routes and future CDN exports. It does **not** delete the
AWS stack or stop its charges. Existing upgraded connections can drain across a
Nginx graceful reload; to revoke an account immediately use the existing account
lock/delete workflow. Manage deletion of AWS resources in your AWS account.

Origin domain changes are blocked while CloudFront is enabled. Disable first,
change DNS/certificate, re-enable, download fresh setup parameters, and update the
stack before reconnecting clients. Preparing again preserves the secret. To rotate
it after exposure, disable routes, stop the panel daemon, replace only the `secret`
field in `/etc/abdulbasit/cloudfront.json` with a newly generated 32-byte URL-safe
random token, retain root:root/0600, restart the daemon, re-enable and update the
CloudFormation stack with the freshly downloaded parameters. Rotation requires a
coordinated AWS update and can interrupt tunnels; it is not performed implicitly.

Nginx validation/reload failure restores the prior managed config and CloudFront
settings. Both the settings file and managed Nginx config are root-only (0600).
The origin secret is excluded from dashboard state, normal exports, subscriptions,
and Xray backups. Back up the private CloudFront config separately if needed.

## Troubleshooting

| Result | Check |
|---|---|
| 403 on a direct `/cloudfront/*` request | Expected without the distribution's private origin header |
| 403 through the distribution | Correct stack parameters/secret; exact allowed path; HTTPS viewer policy |
| 400 during WS upgrade | RFC6455 client, `Sec-WebSocket-Key`/`Version` forwarded, HTTP/1.1, no raw payload mode |
| 502/504 | Public origin DNS, trusted origin certificate matching its hostname, firewall 443, backend service/listener |
| Health passes but a tunnel fails | Enable its backend; verify account expiry/quota/credentials; inspect panel diagnostics |
| Idle disconnect | Client SSH/WS keepalives and reconnect behavior; intermediary timeout still applies |
| All users appear under an edge IP | Expected: this release records the TCP edge peer and does not trust viewer-supplied XFF as identity |
| Lower speed than direct | Compare RTT, loss, CPU, client location, origin region and congestion; retain direct as an option |

## Verification and performance scope

`tests/test_cloudfront.py` covers lifecycle, secret isolation, export/subscription
routing, revoked tokens, hostname validation, rollback and public-only probes.
`tests/test_nginx.py` runs real secret/header/path-denial checks. Native Xray and
Dropbear tests add a **local two-hop TLS edge simulation** with origin certificate
verification and CloudFront-like Host/header behavior. Real Xray clients exercise
VLESS/VMess/Trojan TCP and UDP payloads from JSON and decoded URIs; native Dropbear
checks wrong-key rejection, host keys, 4 MiB forwarding, and denied shell/reverse
forwarding. These are not live AWS distribution tests. CloudFormation is checked
by `cfn-lint`; acceptance by an actual AWS account still requires deployment.

The bridge now uses 64 KiB reads and TCP_NODELAY on its TCP sockets. Bounded
queues, message sizes, connection slots, SSH encryption and authentication remain
in place. Dropbear's existing 128 KiB receive window and keepalives are retained;
blindly expanding windows for every VPS would increase memory consumption.

Reproduce the isolated bridge comparison (test dependencies: wsproto, websockets):

```bash
python scripts/benchmark-ws-bridge.py --rounds 5 --mib 4
```

The script alternates the previous 16 KiB/default-Nagle behavior with the new
64 KiB/TCP_NODELAY profile, checks a SHA-256 digest of every returned payload,
and reports samples and medians. See [recorded result](cloudfront-bridge-benchmark.json).
It measures loopback bridge overhead, excluding SSH encryption, TLS, AWS and WAN;
it cannot establish the fastest provider or guarantee a subscriber's Mbps.

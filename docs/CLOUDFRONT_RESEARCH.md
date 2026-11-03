# CloudFront / SSH research decisions — 2026-11-02

Public GitHub searches covered CloudFront WebSocket/VLESS deployments, AWS
samples, Xray transport examples, Dropbear and maintained TCP/WS bridges. This is
a bounded comparison, not a claim to have inspected every repository on GitHub.
Existing repo research and the superseded PR #2 were considered alongside these
external sources. No external project's code was vendored into this change.

| Primary source | Relevant finding / decision |
|---|---|
| [XTLS/Xray-examples — VLESS-WSS-Nginx](https://github.com/XTLS/Xray-examples/blob/main/VLESS-WSS-Nginx/nginx.conf) | Loopback core behind TLS Nginx with explicit Upgrade/HTTP1.1. Keep our credential/rollback system; do not copy obsolete `ssl on`, five-day timeouts or blindly trust appended XFF. Reviewed blob `97f443532af9d01df54f42e7f5633e2d2077074f`. |
| [XTLS/Xray-docs-next — WebSocket](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/websocket.md) | Path/Host and heartbeat settings inform compatible exports. CloudFront gets WS, not an unverified claim of XHTTP/REALITY support. |
| [AWS private WebSocket agent sample](https://github.com/aws-samples/sample-private-ai-agent-websocket-vpc-origins-opensearch-nextgen) | Separate WS routing and disabled caching; periodic keepalives. Its VPC/ALB/AI infrastructure and broad WAF exceptions are not needed for this VPS. README blob `e7ad9604ed6fa8e4dec635dbd3361cacbf44ce52`. |
| [aws/aws-cdk — CloudFront origins](https://github.com/aws/aws-cdk/tree/main/packages/aws-cdk-lib/aws-cloudfront-origins) | Correct origin Host/TLS behavior. Use a narrow documented origin request policy rather than forwarding admin cookies/all viewer headers. |
| [MotherofallVPNs/MoaV](https://github.com/MotherofallVPNs/MoaV), [published troubleshooting](https://moav.sh/docs/TROUBLESHOOTING/) | CDN-aware troubleshooting and distinguishing standard WS from raw HTTP Upgrade. Keep TLS on our origin hop rather than adopting public plaintext origin examples. Documentation/release comparison; not a full code audit. |
| [mkj/dropbear — receive-window defaults](https://github.com/mkj/dropbear/blob/main/src/default_options.h), [manual](https://github.com/mkj/dropbear/blob/main/manpages/dropbear.8) | Window size trades memory for high-RTT throughput. Retain our 128 KiB window, key authentication, verified host keys and keepalives; do not weaken crypto in pursuit of a speed label. |
| [novnc/websockify](https://github.com/novnc/websockify) | RFC6455 binary-to-TCP model; maintained independent implementation for comparison. Do not paste its LGPL code into this repository. |
| [erebe/wstunnel](https://github.com/erebe/wstunnel) | Restricted destinations, keepalive and throughput measurement practices. Our bridge keeps a fixed local Dropbear destination, rather than exposing arbitrary network forwarding before SSH authentication. |
| [python-hyper/wsproto](https://github.com/python-hyper/wsproto) | Keep the existing maintained framing parser instead of handwritten masking/fragmentation. Backpressure and memory limits remain in our adapter. |
| [vi/websocat](https://github.com/vi/websocat) | Standard binary WS client tooling is a useful interoperable client model; do not imply a raw Upgrade client is CloudFront-compatible. |

Projects named `cf-*` were not assumed to use AWS: several search results implement
Cloudflare Workers instead. `bugfloyd/cloudfront-ws-vless` appeared in search but
its source was not retrievable in this session, so no implementation claims or
code reuse are based on it. Examples claiming a provider is always fastest were
not treated as benchmarks.

The implementation is original glue around existing panel modules and documented
AWS resource schemas. Protocol/configuration patterns are attributed here; external
snippets were not copied. Xray examples are CC-BY-SA and websockify is LGPL; those
licenses are another reason not to paste whole modules/configurations blindly.

## AWS documentation checked

- [WebSocket requirements and recommended headers](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-working-with.websockets.html): RFC6455, HTTP/1.1, forwarded key/version and related headers.
- [Origin custom headers](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/add-origin-custom-headers.html): overwrite viewer values and use a private origin verification header.
- [Origin request policies](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-managed-origin-request-policies.html): origin Host behavior; our narrower policy excludes cookies and Authorization.
- [Request/response behavior](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html): upgrade and forwarding behavior; do not interpret arbitrary viewer XFF as authenticated identity.

Client links contain only account credentials and public endpoint/path settings,
never the CloudFront origin secret. This resolves the practical integration without
replacing the existing panel with another GitHub project's UI or installer.

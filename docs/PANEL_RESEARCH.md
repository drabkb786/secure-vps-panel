# GitHub panel research and implemented upgrade

Reviewed on 27 October 2026 (Asia/Karachi). This is a bounded review of 10 relevant panels/installers plus 2 upstream reference repositories, not a claim to have audited every VPS repository on GitHub. Discovery used GitHub repository search and web search; each repository's README/metadata was read. Selected subscription and recovery source/docs were sampled separately. No external panel installer was executed.

## Comparison

| Repository | Snapshot / license | Relevant capabilities | Decision for NOWAY |
|---|---|---|---|
| [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) | 2026-10-25 · GPL-3.0 | XHTTP, subscriptions, QR sharing, quotas and multi-node management | Adopt live subscriptions, QR and an optional XHTTP transport; defer multi-node and traffic quotas until accounting exists. |
| [Gozargah/Marzban](https://github.com/Gozargah/Marzban) | 2026-10-14 · AGPL-3.0 | Multiple client subscription formats, expiry and backup workflow | Adopt client format adapters and a scoped backup/restore workflow. |
| [hiddify/Hiddify-Manager](https://github.com/hiddify/Hiddify-Manager) | 2026-10-26 · GPL-3.0 | Multiple cores, user limits and automatic backups | Keep the current Xray core; add recovery backups without installing another panel or core. |
| [remnawave/panel](https://github.com/remnawave/panel) | 2026-10-22 · AGPL-3.0 | Installation/documentation hub; separate subscription-page deployment | Keep subscription serving separate from browser authentication while retaining an allow-listed daemon API. |
| [marzneshin/marzneshin](https://github.com/marzneshin/marzneshin) | 2025-10-04 · AGPL-3.0 | Distributed nodes, subscriptions, QR and periodic traffic limits | Adopt sharing ergonomics; defer distributed management. Last push is older than the other sampled active panels. |
| [alireza0/s-ui](https://github.com/alireza0/s-ui) | 2026-10-25 · GPL-3.0 | sing-box backend, link/JSON/Clash subscription formats | Add a documented sing-box client export; do not replace the server engine. |
| [alireza0/x-ui](https://github.com/alireza0/x-ui) | 2026-10-24 · GPL-3.0 | Client monitoring, first-use expiry, IP limits and bot backups | Keep fixed-date expiry and truthful limits; do not claim bandwidth/IP enforcement without a backend. |
| [PasarGuard/panel](https://github.com/PasarGuard/panel) | 2026-10-26 · AGPL-3.0 | Subscription formats, QR, multi-node and HWID/device management | Adopt client sharing/export ideas; defer device identity and multi-node infrastructure. |
| [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) | 2026-10-26 · AGPL-3.0 | Multi-core deployment scripts and modern transport presets | Use upstream protocol documentation and tests instead of importing a second installer. |
| [HamedAp/ShahanPanel](https://github.com/HamedAp/ShahanPanel) | 2026-10-25 · MIT | SSH management, QR, database backup/restore | Adopt recovery ergonomics while explicitly limiting the new backup to Xray accounts/settings. |
| [XTLS/Xray-examples](https://github.com/XTLS/Xray-examples) | 2026-09-16 · CC-BY-SA-4.0 | Protocol deployment examples | Reference transport arrangements; write and test original configs rather than copying an installer. |
| [XTLS/Xray-core](https://github.com/XTLS/Xray-core) | 2026-10-26 · MPL-2.0 | Protocol engine and configuration implementation | Validate all generated configs and the new XHTTP route with the pinned real core. |

Dates above are GitHub's `pushed_at` metadata at retrieval, not a security endorsement, release promise or performance benchmark. License identifiers are metadata; the sampled panel code was not copied into NOWAY.

## Features implemented from the comparison

1. **Live subscription URLs:** per-profile bearer URLs with only token digests stored, rotation/revocation, expiry/disable checks, supported format selection, bounded public request rates and request-log suppression on the sensitive URL route.
2. **Client format exports:** native sing-box JSON and Mihomo/Clash.Meta-compatible configuration in addition to existing Xray JSON, URIs and ZIPs. These adapters export the WS/TLS profiles; the optional XHTTP variant is included in Xray/URI output only.
3. **Local QR sharing:** QR images are generated in the browser for individual links and subscription URLs, without sending credentials to a third-party QR service.
4. **Scoped recovery:** authenticated private Xray backup download and root-CLI restore; strict schema/credential validation, pre-restore recovery copy and rollback. OS users/passwords, TLS keys and admin/bot credentials are deliberately outside this backup format.
5. **Optional VLESS XHTTP:** opt-in loopback listener with TLS/HTTP2 through Nginx, explicit ALPN, streaming proxy settings and a separate import variant; existing WS profiles remain available.

## Selected source/doc samples

- [MHSanaei/3x-ui: docs/content/docs/en/operations/backup-restore.mdx](https://github.com/MHSanaei/3x-ui/blob/main/docs/content/docs/en/operations/backup-restore.mdx) — blob `e73032fe0be01661bc87aea8b052d3b0e65f28dd`.
- [Gozargah/Marzban: app/routers/subscription.py](https://github.com/Gozargah/Marzban/blob/master/app/routers/subscription.py) — blob `a75525209f5286fbaff8a41f9f2c1013f88945bb`.
- [PasarGuard/panel: app/routers/dependencies/subscription.py](https://github.com/PasarGuard/panel/blob/main/app/routers/dependencies/subscription.py) — blob `1aee9487f3ca700e3d6f774c8379768d14251ea9`.
- [remnawave/panel: docs/install/subscription-page/bundled.md](https://github.com/remnawave/panel/blob/main/docs/install/subscription-page/bundled.md) — blob `02e679c14a448932de9abfb0ea2b3eade50c4a2b`.

## README snapshots

- [MHSanaei/3x-ui README](https://github.com/MHSanaei/3x-ui/blob/main/README.md) — blob `5465a5d5b5fbc402456da30967a70ecfd4fbd62e`.
- [Gozargah/Marzban README](https://github.com/Gozargah/Marzban/blob/master/README.md) — blob `e08a332be44dc7c8fbb0b923388ee08c6c70573f`.
- [hiddify/Hiddify-Manager README](https://github.com/hiddify/Hiddify-Manager/blob/dev/README.md) — blob `a675dda0333aba0d9e34af1ea1a2eee02b71b742`.
- [remnawave/panel README](https://github.com/remnawave/panel/blob/main/README.md) — blob `21f9d1fea406203d5ef507debe208416521cecf7`.
- [marzneshin/marzneshin README](https://github.com/marzneshin/marzneshin/blob/master/README.md) — blob `72484a6d2325edbd2cba06180fc4292e457fed69`.
- [alireza0/s-ui README](https://github.com/alireza0/s-ui/blob/main/README.md) — blob `7ca6e78e4c2d8b0e72cf1813dfa453cd048180d9`.
- [alireza0/x-ui README](https://github.com/alireza0/x-ui/blob/main/README.md) — blob `986804ead1c7cc5cf1d9e4f3ef16d04161cb0944`.
- [PasarGuard/panel README](https://github.com/PasarGuard/panel/blob/main/README.md) — blob `bd93e4e663ea3b6e9872b8466478896c71e98a0f`.
- [mack-a/v2ray-agent README](https://github.com/mack-a/v2ray-agent/blob/master/README.md) — blob `8143eda9fc966faad70a2637309730c65add6755`.
- [HamedAp/ShahanPanel README](https://github.com/HamedAp/ShahanPanel/blob/main/README.md) — blob `a4153c9253d0a03d4e3b2a09c691b300dd16cd96`.
- [XTLS/Xray-examples README](https://github.com/XTLS/Xray-examples/blob/main/README.md) — blob `5f4ce5b5d2a8f2ca1de592a1766d50c37162d502`.
- [XTLS/Xray-core README](https://github.com/XTLS/Xray-core/blob/main/README.md) — blob `d52ca9bb34716dcbb39f0e656758fd98ab9c15ef`.

## Third-party asset

The only newly vendored third-party implementation is [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) at commit `83b7e8fe3fddd3b0368dbafd6ce56995bd25e3c8`, under its MIT license. Its license is retained in `src/web/qr.LICENSE.txt`. Panel adapters, subscriptions, backup validation and integration code are original additions.

## Deferred work

Enforced byte quotas/live per-account usage, live gRPC config application, multi-node orchestration, REALITY presets, first-use expiry and external DNS-provider editing require separate integration and tests. They are not represented as completed features. Local compatibility checks cannot establish public connectivity on an untested VPS or client network.

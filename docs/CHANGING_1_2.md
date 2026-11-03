# Changing #1 and #2 — implementation and validation

This release prioritizes OpenSSH migration, interruption reduction, truthful
accounting, and usable client exports. A successful HTTP upgrade is not proof of
SSH authentication, forwarding, or sustained performance.

## Work sequence

1. Dedicated OpenSSH tunnel service, migration rollback, verified session/IP
   attribution, and managed SSH passwords of 3–128 characters.
2. Pinned Xray update, checked binary replacement with rollback, and live account
   additions without restarting unrelated connections. Revocations must retain
   active-connection enforcement; API credential removal alone is insufficient.
3. SSH transport exports in CLI, web and Telegram; real RFC6455 client adapter;
   explicit direct, raw, WSS, CDN and SlowDNS compatibility.
4. Bunny route configuration, CDN identity and connection-limit handling, XHTTP
   delivery, SlowDNS parent delegation diagnostics and configurable MTU.
5. Bounded concurrent diagnostics, optional reversible kernel tuning, native
   integration tests and repeatable throughput/stability measurements.

## Upstream research and reuse

* OpenSSH Portable: https://github.com/openssh/openssh-portable — use the OS
  maintained binary and documented forwarding controls; never replace admin sshd.
* Xray v26.10.31: https://github.com/XTLS/Xray-core/tree/v26.10.31 — official
  binary and HandlerService CLI (`adu`/`rmu`). Check the reported success count:
  the CLI can exit successfully even if individual user operations failed.
* 3x-ui: https://github.com/MHSanaei/3x-ui — runtime account deltas and fallback
  reconciliation, including the need to disconnect existing revoked sessions.
* Marzban: https://github.com/Gozargah/Marzban — bounded runtime operations and
  batched accounting; retain our atomic integer-byte checkpoints.
* Hiddify: https://github.com/hiddify/hiddify-manager — separate transport and
  identity layers; do not assume deprecated SSH files are current architecture.
* dnstm-setup: https://github.com/SamNet-dev/dnstm-setup (MIT) — adjustable DNSTT
  MTU and backend readiness, rather than a universal advertised speed.
* NevermoreSSH/hop: https://github.com/NevermoreSSH/hop — legacy raw payload
  compatibility reference only. Its Python 2 proxy is not imported.
* wsproto (MIT): https://github.com/python-hyper/wsproto — maintained RFC6455
  parser already used by the bridge; preserve masking and frame validation.

The integration uses upstream binaries/libraries with their existing licenses.
GPL/AGPL panel source is design research, not pasted into this differently
structured Python application. New integration code is original. No unlicensed
autoscript, credential store or opaque executable is imported.

## Deliberate constraints

Do not return fake 101 responses to malformed requests, trust arbitrary forwarded
IP headers, disable certificate checks, or route unrelated SNI names. CDN WSS
requires real WebSocket framing. Direct REALITY cannot traverse an HTTP CDN.
Keep SSH byte quotas unavailable until a trustworthy per-account meter exists.
Five-second enforcement is sampled, not a hard instantaneous limit. Preserve
accurate GB/GiB labels and crash-loss disclosure. Do not replace Ubuntu Python or
OpenSSL merely to change their upstream version strings.

Public VPS, Bunny and AWS end-to-end measurements require deployment and a client
on the user's network. Local/CI throughput does not predict mobile/CDN speed.

# v3.1 validation

Checked in the development environment on 27 October 2026 (Asia/Karachi).

## Passing checks

- **104 Python tests and 2 JavaScript regression tests**, including all optional
  real Xray, Nginx and client-parser checks, passed locally with no skips.
- Python compilation, JavaScript syntax, Bash syntax, the repository static audit
  and `git diff --check` passed.
- Official **Xray 26.10.21** was downloaded from XTLS releases and verified against
  its published SHA256 digest before execution.
- Real Xray accepted the generated server configs, an empty-account config, all
  three WS client configs and the additional VLESS XHTTP client config.
- A local end-to-end test exercised **each of VLESS, VMess and Trojan** using real
  Xray server/client processes: loopback SOCKS → verified TLS/WebSocket bridge →
  Xray → a local HTTP fixture. TLS verification stayed enabled; a test CA was
  trusted explicitly. Only the test config allowed that fixture's loopback port;
  production routing continues to block private targets.
- The transport test also independently decoded each generated import URI, built
  a client config from its actual fields, and obtained the same HTTP response.
  This covers the links themselves, not only separately generated client JSON.
- An isolated **Ubuntu Nginx 1.24.0** binary accepted the generated HTTP and TLS
  sites. The tests substituted fixture certificate/log/temp paths and loopback
  high ports; route content and upstream wiring were retained.
- A separate end-to-end test independently imported the generated **VLESS XHTTP
  URI** into real Xray and retrieved the HTTP fixture through real Nginx
  TLS/HTTP2 and the XHTTP backend. TLS verification stayed enabled. Explicit
  `h2` ALPN and Nginx HTTP/2 were required for this path.
- Official **sing-box 1.14.4** and **Mihomo 1.19.33** accepted the generated WS/TLS
  native client exports. The test downloader pins versions and verifies SHA256:
  sing-box `699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968`,
  Mihomo `386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6`.
  Parser acceptance is not a claim of end-to-end traffic testing with those clients.
- Four QR tests render the vendored browser generator's GIF output and decode it
  with an independent QR decoder. VLESS, Trojan, live subscription and actual
  generated VMess values round-trip exactly.
- Browser QA checked the login design, overview, Xray profile form and export
  dialog, local Trojan QR display, subscription rotation/one-time URL and format
  controls, backup scope/restore instructions, DNS/SSL and diagnostics. This used a clearly
  labelled example-data backend, not a connected VPS. No preview bypass is shipped
  in the application source. The screenshot is a UI preview, not live telemetry.
- Authentication coverage includes unauthenticated export denial, same-origin and
  CSRF rejection, login rate limiting, password hashing/rotation, cookie flags,
  logout revocation and idle session expiry.
- Account/config regressions cover failed config tests, failed restarts, rollback,
  expiry removal, renewal, disable-on-boot markers, secret-free profile lists,
  DNS validation and exported protocol credentials.
- Direct-link regressions cover plain CLI output without JSON wrapping, isolated
  warning output, per-protocol TXT downloads, unavailable-protocol errors,
  Trojan password percent encoding, offline-core warnings and authorized Telegram
  link retrieval. Telegram tests send no real messages.
- Repeated Enable now restarts an already-configured but stopped core. Successful
  systemctl startup is followed by listener readiness checks, with rollback if
  they fail. A failed dashboard refresh no longer reports an already-saved account
  creation as a failed mutation.
- A 4 MiB stream/half-close test verifies the SSH upgrade relay preserves data
  under socket backpressure.
- Subscription tests cover hashed-only token storage, rotation/revoke, profile
  expiry/disable and engine-disable denial, dynamic formats, user-agent selection,
  no admin-cookie requirement, private-route logs and bounded public request rates.
- Recovery tests cover credential-preserving restore, domain preservation, private
  recovery copies, invalid/oversized input rejection, restart rollback, corrupt
  JSON recovery and root-only restore IPC. Corrupt account/settings stores fail
  closed during normal operations instead of silently becoming empty defaults.

## Reproduce

```bash
python -m pip install pytest zxing-cpp pillow numpy
```

```bash
python -m pytest -q
```

Tests requiring an external binary are skipped unless its path is supplied:

```bash
python scripts/fetch-test-clients.py --directory /tmp/noway-test-clients
```

```bash
XRAY_TEST_BINARY=/path/to/verified/xray NGINX_TEST_BINARY=/path/to/nginx SINGBOX_TEST_BINARY=/tmp/noway-test-clients/singbox MIHOMO_TEST_BINARY=/tmp/noway-test-clients/mihomo python -m pytest -q
```

```bash
python scripts/static-audit.py
```

```bash
python -m py_compile src/*.py scripts/fetch-test-clients.py
```

```bash
node --check src/web/app.js
```

```bash
node --test tests/test_web_client.js
```

```bash
bash -n install.sh menu.sh scripts/*.sh scripts/tunnel-shell
```

The GitHub workflow runs the base checks, installs the pinned verified Xray binary,
exercises WS and XHTTP transports, parses generated sites with the distro Nginx,
decodes QR output and validates exports using the pinned native clients.

## Still requires the actual VPS

The complete privileged installer, systemd lifecycle, Dropbear authentication on
the deployed OS, public certificate issuance/renewal, DNS propagation, provider
firewall, and connectivity from the user's client/device have **not** been verified
on a live VPS. A real Xray transport test does not establish network availability
from every provider or country.

The core reports deprecation notices for the requested legacy WS/VMess/Trojan
compatibility transports. They pass on the pinned release. Optional XHTTP passes
the local real-core/Nginx test; REALITY remains deferred. Traffic quota enforcement,
multi-node management and live per-account byte usage are not implemented.

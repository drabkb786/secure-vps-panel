# Validation

## v3.3 Dropbear checks — 2 November 2026 (Asia/Karachi)

- Added 30 Python cases for independent WebSocket transport, authenticated
  session attribution, process identity/signals and three native SSH routes.
- Local base suite: 150 passing cases, 12 optional native cases skipped. Both
  JavaScript regressions, compilation, Bash/JS syntax, static audit and whitespace
  checks pass. Native Xray/client/DNS stages remain configured in CI.
- The real-socket bridge suite round-trips 4 MiB with independent WebSocket
  framing, fragmentation, ping/pong and backpressure. It also checks protocol
  errors, message limits, header deadlines, worker saturation and raw compatibility.
- Official Dropbear 2026.94 is built unchanged from the upstream tarball, SHA256
  `e098034a843699200c8c977a991fff73159735bf795d5f72ef672c41a6b1ae81`.
  Local authentication reached upstream's privilege switch; this container
  rejects the required `initgroups` operation. Full direct/legacy/WSS native
  tests therefore run on the GitHub Ubuntu runner. They use temporary keys,
  verify SSH host keys and TLS, transfer 4 MiB per route and reject unauthorized
  keys, reverse forwarding and interactive command execution.
- No live VPS accounts, services, host keys, DNS, firewall or installer/rollback
  have been exercised. SSH quotas remain metadata; session attribution has the
  documented journal/parent-process limits in [DROPBEAR.md](DROPBEAR.md).

## v3.2 evidence

Checked in the development environment on 27 October 2026 (Asia/Karachi).

## Passing checks

- **132 Python tests and 2 JavaScript regression tests**, including all optional
  real Xray, Nginx and client-parser checks, are covered by the local and GitHub native checks. The final UNIX-socket
  transport checks require a host that permits AF_UNIX; this development container
  rejects AF_UNIX socket creation with EPERM. Before the final socket isolation
  change, all 132 passed locally using the loopback statistics fixture.
- Python compilation, JavaScript syntax, Bash syntax, the repository static audit
  and `git diff --check` passed.
- Official **Xray 26.10.21** was downloaded from XTLS releases and verified against
  its published SHA256 digest before execution.
- Real Xray accepted the generated server configs, an empty-account config, all
  three WS client configs and the additional VLESS XHTTP client config.
- A local end-to-end test exercised **each of VLESS, VMess and Trojan** using real
  Xray server/client processes: loopback SOCKS → real Nginx TLS/WebSocket →
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
- All real gateway transport cases now also round-trip **UDP** through SOCKS5
  associations, verify native byte counters, and check authenticated IP reporting.
  Forged client forwarding headers are overwritten by Nginx; the core reports the
  controlled gateway address rather than the forged value.
- Official **dnstt v1.20260501.0** server/client binaries were built using official
  checksum-verified Go 1.27.3 and the public Go checksum database. A native test
  round-trips 6,600 bytes of TCP data through their UDP DNS tunnel and a local echo
  fixture. No real OS SSH account, public DNS delegation or carrier connection is
  involved in this test.
- New operations regressions cover exact trial expiry, persistent/idempotent
  payload counting, crash-between-writes recovery, sampled quota removal, usage
  reset/rollback, corrupt counter recovery, real versus observed IP labelling,
  log redaction, banner rollback, managed SSH locks, root maintenance isolation,
  CLI dispatch and DNS tunnel input/port/restart safeguards.
- Browser QA checks the new daily-action layout, trial form, quota editor,
  traffic refresh/IP distinction, operations controls, journal result modal,
  banner loading and UDP/SlowDNS forms using a labelled example-data backend.

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

Build the official dnstt test binaries using Go 1.27.3 with the public checksum
database, then include their paths for the native DNS test:

```bash
GOBIN=/tmp/noway-dnstt GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go install www.bamsoftware.com/git/dnstt.git/dnstt-server@v1.20260501.0 www.bamsoftware.com/git/dnstt.git/dnstt-client@v1.20260501.0
```

```bash
DNSTT_TEST_SERVER=/tmp/noway-dnstt/dnstt-server DNSTT_TEST_CLIENT=/tmp/noway-dnstt/dnstt-client python -m pytest -q tests/test_slowdns.py
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
exercises WS/XHTTP TCP/UDP and native statistics, parses generated sites with the
distro Nginx, decodes QR output, validates exports with pinned native clients and
builds/tests the official dnstt transport.

## Still requires the actual VPS

The complete privileged installer, systemd lifecycle/capabilities, Dropbear authentication on
the deployed OS, public certificate issuance/renewal, DNS propagation, provider
firewall, and connectivity from the user's client/device have **not** been verified
on a live VPS. Public UDP 53/NS delegation, cache/journal cleanup, reinstall and
uninstall were not executed on the user's server. A real transport test does not establish network availability
from every provider or country.

The core reports deprecation notices for the requested legacy WS/VMess/Trojan
compatibility transports. They pass on the pinned release. Optional XHTTP passes
the local real-core/Nginx test; REALITY and multi-node management remain deferred.
Xray usage/quota enforcement is sampled once per minute and can overshoot or lose
the unsampled tail on an unexpected core crash. SSH GB remains metadata.

# v3 validation

Checked in the development environment on 27 October 2026 (Asia/Karachi).

## Passing checks

- **52 tests**, including real Xray and Nginx checks, passed locally.
- Python compilation, JavaScript syntax, Bash syntax, the repository static audit
  and `git diff --check` passed.
- Official **Xray 26.10.21** was downloaded from XTLS releases and verified against
  its published SHA256 digest before execution.
- Real Xray accepted the generated server config, an empty-account config and all
  three client configs.
- A local end-to-end test exercised **each of VLESS, VMess and Trojan** using real
  Xray server/client processes: loopback SOCKS → verified TLS/WebSocket bridge →
  Xray → a local HTTP fixture. TLS verification stayed enabled; a test CA was
  trusted explicitly. Only the test config allowed that fixture's loopback port;
  production routing continues to block private targets.
- An isolated **Ubuntu Nginx 1.24.0** binary accepted the generated HTTP and TLS
  sites. The tests substituted fixture certificate/log/temp paths and loopback
  high ports; route content and upstream wiring were retained.
- Browser QA checked the login design, overview, Xray profile form and export
  dialog, DNS/SSL controls and diagnostic report rendering. This used a clearly
  labelled example-data backend, not a connected VPS. No preview bypass is shipped
  in the application source. The screenshot is a UI preview, not live telemetry.
- Authentication coverage includes unauthenticated export denial, same-origin and
  CSRF rejection, login rate limiting, password hashing/rotation, cookie flags,
  logout revocation and idle session expiry.
- Account/config regressions cover failed config tests, failed restarts, rollback,
  expiry removal, renewal, disable-on-boot markers, secret-free profile lists,
  DNS validation and exported protocol credentials.
- A 4 MiB stream/half-close test verifies the SSH upgrade relay preserves data
  under socket backpressure.

## Reproduce

```bash
python -m pip install pytest
```

```bash
python -m pytest -q
```

Tests requiring an external binary are skipped unless its path is supplied:

```bash
XRAY_TEST_BINARY=/path/to/verified/xray NGINX_TEST_BINARY=/path/to/nginx python -m pytest -q
```

```bash
python scripts/static-audit.py
```

```bash
python -m py_compile src/*.py
```

```bash
node --check src/web/app.js
```

```bash
bash -n install.sh menu.sh scripts/*.sh scripts/tunnel-shell
```

The GitHub workflow runs the base checks, installs the pinned verified Xray binary,
exercises real transports, and parses generated sites with the distro Nginx.

## Still requires the actual VPS

The complete privileged installer, systemd lifecycle, Dropbear authentication on
the deployed OS, public certificate issuance/renewal, DNS propagation, provider
firewall, and connectivity from the user's client/device have **not** been verified
on a live VPS. A real Xray transport test does not establish network availability
from every provider or country.

The core reports deprecation notices for the requested legacy WS/VMess/Trojan
compatibility transports. They pass on the pinned release; XHTTP/REALITY are a
separate roadmap phase. Traffic quota enforcement and live public subscription
URLs are not implemented.

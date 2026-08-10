from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cloudfront_template_has_websocket_policies_and_origin_guard() -> None:
    text = (ROOT / "infra" / "cloudfront-websocket.yml").read_text(encoding="utf-8")
    assert "X-AbdulBasit-Origin-Verify" in text
    assert "NoEcho: true" in text
    assert "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" in text
    assert "b689b0a8-53d0-40ab-baf2-68738e2966ac" in text
    assert "CloudFrontDefaultCertificate: true" in text
    assert "AllowedMethods: [GET, HEAD, OPTIONS]" in text


def test_systemd_services_are_unprivileged_where_possible() -> None:
    xray = (ROOT / "systemd" / "abdulbasit-xray.service").read_text(encoding="utf-8")
    dashboard = (ROOT / "systemd" / "abdulbasit-dashboard.service").read_text(
        encoding="utf-8"
    )
    dnstt = (ROOT / "systemd" / "abdulbasit-dnstt.service").read_text(encoding="utf-8")
    assert "User=abdulbasit-xray" in xray and "NoNewPrivileges=yes" in xray
    assert (
        "User=abdulbasit-dashboard" in dashboard
        and "IPAddressAllow=localhost" in dashboard
    )
    assert "User=abdulbasit-dnstt" in dnstt and "CAP_NET_BIND_SERVICE" in dnstt


def test_panel_socket_group_excludes_network_daemons() -> None:
    paneld_unit = (ROOT / "systemd" / "abdulbasit-paneld.service").read_text(
        encoding="utf-8"
    )
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "Group=abdulbasit-clients" in paneld_unit
    assert "ReadWritePaths=/etc " in paneld_unit
    assert "usermod -a -G abdulbasit-clients abdulbasit-bot" in installer
    assert "usermod -a -G abdulbasit-clients abdulbasit-dashboard" in installer
    assert "usermod -a -G abdulbasit-clients abdulbasit-xray" not in installer


def test_dnstt_installer_pins_fixed_upstream_and_verified_go_toolchain() -> None:
    text = (ROOT / "scripts" / "install-dnstt.sh").read_text(encoding="utf-8")
    assert "0c5c52a57d899c05428c116898941761a2ed83c2" in text
    assert 'GO_VERSION="1.26.5"' in text
    assert "sha256sum --check" in text
    assert "GOTOOLCHAIN=local" in text


def test_xray_installer_pins_release_checksums_per_architecture() -> None:
    text = (ROOT / "scripts" / "install-xray.sh").read_text(encoding="utf-8")
    assert 'XRAY_VERSION="v26.3.27"' in text
    assert "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae" in text
    assert "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c" in text
    assert "c7265ae13c63ca0241a037df4ef960ad37938c8a67d984cc08834b2cfdf5654b" in text

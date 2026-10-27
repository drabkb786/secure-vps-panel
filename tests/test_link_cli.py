import pytest

import panelctl


@pytest.fixture
def backend(monkeypatch):
    data = {"links": {"vless": "vless://fixture", "trojan": "trojan://fixture"}, "files": {"links.txt": "vless://fixture\ntrojan://fixture\n"}, "readiness": {"warnings": []}}
    monkeypatch.setattr(panelctl, "request", lambda command, **params: data)
    return data


@pytest.mark.parametrize("protocol", ["vless", "trojan"])
def test_single_direct_link_stdout_has_no_json_wrapping(backend, monkeypatch, capsys, protocol):
    monkeypatch.setattr("sys.argv", ["panelctl", "xray-link", "basit", "--protocol", protocol])
    assert panelctl.main() == 0
    out = capsys.readouterr()
    assert out.out == protocol + "://fixture\n" and out.err == ""


def test_all_links_and_offline_warnings_use_separate_streams(backend, monkeypatch, capsys):
    backend["readiness"]["warnings"] = ["Core is offline"]
    monkeypatch.setattr("sys.argv", ["panelctl", "xray-export", "basit", "--links"])
    assert panelctl.main() == 0
    out = capsys.readouterr()
    assert out.out == "vless://fixture\ntrojan://fixture\n"
    assert "Core is offline" in out.err


def test_unavailable_protocol_fails_instead_of_printing_a_fake_link(backend, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["panelctl", "xray-link", "basit", "--protocol", "vmess"])
    assert panelctl.main() == 1
    out = capsys.readouterr()
    assert not out.out and "not enabled" in out.err

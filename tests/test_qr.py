import base64
import io
import subprocess
from pathlib import Path

import pytest
from xray_manager import share_link

zxing = pytest.importorskip("zxingcpp")
np = pytest.importorskip("numpy")
Image = pytest.importorskip("PIL.Image")


@pytest.mark.parametrize("link", [
    "vless://00000000-0000-4000-8000-000000000001@vpn.example.com:443?type=ws&security=tls&path=%2Fvless",
    "trojan://fixture-password@vpn.example.com:443?security=tls&type=ws&path=%2Ftrojan",
    "https://vpn.example.com/panel/sub/" + "A" * 43,
    share_link("vmess", {"name": "qr_test", "uuid": "00000000-0000-4000-8000-000000000001"}, "vpn.example.com"),
])
def test_browser_qr_can_be_decoded_back_to_the_exact_link(link):
    root = Path(__file__).resolve().parents[1]
    script = "const qr=require('./src/web/qr.js'); const c=qr(0,'M'); c.addData(process.argv[1]); c.make(); process.stdout.write(c.createDataURL(4,16));"
    result = subprocess.run(["node", "-e", script, link], cwd=root, capture_output=True, text=True, check=True, timeout=10)
    raw = base64.b64decode(result.stdout.split(",", 1)[1])
    image = Image.open(io.BytesIO(raw)).convert("RGB")
    decoded = zxing.read_barcode(np.asarray(image))
    assert decoded is not None and decoded.text == link

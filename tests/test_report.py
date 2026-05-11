import io
import json

from rich.console import Console

from camscan.bluetooth import parse_bleak_results
from camscan.report import render_bluetooth, render_wifi, to_json
from camscan.wifi import parse_arp_scan

SAMPLE_ARP = """\
192.168.1.1\ta4:2b:b0:11:22:33\tNETGEAR
192.168.1.42\t28:57:be:00:11:22\tHikvision Digital Technology Co.,Ltd.
"""


def test_render_wifi_outputs_flag_for_camera():
    devices = parse_arp_scan(SAMPLE_ARP)
    buf = io.StringIO()
    console = Console(file=buf, width=200, force_terminal=False, color_system=None)
    render_wifi(console, devices)
    out = buf.getvalue()
    assert "CAM" in out
    assert "Hikvision" in out
    assert "28:57:BE:00:11:22" in out


def test_render_bluetooth_handles_empty_list():
    buf = io.StringIO()
    console = Console(file=buf, width=200, force_terminal=False, color_system=None)
    render_bluetooth(console, [])
    out = buf.getvalue()
    assert "Bluetooth scan" in out
    assert "0 device" in out


def test_to_json_includes_match_and_serializes_bytes():
    wifi = parse_arp_scan(SAMPLE_ARP)
    bt = parse_bleak_results(
        [
            {
                "mac": "28:57:BE:00:11:22",
                "name": "WyzeCam",
                "rssi": -42,
                "manufacturer_data": {76: b"\xde\xad"},
            }
        ]
    )
    payload = to_json(wifi=wifi, bluetooth=bt)
    text = json.dumps(payload)  # must be serializable
    assert "Hikvision" in text
    assert payload["bluetooth"][0]["manufacturer_data"]["76"] == "dead"
    assert payload["wifi"][1]["match"]["category"] == "ip-camera"

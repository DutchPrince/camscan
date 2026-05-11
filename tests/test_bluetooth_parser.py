from pathlib import Path

from camscan.bluetooth import parse_bleak_results, parse_bluetoothctl

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_bleak_results_flags_camera_macs():
    devices = parse_bleak_results(
        [
            {
                "mac": "28:57:BE:00:11:22",
                "name": "WyzeCam-V3",
                "rssi": -42,
                "manufacturer_data": {76: b"\x10\x06"},
            },
            {"mac": "11:22:33:44:55:66", "name": "Galaxy-Buds", "rssi": -67},
            {"mac": "2C:AA:8E:AB:CD:EF", "name": None, "rssi": -77},
        ]
    )
    flagged = [d for d in devices if d.is_flagged]
    assert {d.mac for d in flagged} == {"28:57:BE:00:11:22", "2C:AA:8E:AB:CD:EF"}

    hikvision = next(d for d in devices if d.mac == "28:57:BE:00:11:22")
    assert hikvision.rssi == -42
    assert 76 in hikvision.manufacturer_data


def test_parse_bleak_results_skips_rows_with_no_mac():
    devices = parse_bleak_results([{"name": "ghost", "rssi": -90}])
    assert devices == []


def test_parse_bluetoothctl_extracts_new_devices():
    text = (FIXTURES / "bluetoothctl_sample.txt").read_text(encoding="utf-8")
    devices = parse_bluetoothctl(text)
    macs = {d.mac for d in devices}
    assert "28:57:BE:DE:AD:01" in macs
    assert "2C:AA:8E:AB:CD:EF" in macs
    assert "11:22:33:44:55:66" in macs
    wyze = next(d for d in devices if d.mac == "28:57:BE:DE:AD:01")
    assert wyze.is_flagged
    assert wyze.name == "WyzeCam-V3"

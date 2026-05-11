from pathlib import Path

from camscan.wifi import _parse_arp_n, _parse_proc_arp, parse_arp_scan, parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_arp_scan_extracts_devices_and_flags_cameras():
    text = (FIXTURES / "arp_scan_sample.txt").read_text(encoding="utf-8")
    devices = parse_arp_scan(text)

    by_mac = {d.mac: d for d in devices}
    assert "28:57:BE:00:11:22" in by_mac
    assert "2C:AA:8E:AA:BB:CC" in by_mac
    assert "A4:2B:B0:11:22:33" in by_mac
    assert "F0:18:98:DE:AD:BE" in by_mac

    hikvision = by_mac["28:57:BE:00:11:22"]
    assert hikvision.is_flagged
    assert hikvision.ip == "192.168.1.42"
    assert hikvision.match is not None
    assert "Hikvision" in hikvision.match.vendor

    apple = by_mac["F0:18:98:DE:AD:BE"]
    assert not apple.is_flagged


def test_parse_nmap_xml_skips_down_hosts_and_classifies_cameras():
    text = (FIXTURES / "nmap_sn_sample.xml").read_text(encoding="utf-8")
    devices = parse_nmap_xml(text)

    macs = {d.mac for d in devices}
    assert "28:57:BE:00:11:22" in macs
    # The "down" host has no MAC so it should be omitted.
    assert len(devices) == 3

    hikvision = next(d for d in devices if d.mac == "28:57:BE:00:11:22")
    assert hikvision.is_flagged
    assert hikvision.ip == "192.168.1.42"


def test_parse_arp_scan_ignores_header_and_footer_lines():
    devices = parse_arp_scan(
        "Interface: wlan0, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff\n"
        "Starting arp-scan 1.9.7\n"
        "4 packets received by filter\n"
    )
    assert devices == []


_NMAP_NO_MAC = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.68.1" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.68.42" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_arp_cache_enriches_hosts_without_mac():
    arp = {"192.168.68.42": "28:57:BE:00:11:22"}
    devices = parse_nmap_xml(_NMAP_NO_MAC, arp_cache=arp)
    by_ip = {d.ip: d for d in devices}

    hikvision = by_ip["192.168.68.42"]
    assert hikvision.mac == "28:57:BE:00:11:22"
    assert hikvision.is_flagged

    router = by_ip["192.168.68.1"]
    assert router.mac == ""
    assert not router.is_flagged


def test_proc_net_arp_parser():
    sample = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.68.1     0x1         0x2         b0:a7:b9:ba:97:b0     *        wlan0\n"
        "192.168.68.42    0x1         0x2         28:57:be:00:11:22     *        wlan0\n"
        "192.168.68.99    0x1         0x0         00:00:00:00:00:00     *        wlan0\n"
    )
    parsed = _parse_proc_arp(sample)
    assert parsed == {
        "192.168.68.1": "B0:A7:B9:BA:97:B0",
        "192.168.68.42": "28:57:BE:00:11:22",
    }


def test_arp_n_parser():
    sample = (
        "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
        "192.168.68.1             ether   b0:a7:b9:ba:97:b0   C                     wlan0\n"
        "192.168.68.42            ether   28:57:be:00:11:22   C                     wlan0\n"
    )
    parsed = _parse_arp_n(sample)
    assert parsed["192.168.68.42"] == "28:57:BE:00:11:22"

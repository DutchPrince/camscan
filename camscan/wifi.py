"""Active LAN scanning — enumerate devices on the joined WiFi.

Tries `arp-scan` first (faster, more reliable), falls back to `nmap -sn`.
Parsers are pure functions and unit-tested with captured fixtures.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field

from camscan.oui import normalize, vendor_of
from camscan.runners import MissingBinaryError, RunResult, have, run
from camscan.vendors import CameraMatch, classify

_ARP_SCAN_LINE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9A-Fa-f:]{17})"
    r"(?:\s+(?P<vendor>.+))?$"
)


@dataclass(frozen=True)
class Device:
    """A network device discovered on the LAN."""

    mac: str
    ip: str | None = None
    vendor: str | None = None
    match: CameraMatch | None = None
    extras: dict[str, str] = field(default_factory=dict)

    @property
    def is_flagged(self) -> bool:
        return self.match is not None


def _enrich(mac: str, ip: str | None, vendor_hint: str | None) -> Device:
    mac_norm = normalize(mac)
    vendor = vendor_hint or vendor_of(mac_norm)
    return Device(mac=mac_norm, ip=ip, vendor=vendor, match=classify(mac_norm))


def parse_arp_scan(output: str) -> list[Device]:
    """Parse stdout of `arp-scan -l` (or `--interface=...`)."""
    devices: list[Device] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        m = _ARP_SCAN_LINE.match(line)
        if not m:
            continue
        vendor_text = (m.group("vendor") or "").strip() or None
        devices.append(_enrich(m.group("mac"), m.group("ip"), vendor_text))
    return _dedupe(devices)


def parse_nmap_xml(xml_text: str) -> list[Device]:
    """Parse stdout of `nmap -sn -oX -`."""
    root = ET.fromstring(xml_text)
    devices: list[Device] = []
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip: str | None = None
        mac: str | None = None
        vendor: str | None = None
        for addr in host.iter("address"):
            kind = addr.get("addrtype")
            if kind == "ipv4":
                ip = addr.get("addr")
            elif kind == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor") or None
        if not mac:
            continue
        devices.append(_enrich(mac, ip, vendor))
    return _dedupe(devices)


def _dedupe(devices: Iterable[Device]) -> list[Device]:
    seen: dict[str, Device] = {}
    for d in devices:
        existing = seen.get(d.mac)
        if existing is None or (existing.ip is None and d.ip is not None):
            seen[d.mac] = d
    return list(seen.values())


def active_scan(interface: str | None = None, *, timeout: float = 30.0) -> list[Device]:
    """Run an active LAN scan and return discovered devices.

    Tries `arp-scan` first; falls back to `nmap -sn` against the local /24
    derived from the routing table. Raises MissingBinaryError if neither
    binary is available.
    """
    if have("arp-scan"):
        cmd = ["arp-scan", "--localnet", "--quiet"]
        if interface:
            cmd += [f"--interface={interface}"]
        result = run(cmd, timeout=timeout, needs_root=True)
        return parse_arp_scan(result.stdout)
    if have("nmap"):
        target = _local_cidr(interface) or "192.168.0.0/24"
        result = run(["nmap", "-sn", "-oX", "-", target], timeout=timeout)
        return parse_nmap_xml(result.stdout)
    raise MissingBinaryError("arp-scan or nmap")


def _local_cidr(interface: str | None) -> str | None:
    """Best-effort lookup of the local /24 via `ip route`. None if unavailable."""
    if not have("ip"):
        return None
    cmd = ["ip", "-4", "route", "show"]
    if interface:
        cmd += ["dev", interface]
    try:
        result: RunResult = run(cmd, timeout=5.0)
    except MissingBinaryError:
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts and "/" in parts[0] and not parts[0].startswith("default"):
            return parts[0]
    return None

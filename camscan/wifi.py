"""Active LAN scanning — enumerate devices on the joined WiFi.

Tries `arp-scan` first (faster, more reliable), falls back to `nmap -sn`.
Parsers are pure functions and unit-tested with captured fixtures.
"""

from __future__ import annotations

import ipaddress
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


def parse_nmap_xml(xml_text: str, *, arp_cache: dict[str, str] | None = None) -> list[Device]:
    """Parse stdout of `nmap -sn -oX -`.

    `arp_cache` (optional `{ip: mac}` map) is consulted when nmap doesn't
    provide a MAC for a host — this is the common case in unprivileged /
    chroot environments where nmap uses TCP-connect discovery and never
    sees ARP replies.
    """
    arp_cache = arp_cache or {}
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
        if not mac and ip:
            mac = arp_cache.get(ip)
        if not mac:
            if not ip:
                continue
            devices.append(Device(mac="", ip=ip, vendor=None, match=None))
            continue
        devices.append(_enrich(mac, ip, vendor))
    return _dedupe(devices)


def read_arp_cache() -> dict[str, str]:
    """Return `{ip: mac}` from `/proc/net/arp`, falling back to `arp -n`."""
    try:
        with open("/proc/net/arp", encoding="utf-8") as fh:
            return _parse_proc_arp(fh.read())
    except (FileNotFoundError, PermissionError, OSError):
        pass
    if have("arp"):
        try:
            result = run(["arp", "-n"], timeout=5.0)
        except MissingBinaryError:
            return {}
        return _parse_arp_n(result.stdout)
    return {}


_PROC_ARP_LINE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+(?P<mac>[0-9A-Fa-f:]{17})\s"
)
_ARP_N_LINE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(?P<mac>[0-9A-Fa-f:]{17})"
)


def _parse_proc_arp(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines()[1:]:  # skip header
        m = _PROC_ARP_LINE.match(line)
        if m and m.group("mac") != "00:00:00:00:00:00":
            out[m.group("ip")] = m.group("mac").upper()
    return out


def _parse_arp_n(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _ARP_N_LINE.match(line)
        if m:
            out[m.group("ip")] = m.group("mac").upper()
    return out


def _dedupe(devices: Iterable[Device]) -> list[Device]:
    seen: dict[str, Device] = {}
    for d in devices:
        key = d.mac or f"ip:{d.ip}"
        existing = seen.get(key)
        if existing is None or (existing.ip is None and d.ip is not None):
            seen[key] = d
    return list(seen.values())


class ScanError(RuntimeError):
    """Underlying scanner returned an error."""


def active_scan(
    interface: str | None = None,
    *,
    timeout: float = 30.0,
    target: str | None = None,
) -> list[Device]:
    """Run an active LAN scan and return discovered devices.

    Tries `arp-scan` first; falls back to `nmap -sn` against the local /24
    (auto-detected via `ip route` or `ifconfig`, override with `target`).
    Raises MissingBinaryError if neither binary is available, or ScanError
    if the underlying scanner failed.
    """
    if have("arp-scan"):
        cmd = ["arp-scan", "--localnet", "--quiet"]
        if interface:
            cmd += [f"--interface={interface}"]
        result = run(cmd, timeout=timeout, needs_root=True)
        return parse_arp_scan(result.stdout)
    if have("nmap"):
        cidr = target or _local_cidr(interface)
        if not cidr:
            raise ScanError(
                "Could not auto-detect local subnet. Pass --target <cidr> "
                "(find your subnet with `ip -4 addr`)."
            )
        # `--unprivileged` forces connect()-based discovery for non-root /
        # chroot environments (UserLAnd, Docker without --cap-add=NET_RAW).
        # `-T4` + `--min-rate` keep scans responsive on phones.
        result = run(
            [
                "nmap", "-sn", "--unprivileged",
                "-T4", "--min-rate", "200",
                "-oX", "-", cidr,
            ],
            timeout=timeout,
        )
        if not result.stdout.lstrip().startswith("<?xml"):
            err = (result.stderr or result.stdout).strip() or "nmap produced no XML output"
            raise ScanError(f"nmap failed for {cidr!r} (rc={result.rc}): {err}")
        return parse_nmap_xml(result.stdout, arp_cache=read_arp_cache())
    raise MissingBinaryError("arp-scan or nmap")


def _local_cidr(interface: str | None) -> str | None:
    """Best-effort lookup of the local /24 via `ip route`, then `ifconfig`."""
    cidr = _cidr_from_ip_route(interface)
    if cidr:
        return cidr
    return _cidr_from_ifconfig(interface)


def _cidr_from_ip_route(interface: str | None) -> str | None:
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


def _cidr_from_ifconfig(interface: str | None) -> str | None:
    if not have("ifconfig"):
        return None
    cmd = ["ifconfig"] + ([interface] if interface else [])
    try:
        result = run(cmd, timeout=5.0)
    except MissingBinaryError:
        return None
    for ip, mask in _ifconfig_inet_pairs(result.stdout):
        if ip.startswith("127."):
            continue
        try:
            return str(ipaddress.IPv4Network(f"{ip}/{mask}", strict=False))
        except ValueError:
            continue
    return None


def _ifconfig_inet_pairs(text: str):
    """Yield (ip, mask) tuples found in ifconfig output, in order."""
    ip = mask = None
    for line in text.splitlines():
        m = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            if ip and mask:
                yield ip, mask
                ip = mask = None
            ip = m.group(1)
        m = re.search(r"(?:Mask:|netmask )(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            mask = m.group(1)
            if ip:
                yield ip, mask
                ip = mask = None

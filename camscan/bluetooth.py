"""BLE scanning — discover nearby Bluetooth Low Energy devices.

Primary path uses the `bleak` library (BlueZ on Linux). If bleak fails — which
can happen in NetHunter chroots where DBus is unavailable — falls back to
parsing `bluetoothctl scan le` output.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any

from camscan.oui import normalize, vendor_of
from camscan.runners import MissingBinaryError, have, run
from camscan.vendors import CameraMatch, classify


@dataclass(frozen=True)
class BleDevice:
    """A nearby Bluetooth Low Energy device."""

    mac: str
    name: str | None = None
    rssi: int | None = None
    vendor: str | None = None
    match: CameraMatch | None = None
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)

    @property
    def is_flagged(self) -> bool:
        return self.match is not None


def _enrich(
    mac: str,
    name: str | None,
    rssi: int | None,
    vendor_hint: str | None = None,
    manufacturer_data: dict[int, bytes] | None = None,
) -> BleDevice:
    mac_norm = normalize(mac)
    return BleDevice(
        mac=mac_norm,
        name=name or None,
        rssi=rssi,
        vendor=vendor_hint or vendor_of(mac_norm),
        match=classify(mac_norm),
        manufacturer_data=manufacturer_data or {},
    )


def parse_bleak_results(results: list[dict[str, Any]]) -> list[BleDevice]:
    """Convert a list of `{mac, name, rssi, manufacturer_data}` dicts to BleDevices.

    Pure function — keeps the bleak SDK out of the unit-test path.
    """
    return [
        _enrich(
            r["mac"],
            r.get("name"),
            r.get("rssi"),
            manufacturer_data=r.get("manufacturer_data"),
        )
        for r in results
        if r.get("mac")
    ]


_BTCTL_DEVICE = re.compile(
    r"\[NEW\]\s+Device\s+(?P<mac>[0-9A-Fa-f:]{17})(?:\s+(?P<name>.+))?$"
)


def parse_bluetoothctl(output: str) -> list[BleDevice]:
    """Parse output captured from a `bluetoothctl --timeout N scan le` run."""
    devices: list[BleDevice] = []
    for line in output.splitlines():
        m = _BTCTL_DEVICE.search(line.strip())
        if not m:
            continue
        name = (m.group("name") or "").strip() or None
        if name == m.group("mac"):
            name = None
        devices.append(_enrich(m.group("mac"), name, rssi=None))
    return devices


async def _bleak_scan(duration: float) -> list[BleDevice]:
    from bleak import BleakScanner

    discovered = await BleakScanner.discover(timeout=duration, return_adv=True)
    rows: list[dict[str, Any]] = []
    for device, adv in discovered.values():
        rows.append(
            {
                "mac": device.address,
                "name": adv.local_name or device.name,
                "rssi": adv.rssi,
                "manufacturer_data": dict(adv.manufacturer_data),
            }
        )
    return parse_bleak_results(rows)


def scan(duration: float = 8.0) -> list[BleDevice]:
    """Scan for nearby BLE devices for `duration` seconds.

    Tries bleak first, falls back to `bluetoothctl scan le` on failure.
    """
    try:
        return asyncio.run(_bleak_scan(duration))
    except Exception:
        if have("bluetoothctl"):
            timeout = int(duration) + 2
            result = run(
                ["bluetoothctl", "--timeout", str(int(duration)), "scan", "le"],
                timeout=timeout,
            )
            return parse_bluetoothctl(result.stdout)
        raise MissingBinaryError("bleak or bluetoothctl") from None

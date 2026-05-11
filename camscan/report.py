"""Reporting — rich tables for the terminal and JSON export for machines."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, is_dataclass
from typing import Any, Protocol

from rich.console import Console
from rich.table import Table


class _Scannable(Protocol):
    mac: str
    vendor: str | None
    match: Any
    is_flagged: bool


def _confidence_color(confidence: str) -> str:
    return {"high": "red", "medium": "yellow", "low": "cyan"}.get(confidence, "white")


def render_wifi(console: Console, devices: Iterable) -> None:
    """Render discovered WiFi devices as a rich table."""
    devices = list(devices)
    table = Table(title=f"WiFi scan — {len(devices)} device(s)", show_lines=False)
    table.add_column("Flag", justify="center", no_wrap=True)
    table.add_column("IP", no_wrap=True)
    table.add_column("MAC", no_wrap=True)
    table.add_column("Vendor")
    table.add_column("Category")
    table.add_column("Confidence")
    table.add_column("Notes")

    for d in sorted(devices, key=lambda x: (not x.is_flagged, x.ip or "")):
        flag = "[bold red]CAM[/]" if d.is_flagged else ""
        if d.match:
            category = d.match.category
            confidence = f"[{_confidence_color(d.match.confidence)}]{d.match.confidence}[/]"
            notes = d.match.notes
        else:
            category = confidence = notes = ""
        table.add_row(
            flag, d.ip or "", d.mac, d.vendor or "", category, confidence, notes
        )
    console.print(table)


def render_bluetooth(console: Console, devices: Iterable) -> None:
    """Render discovered BLE devices as a rich table."""
    devices = list(devices)
    table = Table(title=f"Bluetooth scan — {len(devices)} device(s)", show_lines=False)
    table.add_column("Flag", justify="center", no_wrap=True)
    table.add_column("MAC", no_wrap=True)
    table.add_column("Name")
    table.add_column("RSSI", justify="right", no_wrap=True)
    table.add_column("Vendor")
    table.add_column("Category")
    table.add_column("Confidence")

    for d in sorted(devices, key=lambda x: (not x.is_flagged, -(x.rssi or -999))):
        flag = "[bold red]CAM[/]" if d.is_flagged else ""
        if d.match:
            category = d.match.category
            confidence = f"[{_confidence_color(d.match.confidence)}]{d.match.confidence}[/]"
        else:
            category = confidence = ""
        rssi = f"{d.rssi} dBm" if d.rssi is not None else ""
        table.add_row(flag, d.mac, d.name or "", rssi, d.vendor or "", category, confidence)
    console.print(table)


def to_json(*, wifi: Iterable | None = None, bluetooth: Iterable | None = None) -> dict:
    """Return a JSON-serializable dict summarising one or both scans."""
    payload: dict[str, Any] = {}
    if wifi is not None:
        payload["wifi"] = [_device_to_dict(d) for d in wifi]
    if bluetooth is not None:
        payload["bluetooth"] = [_device_to_dict(d) for d in bluetooth]
    return payload


def _device_to_dict(device: Any) -> dict[str, Any]:
    data = asdict(device) if is_dataclass(device) else dict(device)
    match = data.get("match")
    if match is not None and not isinstance(match, dict):
        data["match"] = match.model_dump() if hasattr(match, "model_dump") else dict(match)
    # bytes from BLE manufacturer_data → hex strings for JSON
    if "manufacturer_data" in data and isinstance(data["manufacturer_data"], dict):
        data["manufacturer_data"] = {
            str(k): (v.hex() if isinstance(v, (bytes, bytearray)) else v)
            for k, v in data["manufacturer_data"].items()
        }
    return data

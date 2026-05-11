"""Typer-based CLI: `camscan wifi | bluetooth | all | oui-lookup`."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from camscan import __version__
from camscan import bluetooth as bt_mod
from camscan import services as svc_mod
from camscan import wifi as wifi_mod
from camscan.oui import normalize, vendor_of
from camscan.report import render_bluetooth, render_services, render_wifi, to_json
from camscan.runners import MissingBinaryError, NeedsRootError
from camscan.vendors import classify
from camscan.wifi import ScanError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode=None,
    help=(
        "Hidden-camera scanner. Use only on networks and in spaces you have "
        "authorization to scan."
    ),
)

_DISCLAIMER = (
    "[yellow]⚠ Scan only networks/spaces you have authorization to assess. "
    "Misuse may violate local law.[/yellow]"
)


def _console(no_color: bool) -> Console:
    return Console(no_color=no_color, highlight=False)


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


@app.command()
def version() -> None:
    """Print the camscan version and exit."""
    typer.echo(f"camscan {__version__}")


@app.command()
def wifi(
    interface: str | None = typer.Option(
        None, "-i", "--interface", help="Network interface to scan from (e.g. wlan0)."
    ),
    target: str | None = typer.Option(
        None,
        "--target",
        help="CIDR to scan (e.g. 192.168.1.0/24). Overrides auto-detection.",
    ),
    timeout: float = typer.Option(90.0, "--timeout", help="Scan timeout in seconds."),
    from_file: Path | None = typer.Option(
        None,
        "--from-file",
        help="Dev only: parse a saved arp-scan output instead of running a live scan.",
    ),
    json_out: Path | None = typer.Option(None, "--json", help="Write JSON report to this path."),
    no_color: bool = typer.Option(False, "--no-color"),
) -> None:
    """Active LAN scan for camera-vendor devices."""
    console = _console(no_color)
    console.print(_DISCLAIMER)
    try:
        if from_file is not None:
            devices = wifi_mod.parse_arp_scan(from_file.read_text(encoding="utf-8"))
        else:
            devices = wifi_mod.active_scan(
                interface=interface, timeout=timeout, target=target
            )
    except NeedsRootError as e:
        console.print(f"[red]'{e}' needs root. Try: sudo camscan wifi ...[/red]")
        raise typer.Exit(code=2) from e
    except MissingBinaryError as e:
        console.print(f"[red]Required binary not found: {e}. Install arp-scan or nmap.[/red]")
        raise typer.Exit(code=3) from e
    except ScanError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        console.print(
            "[yellow]Hint: pass --target <cidr> explicitly, "
            "or check that the interface is up.[/yellow]"
        )
        raise typer.Exit(code=4) from e

    render_wifi(console, devices)
    if json_out:
        _write_json(json_out, to_json(wifi=devices))
        console.print(f"[green]Wrote {json_out}[/green]")


@app.command()
def bluetooth(
    duration: float = typer.Option(8.0, "--duration", help="BLE scan duration in seconds."),
    json_out: Path | None = typer.Option(None, "--json", help="Write JSON report to this path."),
    no_color: bool = typer.Option(False, "--no-color"),
) -> None:
    """BLE scan for camera-vendor devices."""
    console = _console(no_color)
    console.print(_DISCLAIMER)
    try:
        devices = bt_mod.scan(duration=duration)
    except MissingBinaryError as e:
        console.print(f"[red]No BLE backend available: {e}.[/red]")
        raise typer.Exit(code=3) from e

    render_bluetooth(console, devices)
    if json_out:
        _write_json(json_out, to_json(bluetooth=devices))
        console.print(f"[green]Wrote {json_out}[/green]")


@app.command(name="all")
def scan_all(
    interface: str | None = typer.Option(None, "-i", "--interface"),
    timeout: float = typer.Option(90.0, "--timeout"),
    duration: float = typer.Option(8.0, "--duration", help="BLE scan duration."),
    json_out: Path | None = typer.Option(None, "--json"),
    no_color: bool = typer.Option(False, "--no-color"),
) -> None:
    """Run both WiFi and Bluetooth scans."""
    console = _console(no_color)
    console.print(_DISCLAIMER)

    wifi_devices: list = []
    bt_devices: list = []

    try:
        wifi_devices = wifi_mod.active_scan(interface=interface, timeout=timeout)
        render_wifi(console, wifi_devices)
    except (NeedsRootError, MissingBinaryError, ScanError) as e:
        console.print(f"[yellow]WiFi scan skipped: {e}[/yellow]")

    try:
        bt_devices = bt_mod.scan(duration=duration)
        render_bluetooth(console, bt_devices)
    except MissingBinaryError as e:
        console.print(f"[yellow]Bluetooth scan skipped: {e}[/yellow]")

    if json_out:
        _write_json(json_out, to_json(wifi=wifi_devices, bluetooth=bt_devices))
        console.print(f"[green]Wrote {json_out}[/green]")


@app.command()
def services(
    hosts: list[str] = typer.Argument(  # noqa: B008
        None,
        help="One or more IP/hostnames to probe. Omit to discover via --target.",
    ),
    target: str | None = typer.Option(
        None,
        "--target",
        help="CIDR to discover hosts in first (e.g. 192.168.1.0/24).",
    ),
    interface: str | None = typer.Option(
        None, "-i", "--interface", help="Interface used during host discovery."
    ),
    timeout: float = typer.Option(
        3.0, "--probe-timeout", help="Per-probe TCP timeout in seconds."
    ),
    discovery_timeout: float = typer.Option(
        90.0, "--discovery-timeout", help="Host-discovery (nmap) timeout."
    ),
    workers: int = typer.Option(20, "--workers", help="Concurrent probe workers."),
    json_out: Path | None = typer.Option(None, "--json"),
    no_color: bool = typer.Option(False, "--no-color"),
) -> None:
    """Probe hosts for camera services (RTSP, HTTP banner, vendor fingerprints).

    Works without root or ARP access — useful in proot / UserLAnd / Docker
    where OUI-based detection can't read the kernel ARP cache.
    """
    console = _console(no_color)
    console.print(_DISCLAIMER)

    targets: list[str]
    if hosts:
        targets = list(hosts)
    else:
        try:
            devices = wifi_mod.active_scan(
                interface=interface, timeout=discovery_timeout, target=target
            )
        except (NeedsRootError, MissingBinaryError, ScanError) as e:
            console.print(f"[red]Host discovery failed: {e}[/red]")
            console.print(
                "[yellow]Tip: pass IP arguments directly to skip discovery, "
                "or use --target <cidr>.[/yellow]"
            )
            raise typer.Exit(code=4) from e
        targets = [d.ip for d in devices if d.ip]

    if not targets:
        console.print("[yellow]No hosts to probe.[/yellow]")
        raise typer.Exit(code=0)

    console.print(f"Probing {len(targets)} host(s)…")
    matches = svc_mod.scan_hosts(targets, timeout=timeout, workers=workers)
    render_services(console, matches)
    if json_out:
        _write_json(json_out, to_json(services=matches))
        console.print(f"[green]Wrote {json_out}[/green]")


@app.command(name="oui-lookup")
def oui_lookup(
    mac: str = typer.Argument(..., help="A full MAC address or just the 24-bit OUI."),
    no_color: bool = typer.Option(False, "--no-color"),
) -> None:
    """Show IEEE vendor and camera-vendor classification for a MAC/OUI."""
    console = _console(no_color)
    try:
        normalized = normalize(mac if mac.count(":") >= 5 else mac + ":00:00:00")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1) from e

    vendor = vendor_of(normalized)
    match = classify(normalized)
    console.print(f"MAC      : [bold]{normalized}[/bold]")
    console.print(f"Vendor   : {vendor or '[dim]unknown[/dim]'}")
    if match:
        console.print(
            f"Camera   : [bold red]{match.vendor}[/bold red] "
            f"({match.category}, confidence={match.confidence})"
        )
        if match.notes:
            console.print(f"Notes    : {match.notes}")
    else:
        console.print("Camera   : [dim]not in camera-vendor list[/dim]")

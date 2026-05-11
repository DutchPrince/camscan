# camscan

A hidden-camera scanner CLI for Kali Linux (including Kali NetHunter on
Android). Detects nearby networked cameras by scanning the local WiFi
network and Bluetooth Low Energy and matching MAC OUIs against a curated
list of known camera-vendor prefixes (Hikvision, Dahua, Wyze, Reolink,
Axis, Bosch, Eufy, Ring, Nest, and more).

> **Use only on networks and in physical spaces where you have explicit
> authorization to scan.** Scanning networks you don't own may be illegal
> in your jurisdiction. See [LICENSE](LICENSE) for the full ethics notice.

## What it does (and does not) detect

| Method                         | Status        |
|--------------------------------|---------------|
| WiFi LAN scan (OUI lookup)     | ✅ Phase 1    |
| Bluetooth LE scan (OUI lookup) | ✅ Phase 1    |
| Service probe (RTSP / HTTP)    | ✅ Phase 1.5  |
| 802.11 monitor-mode capture    | ⏳ Phase 2    |
| BLE manufacturer-data deep dig | ⏳ Phase 2    |
| RF spectrum / SDR sweep        | ❌ Out of scope (needs hardware) |
| Optical IR-LED detection       | ❌ Out of scope (use a phone camera) |
| Lens-reflection detection      | ❌ Out of scope (use a phone camera + light) |

A device flagged as `CAM` means its MAC's OUI belongs to a vendor that
manufactures cameras — not that the device is definitively a camera.
The `confidence` column helps you weigh false positives: `high` means
the vendor's primary business is cameras; `low` means the OUI is shared
across many product lines (e.g. TP-Link makes Tapo cameras *and* routers).

## Install

### Kali NetHunter / Kali Linux

```bash
sudo apt install -y arp-scan nmap bluetooth bluez python3-pip
git clone <repo> camscan && cd camscan
pip install -e .
```

For monitor-mode features (Phase 2): also install `aircrack-ng`.

### macOS / generic Linux (limited)

```bash
pip install -e .
```

`arp-scan` is Linux-only; on macOS the tool falls back to `nmap -sn`.

## Usage

```bash
# Show vendor + camera classification for a single MAC or OUI
camscan oui-lookup 28:57:be:00:11:22

# Scan the joined WiFi network (needs root for arp-scan)
sudo camscan wifi -i wlan0

# Scan nearby Bluetooth Low Energy devices
camscan bluetooth --duration 12

# Service probe: identify cameras by RTSP/HTTP banners (works without root)
camscan services --target 192.168.1.0/24
camscan services 192.168.1.42 192.168.1.43       # explicit hosts

# Run both, write a JSON report
sudo camscan all --json /tmp/report.json
```

### Service probing — when OUI lookup isn't available

Some environments (proot-based Kali on Android via UserLAnd, Docker without
`--cap-add=NET_RAW`) can't reach the kernel ARP cache, so MAC-vendor
classification doesn't work. `camscan services` skips ARP entirely and
identifies cameras by what they speak on the wire:

- **RTSP/554** — virtually every IP camera responds to `OPTIONS rtsp://…`
- **HTTP/80, 8080, 8000** — `Server:` header, `WWW-Authenticate` realm
  (e.g. `WEB_REALM_HIKVISION`, `WEB_REALM_DAHUA`), page title, body hints
  (`/ISAPI/`, `/cgi-bin/snapshot.cgi`, `/onvif/`)

Vendor-specific fingerprints in `camscan/services.py` cover Hikvision,
Dahua, Reolink, Wyze, Axis, Foscam, Amcrest, Tapo, Eufy, Arlo, Nest, Ring,
Mobotix, Bosch, and Ubiquiti UniFi. Hosts that don't match a specific
vendor but expose generic camera signals (Boa server, GoAhead-Webs, an
RTSP responder on 554) are still flagged at lower confidence.

Concurrency is `--workers` (default 20), so a /22 of ~27 live hosts
finishes in well under a minute.

### Example output

```
⚠ Scan only networks/spaces you have authorization to assess.

                    WiFi scan — 4 device(s)
┏━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┓
┃Flag ┃ IP           ┃ MAC               ┃ Vendor          ┃ Category ┃ Confidence ┃
┡━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━┩
│ CAM │ 192.168.1.42 │ 28:57:BE:00:11:22 │ Hikvision …     │ ip-camera│ high       │
│ CAM │ 192.168.1.77 │ 2C:AA:8E:AA:BB:CC │ Wyze Labs/Hualai│ ip-camera│ high       │
│     │ 192.168.1.1  │ A4:2B:B0:11:22:33 │ NETGEAR         │          │            │
│     │ 192.168.1.250│ F0:18:98:DE:AD:BE │ Apple, Inc.     │          │            │
└─────┴──────────────┴───────────────────┴─────────────────┴──────────┴────────────┘
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

Unit tests cover MAC normalization, vendor classification, scan-output
parsing, and report rendering. No hardware required.

A reviewer can also demo flagged output without a camera using a captured
fixture:

```bash
camscan wifi --from-file tests/fixtures/arp_scan_sample.txt
```

## Architecture

```
camscan/
├── cli.py          # Typer subcommands
├── oui.py          # MAC normalization + IEEE OUI lookup (via `manuf`)
├── vendors.py      # Camera-vendor classification (loads data/vendors.json)
├── wifi.py         # Active LAN scan: arp-scan → fallback to nmap + /proc/net/arp
├── bluetooth.py    # BLE scan via bleak → fallback to bluetoothctl
├── services.py     # RTSP/HTTP probe + vendor fingerprints (no root needed)
├── report.py       # rich tables + JSON exporter
├── runners.py      # subprocess + sudo helpers
└── data/
    ├── vendors.json
    └── SOURCES.md
```

## Limitations

- **Restricted environments (UserLAnd, Docker).** proot strips the kernel
  ARP table from the chroot's view of `/proc` and blocks netlink, so MAC
  addresses for LAN hosts aren't reachable from userspace. `camscan wifi`
  will still enumerate IPs but won't flag vendors. Use `camscan services`
  (RTSP/HTTP fingerprinting) instead — it needs only TCP connect.
- **MAC randomization.** Many modern phones and some cameras randomize
  their MAC. OUI lookup misses those.
- **Joined network only.** `arp-scan` finds devices on the WiFi you're
  joined to. A hidden camera on a separate SSID/VLAN is invisible until
  Phase 2 monitor mode lands.
- **OUI db staleness.** `manuf` ships a snapshot of the IEEE registry.
  Refresh occasionally.
- **Mixed-vendor OUIs.** Some vendors (TP-Link, D-Link, Ubiquiti) make
  cameras *and* many other devices — those entries are tagged
  `mixed-iot` / `low` confidence to keep false positives manageable.

## Roadmap

Phase 2 (portfolio polish, not yet implemented):

- 802.11 monitor mode via airodump-ng with auto teardown
- BLE manufacturer-data deep inspection (BT SIG company IDs)
- Probe-request analysis for cameras not joined to the current WiFi
- `--watch` mode that re-scans and diffs every N seconds
- GitHub Actions CI (pytest + ruff)
- asciinema demo recorded on real NetHunter hardware

## License

MIT — see [LICENSE](LICENSE).
# camscan

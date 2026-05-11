# Vendor OUI sources & provenance

The `vendors.json` file maps known camera-vendor OUIs (first 24 bits of a MAC
address) to a vendor name, a category, and a confidence level.

## Authoritative source

The IEEE Registration Authority publishes the official MAC address registry:

  https://standards-oui.ieee.org/oui/oui.txt
  https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries

The `manuf` Python package ships a snapshot of this registry and is used at
runtime for *generic* MAC → vendor lookup. `vendors.json` in this package is a
*separate, narrower* layer that classifies which of those vendors are camera
manufacturers, and how confidently that signals "this is a camera".

## How entries were selected

1. Public IEEE OUI assignments for known security-camera and IoT-camera vendors.
2. Cross-referenced with publicly documented product MAC prefixes (e.g.,
   teardown blogs, vendor support pages, network-scanning research papers).
3. Confidence levels are conservative:
   - `high`   — vendor's primary business is cameras (Hikvision, Dahua, Axis).
   - `medium` — vendor sells cameras and a small number of other products
     (Nest, Eufy, Ring).
   - `low`    — vendor's OUI is shared across many product lines, of which
     cameras are only one (TP-Link, D-Link, Ubiquiti, Xiaomi). These are
     `category: "mixed-iot"` and should be treated as hints, not confirmations.

## Limitations

- The list is **not exhaustive**. Vendors hold many OUI ranges; this file ships
  a curated seed list. Contributions welcome.
- OUIs do not change ownership often, but they *can* be transferred or
  reassigned. Treat any single entry as a heuristic, not proof.
- Many cameras use MAC randomization or rotate addresses; OUI lookup will
  miss those. Phase 2 of the tool augments OUI with BLE manufacturer-data
  inspection and SSID-pattern matching for that reason.
- Some OEMs (notably Hangzhou Xiongmai) supply the same hardware to dozens
  of rebranded "no-name" cameras — flagging the OEM OUI catches all of them.

## Refreshing the data

To refresh the generic OUI database used by `manuf`:

```
python -c "from manuf import manuf; manuf.MacParser().refresh()"
```

To extend the camera-vendor classification list, edit `vendors.json` and add
an entry referencing the IEEE OUI registration. Run `pytest tests/test_vendors.py`
to confirm the file still validates.

"""MAC address normalization and IEEE OUI vendor lookup."""

from __future__ import annotations

import re
from functools import lru_cache

_HEX_PAIR = re.compile(r"[0-9A-Fa-f]{2}")


def normalize(mac: str) -> str:
    """Return a MAC as 12 uppercase hex pairs separated by colons.

    Accepts common forms: `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`,
    `AABB.CCDD.EEFF`, `aabbccddeeff`. Raises ValueError on anything that
    can't be coerced into exactly 12 hex digits.
    """
    pairs = _HEX_PAIR.findall(mac)
    if len(pairs) == 6:
        return ":".join(p.upper() for p in pairs)
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(digits) == 12:
        return ":".join(digits[i : i + 2].upper() for i in range(0, 12, 2))
    raise ValueError(f"not a MAC address: {mac!r}")


def oui_of(mac: str) -> str:
    """Return the 24-bit OUI (first three octets) of a MAC, e.g. `44:EF:BF`."""
    return ":".join(normalize(mac).split(":")[:3])


@lru_cache(maxsize=1)
def _parser():
    from manuf import manuf

    return manuf.MacParser()


def vendor_of(mac: str) -> str | None:
    """Generic IEEE-OUI vendor lookup via the `manuf` package.

    Returns the long vendor name, or None if not registered.
    """
    try:
        normalized = normalize(mac)
    except ValueError:
        return None
    result = _parser().get_all(normalized)
    return result.manuf_long or result.manuf or None

"""Camera-vendor classification: maps an OUI to a CameraMatch when known."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from camscan.oui import oui_of

Category = Literal["ip-camera", "doorbell", "baby-monitor", "dvr-nvr", "camera-oem", "mixed-iot"]
Confidence = Literal["high", "medium", "low"]


class CameraMatch(BaseModel):
    """A single camera-vendor OUI entry."""

    model_config = ConfigDict(frozen=True)

    oui: str = Field(pattern=r"^[0-9A-F]{2}(:[0-9A-F]{2}){2}$")
    vendor: str
    category: Category
    confidence: Confidence
    notes: str = ""


class VendorDatabase(BaseModel):
    """Top-level schema of `data/vendors.json`."""

    model_config = ConfigDict(frozen=True)

    version: str
    source: str
    entries: tuple[CameraMatch, ...]


@lru_cache(maxsize=1)
def _db() -> VendorDatabase:
    raw = (files("camscan.data") / "vendors.json").read_text(encoding="utf-8")
    return VendorDatabase.model_validate(json.loads(raw))


@lru_cache(maxsize=1)
def _by_oui() -> dict[str, CameraMatch]:
    return {entry.oui: entry for entry in _db().entries}


def all_entries() -> tuple[CameraMatch, ...]:
    """Return every curated camera-vendor entry."""
    return _db().entries


def classify(mac: str) -> CameraMatch | None:
    """Return a CameraMatch if the MAC's OUI is in the curated camera-vendor list."""
    try:
        return _by_oui().get(oui_of(mac))
    except ValueError:
        return None

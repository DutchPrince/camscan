from camscan.vendors import all_entries, classify


def test_database_loads_and_has_entries():
    entries = all_entries()
    assert len(entries) > 10
    ouis = {e.oui for e in entries}
    assert len(ouis) == len(entries), "duplicate OUI in vendors.json"


def test_classify_known_hikvision_oui():
    match = classify("28:57:BE:00:11:22")
    assert match is not None
    assert "Hikvision" in match.vendor
    assert match.category == "ip-camera"
    assert match.confidence == "high"


def test_classify_unknown_returns_none():
    # Apple OUI — present in IEEE but not in our camera-vendor list
    assert classify("F0:18:98:DE:AD:BE") is None


def test_classify_handles_lowercase_and_separator_variants():
    assert classify("28-57-be-aa-bb-cc") is not None
    assert classify("2857.BEAA.BBCC") is not None


def test_classify_returns_none_for_invalid_mac():
    assert classify("not a mac") is None

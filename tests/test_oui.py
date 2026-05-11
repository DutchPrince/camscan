import pytest

from camscan.oui import normalize, oui_of


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"),
        ("AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF"),
        ("AABB.CCDD.EEFF", "AA:BB:CC:DD:EE:FF"),
        ("aabbccddeeff", "AA:BB:CC:DD:EE:FF"),
        ("aa:bB:cC:Dd:Ee:FF", "AA:BB:CC:DD:EE:FF"),
        ("  44:ef:bf:00:11:22 ", "44:EF:BF:00:11:22"),
    ],
)
def test_normalize_accepts_common_forms(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize(
    "bad", ["", "not a mac", "AA:BB:CC:DD:EE", "AABBCCDDEE", "ZZ:BB:CC:DD:EE:FF"]
)
def test_normalize_rejects_malformed(bad):
    with pytest.raises(ValueError):
        normalize(bad)


def test_oui_of_returns_three_octets():
    assert oui_of("44:ef:bf:00:11:22") == "44:EF:BF"
    assert oui_of("AABB.CCDD.EEFF") == "AA:BB:CC"

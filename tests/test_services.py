from camscan.services import (
    ServiceProbe,
    _parse_http,
    _parse_rtsp,
    classify,
)


def test_parse_rtsp_recognizes_options_response():
    data = (
        b"RTSP/1.0 200 OK\r\n"
        b"CSeq: 1\r\n"
        b"Server: Hipcam RealServer/V1.0\r\n"
        b"Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n"
    )
    probe = _parse_rtsp("192.168.1.42", 554, data)
    assert probe is not None
    assert probe.protocol == "rtsp"
    assert probe.rtsp_status == "RTSP/1.0 200 OK"
    assert probe.server == "Hipcam RealServer/V1.0"


def test_parse_rtsp_rejects_non_rtsp_response():
    assert _parse_rtsp("h", 554, b"HTTP/1.1 200 OK\r\n\r\n") is None
    assert _parse_rtsp("h", 554, b"") is None


def test_parse_http_extracts_server_title_and_realm():
    raw = (
        b"HTTP/1.1 401 Unauthorized\r\n"
        b"Server: App-webs/\r\n"
        b'WWW-Authenticate: Digest realm="WEB_REALM_HIKVISION", nonce="abc"\r\n'
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head><title>Network Camera</title></head><body></body></html>"
    )
    probe = _parse_http("192.168.1.42", 80, raw)
    assert probe.server == "App-webs/"
    assert probe.realm == "WEB_REALM_HIKVISION"
    assert probe.title == "Network Camera"
    assert "Network Camera" in probe.body_excerpt


def test_classify_flags_hikvision_with_high_confidence():
    probes = [
        ServiceProbe(
            host="192.168.1.42", port=80, protocol="http",
            server="App-webs/", realm="WEB_REALM_HIKVISION",
            title="Network Camera",
            body_excerpt="<html>/ISAPI/Security/userCheck</html>",
        )
    ]
    m = classify("192.168.1.42", probes)
    assert m.is_flagged
    assert m.vendor == "Hikvision"
    assert m.confidence == "high"


def test_classify_returns_unflagged_for_random_web_server():
    probes = [
        ServiceProbe(
            host="192.168.1.1", port=80, protocol="http",
            server="nginx/1.24", title="Welcome", body_excerpt="<h1>hi</h1>",
        )
    ]
    m = classify("192.168.1.1", probes)
    assert not m.is_flagged
    assert m.vendor is None


def test_classify_flags_generic_camera_signal_when_no_vendor_match():
    probes = [
        ServiceProbe(
            host="192.168.1.99", port=80, protocol="http",
            server="Boa/0.94.14rc21", title="IP Camera", body_excerpt="",
        )
    ]
    m = classify("192.168.1.99", probes)
    assert m.is_flagged
    assert m.vendor is None
    assert m.confidence == "medium"
    assert any("generic camera" in e for e in m.evidence)


def test_classify_rtsp_only_is_medium_confidence_unflagged_vendor():
    probes = [
        ServiceProbe(
            host="192.168.1.55", port=554, protocol="rtsp",
            rtsp_status="RTSP/1.0 200 OK",
        )
    ]
    m = classify("192.168.1.55", probes)
    assert m.is_flagged
    assert m.vendor is None
    assert any("RTSP" in e for e in m.evidence)


def test_classify_empty_probes_is_not_flagged():
    m = classify("192.168.1.250", [])
    assert not m.is_flagged


def test_classify_reolink_doorbell_by_camara_realm():
    # Real-world signature captured from a Reolink doorbell: gSOAP/2.8 on
    # port 8000, ONVIF SOAP, realm="camara", no "Reolink" anywhere.
    probes = [
        ServiceProbe(
            host="192.168.68.17", port=554, protocol="rtsp",
            rtsp_status="RTSP/1.0 200 OK",
        ),
        ServiceProbe(
            host="192.168.68.17", port=8000, protocol="http",
            server="gSOAP/2.8", realm="camara",
        ),
    ]
    m = classify("192.168.68.17", probes)
    assert m.is_flagged
    assert m.vendor == "Reolink (doorbell/OEM)"
    assert m.confidence == "high"


def test_classify_gsoap_alone_is_generic_camera_signal():
    probes = [
        ServiceProbe(
            host="192.168.1.50", port=8000, protocol="http", server="gSOAP/2.8",
        )
    ]
    m = classify("192.168.1.50", probes)
    assert m.is_flagged
    assert m.confidence == "medium"
    assert any("gSOAP" in e for e in m.evidence)

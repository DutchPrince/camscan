"""Service-level camera detection: probe RTSP/HTTP for camera fingerprints.

Works in restricted environments (proot/UserLAnd) because it only needs
plain TCP connect, not raw sockets or ARP. Complementary to OUI-based
detection in `wifi.py` — use both when running with full privileges,
fall back to this alone when ARP isn't reachable.
"""

from __future__ import annotations

import re
import socket
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Literal

Confidence = Literal["high", "medium", "low"]
ProbeProtocol = Literal["rtsp", "http"]

# Default ports to probe. Cameras almost always speak RTSP/554 and HTTP on
# 80/8080. Some Hikvision/Dahua web UIs live on 8000. Keeping this small
# keeps a /22 scan well under a minute.
DEFAULT_RTSP_PORTS = (554,)
DEFAULT_HTTP_PORTS = (80, 8080, 8000)


@dataclass(frozen=True)
class ServiceProbe:
    host: str
    port: int
    protocol: ProbeProtocol
    server: str | None = None
    title: str | None = None
    realm: str | None = None
    body_excerpt: str | None = None
    rtsp_status: str | None = None


@dataclass(frozen=True)
class ServiceMatch:
    host: str
    vendor: str | None
    confidence: Confidence
    evidence: tuple[str, ...]
    probes: tuple[ServiceProbe, ...] = field(default_factory=tuple)

    @property
    def is_flagged(self) -> bool:
        return bool(self.evidence)


# Vendor fingerprints: list of (vendor, confidence, regex, field).
# Order matters slightly — first match wins for vendor naming, but every
# matching pattern is recorded as evidence.
_FINGERPRINTS: tuple[tuple[str, Confidence, re.Pattern, str], ...] = (
    ("Hikvision", "high",   re.compile(r"WEB_REALM_HIKVISION", re.I), "realm"),
    ("Hikvision", "high",   re.compile(r"App-webs/", re.I),           "server"),
    ("Hikvision", "high",   re.compile(r"DNVRS-Webs", re.I),          "server"),
    ("Hikvision", "medium", re.compile(r"/ISAPI/", re.I),             "body"),
    ("Dahua",     "high",   re.compile(r"WEB_REALM_DAHUA", re.I),     "realm"),
    ("Dahua",     "high",   re.compile(r"webs/[\d.]+", re.I),         "server"),
    ("Dahua",     "medium", re.compile(r"DH-[A-Z0-9-]+", re.I),       "body"),
    ("Reolink",   "high",   re.compile(r"Reolink", re.I),             "any"),
    ("Wyze",      "high",   re.compile(r"WyzeCam|wyze\.com", re.I),   "any"),
    ("Axis",      "high",   re.compile(r"AXIS\s+\w+\s+Network Camera", re.I), "any"),
    ("Axis",      "medium", re.compile(r"^AXIS\b", re.I),             "server"),
    ("Foscam",    "high",   re.compile(r"Foscam", re.I),              "any"),
    ("Amcrest",   "high",   re.compile(r"Amcrest", re.I),             "any"),
    ("Tapo / TP-Link", "high", re.compile(r"Tapo[- ]?C\d", re.I),     "any"),
    ("Eufy",      "high",   re.compile(r"eufy", re.I),                "any"),
    ("Arlo",      "high",   re.compile(r"Arlo", re.I),                "any"),
    ("Nest",      "high",   re.compile(r"Nest\s*Cam|nest\.com", re.I),"any"),
    ("Ring",      "high",   re.compile(r"Ring\s*Doorbell|ring\.com", re.I),"any"),
    ("Mobotix",   "high",   re.compile(r"Mobotix", re.I),             "any"),
    ("Bosch",     "high",   re.compile(r"Bosch Security|VRM", re.I),  "any"),
    ("Ubiquiti UniFi Camera", "high", re.compile(r"UniFi[- ]?(?:Video|Protect)", re.I),"any"),
)

# Weaker signals that suggest a camera without naming a specific vendor.
_GENERIC_SIGNALS = (
    re.compile(r"Network\s+Camera", re.I),
    re.compile(r"IP\s+Camera", re.I),
    re.compile(r"\bIPC[- ]?\d", re.I),
    re.compile(r"/cgi-bin/snapshot\.cgi", re.I),
    re.compile(r"/onvif/", re.I),
    re.compile(r"^Boa/", re.I),  # Boa is the embedded HTTP server in many cams
    re.compile(r"GoAhead-Webs", re.I),
)


def probe_rtsp(host: str, port: int = 554, timeout: float = 3.0) -> ServiceProbe | None:
    """Send an RTSP OPTIONS request and return a probe if it speaks RTSP."""
    request = (
        f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\nUser-Agent: camscan\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            data = sock.recv(2048)
    except OSError:
        return None
    return _parse_rtsp(host, port, data)


def _parse_rtsp(host: str, port: int, data: bytes) -> ServiceProbe | None:
    text = data.decode("latin-1", errors="replace")
    if not text.startswith("RTSP/"):
        return None
    first_line, _, _ = text.partition("\r\n")
    server = _header(text, "Server")
    return ServiceProbe(
        host=host, port=port, protocol="rtsp",
        server=server, rtsp_status=first_line.strip(),
    )


def probe_http(host: str, port: int = 80, timeout: float = 3.0) -> ServiceProbe | None:
    """GET / and capture Server, title, WWW-Authenticate realm, body excerpt."""
    request = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: camscan\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            chunks: list[bytes] = []
            total = 0
            while total < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
    except OSError:
        return None
    raw = b"".join(chunks)
    if not raw.startswith(b"HTTP/"):
        return None
    return _parse_http(host, port, raw)


def _parse_http(host: str, port: int, raw: bytes) -> ServiceProbe:
    text = raw.decode("latin-1", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    server = _header(head, "Server")
    realm = _realm(_header(head, "WWW-Authenticate") or "")
    title_match = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I | re.S)
    title = title_match.group(1).strip() if title_match else None
    return ServiceProbe(
        host=host, port=port, protocol="http",
        server=server, realm=realm, title=title,
        body_excerpt=body[:512] or None,
    )


def _header(head: str, name: str) -> str | None:
    pattern = re.compile(rf"^{re.escape(name)}:\s*(.+?)\s*$", re.I | re.M)
    m = pattern.search(head)
    return m.group(1) if m else None


def _realm(value: str) -> str | None:
    m = re.search(r'realm\s*=\s*"?([^",]+)"?', value, re.I)
    return m.group(1) if m else None


def probe_host(
    host: str,
    *,
    rtsp_ports: Iterable[int] = DEFAULT_RTSP_PORTS,
    http_ports: Iterable[int] = DEFAULT_HTTP_PORTS,
    timeout: float = 3.0,
) -> list[ServiceProbe]:
    """Run all camera-relevant probes against a single host."""
    probes: list[ServiceProbe] = []
    for port in rtsp_ports:
        p = probe_rtsp(host, port, timeout=timeout)
        if p:
            probes.append(p)
    for port in http_ports:
        p = probe_http(host, port, timeout=timeout)
        if p:
            probes.append(p)
    return probes


def scan_hosts(
    hosts: Iterable[str],
    *,
    timeout: float = 3.0,
    workers: int = 20,
) -> list[ServiceMatch]:
    """Probe many hosts concurrently and return a classification for each."""
    host_list = list(hosts)
    matches: list[ServiceMatch] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_host = {
            pool.submit(probe_host, h, timeout=timeout): h for h in host_list
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                probes = future.result()
            except Exception:
                probes = []
            matches.append(classify(host, probes))
    matches.sort(key=lambda m: (not m.is_flagged, m.host))
    return matches


def classify(host: str, probes: Iterable[ServiceProbe]) -> ServiceMatch:
    """Decide whether a set of probes points at a camera, and which vendor."""
    probes = tuple(probes)
    if not probes:
        return ServiceMatch(host=host, vendor=None, confidence="low", evidence=(), probes=())

    haystacks: dict[str, str] = {}
    pieces: list[str] = []
    for p in probes:
        for field_name, value in (
            ("server", p.server),
            ("title", p.title),
            ("realm", p.realm),
            ("body", p.body_excerpt),
            ("rtsp_status", p.rtsp_status),
        ):
            if value:
                haystacks.setdefault(field_name, "")
                haystacks[field_name] += " " + value
                pieces.append(value)
    haystacks["any"] = " ".join(pieces)

    vendor: str | None = None
    best_conf: Confidence = "low"
    evidence: list[str] = []

    for vname, conf, pattern, where in _FINGERPRINTS:
        target = haystacks.get(where, "")
        m = pattern.search(target)
        if m:
            evidence.append(f"{vname} ({conf}) → {where}={m.group(0)!r}")
            if vendor is None or _conf_rank(conf) > _conf_rank(best_conf):
                vendor, best_conf = vname, conf

    if not vendor:
        any_blob = haystacks.get("any", "")
        for pattern in _GENERIC_SIGNALS:
            m = pattern.search(any_blob)
            if m:
                evidence.append(f"generic camera signal → {m.group(0)!r}")
                best_conf = "medium"

    # An RTSP responder with no HTTP info is still strong evidence.
    if not evidence and any(p.protocol == "rtsp" for p in probes):
        evidence.append("RTSP server responding on 554")
        best_conf = "medium"

    return ServiceMatch(
        host=host, vendor=vendor, confidence=best_conf,
        evidence=tuple(evidence), probes=probes,
    )


def _conf_rank(c: Confidence) -> int:
    return {"low": 0, "medium": 1, "high": 2}[c]

"""tls_handshakes: client offer vs server choice, alerts, certificates and outcome, on synthetic captures.

The TLS records are built by hand from RFC 8446 / RFC 5246 so the tests need no TLS library.
The certificate is a structurally valid DER X.509 with a dummy key and signature; it is never verified.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw  # type: ignore

from tshark_mcp import tls as tlsmod

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

CLIENT = "198.51.100.30"
SERVER = "203.0.113.43"
GREASE = 0x0A0A


# ----------------------------------------------------------------- TLS records
def _u8(b: bytes) -> bytes:
    return struct.pack("!B", len(b)) + b


def _u16(b: bytes) -> bytes:
    return struct.pack("!H", len(b)) + b


def _u24(b: bytes) -> bytes:
    return struct.pack("!I", len(b))[1:] + b


def record(ctype: int, body: bytes, version: int = 0x0303) -> bytes:
    return struct.pack("!BHH", ctype, version, len(body)) + body


def handshake(htype: int, body: bytes) -> bytes:
    return struct.pack("!B", htype) + _u24(body)


def ext(etype: int, body: bytes) -> bytes:
    return struct.pack("!H", etype) + _u16(body)


def client_hello(sni: str | None, versions=(0x0304, 0x0303), alpn=("h2", "http/1.1"),
                 suites=(GREASE, 0x1301, 0x1302, 0xC02F, 0xC030)) -> bytes:
    exts = b""
    if sni:
        exts += ext(0, _u16(b"\x00" + _u16(sni.encode())))
    if alpn:
        exts += ext(16, _u16(b"".join(_u8(a.encode()) for a in alpn)))
    if versions:
        exts += ext(43, _u8(b"".join(struct.pack("!H", v) for v in (GREASE, *versions))))
    body = (struct.pack("!H", 0x0303) + os.urandom(32) + _u8(os.urandom(32))
            + _u16(b"".join(struct.pack("!H", s) for s in suites)) + b"\x01\x00" + _u16(exts))
    return record(22, handshake(1, body), version=0x0301)


def server_hello(version: int = 0x0304, suite: int = 0x1301, random: bytes | None = None) -> bytes:
    exts = ext(43, struct.pack("!H", version)) if version == 0x0304 else b""
    body = (struct.pack("!H", 0x0303) + (random or os.urandom(32)) + _u8(os.urandom(32)) + struct.pack("!H", suite)
            + b"\x00" + _u16(exts))
    return record(22, handshake(2, body))


def certificate_msg(der: bytes) -> bytes:
    return handshake(11, _u24(_u24(der)))


def alert(level: int, desc: int) -> bytes:
    return record(21, bytes([level, desc]))


CCS = record(20, b"\x01")


def app_data(n: int) -> bytes:
    return record(23, os.urandom(n))


# ----------------------------------------------------------------- DER certificate
def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = b"\x81" + bytes([n])
    else:
        length = b"\x82" + struct.pack("!H", n)
    return bytes([tag]) + length + content


def _seq(*items: bytes) -> bytes:
    return _der(0x30, b"".join(items))


def _name(cn: str, org: str) -> bytes:
    return _seq(_der(0x31, _seq(_der(0x06, bytes.fromhex("55040a")), _der(0x0C, org.encode()))),
                _der(0x31, _seq(_der(0x06, bytes.fromhex("550403")), _der(0x0C, cn.encode()))))


def make_cert(cn: str, sans: list[str], not_before: str, not_after: str, issuer: str = "Test CA") -> bytes:
    alg = _seq(_der(0x06, bytes.fromhex("2a864886f70d01010b")), b"\x05\x00")
    spki = _seq(_seq(_der(0x06, bytes.fromhex("2a864886f70d010101")), b"\x05\x00"), _der(0x03, b"\x00" + b"\x01" * 16))
    san = _seq(_der(0x06, bytes.fromhex("551d11")), _der(0x04, _seq(*[_der(0x82, s.encode()) for s in sans])))
    tbs = _seq(_der(0xA0, _der(0x02, b"\x02")), _der(0x02, b"\x01\x23"), alg, _name(issuer, "Example Test Org"),
               _seq(_der(0x17, not_before.encode()), _der(0x17, not_after.encode())), _name(cn, "Example Org"), spki,
               _der(0xA3, _seq(san)))
    return _seq(tbs, alg, _der(0x03, b"\x00" + b"\x02" * 16))


# ----------------------------------------------------------------- TCP connections
class Capture:
    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.t = 1_700_040_000.0
        self.port = 50000

    def conn(self) -> "Conn":
        self.port += 1
        return Conn(self, self.port)

    def write(self, path: Path) -> Path:
        return g._frames_to_pcap(path, self.frames)


class Conn:
    def __init__(self, cap: Capture, port: int) -> None:
        self.cap, self.port = cap, port
        self.seq = {"c": 1000, "s": 9000}

    def send(self, side: str, payload: bytes = b"", flags: str = "PA", dt: float = 0.005, copy: bool = False) -> None:
        other = "s" if side == "c" else "c"
        src, dst, sport, dport = (CLIENT, SERVER, self.port, 443) if side == "c" else (SERVER, CLIENT, 443, self.port)
        pkt = Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=src, dst=dst) / TCP(
            sport=sport, dport=dport, flags=flags, seq=self.seq[side], ack=self.seq[other]) / (Raw(payload) if payload else b"")
        self.cap.t += dt
        self.cap.frames.append((self.cap.t, bytes(pkt)))
        if copy:
            self.cap.frames.append((self.cap.t + 0.0001, bytes(pkt)))
        self.seq[side] += len(payload) + (1 if "S" in flags or "F" in flags else 0)

    def open(self) -> "Conn":
        self.send("c", flags="S")
        self.send("s", flags="SA")
        self.send("c", flags="A")
        return self


def tls13_ok(cap: Capture, sni: str, copy_hello: bool = False) -> None:
    c = cap.conn().open()
    c.send("c", client_hello(sni), copy=copy_hello)
    c.send("s", server_hello() + CCS + app_data(1200) + app_data(80), dt=0.030)
    c.send("c", CCS + app_data(53))
    c.send("c", app_data(300))
    c.send("s", app_data(900), dt=0.040)


def scenario(path: Path) -> Path:
    cap = Capture()
    tls13_ok(cap, "ok.example.com", copy_hello=True)
    # The server refuses the offer outright.
    c = cap.conn().open()
    c.send("c", client_hello("legacy.example.net", versions=(), suites=(0x000A,)))
    c.send("s", alert(2, 40), dt=0.020)
    c.send("s", flags="FA")
    # TLS 1.2 with a certificate that has expired and does not name the SNI; the handshake still completes.
    c = cap.conn().open()
    c.send("c", client_hello("api.example.com"))
    cert = make_cert("www.example.com", ["www.example.com", "*.cdn.example.com"], "200101000000Z", "210101000000Z")
    c.send("s", server_hello(0x0303, 0xC02F) + record(22, certificate_msg(cert) + handshake(14, b"")), dt=0.025)
    c.send("c", record(22, handshake(16, os.urandom(66))) + CCS + record(22, os.urandom(40)))
    c.send("s", CCS + record(22, os.urandom(40)), dt=0.020)
    c.send("c", app_data(200))
    # TLS 1.3: the client answers the encrypted server flight with one alert-sized record and leaves.
    c = cap.conn().open()
    c.send("c", client_hello("reject.example.com"))
    c.send("s", server_hello() + CCS + app_data(2500) + app_data(90), dt=0.030)
    c.send("c", CCS + record(23, os.urandom(19)))
    c.send("c", flags="FA")
    # Reset by the server instead of a ServerHello.
    c = cap.conn().open()
    c.send("c", client_hello("rst.example.com"))
    c.send("s", flags="RA", dt=0.010)
    # HelloRetryRequest, then a second ClientHello and the real ServerHello.
    c = cap.conn().open()
    c.send("c", client_hello("hrr.example.com"))
    c.send("s", server_hello(random=bytes.fromhex(tlsmod.HRR_RANDOM)) + CCS, dt=0.020)
    c.send("c", client_hello("hrr.example.com"))
    c.send("s", server_hello() + app_data(1500) + app_data(80), dt=0.020)
    c.send("c", app_data(53) + app_data(200))
    # Nothing ever comes back.
    c = cap.conn().open()
    c.send("c", client_hello("silent.example.org"))
    return cap.write(path)


def _row(rows, sni):
    return next(r for r in rows if r.get("sni") == sni)


def test_established_tls13_offer_and_choice(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.tls_handshakes(str(scenario(tmp_path / "tls.pcap")))
    ok = _row(out["connections"], "ok.example.com")
    assert ok["outcome"] == "established" and "issues" not in ok
    assert ok["offered"] == {"versions": ["TLS 1.3", "TLS 1.2"], "alpn": ["h2", "http/1.1"], "cipher_suites": 4}
    assert ok["chosen"] == {"version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256"}
    assert ok["server_hello_ms"] == 30.0 and ok["tcp_to_hello_ms"] == 15.0
    assert ok["duplicate_copies"] == 1 and "client_hellos" not in ok  # the copied ClientHello counts once
    assert out["summary"]["connections"] == out["total_found"] == 7


def test_server_alert_before_server_hello(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.tls_handshakes(str(scenario(tmp_path / "tls.pcap")))
    row = _row(out["connections"], "legacy.example.net")
    assert row["outcome"] == "alert" and row["note"] == "server sent handshake_failure"
    assert row["alerts"][0] == {"from": "server", "level": "fatal", "description": "handshake_failure",
                                "frame": row["alerts"][0]["frame"]}
    assert row["offered"]["versions"] == ["TLS 1.2"] and row["offered"]["cipher_suites"] == 1
    assert out["summary"]["alerts"] == {"server: handshake_failure": 1}


def test_tls12_certificate_expired_and_name_mismatch(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.tls_handshakes(str(scenario(tmp_path / "tls.pcap")))
    row = _row(out["connections"], "api.example.com")
    assert row["outcome"] == "established"
    assert row["chosen"]["version"] == "TLS 1.2"
    assert row["chosen"]["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    cert = row["certificate"]
    assert cert["subject_cn"] == "www.example.com" and cert["issuer_cn"] == "Test CA"
    assert cert["san"] == ["www.example.com", "*.cdn.example.com"] and cert["chain_length"] == 1
    assert cert["not_after"] == "2021-01-01T00:00:00.000Z"
    assert any("certificate expired 2021-01-01" in i for i in row["issues"])
    assert any("does not name api.example.com" in i for i in row["issues"])


def test_failed_outcomes(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.tls_handshakes(str(scenario(tmp_path / "tls.pcap")))
    rows = out["connections"]
    assert _row(rows, "reject.example.com")["outcome"] == "client_rejected_likely"
    assert _row(rows, "rst.example.com")["outcome"] == "reset_by_server"
    assert _row(rows, "silent.example.org")["outcome"] == "no_server_hello"
    hrr = _row(rows, "hrr.example.com")
    assert hrr["hello_retry_request"] is True and hrr["client_hellos"] == 2 and hrr["outcome"] == "established"
    assert any("HelloRetryRequest" in i for i in hrr["issues"])
    assert out["summary"]["outcomes"] == {"established": 3, "alert": 1, "client_rejected_likely": 1,
                                          "reset_by_server": 1, "no_server_hello": 1}
    # Problem connections first.
    assert rows[-1]["sni"] == "ok.example.com"
    assert any(i.startswith("4 of 7 handshakes did not complete") for i in out["issues"])


def test_server_name_filter(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(scenario(tmp_path / "tls.pcap"))
    out = srv.tls_handshakes(path, server_name="Example.COM")
    assert {r["sni"] for r in out["connections"]} == {
        "ok.example.com", "api.example.com", "reject.example.com", "rst.example.com", "hrr.example.com"}
    assert srv.tls_handshakes(path, server_name="a b")["error"]["type"] == "invalid_argument"


def test_certificate_parser_and_name_matching():
    der = make_cert("svc.example.com", ["svc.example.com", "*.example.org"], "250101000000Z", "991231235959Z")
    cert = tlsmod.parse_certificate(der)
    assert cert["subject_o"] == "Example Org" and cert["issuer_o"] == "Example Test Org"
    assert cert["not_after"] is not None and cert["san_dns"] == ["svc.example.com", "*.example.org"]
    assert tlsmod.name_covered("svc.example.com", cert)
    assert tlsmod.name_covered("a.example.org", cert) and not tlsmod.name_covered("a.b.example.org", cert)
    assert tlsmod.parse_certificate(b"\x30\x05\x01") is None
    assert tlsmod._grease(0x1A1A) and not tlsmod._grease(0x1301)


def test_server_side_reported_when_client_hello_is_not_in_the_capture(configure, tmp_path: Path):
    cap = Capture()
    c = cap.conn().open()
    c.seq["c"] += 517  # the ClientHello was sent but not captured
    cert = make_cert("mid.example.com", ["mid.example.com"], "250101000000Z", "991231235959Z")
    c.send("s", server_hello(0x0303, 0xC030) + record(22, certificate_msg(cert) + handshake(14, b"")), dt=0.02)
    c.send("c", record(22, handshake(16, os.urandom(66))) + CCS + record(22, os.urandom(40)))
    c.send("s", CCS + record(22, os.urandom(40)), dt=0.02)
    c.send("c", app_data(120))
    other = cap.conn().open()  # a connection with no TLS at all is not listed
    other.send("c", b"x" * 10)
    srv = configure(allow=[str(tmp_path)])
    path = str(cap.write(tmp_path / "noch.pcap"))
    out = srv.tls_handshakes(path)
    assert out["summary"]["connections"] == 1 and out["summary"]["streams_without_client_hello"] == 1
    row = out["connections"][0]
    assert row["client_hello_missing"] is True and "sni" not in row and row["outcome"] == "established"
    assert row["chosen"]["version"] == "TLS 1.2" and row["certificate"]["subject_cn"] == "mid.example.com"
    assert row["client"] == f"{CLIENT}:{c.port}"
    assert srv.tls_handshakes(path, server_name="mid.example.com")["summary"]["connections"] == 1


def test_pages(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(scenario(tmp_path / "tls.pcap"))
    full = srv.tls_handshakes(path)
    page = srv.tls_handshakes(path, limit=2, offset=2)
    assert page["connections"] == full["connections"][2:4]
    assert page["total_matched"] == 7 and page["dropped"] == 3 and page["next_offset"] == 4

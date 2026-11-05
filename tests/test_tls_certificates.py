"""tls_certificates: chains built by hand in DER and sent in TLS 1.2 handshakes (the test_tls generators)."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from tshark_mcp import certs, models
from tshark_mcp import server as srv
from tshark_mcp.limits import Limits

from .conftest import TSHARK, requires_tshark
from .test_tls import (SERVER, CCS, Capture, _der, _seq, _u24, alert, app_data, client_hello, handshake, record,
                       server_hello, tls13_ok)

pytestmark = requires_tshark

SHA256_RSA = "2a864886f70d01010b"
SHA1_RSA = "2a864886f70d010105"


def _name(cn: str) -> bytes:
    return _seq(_der(0x31, _seq(_der(0x06, bytes.fromhex("55040a")), _der(0x0C, b"Example Test Org"))),
                _der(0x31, _seq(_der(0x06, bytes.fromhex("550403")), _der(0x0C, cn.encode()))))


def _rsa_spki(bits: int) -> bytes:
    modulus = (1 << (bits - 1)) | 1                     # top bit set: exactly ``bits`` long; nobody verifies it
    body = _seq(_der(0x02, b"\x00" + modulus.to_bytes(bits // 8, "big")), _der(0x02, b"\x01\x00\x01"))
    return _seq(_seq(_der(0x06, bytes.fromhex("2a864886f70d010101")), b"\x05\x00"), _der(0x03, b"\x00" + body))


def _ec_spki() -> bytes:
    return _seq(_seq(_der(0x06, bytes.fromhex("2a8648ce3d0201")), _der(0x06, bytes.fromhex("2a8648ce3d030107"))),
                _der(0x03, b"\x00\x04" + b"\x11" * 64))


def cert(cn: str, issuer: str, sans: list[str] | None = None, not_after: str = "301231235959Z",
         sig: str = SHA256_RSA, spki: bytes | None = None, ca: bool = False, serial: int = 7) -> bytes:
    alg = _seq(_der(0x06, bytes.fromhex(sig)), b"\x05\x00")
    exts = []
    if sans is not None:
        exts.append(_seq(_der(0x06, bytes.fromhex("551d11")), _der(0x04, _seq(*[_der(0x82, s.encode()) for s in sans]))))
    if ca:
        exts.append(_seq(_der(0x06, bytes.fromhex("551d13")), _der(0x01, b"\xff"), _der(0x04, _seq(_der(0x01, b"\xff")))))
    tbs = _seq(_der(0xA0, _der(0x02, b"\x02")), _der(0x02, serial.to_bytes(2, "big")), alg, _name(issuer),
               _seq(_der(0x17, b"230101000000Z"), _der(0x17, not_after.encode())), _name(cn),
               spki or _rsa_spki(2048), *( [_der(0xA3, _seq(*exts))] if exts else []))
    return _seq(tbs, alg, _der(0x03, b"\x00" + b"\x02" * 16))


INTERMEDIATE = cert("Test Intermediate CA", "Test Root CA", ca=True, serial=2)
ROOT = cert("Test Root CA", "Test Root CA", ca=True, serial=1)


def chain_msg(ders: list[bytes]) -> bytes:
    return handshake(11, _u24(b"".join(_u24(d) for d in ders)))


def tls12(cap: Capture, sni: str, chain: list[bytes], staple: bool = False, client_alert: int | None = None) -> None:
    c = cap.conn().open()
    c.send("c", client_hello(sni))
    flight = chain_msg(chain) + (handshake(22, b"\x01" + _u24(b"ocsp-response")) if staple else b"") + handshake(14, b"")
    c.send("s", server_hello(0x0303, 0xC02F) + record(22, flight), dt=0.025)
    if client_alert is not None:
        c.send("c", alert(2, client_alert))
        c.send("c", flags="FA")
        return
    c.send("c", record(22, handshake(16, os.urandom(66))) + CCS + record(22, os.urandom(40)))
    c.send("s", CCS + record(22, os.urandom(40)), dt=0.020)
    c.send("c", app_data(200))


@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    cap = Capture()  # starts at 2023-11-15 09:20 UTC
    good = cert("good.example.com", "Test Intermediate CA", ["good.example.com", "*.good.example.com"])
    tls12(cap, "good.example.com", [good, INTERMEDIATE], staple=True)
    tls12(cap, "good.example.com", [good, INTERMEDIATE], staple=True)
    tls12(cap, "noint.example.com", [cert("noint.example.com", "Test Intermediate CA", ["noint.example.com"])])
    tls12(cap, "self.example.com", [cert("self.example.com", "self.example.com", ["self.example.com"])])
    tls12(cap, "sha1.example.com", [cert("sha1.example.com", "Test Intermediate CA", ["sha1.example.com"], sig=SHA1_RSA,
                                         spki=_rsa_spki(1024)), INTERMEDIATE])
    tls12(cap, "soon.example.com", [cert("soon.example.com", "Test Intermediate CA", ["soon.example.com"],
                                         not_after="231118000000Z", spki=_ec_spki()), INTERMEDIATE])
    tls12(cap, "wrong.example.com", [cert("other.example.com", "Test Intermediate CA", ["other.example.com"]),
                                     INTERMEDIATE], client_alert=42)
    tls12(cap, "order.example.com", [cert("order.example.com", "Test Intermediate CA", ["order.example.com"]),
                                     ROOT, INTERMEDIATE])
    tls13_ok(cap, "tls13.example.com")
    d = tmp_path_factory.mktemp("certs")
    return cap.write(d / "certs.pcap")


@pytest.fixture
def tc(capture: Path):
    srv.configure([str(capture.parent)], limits=Limits(), tshark=TSHARK)
    yield srv
    srv._STATE = None


def _chain(out: dict, sni: str) -> dict:
    return next(c for c in out["chains"] if c.get("sni") == sni)


def test_good_chain_is_grouped_and_clean(tc, capture: Path):
    out = tc.tls_certificates(str(capture))
    assert "error" not in out, out
    TypeAdapter(models.TlsCertificatesResult).validate_python(out)
    good = _chain(out, "good.example.com")
    assert good["connections"] == 2 and good["chain_length"] == 2 and good["order_ok"] and good["ocsp_stapled"]
    assert not good["missing_intermediate"] and not good["expired"] and good["name_matches"] and "issues" not in good
    leaf = good["leaf"]
    assert leaf["subject_cn"] == "good.example.com" and leaf["issuer_cn"] == "Test Intermediate CA"
    assert leaf["key_algorithm"] == "RSA" and leaf["key_bits"] == 2048 and leaf["wildcard"]
    assert leaf["signature_algorithm"] == "sha256WithRSAEncryption" and len(leaf["fingerprint_sha256"]) == 64
    assert leaf["days_left"] > 2500 and good["intermediates"][0]["is_ca"]
    assert good["tls_versions"] == {"TLS 1.2": 2} and good["server"] == f"{SERVER}:443"
    s = out["summary"]
    assert s["chains"] == 7 and s["connections"] == 8 and s["tls13_connections_skipped"] == 1
    assert any("1 TLS 1.3 connections carry their certificates encrypted" in i for i in out["issues"])


def test_each_problem_is_named(tc, capture: Path):
    out = tc.tls_certificates(str(capture))
    noint = _chain(out, "noint.example.com")
    assert noint["missing_intermediate"] and any("none issued the leaf" in i for i in noint["issues"])
    own = _chain(out, "self.example.com")
    assert own["self_signed"] and not own["missing_intermediate"] and any("self-signed" in i for i in own["issues"])
    weak = _chain(out, "sha1.example.com")
    assert any("signed with sha1WithRSAEncryption" in i for i in weak["issues"])
    assert any("1024-bit RSA key" in i for i in weak["issues"])
    soon = _chain(out, "soon.example.com")
    assert 0 < soon["leaf"]["days_left"] < 3 and soon["leaf"]["key_algorithm"] == "EC" and soon["leaf"]["key_curve"] == "P-256"
    assert any("expires in" in i for i in soon["issues"])
    wrong = _chain(out, "wrong.example.com")
    assert wrong["name_matches"] is False and wrong["clients_rejected"] == 1
    assert any("does not name wrong.example.com" in i for i in wrong["issues"])
    assert wrong["alerts"] == {"client: bad_certificate": 1}
    order = _chain(out, "order.example.com")
    assert order["order_ok"] is False and order["chain_length"] == 3
    assert out["chains"][-1]["sni"] == "good.example.com"  # chains with issues first
    s = out["summary"]
    assert (s["self_signed"], s["name_mismatch"], s["missing_intermediate"], s["weak_signature"]) == (1, 1, 1, 1)
    assert s["expiring_within_30_days"] == 1


def test_narrowing_and_paging(tc, capture: Path):
    one = tc.tls_certificates(str(capture), server_name="noint.example.com")
    assert [c["sni"] for c in one["chains"]] == ["noint.example.com"]
    soon = tc.tls_certificates(str(capture), expiring_within_days=10)
    assert [c["sni"] for c in soon["chains"]] == ["soon.example.com"]
    assert len(tc.tls_certificates(str(capture), server=SERVER)["chains"]) == 7
    assert tc.tls_certificates(str(capture), server="192.0.2.99")["chains"] == []
    page = tc.tls_certificates(str(capture), limit=2, offset=2)
    assert page["returned"] == 2 and page["next_offset"] == 4
    assert tc.tls_certificates(str(capture), expiring_within_days="soon")["error"]["type"] == "invalid_argument"
    assert tc.tls_certificates(str(capture), server="nope")["error"]["type"] == "invalid_argument"
    early = tc.tls_certificates(str(capture), end="+0.1s")
    assert {c["sni"] for c in early["chains"]} <= {"good.example.com"}


def test_parser_reads_ca_flag_and_self_signed_root():
    root = certs.parse_full(ROOT)
    assert root["self_signed"] and root["is_ca"] and root["subject_cn"] == "Test Root CA"
    leaf = certs.parse_full(cert("x.example", "Test Root CA", ["x.example"]))
    assert not leaf["is_ca"] and leaf["issuer_dn"] == root["subject_dn"]
    assert certs.parse_full(b"\x30\x03\x02\x01\x00") is None


async def _over_stdio(capture: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "tshark_mcp.server", "--allow-dir", str(capture.parent)],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool("tls_certificates", {"path": str(capture), "server_name": "wrong.example.com"})


def test_tls_certificates_over_stdio(capture: Path):
    got = asyncio.run(_over_stdio(capture))
    out = got.structured_content
    assert not got.is_error and out["chains"][0]["name_matches"] is False and "untrusted_text_fields" in out

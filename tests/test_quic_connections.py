"""quic_connections: QUIC long and short headers written by hand (dummy payloads), plus a TCP fallback."""

from __future__ import annotations

import asyncio
import os
import struct
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import IP, UDP, Ether, Raw  # type: ignore

from tshark_mcp import models
from tshark_mcp import server as srv
from tshark_mcp.limits import Limits

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark
from .test_tls import CLIENT, SERVER, Capture, client_hello

pytestmark = requires_tshark

OK_SRV, VN_SRV, RETRY_SRV, HALF_SRV = "203.0.113.60", "203.0.113.61", "203.0.113.62", "203.0.113.63"
CD, CS, SS = bytes.fromhex("1122334455667788"), bytes.fromhex("a1a2a3a4"), bytes.fromhex("b1b2b3b4b5b6b7b8")


def long_hdr(ptype: int, version: int, dcid: bytes, scid: bytes, size: int = 40) -> bytes:
    b = bytes([0xC0 | (ptype << 4) | 0x03]) + struct.pack(">I", version) + bytes([len(dcid)]) + dcid
    b += bytes([len(scid)]) + scid
    if ptype == 0:
        b += b"\x00"  # empty token
    body = b"\x00\x00\x00\x01" + b"\x00" * size
    return b + struct.pack(">H", 0x4000 | len(body)) + body


def version_negotiation(dcid: bytes, scid: bytes, versions: list[int]) -> bytes:
    return (bytes([0x80]) + b"\x00" * 4 + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
            + b"".join(struct.pack(">I", v) for v in versions))


def retry(dcid: bytes, scid: bytes, token: bytes) -> bytes:
    return bytes([0xF0]) + struct.pack(">I", 1) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + token + b"\x00" * 16


def short_hdr(dcid: bytes, spin: int) -> bytes:
    return bytes([0x40 | (spin << 5) | 0x03]) + dcid + b"\x00\x00\x00\x02" + b"\x00" * 30


class Quic:
    def __init__(self, cap: Capture) -> None:
        self.cap = cap

    def send(self, src: str, dst: str, sport: int, dport: int, payload: bytes, dt: float = 0.01) -> None:
        self.cap.t += dt
        self.cap.frames.append((self.cap.t, bytes(Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=src, dst=dst)
                                                  / UDP(sport=sport, dport=dport) / Raw(payload))))


@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    cap = Capture()
    q = Quic(cap)
    # Established, with spin-bit flips every 50 ms from the client, then a move to a new port.
    q.send(CLIENT, OK_SRV, 50000, 443, long_hdr(0, 1, CD, CS, 1100))
    q.send(OK_SRV, CLIENT, 443, 50000, long_hdr(0, 1, CS, SS) + long_hdr(2, 1, CS, SS))
    q.send(CLIENT, OK_SRV, 50000, 443, long_hdr(2, 1, SS, CS))
    for i in range(8):
        q.send(CLIENT, OK_SRV, 50000, 443, short_hdr(SS, (i // 2) % 2), dt=0.025)
        q.send(OK_SRV, CLIENT, 443, 50000, short_hdr(CS, (i // 2) % 2), dt=0.001)
    q.send(CLIENT, OK_SRV, 50010, 443, short_hdr(SS, 0))
    q.send(OK_SRV, CLIENT, 443, 50010, short_hdr(CS, 0))
    # A version the server does not support: Version Negotiation and nothing after it.
    q.send(CLIENT, VN_SRV, 50001, 443, long_hdr(0, 0x1A2A3A4A, bytes.fromhex("0102030405060708"), b"\x09\x09"))
    q.send(VN_SRV, CLIENT, 443, 50001, version_negotiation(b"\x09\x09", bytes.fromhex("0102030405060708"),
                                                           [1, 0x6B3343CF]))
    # A Retry the client never follows.
    q.send(CLIENT, RETRY_SRV, 50002, 443, long_hdr(0, 1, bytes.fromhex("2122232425262728"), b"\x31\x32"))
    q.send(RETRY_SRV, CLIENT, 443, 50002, retry(b"\x31\x32", b"\x41\x42\x43\x44", b"retry-token"))
    # The server answers the Initial; nothing more.
    q.send(CLIENT, HALF_SRV, 50003, 443, long_hdr(0, 1, bytes.fromhex("5152535455565758"), b"\x61\x62"))
    q.send(HALF_SRV, CLIENT, 443, 50003, long_hdr(0, 1, b"\x61\x62", b"\x71\x72\x73\x74"))
    # Three Initials to SERVER unanswered, then the same client opens TCP with a ClientHello.
    for _ in range(3):
        q.send(CLIENT, SERVER, 50004, 443, long_hdr(0, 1, bytes.fromhex("8182838485868788"), b"\x91\x92", 1100), dt=0.3)
    c = cap.conn().open()
    c.send("c", client_hello("blocked.example.com"))
    d = tmp_path_factory.mktemp("quic")
    return cap.write(d / "quic.pcap")


@pytest.fixture
def qc(capture: Path):
    srv.configure([str(capture.parent)], limits=Limits(), tshark=TSHARK)
    yield srv
    srv._STATE = None


def _conn(out: dict, server: str) -> dict:
    return next(r for r in out["connections"] if r["server"].startswith(server + ":"))


def test_outcomes_per_connection(qc, capture: Path):
    out = qc.quic_connections(str(capture))
    assert "error" not in out, out
    TypeAdapter(models.QuicConnectionsResult).validate_python(out)
    assert out["summary"]["outcomes"] == {"established": 1, "version_negotiation": 1, "retry_unanswered": 1,
                                          "handshake_incomplete": 1, "no_response": 1}
    ok = _conn(out, OK_SRV)
    assert ok["version"] == "QUICv1" and ok["server_initial"] and ok["handshake_packets_both_ways"]
    assert ok["one_rtt_both_ways"] and ok["initial_sent"] == 1 and ok["client"] == f"{CLIENT}:50000"
    assert ok["packets"]["client_1rtt"] == 9 and ok["packets"]["server_handshake"] == 1
    vn = _conn(out, VN_SRV)
    assert vn["version_negotiation"]["supported"] == ["QUICv1", "QUICv2"]
    assert vn["version"].startswith("0x1a2a3a4a (reserved")
    assert any("does not support" in i for i in vn["issues"])
    rt = _conn(out, RETRY_SRV)
    assert rt["retry"]["token"] is True and any("Retry" in i for i in rt["issues"])
    assert _conn(out, HALF_SRV)["server_initial"] and not _conn(out, HALF_SRV).get("handshake_packets_both_ways")
    assert out["connections"][-1]["outcome"] == "established"  # failures first


def test_migration_and_spin_rtt(qc, capture: Path):
    ok = _conn(qc.quic_connections(str(capture)), OK_SRV)
    assert ok["migrated"] and len(ok["migration_frames"]) == 1
    assert any("moved to a new address or port" in i for i in ok["issues"])
    assert ok["spin_rtt_ms"] == pytest.approx(52.0, abs=1.0)  # two client packets 26 ms apart per spin value


def test_tcp_fallback_and_blocked_udp(qc, capture: Path):
    out = qc.quic_connections(str(capture))
    blocked = _conn(out, SERVER)
    assert blocked["outcome"] == "no_response" and blocked["initial_sent"] == 3
    fb = blocked["tcp_fallback"]
    assert fb["sni"] == "blocked.example.com" and fb["server"] == f"{SERVER}:443" and 0 < fb["after_ms"] < 2000
    assert out["summary"]["tcp_fallbacks"] == 1 and "udp_443_blocked_likely" not in out["summary"]
    only = qc.quic_connections(str(capture), server=SERVER)
    assert [r["outcome"] for r in only["connections"]] == ["no_response"]
    assert only["summary"]["udp_443_blocked_likely"] is True and only["issues"][0].startswith("no QUIC server")


def test_arguments_window_and_paging(qc, capture: Path):
    page = qc.quic_connections(str(capture), limit=2)
    assert page["returned"] == 2 and page["next_offset"] == 2 and page["total_matched"] == 5
    assert qc.quic_connections(str(capture), server_name="none.example.com")["connections"] == []
    assert qc.quic_connections(str(capture), server="x")["error"]["type"] == "invalid_argument"
    early = qc.quic_connections(str(capture), end="+0.05s")
    assert [r["server"] for r in early["connections"]] == [f"{OK_SRV}:443"]


async def _over_stdio(capture: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "tshark_mcp.server", "--allow-dir", str(capture.parent)],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool("quic_connections", {"path": str(capture), "server": SERVER})


def test_quic_connections_over_stdio(capture: Path):
    got = asyncio.run(_over_stdio(capture))
    out = got.structured_content
    assert not got.is_error and out["summary"]["udp_443_blocked_likely"] is True

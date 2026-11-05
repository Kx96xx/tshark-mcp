"""quic_connections: both ends on one address, and Google QUIC (public-validation D4, D18).

On a loopback capture the client and the server share an address, so the side of a packet
must come from the (address, port) pair: before the fix every server packet counted as the
client's and a working handshake read as "no answer: UDP 443 blocked". Google QUIC (Q0xx)
packets are not analysed, which the result now says instead of returning nothing.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from .conftest import requires_tshark
from .test_quic_connections import Quic, long_hdr, short_hdr
from .test_tls import Capture

pytestmark = requires_tshark

HOST = "192.0.2.77"
CD, CS, SS = bytes.fromhex("0102030405060708"), bytes.fromhex("c1c2c3c4"), bytes.fromhex("d1d2d3d4d5d6d7d8")


def same_address(path: Path, *, answered: bool = True) -> Path:
    """A client on HOST:42086 and a server on HOST:4443 (both ends on one address)."""
    cap = Capture()
    q = Quic(cap)
    q.send(HOST, HOST, 42086, 4443, long_hdr(0, 1, CD, CS, 1100))
    if answered:
        q.send(HOST, HOST, 4443, 42086, long_hdr(0, 1, CS, SS) + long_hdr(2, 1, CS, SS))
        q.send(HOST, HOST, 42086, 4443, long_hdr(2, 1, SS, CS))
        for i in range(3):
            q.send(HOST, HOST, 42086, 4443, short_hdr(SS, 0), dt=0.02)
            q.send(HOST, HOST, 4443, 42086, short_hdr(CS, 0), dt=0.001)
    else:
        q.send(HOST, HOST, 42086, 4443, long_hdr(0, 1, CD, CS, 1100), dt=0.3)
    return cap.write(path)


def gquic(path: Path, n: int = 4) -> Path:
    """Google QUIC Q043 public headers (flags: version + 8-byte connection ID, 1-byte packet number) on UDP 443."""
    cap = Capture()
    q = Quic(cap)
    cid = bytes.fromhex("1112131415161718")
    for pn in range(1, n + 1):
        q.send("198.51.100.30", "203.0.113.90", 51000, 443, bytes([0x09]) + cid + b"Q043" + bytes([pn]) + b"\x00" * 60)
    return cap.write(path)


def _call(configure, tmp_path: Path, path: Path) -> dict:
    srv = configure(allow=[str(tmp_path)])
    out = srv.quic_connections(str(path))
    assert "error" not in out, out
    return out


def test_same_address_handshake_is_established(configure, tmp_path):
    out = _call(configure, tmp_path, same_address(tmp_path / "loop.pcap"))
    [row] = out["connections"]
    assert row["client"] == f"{HOST}:42086" and row["server"] == f"{HOST}:4443"
    assert row["outcome"] == "established" and row["server_initial"] is True
    assert row["packets"]["server_initial"] == 1 and row["packets"]["server_1rtt"] == 3
    assert "servers_never_answering" not in out["summary"]
    assert not any("no answer" in i for i in out["issues"])


def test_unanswered_issue_names_the_real_port(configure, tmp_path):
    out = _call(configure, tmp_path, same_address(tmp_path / "loop.pcap", answered=False))
    [row] = out["connections"]
    assert row["outcome"] == "no_response"
    assert any("UDP 4443 blocked" in i for i in row["issues"]) and not any("443 blocked" in i and "4443" not in i
                                                                           for i in row["issues"])


def test_gquic_is_counted_not_silent(configure, tmp_path):
    out = _call(configure, tmp_path, gquic(tmp_path / "gquic.pcap"))
    assert out["connections"] == []
    assert out["summary"]["gquic_packets"] == 4
    assert any("Google QUIC" in i and "not analysed" in i for i in out["issues"])


def test_same_address_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = same_address(tmp_path / "loop.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("quic_connections", {"path": str(cap)})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    out = asyncio.run(go())
    assert out["summary"]["outcomes"] == {"established": 1}


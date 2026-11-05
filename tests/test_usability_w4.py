"""Usability fixes from the public-capture validation (D20, D21, D23).

D20: throughput_timeline refused a capture longer than 10,000 s by default; without an
`interval` it now picks one that fits and says so.
D21: cause_lookup refused nas, dns and tls; `nas` searches the four NAS tables, and DNS rcodes,
TLS alerts, ICMP type:code and HTTP status codes have small tables.
D23: find_identifier on a directory of subdirectories found nothing and did not say why; it
names the subdirectories that hold captures, and max_files defaults to the server cap.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import IP, UDP, Ether, Raw  # type: ignore

from tshark_mcp import models
from tshark_mcp.limits import Limits

from . import pcapgen as g
from .conftest import requires_tshark


def _long_capture(path: Path, days: float = 3.0) -> Path:
    """Two UDP packets ``days`` apart (more than 10,000 one-second intervals)."""
    pkt = bytes(Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1000, dport=2000)
                / Raw(b"x" * 20))
    t0 = 1_700_004_000.0
    return g._frames_to_pcap(path, [(t0, pkt), (t0 + days * 86_400, pkt)])


@requires_tshark
def test_throughput_picks_an_interval_that_fits(configure, tmp_path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.throughput_timeline(str(_long_capture(tmp_path / "long.pcap")))
    assert "error" not in out, out
    TypeAdapter(models.ThroughputTimelineResult).validate_python(out)
    assert out["interval_auto"] is True and out["interval_s"] == 30.0  # 3 days / 30 s = 8,641 intervals
    explicit = srv.throughput_timeline(str(tmp_path / "long.pcap"), interval=1.0)
    assert explicit["error"]["type"] == "invalid_argument"  # an explicit interval is still honoured


@requires_tshark
def test_throughput_keeps_one_second_on_short_captures(configure, tmp_path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.throughput_timeline(str(_long_capture(tmp_path / "short.pcap", days=0.001)))
    assert out["interval_s"] == 1.0 and out["interval_auto"] is True


@pytest.mark.parametrize("protocol, code, name", [
    ("dns", 2, "SERVFAIL"), ("rcode", 3, "NXDOMAIN"), ("tls", 48, "unknown_ca"), ("tls_alert", 112, "unrecognized_name"),
    ("icmp", "3:13", "communication administratively prohibited"), ("icmp", "3/4", "fragmentation needed"),
    ("icmpv6", "2:0", "packet too big"), ("http", 502, "Bad Gateway"),
])
def test_cause_lookup_network_tables(server, protocol, code, name):
    out = server.cause_lookup(protocol, code=code)
    assert "error" not in out, out
    assert out["name"] == name and out["known"] is True and out["explained"] is True and out["ref"]


def test_cause_lookup_nas_searches_every_nas_table(server):
    out = server.cause_lookup("nas", code=7)
    assert out["protocol"] == "nas_emm" and out["name"]
    assert {t["protocol"] for t in out["other_tables"]} <= {"nas_esm", "nas_5gmm", "nas_5gsm"}
    assert "searched EMM, ESM, 5GMM and 5GSM" in out["note"]
    found = server.cause_lookup("nas", query="roaming")
    assert found["codes"] and {c["protocol"] for c in found["codes"]} <= {"nas_emm", "nas_esm", "nas_5gmm", "nas_5gsm"}


def test_cause_lookup_icmp_needs_type_and_code(server):
    assert server.cause_lookup("icmp", code=3)["error"]["type"] == "invalid_argument"


@requires_tshark
def test_find_identifier_names_subdirectories_and_scans_up_to_the_cap(configure, tmp_path):
    root = tmp_path / "caps"
    for name in ("site-a", "site-b"):
        (root / name).mkdir(parents=True)
        g.write_diameter_pcap(root / name / "s6a.pcap")
    (root / "empty").mkdir()
    srv = configure(allow=[str(tmp_path)])
    out = srv.find_identifier(str(root), g.IMSI)
    assert out["files_found"] == 0 and out["subdirectories_with_captures"] == ["site-a", "site-b"]
    assert "not searched" in out["note"]
    # Without max_files every file up to the server cap is scanned (the old default was 20).
    flat = tmp_path / "flat"
    flat.mkdir()
    for i in range(25):
        (flat / f"c{i:02d}.pcap").write_bytes((root / "site-a" / "s6a.pcap").read_bytes())
    srv = configure(allow=[str(tmp_path)], limits=Limits(max_files=30))
    out = srv.find_identifier(str(flat), g.IMSI)
    assert out["files_scanned"] == 25 and out["files_with_hits"] == 25 and "next_offset" not in out


@requires_tshark
def test_usability_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = _long_capture(tmp_path / "long.pcap")

    async def go() -> tuple[dict, dict]:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                outs = []
                for name, args in (("throughput_timeline", {"path": str(cap)}),
                                   ("cause_lookup", {"protocol": "dns", "code": 2})):
                    res = await session.call_tool(name, args)
                    structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                    outs.append(structured or json.loads(res.content[0].text))
                return outs[0], outs[1]

    tput, cause = asyncio.run(go())
    assert tput["interval_auto"] is True and cause["name"] == "SERVFAIL"

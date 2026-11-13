"""correlate_captures: one traffic captured upstream (A) and downstream (B) of a NAT."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap  # type: ignore

from tshark_mcp import server as srv
from tshark_mcp.limits import Limits

from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark
T0 = 1_700_000_000.0


def _pkts(nat: bool) -> list:
    """20 TCP and 10 UDP packets from 10.0.0.5; at B (nat=True) the source is 203.0.113.9, TTL is 2
    lower, UDP DSCP is remarked 46 -> 0, the clock is 0.5 s later and UDP packets 3 and 7 are gone."""
    out = []
    src = "203.0.113.9" if nat else "10.0.0.5"
    for i in range(20):
        p = Ether() / IP(src=src, dst="198.51.100.20", id=100 + i, ttl=62 if nat else 64) / TCP(
            sport=40000 if not nat else 61000, dport=443, seq=1000 + 100 * i, ack=5000, flags="A") / Raw(b"x" * 60)
        p.time = T0 + 0.01 * i + (0.5 if nat else 0)
        out.append(p)
    for i in range(10):
        if nat and i in (3, 7):
            continue
        p = Ether() / IP(src=src, dst="198.51.100.30", id=500 + i, ttl=62 if nat else 64, tos=0 if nat else 46 << 2) / UDP(
            sport=5060 if not nat else 62000, dport=5060) / Raw(b"y" * (40 + i))
        p.time = T0 + 0.05 + 0.02 * i + (0.5 if nat else 0)
        out.append(p)
    return sorted(out, key=lambda p: p.time)


@pytest.fixture(scope="module")
def caps(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("correlate")
    wrpcap(str(d / "a.pcap"), _pkts(False))
    wrpcap(str(d / "b.pcap"), _pkts(True))
    return d


@pytest.fixture
def cc(caps: Path):
    srv.configure([str(caps)], limits=Limits(), tshark=TSHARK)
    from tshark_mcp.tools import correlate_captures as mod
    yield mod
    srv._STATE = None


def test_loss_nat_ttl_dscp_and_clock_offset(cc, caps: Path):
    out = cc.correlate_captures(str(caps / "a.pcap"), str(caps / "b.pcap"))
    assert "error" not in out, out
    TypeAdapter(cc.CorrelateCapturesResult).validate_python(out)
    s = out["summary"]
    assert s["packets_a"] == 30 and s["packets_b"] == 28 and s["matched"] == 28 and s["ambiguous"] == 0
    assert s["lost_between"] == 2 and s["only_b"] == 0 and abs(s["clock_offset_ms"] - 500) < 1
    (lost,) = out["lost_flows"]
    assert lost["flow"] == "udp 10.0.0.5:5060 > 198.51.100.30:5060" and lost["lost"] == 2 and lost["of"] == 10
    assert {r["a"] for r in out["rewrites"]} == {"tcp 10.0.0.5:40000 > 198.51.100.20:443",
                                                  "udp 10.0.0.5:5060 > 198.51.100.30:5060"}
    assert out["ttl_drop"] == {"2": 28}
    assert out["dscp_changes"] == [{"a": 46, "b": 0, "packets": 8}]
    assert "never reached B" in out["verdict"] and "NAT" in out["verdict"] and "2 hop(s)" in out["verdict"]


def test_same_file_matches_everything(cc, caps: Path):
    out = cc.correlate_captures(str(caps / "a.pcap"), str(caps / "a.pcap"))
    assert out["summary"]["matched"] == 30 and out["summary"]["lost_between"] == 0
    assert out["rewrites"] == [] and out["issues"] == [] and out["verdict"].endswith("went missing before B.")


def test_filter_narrows_both_sides(cc, caps: Path):
    out = cc.correlate_captures(str(caps / "a.pcap"), str(caps / "b.pcap"), filter="tcp")
    assert out["summary"]["matched"] == 20 and out["summary"]["lost_between"] == 0


def test_unrelated_captures():
    from tshark_mcp import correlate
    a = [{"frame": 1, "t": 1.0, "src": "a", "dst": "b", "sport": "1", "dport": "2", "proto": 17, "ttl": 64,
          "dscp": 0, "key": (17, "1", "50", "30")}]
    b = [dict(a[0], key=(17, "9", "50", "30"))]
    out = correlate.correlate(a, b)
    assert out["summary"]["matched"] == 0 and "No packet could be matched" in out["verdict"]

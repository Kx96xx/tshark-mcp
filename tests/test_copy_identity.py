"""Which packets are capture copies (public-validation D5, D6).

D5: without an IP ID (IPv6, or IPv4 with ID 0) the copy key relied on the UDP checksum. A
checksum offloaded to the NIC is the same partial sum on every datagram of one size, so
distinct packets of one flow (QUIC, RTP, DNS) were taken for copies, and because the tracker
kept the latest sighting a run of them chained far past the 5 ms window. The key now holds a
payload identifier (QUIC packet number, RTP sequence and SSRC, DNS ID) and the window is
measured from the first sighting.

D6: a stack with IP ID 0 sends byte-identical RSTs, one per segment still arriving after a
close. Without link-layer evidence (another interface, VLAN, MAC pair or SLL direction) they
are counted as ``repeated_identical``, not as copies.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Dot1Q, Ether, IPv6  # type: ignore

from tshark_mcp.copies import CopyTracker

from . import pcapgen as g
from .conftest import requires_tshark
from .test_capture_quality import Cap

pytestmark = requires_tshark

V6_CLI, V6_SRV = "2001:db8::10", "2001:db8::53"
CLI, SRV = "192.0.2.80", "198.51.100.80"
OFFLOADED = 0x5BB  # the same partial checksum on every datagram of one size


def dns_offloaded(path: Path) -> Path:
    """Six DNS queries over IPv6 (no IP ID), same size and the same offloaded checksum, 1 ms apart,
    then one real mirrored copy of the last query 50 microseconds after it."""
    cap = Cap(step=0.001)
    for qid in range(1, 7):
        pkt = (Ether(src=g.MAC_A, dst=g.MAC_B) / IPv6(src=V6_CLI, dst=V6_SRV)
               / UDP(sport=53001, dport=53, chksum=OFFLOADED) / DNS(id=qid, rd=1, qd=DNSQR(qname="a.example.com")))
        cap.add(pkt)
    cap.add(pkt, t=round(cap.t + 0.00005, 6))
    return cap.write(path)


def chargen_rsts(path: Path, vlan_copy: bool = False) -> Path:
    """Six byte-identical RSTs (IP ID 0, same sequence number) within 60 microseconds; with
    ``vlan_copy`` the last one is the first seen again on another VLAN (a real SPAN copy)."""
    cap = Cap(step=0.00001)
    rst = IP(src=SRV, dst=CLI, id=0, flags="DF") / TCP(sport=19, dport=40000, flags="R", seq=6)
    for _ in range(6):
        cap.add(Ether(src=g.MAC_A, dst=g.MAC_B) / Dot1Q(vlan=10) / rst)
    if vlan_copy:
        cap.add(Ether(src=g.MAC_A, dst=g.MAC_B) / Dot1Q(vlan=20) / rst)
    return cap.write(path)


def _quality(configure, tmp_path: Path, path: Path) -> dict:
    srv = configure(allow=[str(tmp_path)])
    out = srv.capture_quality(str(path))
    assert "error" not in out, out
    return out


def test_distinct_udp_packets_with_one_checksum_are_not_copies(configure, tmp_path):
    dup = _quality(configure, tmp_path, dns_offloaded(tmp_path / "dns.pcap"))["duplicates"]
    assert dup["copies"] == 1  # only the real mirrored copy
    assert dup["examples"] == [{"frame": 7, "copy_of": 6, "cause": dup["examples"][0]["cause"]}]


def test_identical_rsts_without_link_evidence_are_repeats(configure, tmp_path):
    out = _quality(configure, tmp_path, chargen_rsts(tmp_path / "rst.pcap"))
    assert out["duplicates"]["copies"] == 0
    assert out["duplicates"]["repeated_identical"] == {"rsts": 5}
    assert not any("duplicate" in r for r in out["verdict"]["reasons"])


def test_an_rst_seen_on_another_vlan_is_still_a_copy(configure, tmp_path):
    dup = _quality(configure, tmp_path, chargen_rsts(tmp_path / "rst.pcap", vlan_copy=True))["duplicates"]
    assert dup["copies"] == 1 and "VLAN" in next(iter(dup["causes"]))
    assert dup["repeated_identical"] == {"rsts": 5}


def test_window_is_measured_from_the_first_sighting():
    t = CopyTracker(zero_window=0.005)
    assert t.check("k", False, 0.000, info=1) == (False, None)
    assert t.check("k", False, 0.003, info=2) == (True, 1)
    # 6 ms after the first sighting: not a copy, even though only 3 ms after the previous one.
    assert t.check("k", False, 0.006, info=3) == (False, None)
    # It started a new sighting: a packet 2 ms later is a copy of frame 3, not of frame 1.
    assert t.check("k", False, 0.008, info=4) == (True, 3)


def test_copy_identity_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = chargen_rsts(tmp_path / "rst.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("capture_quality", {"path": str(cap)})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    out = asyncio.run(go())
    assert out["duplicates"]["copies"] == 0 and out["duplicates"]["repeated_identical"] == {"rsts": 5}

"""tunnels_overview: GRE, VXLAN, Geneve, IP-in-IP, IPsec, WireGuard, OpenVPN and GTP-U in one synthetic capture."""

from __future__ import annotations

import asyncio
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import GRE, ICMP, IP, TCP, UDP, Ether, Raw  # type: ignore
from scapy.contrib.geneve import GENEVE  # type: ignore
from scapy.layers.ipsec import ESP  # type: ignore
from scapy.layers.vxlan import VXLAN  # type: ignore

from tshark_mcp import models
from tshark_mcp import server as srv
from tshark_mcp.limits import Limits

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark

T0 = 1_700_500_000.0
GRE_A, GRE_B = "192.0.2.1", "192.0.2.2"
VX_A, VX_B = "192.0.2.3", "192.0.2.4"
GEN_A, GEN_B = "192.0.2.5", "192.0.2.6"
ESP_A, ESP_B = "192.0.2.7", "192.0.2.8"
IPIP_A, IPIP_B = "192.0.2.9", "192.0.2.10"
IKE_A, IKE_B = "192.0.2.11", "192.0.2.12"
OVPN_A, OVPN_B = "192.0.2.13", "192.0.2.14"
GTP_A, GTP_B = "192.0.2.15", "192.0.2.16"
WG_BAD, WG_PEER = "203.0.113.9", "198.51.100.1"
WG_A, WG_B = "203.0.113.20", "198.51.100.20"


def _eth(p) -> bytes:
    return bytes(Ether(src=g.MAC_A, dst=g.MAC_B) / p)


def _inner_eth():
    return Ether(src=g.MAC_A, dst=g.MAC_B)


def _ike(ispi: int, rspi: int, exchange: int, response: bool, msgid: int, notify: int | None = None) -> bytes:
    flags = 0x20 if response else 0x08
    body = b""
    nxt = 0
    if notify is not None:
        nxt = 41
        body = struct.pack(">BBHBBH", 0, 0, 8, 0, 0, notify)
    return struct.pack(">QQBBBBII", ispi, rspi, nxt, 0x20, exchange, flags, msgid, 28 + len(body)) + body


def _wg_init(sender: int) -> bytes:
    return struct.pack("<BxxxI", 1, sender) + b"\x00" * 140


def _wg_resp(sender: int, receiver: int) -> bytes:
    return struct.pack("<BxxxII", 2, sender, receiver) + b"\x00" * 80


def _wg_data(receiver: int, counter: int, size: int) -> bytes:
    return struct.pack("<BxxxIQ", 4, receiver, counter) + b"\x00" * size


@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    fr: list[tuple[float, bytes]] = []
    t = T0

    def add(p) -> None:
        nonlocal t
        fr.append((t, _eth(p)))
        t += 0.01

    # GRE key 42 both ways; the inner SYN offers MSS 1460, too much with 28 bytes of GRE overhead (key present).
    add(IP(src=GRE_A, dst=GRE_B) / GRE(key_present=1, key=42)
        / IP(src="10.1.0.1", dst="10.2.0.1") / TCP(sport=40000, dport=443, flags="S", options=[("MSS", 1460)]))
    add(IP(src=GRE_B, dst=GRE_A) / GRE(key_present=1, key=42)
        / IP(src="10.2.0.1", dst="10.1.0.1") / TCP(sport=443, dport=40000, flags="SA", options=[("MSS", 1400)]))
    add(IP(src=GRE_A, dst=GRE_B) / GRE(key_present=1, key=42) / IP(src="10.1.0.1", dst="10.2.0.1") / ICMP())
    # VXLAN VNI 100 one way only, one DF packet above 1500 bytes.
    for size in (100, 1480):
        add(IP(src=VX_A, dst=VX_B, flags="DF") / UDP(sport=50000, dport=4789) / VXLAN(vni=100) / _inner_eth()
            / IP(src="10.3.0.1", dst="10.3.0.2") / UDP(sport=1000, dport=2000) / Raw(b"v" * size))
    # Geneve VNI 7 both ways.
    add(IP(src=GEN_A, dst=GEN_B) / UDP(sport=50001, dport=6081) / GENEVE(vni=7, proto=0x6558) / _inner_eth()
        / IP(src="10.4.0.1", dst="10.4.0.2") / UDP(sport=1000, dport=2000) / Raw(b"g"))
    add(IP(src=GEN_B, dst=GEN_A) / UDP(sport=50002, dport=6081) / GENEVE(vni=7, proto=0x6558) / _inner_eth()
        / IP(src="10.4.0.2", dst="10.4.0.1") / UDP(sport=2000, dport=1000) / Raw(b"g"))
    # ESP: SPI 0x2a1f flows only from ESP_A to ESP_B.
    for seq in range(1, 4):
        add(IP(src=ESP_A, dst=ESP_B, proto=50) / ESP(spi=0x2A1F, seq=seq) / Raw(b"\x00" * 64))
    # IP-in-IP both ways.
    add(IP(src=IPIP_A, dst=IPIP_B) / IP(src="10.5.0.1", dst="10.5.0.2") / ICMP())
    add(IP(src=IPIP_B, dst=IPIP_A) / IP(src="10.5.0.2", dst="10.5.0.1") / ICMP(type=0))
    # IKEv2: SA_INIT answered, IKE_AUTH answered with AUTHENTICATION_FAILED.
    add(IP(src=IKE_A, dst=IKE_B) / UDP(sport=500, dport=500) / Raw(_ike(0x1111, 0, 34, False, 0)))
    add(IP(src=IKE_B, dst=IKE_A) / UDP(sport=500, dport=500) / Raw(_ike(0x1111, 0x2222, 34, True, 0)))
    add(IP(src=IKE_A, dst=IKE_B) / UDP(sport=500, dport=500) / Raw(_ike(0x1111, 0x2222, 35, False, 1)))
    add(IP(src=IKE_B, dst=IKE_A) / UDP(sport=500, dport=500) / Raw(_ike(0x1111, 0x2222, 35, True, 1, notify=24)))
    # WireGuard: 12 initiations never answered.
    for i in range(12):
        add(IP(src=WG_BAD, dst=WG_PEER) / UDP(sport=51820, dport=51820) / Raw(_wg_init(0x1000 + i)))
    # WireGuard: a working peer pair, data both ways and a keepalive.
    add(IP(src=WG_A, dst=WG_B) / UDP(sport=51820, dport=51820) / Raw(_wg_init(0xA1)))
    add(IP(src=WG_B, dst=WG_A) / UDP(sport=51820, dport=51820) / Raw(_wg_resp(0xB1, 0xA1)))
    add(IP(src=WG_A, dst=WG_B) / UDP(sport=51820, dport=51820) / Raw(_wg_data(0xB1, 0, 64)))
    add(IP(src=WG_B, dst=WG_A) / UDP(sport=51820, dport=51820) / Raw(_wg_data(0xA1, 0, 64)))
    add(IP(src=WG_A, dst=WG_B) / UDP(sport=51820, dport=51820) / Raw(_wg_data(0xB1, 1, 16)))
    # OpenVPN: two client hard resets, no server reset.
    for pid in range(2):
        add(IP(src=OVPN_A, dst=OVPN_B) / UDP(sport=40001, dport=1194)
            / Raw(bytes([7 << 3]) + b"\x01" * 8 + b"\x00" + struct.pack(">I", pid)))
    # GTP-U both ways with two TEIDs.
    inner = bytes(IP(src="100.64.0.7", dst="203.0.113.80") / UDP(sport=1, dport=2) / Raw(b"u"))
    add(IP(src=GTP_A, dst=GTP_B) / UDP(sport=2152, dport=2152) / Raw(struct.pack(">BBHI", 0x30, 0xFF, len(inner), 0xABC) + inner))
    add(IP(src=GTP_B, dst=GTP_A) / UDP(sport=2152, dport=2152) / Raw(struct.pack(">BBHI", 0x30, 0xFF, len(inner), 0xDEF) + inner))
    # Background traffic that is no tunnel.
    add(IP(src="192.0.2.100", dst="192.0.2.101") / TCP(sport=1234, dport=80, flags="S"))
    d = tmp_path_factory.mktemp("tunnels")
    return g._frames_to_pcap(d / "tunnels.pcap", fr)


@pytest.fixture
def tun(capture: Path):
    srv.configure([str(capture.parent)], limits=Limits(), tshark=TSHARK)
    yield srv
    srv._STATE = None


def _by(out: dict, kind: str, a: str | None = None) -> dict:
    return next(r for r in out["tunnels"] if r["kind"] == kind and (a is None or r["endpoint_a"] == a))


def test_every_kind_is_found_with_its_endpoints(tun, capture: Path):
    out = tun.tunnels_overview(str(capture))
    assert "error" not in out, out
    TypeAdapter(models.TunnelsOverviewResult).validate_python(out)
    assert out["summary"]["by_kind"] == {"GRE": 1, "VXLAN": 1, "Geneve": 1, "IPsec": 2, "IP-in-IP": 1,
                                         "WireGuard": 2, "OpenVPN": 1, "GTP-U": 1}
    gre = _by(out, "GRE")
    assert (gre["endpoint_a"], gre["endpoint_b"], gre["key"]) == (GRE_A, GRE_B, 42)
    assert gre["packets_a_to_b"] == 2 and gre["packets_b_to_a"] == 1 and not gre["one_way"]
    assert gre["inner_protocols"] == {"tcp": 2, "icmp": 1} and gre["overhead_bytes"] == 28
    assert gre["inner_conversations"][0] == {"pair": "10.1.0.1 <-> 10.2.0.1", "packets": 3}
    assert gre["inner_syn_mss"] == {"1400": 1, "1460": 1} and gre["first_frame"] == 1
    gtp = _by(out, "GTP-U")
    assert gtp["teids"] == 2 and gtp["inner_protocols"] == {"udp": 2}
    gen = _by(out, "Geneve")
    assert gen["vni"] == 7 and gen["inner_ethernet"] and gen["overhead_bytes"] == 50


def _empty_profile(tmp_path: Path) -> dict[str, str]:
    """A personal Wireshark profile (ESP SA preferences, say) must not change the raw count."""
    return dict(os.environ, WIRESHARK_CONFIG_DIR=str(tmp_path))


def test_counts_match_raw_tshark(tun, capture: Path, tmp_path: Path):
    out = tun.tunnels_overview(str(capture))
    raw = subprocess.run([TSHARK, "-n", "-r", str(capture), "-Y", "gre || vxlan || geneve || esp || isakmp || wg || "
                          "openvpn || gtp || ip.proto == 4", "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True, check=True, env=_empty_profile(tmp_path)).stdout.split()
    assert out["summary"]["packets"] == len(raw) == 37
    total = sum(r["packets_a_to_b"] + r["packets_b_to_a"] for r in out["tunnels"])
    assert total == len(raw)


def test_mtu_and_mss_issues(tun, capture: Path):
    out = tun.tunnels_overview(str(capture))
    gre = _by(out, "GRE")
    assert any("adds 28 bytes; inner SYNs offer MSS 1460: 1528 bytes on the wire" in i for i in gre["issues"])
    assert not any("MSS 1400" in i for i in gre["issues"])
    vx = _by(out, "VXLAN")
    assert vx["vni"] == 100 and vx["one_way"] and vx["df_above_mtu"] == 1 and vx["largest_outer_ip_len"] > 1500
    assert any("one way only" in i for i in vx["issues"]) and any("DF set" in i for i in vx["issues"])
    assert vx["overhead_bytes"] == 50
    big = tun.tunnels_overview(str(capture), mtu=9000)
    assert not _by(big, "GRE").get("issues") and "df_above_mtu" not in _by(big, "VXLAN")


def test_ipsec_handshake_and_one_way_sa(tun, capture: Path):
    out = tun.tunnels_overview(str(capture), kind="ipsec")
    assert {r["kind"] for r in out["tunnels"]} == {"IPsec"}
    ike = _by(out, "IPsec", IKE_A)
    hs = ike["handshake"]
    assert hs["protocol"] == "IKEv2" and hs["exchanges"] == {"IKE_SA_INIT": 2, "IKE_AUTH": 2}
    assert hs["error_notifies"] == {"AUTHENTICATION_FAILED": 1} and hs["outcome"] == "failed"
    assert any("AUTHENTICATION_FAILED: the pre-shared key" in i for i in ike["issues"])
    esp = _by(out, "IPsec", ESP_A)
    assert esp["inner"] == "encrypted" and esp["esp_pairs"] == "one direction only"
    assert esp["esp_sas"] == [{"spi": "0x00002a1f", "packets": 3, "bytes": esp["bytes_a_to_b"], "first_frame": 8,
                               "direction": "a_to_b"}]
    assert any(i.startswith("ESP SPI 0x00002a1f flows only 192.0.2.7 -> 192.0.2.8") for i in esp["issues"])


def test_wireguard_and_openvpn_handshakes(tun, capture: Path):
    out = tun.tunnels_overview(str(capture), kind="wireguard")
    bad = _by(out, "WireGuard", WG_BAD)
    assert bad["handshake"]["unanswered_initiations"] == 12 and bad["handshake"]["outcome"] == "no response"
    assert bad["issues"][0] == ("12 WireGuard handshake initiations from 203.0.113.9 and no response: the peer's "
                                "public key or endpoint is wrong, or UDP 51820 is blocked")
    good = _by(out, "WireGuard", WG_A)
    hs = good["handshake"]
    assert hs["initiations"] == 1 and hs["responses"] == 1 and hs["outcome"] == "data both ways"
    assert hs["keepalives"] == 1 and hs["data_a_to_b"] == 1 and hs["data_b_to_a"] == 1 and not good.get("issues")
    assert out["tunnels"][0]["endpoint_a"] == WG_BAD  # rows with issues first
    ovpn = _by(tun.tunnels_overview(str(capture), kind="openvpn"), "OpenVPN")
    assert ovpn["handshake"]["client_resets"] == 2 and ovpn["handshake"]["outcome"] == "no response"
    assert any("no server reset back" in i for i in ovpn["issues"])


def test_endpoint_filter_window_paging_and_bad_arguments(tun, capture: Path):
    one = tun.tunnels_overview(str(capture), endpoint=GRE_B)
    assert [r["kind"] for r in one["tunnels"]] == ["GRE"]
    page = tun.tunnels_overview(str(capture), limit=3, offset=3)
    assert page["returned"] == 3 and page["next_offset"] == 6 and page["total_matched"] == 10
    early = tun.tunnels_overview(str(capture), end="+0.025s")
    assert [r["kind"] for r in early["tunnels"]] == ["GRE"]
    udp_only = tun.tunnels_overview(str(capture), filter="udp")
    assert "GRE" not in udp_only["summary"]["by_kind"] and udp_only["display_filter"] == "udp"
    assert tun.tunnels_overview(str(capture), kind="mpls")["error"]["type"] == "invalid_argument"
    assert tun.tunnels_overview(str(capture), endpoint="not-an-ip")["error"]["type"] == "invalid_argument"
    assert tun.tunnels_overview(str(capture), mtu=100)["error"]["type"] == "invalid_argument"
    assert tun.tunnels_overview(str(capture), kind="IP-in-IP")["tunnels"][0]["kind"] == "IP-in-IP"


def test_ids_plus_ips_redaction_hides_outer_and_inner_addresses(tun, capture: Path):
    out = tun.tunnels_overview(str(capture), kind="gre", redact="ids+ips")
    text = repr(out)
    assert GRE_A not in text and "10.1.0.1" not in text


async def _over_stdio(capture: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "tshark_mcp.server", "--allow-dir", str(capture.parent)],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool("tunnels_overview", {"path": str(capture), "kind": "wireguard"})


def test_tunnels_overview_over_stdio(capture: Path):
    got = asyncio.run(_over_stdio(capture))
    out = got.structured_content
    assert not got.is_error and out["summary"]["by_kind"] == {"WireGuard": 2}
    assert out["tunnels"][0]["handshake"]["unanswered_initiations"] == 12

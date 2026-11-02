"""gtp_tunnel_health: inner TCP, ICMP and MTU per GTP-U tunnel, on synthetic captures."""

from __future__ import annotations

from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw  # type: ignore

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

ENB, SGW = "192.0.2.70", "192.0.2.71"
UE, SRV = "100.64.0.9", "203.0.113.9"
UL, DL = 0x1001, 0x2001  # uplink TEID (eNB to SGW), downlink TEID (SGW to eNB)


class Builder:
    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.t = 1_700_009_000.0
        self.outer_id = {True: 100, False: 5000}

    def gpdu(self, uplink: bool, inner, outer_id: int | None = None, teid: int | None = None) -> None:
        src, dst = (ENB, SGW) if uplink else (SGW, ENB)
        if outer_id is None:
            self.outer_id[uplink] += 1
            outer_id = self.outer_id[uplink]
        pkt = (Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=src, dst=dst, id=outer_id) / UDP(sport=2152, dport=2152)
               / Raw(g._gtpu(teid if teid is not None else (UL if uplink else DL), bytes(inner))))
        self.t += 0.01
        self.frames.append((self.t, bytes(pkt)))

    def raw(self, pkt) -> None:
        self.t += 0.01
        self.frames.append((self.t, bytes(pkt)))

    def write(self, path: Path) -> Path:
        return g._frames_to_pcap(path, self.frames)


def tcp(uplink: bool, ip_id: int, seq: int, ack: int, flags: str = "A", payload: int = 0, mss: int | None = None, df=True):
    src, dst, sport, dport = (UE, SRV, 40000, 443) if uplink else (SRV, UE, 443, 40000)
    options = [("MSS", mss)] if mss else []
    return (IP(src=src, dst=dst, id=ip_id, flags="DF" if df else 0) / TCP(sport=sport, dport=dport, seq=seq, ack=ack,
                                                                        flags=flags, options=options, window=1000)
            / (Raw(b"x" * payload) if payload else b""))


def handshake(b: Builder, mss_ue: int, mss_srv: int) -> None:
    b.gpdu(True, tcp(True, 1, 1000, 0, "S", mss=mss_ue))
    b.gpdu(False, tcp(False, 1, 5000, 1001, "SA", mss=mss_srv))
    b.gpdu(True, tcp(True, 2, 1001, 5001, "A"))


def download(b: Builder, segments: int, size: int = 1000, first_id: int = 10) -> int:
    """``segments`` downlink data segments with ACKs; returns the next sequence number."""
    seq = 5001
    for i in range(segments):
        b.gpdu(False, tcp(False, first_id + i, seq, 1001, "PA", payload=size))
        seq += size
        b.gpdu(True, tcp(True, 100 + i, 1001, seq, "A"))
    return seq


def test_mss_too_large_for_the_tunnelled_path(configure, tmp_path: Path):
    b = Builder()
    handshake(b, 1460, 1380)
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_tunnel_health(str(b.write(tmp_path / "mss.pcap")))
    up = next(r for r in result["tunnels"] if r["teid"] == f"0x{UL:08x}")
    down = next(r for r in result["tunnels"] if r["teid"] == f"0x{DL:08x}")
    assert up["tcp"]["mss_in_syn"] == {"1460": 1} and down["tcp"]["mss_in_syn"] == {"1380": 1}
    assert up["tunnel_overhead"] == 36
    assert any("MSS 1460" in i and "1536 bytes" in i and "at most 1424" in i for i in up["issues"])
    assert not any("MSS" in i for i in down.get("issues", []))
    assert up["reverse_teids"] == [f"0x{DL:08x}"]
    relaxed = srv.gtp_tunnel_health(str(tmp_path / "mss.pcap"), mtu=1600)
    assert not any("MSS" in i for r in relaxed["tunnels"] for i in r.get("issues", []))


def test_retransmissions_counted_and_flagged(configure, tmp_path: Path):
    b = Builder()
    handshake(b, 1380, 1380)
    download(b, 24)
    for k in range(3):  # three segments resent later with new IP IDs
        b.gpdu(False, tcp(False, 200 + k, 5001 + k * 1000, 1001, "PA", payload=1000))
    srv = configure(allow=[str(tmp_path)])
    down = next(r for r in srv.gtp_tunnel_health(str(b.write(tmp_path / "rtx.pcap")))["tunnels"] if r["teid"] == f"0x{DL:08x}")
    assert down["tcp"]["data_segments"] == 27 and down["tcp"]["data_retransmissions"] == 3
    assert down["tcp"]["retransmission_ratio"] == round(3 / 27, 3)
    assert any("are retransmissions (3 of 27)" in i for i in down["issues"])


def test_capture_copies_are_not_retransmissions(configure, tmp_path: Path):
    b = Builder()
    handshake(b, 1380, 1380)
    seq = 5001
    for i in range(22):
        inner = tcp(False, 10 + i, seq, 1001, "PA", payload=500)
        b.gpdu(False, inner)
        b.gpdu(False, inner, outer_id=b.outer_id[False])  # the same packet captured on a second interface
        seq += 500
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_tunnel_health(str(b.write(tmp_path / "copies.pcap")))
    down = next(r for r in result["tunnels"] if r["teid"] == f"0x{DL:08x}")
    assert down["duplicate_copies"] == 22 and down["packets"] == 23
    assert down["tcp"]["data_segments"] == 22 and down["tcp"]["retransmissions"] == 0
    assert any("extra copies" in i for i in down["issues"])


def test_reordered_segments_are_not_retransmissions(configure, tmp_path: Path):
    b = Builder()
    handshake(b, 1380, 1380)
    seq, ip_id = 5001, 10
    for _ in range(11):  # pairs sent as (a, b) and seen as (b, a)
        first = tcp(False, ip_id, seq, 1001, "PA", payload=1000)
        second = tcp(False, ip_id + 1, seq + 1000, 1001, "PA", payload=300)
        b.gpdu(False, second)
        b.gpdu(False, first)
        seq, ip_id = seq + 1300, ip_id + 2
    srv = configure(allow=[str(tmp_path)])
    down = next(r for r in srv.gtp_tunnel_health(str(b.write(tmp_path / "ooo.pcap")))["tunnels"] if r["teid"] == f"0x{DL:08x}")
    assert down["tcp"]["out_of_order"] == 11 and down["tcp"]["retransmissions"] == 0
    assert any("out of order" in i for i in down["issues"])


def test_keepalives_are_not_retransmissions(configure, tmp_path: Path):
    b = Builder()
    handshake(b, 1380, 1380)
    nxt = download(b, 3)
    for k in range(4):
        b.gpdu(False, tcp(False, 300 + k, nxt - 1, 1001, "A", payload=1))
    srv = configure(allow=[str(tmp_path)])
    down = next(r for r in srv.gtp_tunnel_health(str(b.write(tmp_path / "ka.pcap")))["tunnels"] if r["teid"] == f"0x{DL:08x}")
    assert down["tcp"]["keepalives"] == 4 and down["tcp"]["retransmissions"] == 0


def test_icmp_inside_and_outside_the_tunnel(configure, tmp_path: Path):
    b = Builder()
    # Inside: a router on the Internet side tells the server the UE path needs 1400 bytes.
    inner_error = IP(src="198.51.100.1", dst=UE) / ICMP(type=3, code=4, nexthopmtu=1400) / bytes(
        IP(src=UE, dst=SRV, flags="DF") / TCP(sport=40000, dport=443))[:28]
    b.gpdu(False, inner_error)
    # Outside: the transport cannot carry a large G-PDU to the SGW and says so.
    big = IP(src=ENB, dst=SGW, id=77, flags="DF") / UDP(sport=2152, dport=2152) / Raw(
        g._gtpu(UL, bytes(IP(src=UE, dst=SRV, id=9, flags="DF") / TCP(sport=40000, dport=443) / Raw(b"y" * 1400))))
    b.raw(Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src="192.0.2.99", dst=ENB) / ICMP(type=3, code=4, nexthopmtu=1450)
          / Raw(bytes(big)[:576]))
    b.gpdu(True, IP(src=UE, dst=SRV, id=9, flags="DF") / TCP(sport=40000, dport=443) / Raw(b"y" * 1400))
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_tunnel_health(str(b.write(tmp_path / "icmp.pcap")), mtu=1450)
    down = next(r for r in result["tunnels"] if r["teid"] == f"0x{DL:08x}")
    assert down["icmp"] == {"fragmentation needed": 1} and down["icmp_frag_needed_mtu"] == {"1400": 1}
    assert any("next-hop MTU 1400" in i for i in down["issues"])
    assert result["outer_icmp"] == [{"from": "192.0.2.99", "to": ENB, "error": "fragmentation needed", "mtu": 1450,
                                     "count": 1, "first": result["outer_icmp"][0]["first"], "teids": [f"0x{UL:08x}"]}]
    up = next(r for r in result["tunnels"] if r["teid"] == f"0x{UL:08x}")
    assert up["max_outer_ip_len"] == 1476 and up["inner_df_above_mtu"] == 1
    assert result["summary"]["outer_icmp_errors"] == 1


def test_one_way_tunnel_and_teid_filter(configure, tmp_path: Path):
    b = Builder()
    for i in range(3):
        b.gpdu(False, IP(src=SRV, dst=UE, id=i + 1) / ICMP(type=0, id=1, seq=i))
    b.gpdu(True, tcp(True, 1, 1000, 0, "S", mss=1300), teid=0x3003)
    b.gpdu(False, tcp(False, 1, 5000, 1001, "SA", mss=1300), teid=0x4004)
    srv = configure(allow=[str(tmp_path)])
    path = str(b.write(tmp_path / "oneway.pcap"))
    result = srv.gtp_tunnel_health(path)
    down = next(r for r in result["tunnels"] if r["teid"] == f"0x{DL:08x}")
    assert down["icmp"] == {"echo reply": 3}
    assert down["reverse_teids"] == ["0x00003003"]
    only = srv.gtp_tunnel_health(path, teid=DL)
    assert [r["teid"] for r in only["tunnels"]] == [f"0x{DL:08x}"]
    assert only["tunnels"][0]["reverse_seen"] is False
    assert any("reverse direction" in i for i in only["tunnels"][0]["issues"])


def test_invalid_mtu(configure, tmp_path: Path):
    b = Builder()
    handshake(b, 1380, 1380)
    srv = configure(allow=[str(tmp_path)])
    assert srv.gtp_tunnel_health(str(b.write(tmp_path / "x.pcap")), mtu=100)["error"]["type"] == "invalid_argument"

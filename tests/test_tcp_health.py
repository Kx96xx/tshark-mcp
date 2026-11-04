"""tcp_health: per TCP stream loss location, resets, windows and MTU, on synthetic captures."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw  # type: ignore

from tshark_mcp import models

from . import pcapgen as g
from .conftest import requires_tshark
from .test_capture_quality import Cap

pytestmark = requires_tshark

CLI, SRV = "192.0.2.90", "198.51.100.90"
ROUTER_MAC = "02:00:00:00:00:99"


class Conn:
    """One TCP connection; every packet gets a fresh IP ID unless told otherwise."""

    def __init__(self, cap: Cap, cport: int = 40001, sport: int = 443, srv_ttl: int = 50) -> None:
        self.cap, self.cport, self.sport, self.srv_ttl = cap, cport, sport, srv_ttl
        self.cid, self.sid = 100, 9000
        self.cseq, self.sseq = 1000, 70000

    def pkt(self, from_client: bool, seq: int, ack: int, flags: str, payload: int = 0, ip_id: int | None = None,
            ttl: int | None = None, mac: str | None = None, window: int = 8000, options=None, df: bool = True):
        if ip_id is None:
            if from_client:
                self.cid += 1
                ip_id = self.cid
            else:
                self.sid += 1
                ip_id = self.sid
        src, dst = (CLI, SRV) if from_client else (SRV, CLI)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        eth = Ether(src=mac or (g.MAC_A if from_client else g.MAC_B), dst=g.MAC_B if from_client else g.MAC_A)
        ip = IP(src=src, dst=dst, id=ip_id, ttl=ttl or (64 if from_client else self.srv_ttl), flags="DF" if df else 0)
        tcp = TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags, window=window, options=options or [])
        return eth / ip / tcp / (Raw(b"q" * payload) if payload else b"")

    def handshake(self, rtt_server: float = 0.03, rtt_client: float = 0.002, mss: tuple[int, int] = (1460, 1400)) -> None:
        self.cap.add(self.pkt(True, self.cseq, 0, "S", options=[("MSS", mss[0]), ("WScale", 7), ("SAckOK", b"")]))
        self.cap.add(self.pkt(False, self.sseq, self.cseq + 1, "SA", options=[("MSS", mss[1]), ("WScale", 9), ("SAckOK", b"")]),
                     t=round(self.cap.t + rtt_server, 6))
        self.cap.t = round(self.cap.t + rtt_server, 6)
        self.cseq += 1
        self.sseq += 1
        self.cap.add(self.pkt(True, self.cseq, self.sseq, "A"), t=round(self.cap.t + rtt_client, 6))
        self.cap.t = round(self.cap.t + rtt_client, 6)

    def down(self, n: int = 1, size: int = 500, ack: bool = True) -> list:
        sent = []
        for _ in range(n):
            p = self.pkt(False, self.sseq, self.cseq, "PA", payload=size)
            self.cap.add(p)
            sent.append(p)
            self.sseq += size
            if ack:
                self.ack()
        return sent

    def ack(self, **kw) -> None:
        self.cap.add(self.pkt(True, self.cseq, self.sseq, "A", **kw))


def run(configure, tmp_path: Path, cap: Cap, **kw):
    srv = configure(allow=[str(tmp_path)])
    out = srv.tcp_health(str(cap.write(tmp_path / "t.pcap")), **kw)
    TypeAdapter(models.TcpHealthResult).validate_python(out)
    return out


def only(out):
    assert out["count"] == 1, out
    return out["streams"][0]


def test_handshake_split_rtt_and_options(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake(rtt_server=0.030, rtt_client=0.002)
    c.down(5)
    s = only(run(configure, tmp_path, cap))
    hs = s["handshake"]
    assert hs["server_side_rtt_ms"] == pytest.approx(30.0, abs=0.01)
    assert hs["client_side_rtt_ms"] == pytest.approx(2.0, abs=0.01)
    assert hs["rtt_ms"] == pytest.approx(32.0, abs=0.02)
    assert (hs["client_mss"], hs["server_mss"], hs["client_wscale"], hs["server_wscale"], hs["sack"]) == (1460, 1400, 7, 9, True)
    assert s["client"] == f"{CLI}:40001" and s["server"] == f"{SRV}:443"
    assert s["server_to_client"]["data_segments"] == 5 and s["server_to_client"]["retransmissions"] == 0
    assert s["loss"] == "no loss seen" and s.get("issues", []) == []


def test_mirror_copies_are_not_retransmissions(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake()
    for p in c.down(25, ack=False):
        cap.add(p, t=round(cap.t + 0.00001, 6))  # the same packet again, as a SPAN of both directions shows it
    c.ack()
    out = run(configure, tmp_path, cap)
    s = only(out)
    assert s["copies_dropped"] == 25 and out["summary"]["copies_dropped"] == 25
    assert s["server_to_client"]["retransmissions"] == 0 and s["server_to_client"]["data_segments"] == 25
    assert "duplicate_acks" not in s["client_to_server"]


def test_loss_before_and_after_the_capture_point_and_capture_misses(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake()
    c.down(3)
    # 1. lost before the capture point: a gap, then the retransmission fills it
    hole = c.sseq
    c.sseq += 500
    c.sid += 1
    c.down(1, ack=False)
    c.cap.add(c.pkt(True, c.cseq, hole, "A"))
    cap.add(c.pkt(False, hole, c.cseq, "PA", payload=500), t=round(cap.t + 0.2, 6))
    cap.t = round(cap.t + 0.2, 6)
    c.ack()
    # 2. retransmitted although the capture saw the original
    seen = c.down(1, ack=False)[0]
    cap.add(c.pkt(False, seen[TCP].seq, c.cseq, "PA", payload=500), t=round(cap.t + 0.3, 6))
    cap.t = round(cap.t + 0.3, 6)
    c.ack()
    # 3. never captured but acknowledged
    c.sseq += 500
    c.ack()
    c.down(2)
    s = only(run(configure, tmp_path, cap))
    d = s["server_to_client"]
    assert d["lost_before_capture"] == 1 and d["retransmitted_after_capture"] == 1 and d["missed_by_capture"] == 1
    assert d["retransmissions"] == 2
    assert s["loss"] == ("1 lost on the network before the capture point; 1 retransmitted after the capture saw the "
                         "original (lost beyond the capture point, or the ACK was); 1 missing only from the capture "
                         "(the receiver acknowledged them)")
    assert any("absent from the capture" in i for i in s["issues"])


def test_gap_filled_within_a_round_trip_is_reordering_even_with_a_later_ip_id(configure, tmp_path: Path):
    """A multi-queue sender emits segments out of order with IP IDs in emission order: the
    filler has a later ID than the segment that opened the gap, yet it arrives 10 ms after
    it on a 300 ms path, long before any duplicate ACK could have reached the sender. The
    same filler half a second later is a retransmission of a segment lost before the capture."""
    cap = Cap()
    c = Conn(cap)
    c.handshake(rtt_server=0.15, rtt_client=0.15)
    c.down(2)
    # reordered: skip 500 bytes, send the next segment, then the skipped one 10 ms later
    skipped = c.sseq
    c.sseq += 500
    c.down(1, ack=False)
    cap.add(c.pkt(False, skipped, c.cseq, "PA", payload=500), t=round(cap.t + 0.010, 6))
    cap.t = round(cap.t + 0.010, 6)
    c.ack()
    # lost before the capture point: the gap is filled 0.5 s later, more than one round trip
    hole = c.sseq
    c.sseq += 500
    c.down(1, ack=False)
    cap.add(c.pkt(True, c.cseq, hole, "A"))
    cap.add(c.pkt(False, hole, c.cseq, "PA", payload=500), t=round(cap.t + 0.5, 6))
    cap.t = round(cap.t + 0.5, 6)
    c.ack()
    c.down(1)
    d = only(run(configure, tmp_path, cap))["server_to_client"]
    assert d.get("out_of_order") == 1 and d.get("lost_before_capture") == 1 and d["retransmissions"] == 1


def test_constant_ip_id_falls_back_to_the_time_window(configure, tmp_path: Path):
    """Every packet with IP ID 1 (some stacks, scapy's default): the IDs say nothing about
    emission order, so a gap filled within 3 ms is reordering, not a retransmission."""
    cap = Cap(step=0.0005)
    c = Conn(cap)
    c.handshake()
    for _ in range(2):
        cap.add(c.pkt(False, c.sseq, c.cseq, "PA", payload=500, ip_id=1)); c.sseq += 500
    skipped = c.sseq
    c.sseq += 500
    cap.add(c.pkt(False, c.sseq, c.cseq, "PA", payload=500, ip_id=1)); c.sseq += 500
    cap.add(c.pkt(False, skipped, c.cseq, "PA", payload=500, ip_id=1))
    c.ack()
    d = only(run(configure, tmp_path, cap))["server_to_client"]
    assert d.get("out_of_order") == 1 and d["retransmissions"] == 0


def test_duplicate_acks_and_zero_window(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake()
    c.down(2)
    c.ack()
    c.ack()
    c.ack(window=0)
    s = only(run(configure, tmp_path, cap))
    up = s["client_to_server"]
    assert up["duplicate_acks"] == 2 and up["zero_windows"] == 1
    assert any("client advertised a zero window 1 time" in i for i in s["issues"])


def test_unanswered_syns(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap, cport=40002, sport=8443)
    for _ in range(3):
        cap.add(c.pkt(True, 5000, 0, "S", options=[("MSS", 1460)]), t=round(cap.t + 1.0, 6))
        cap.t = round(cap.t + 1.0, 6)
    s = only(run(configure, tmp_path, cap))
    assert s["handshake"]["syn"] == 3 and s["handshake"]["syn_retransmissions"] == 2 and s["handshake"]["syn_ack"] == 0
    assert s["issues"] == ["3 SYNs and no SYN-ACK: the server did not answer (down, filtered, or the answer took another path)"]


def test_reset_from_the_endpoint(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake()
    c.down(3)
    cap.add(c.pkt(False, c.sseq, c.cseq, "R"))
    s = only(run(configure, tmp_path, cap))
    r = s["resets"][0]
    assert r["from"] == "server" and r["likely_from"] == "endpoint" and r["ttl"] == 50 and r["usual_ttl"] == 50
    assert "the server reset the connection" in " ".join(s["issues"])


def test_resets_injected_by_a_middlebox_after_idle(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake()
    c.down(3)
    cap.t = round(cap.t + 3600, 6)  # an hour of silence, then a firewall resets both sides
    cap.add(c.pkt(False, c.sseq, c.cseq, "RA", ttl=61, mac=ROUTER_MAC, ip_id=0))
    cap.add(c.pkt(True, c.cseq, c.sseq, "RA", ttl=61, mac=ROUTER_MAC, ip_id=0))
    s = only(run(configure, tmp_path, cap))
    by = {r["from"]: r for r in s["resets"]}
    assert by["server"]["likely_from"] == "middlebox" and by["client"]["likely_from"] == "middlebox"
    assert "TTL 61 (about 3 hops away) where that side's packets carry 50 (about 14 hops away)" in by["server"]["why"]
    assert f"source MAC {ROUTER_MAC}" in by["server"]["why"] and by["server"]["usual_mac"] == g.MAC_B
    assert by["server"]["idle_before_s"] == pytest.approx(3600, abs=0.1)
    text = " ".join(s["issues"])
    assert "most likely came from a middlebox" in text and "an idle timer" in text
    assert "resets towards both ends that neither end sent" in text


def test_mss_above_the_path_mtu_icmp_and_black_hole(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake(mss=(1460, 1460))
    c.down(3, size=300)  # small segments pass and are acknowledged
    stuck = c.sseq
    for attempt in range(4):  # the full-size segment never gets through
        cap.add(c.pkt(False, stuck, c.cseq, "PA", payload=1460), t=round(cap.t + 0.2 * (attempt + 1), 6))
        cap.t = round(cap.t + 0.2 * (attempt + 1), 6)
        c.ack()
    quoted = bytes(c.pkt(False, stuck, c.cseq, "PA", payload=1460)[IP])[:28]
    cap.add(Ether() / IP(src="203.0.113.1", dst=SRV) / ICMP(type=3, code=4, nexthopmtu=1400) / Raw(quoted))
    out = run(configure, tmp_path, cap, mtu=1400)
    s = only(out)
    text = " | ".join(s["issues"])
    assert "the client announced MSS 1460" in text and "an MSS of at most 1360 fits" in text
    assert "a path MTU black hole" in text and "retransmitted 3 times" in text
    assert "203.0.113.1 sent 1 ICMP fragmentation needed about this stream, next-hop MTU 1400" in text
    assert "4 packets with DF set are larger than the 1400-byte path MTU and were not acknowledged" in text
    assert s["df_above_mtu"] == 4 and s["icmp"] == [{"from": "203.0.113.1", "error": "fragmentation needed", "mtu": 1400, "count": 1}]
    relaxed = only(run(configure, tmp_path, cap, mtu=1500))
    assert not any("announced MSS" in i or "DF set" in i for i in relaxed["issues"])
    assert any("black hole" in i for i in relaxed["issues"])


def test_oversized_packets_that_were_acknowledged_are_offload_not_an_issue(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake()
    c.down(3, size=2900)  # GRO on the capturing host merges two segments into one frame
    s = only(run(configure, tmp_path, cap))
    assert s["df_above_mtu"] == 3 and s["df_above_mtu_acknowledged"] == 3
    assert not any("DF set" in i for i in s.get("issues", []))


def test_dead_path_without_any_acknowledged_data_is_not_called_a_black_hole(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake()
    for attempt in range(4):  # nothing at all gets through: an outage, not an MTU problem
        cap.add(c.pkt(False, c.sseq, c.cseq, "PA", payload=1400), t=round(cap.t + 0.5 * (attempt + 1), 6))
        cap.t = round(cap.t + 0.5 * (attempt + 1), 6)
    s = only(run(configure, tmp_path, cap))
    assert s["server_to_client"]["retransmitted_after_capture"] == 3
    assert not any("black hole" in i for i in s["issues"])


def test_inner_tcp_of_a_gtp_tunnel_seen_tunnelled_and_decapsulated(configure, tmp_path: Path):
    cap = Cap()
    c = Conn(cap)
    c.handshake()
    for p in c.down(5, ack=False):
        tunnelled = (Ether() / IP(src="192.0.2.71", dst="192.0.2.70", id=0) / UDP(sport=2152, dport=2152)
                     / Raw(g._gtpu(0x2001, bytes(p[IP]))))
        cap.add(tunnelled, t=round(cap.t + 0.0001, 6))
    c.ack()
    s = only(run(configure, tmp_path, cap))
    assert s["copies_dropped"] == 5 and s["server_to_client"]["retransmissions"] == 0


def test_stream_and_filter_arguments(configure, tmp_path: Path):
    cap = Cap()
    a, b = Conn(cap, cport=40010), Conn(cap, cport=40011)
    a.handshake()
    b.handshake()
    a.down(2)
    b.down(2)
    out = run(configure, tmp_path, cap)
    assert out["count"] == 2 and out["summary"]["streams"] == 2
    one = run(configure, tmp_path, cap, stream=1)
    assert one["count"] == 1 and one["streams"][0]["stream"] == 1 and one["display_filter"].startswith("(tcp.stream == 1)")
    filt = run(configure, tmp_path, cap, filter="tcp.port == 40010")
    assert filt["count"] == 1 and filt["streams"][0]["client"].endswith(":40010")
    srv = configure(allow=[str(tmp_path)])
    assert srv.tcp_health(str(tmp_path / "t.pcap"), mtu=100)["error"]["type"] == "invalid_argument"
    assert srv.tcp_health(str(tmp_path / "t.pcap"), stream=-1)["error"]["type"] == "invalid_argument"
    assert srv.tcp_health(str(tmp_path / "t.pcap"), filter="tcp.port == ;")["error"]["type"] in ("invalid_filter", "invalid_argument")
    limited = run(configure, tmp_path, cap, limit=1)
    assert limited["returned"] == 1 and limited["total_matched"] == 2 and limited["truncated"] is True
    nxt = run(configure, tmp_path, cap, limit=1, offset=limited["next_offset"])
    assert nxt["returned"] == 1 and nxt["streams"][0]["stream"] != limited["streams"][0]["stream"]
    assert "next_offset" not in nxt



class ZeroIdConn(Conn):
    """Every inner packet has IP ID 0 (DF set), as many UEs send."""

    def pkt(self, *a, **kw):
        return super().pkt(*a, **{**kw, "ip_id": 0})


class TunnelCap(Cap):
    """Every packet added is sent in GTP-U, each with a new outer IP ID."""

    def __init__(self) -> None:
        super().__init__()
        self.outer_id = 500

    def add(self, pkt, t=None, orig_len=None) -> None:
        self.outer_id += 1
        super().add(gtpu(pkt, self.outer_id), t, orig_len)


def gtpu(pkt, outer_id: int):
    return (Ether() / IP(src="192.0.2.71", dst="192.0.2.70", id=outer_id) / UDP(sport=2152, dport=2152)
            / Raw(g._gtpu(0x2002, bytes(pkt[IP]))))


def test_tunnelled_retransmission_with_inner_ip_id_zero_is_not_a_copy(configure, tmp_path: Path):
    """Inner IP ID 0 and a new outer ID per packet: a retransmission 200 ms later repeats the inner header
    and checksum. The outer ID is not in the copy key, so it must not choose the 1 s IP-ID window."""
    cap = TunnelCap()
    c = ZeroIdConn(cap)
    c.handshake()
    sent = c.down(3, ack=False)
    cap.add(sent[-1], t=round(cap.t + 0.2, 6))
    cap.t = round(cap.t + 0.2, 6)
    c.ack()
    out = run(configure, tmp_path, cap)
    s = only(out)
    assert out["summary"]["copies_dropped"] == 0
    assert s["server_to_client"]["retransmissions"] == 1


def test_tunnelled_and_decapsulated_copy_with_inner_ip_id_zero(configure, tmp_path: Path):
    """The same inner packet (IP ID 0) seen decapsulated and, 100 us later, in GTP-U is one packet."""
    cap = Cap()
    c = ZeroIdConn(cap)
    c.handshake()
    for i in range(4):
        p = c.down(1, ack=False)[0]
        cap.add(gtpu(p, 700 + i), t=round(cap.t + 0.0001, 6))
    c.ack()
    out = run(configure, tmp_path, cap)
    s = only(out)
    assert out["summary"]["copies_dropped"] == 4
    assert s["server_to_client"]["retransmissions"] == 0 and s["server_to_client"]["data_segments"] == 4


def _blackhole(cap: Cap) -> tuple[Conn, list[bytes]]:
    """A stream whose full-size segments never get through; returns the quoted headers of two
    of those attempts (each with its own IP ID)."""
    c = Conn(cap)
    c.handshake(mss=(1460, 1460))
    c.down(3, size=300)
    stuck = c.sseq
    quoted = []
    for attempt in range(2):
        p = c.pkt(False, stuck, c.cseq, "PA", payload=1460)
        cap.add(p, t=round(cap.t + 0.2 * (attempt + 1), 6))
        cap.t = round(cap.t + 0.2 * (attempt + 1), 6)
        quoted.append(bytes(p[IP])[:28])
    return c, quoted


def test_mirrored_icmp_error_counts_once(configure, tmp_path: Path):
    """The router's fragmentation-needed, mirrored (same IP ID, 0.1 ms apart), is one error."""
    cap = Cap()
    _, quoted = _blackhole(cap)
    err = Ether() / IP(src="203.0.113.1", dst=SRV, id=0x4242) / ICMP(type=3, code=4, nexthopmtu=1400) / Raw(quoted[0])
    t = round(cap.t + 0.001, 6)
    cap.add(err, t=t)
    cap.add(err, t=round(t + 0.0001, 6))
    out = run(configure, tmp_path, cap, mtu=1400)
    s = only(out)
    assert s["icmp"] == [{"from": "203.0.113.1", "error": "fragmentation needed", "mtu": 1400, "count": 1}]
    assert out["summary"]["icmp_copies_dropped"] == 1
    assert "203.0.113.1 sent 1 ICMP fragmentation needed about this stream" in " | ".join(s["issues"])


def test_icmp_errors_without_ip_id(configure, tmp_path: Path):
    """IP ID 0 (as Linux routers send ICMP): an error and its mirror copy count once; a
    second error 1 ms later about another attempt (another quoted IP ID) is a new error."""
    cap = Cap()
    _, quoted = _blackhole(cap)
    t = round(cap.t + 0.001, 6)
    for dt, q in ((0.0, quoted[0]), (0.0001, quoted[0]), (0.001, quoted[1])):
        cap.add(Ether() / IP(src="203.0.113.1", dst=SRV, id=0) / ICMP(type=3, code=4, nexthopmtu=1400) / Raw(q),
                t=round(t + dt, 6))
    out = run(configure, tmp_path, cap, mtu=1400)
    s = only(out)
    assert s["icmp"] == [{"from": "203.0.113.1", "error": "fragmentation needed", "mtu": 1400, "count": 2}]
    assert out["summary"]["icmp_copies_dropped"] == 1

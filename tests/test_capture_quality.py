"""capture_quality: duplicates, capture drops, truncation, checksums, one-sided streams
and timestamps, on synthetic captures."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import ICMP, IP, TCP, UDP, CookedLinux, Dot1Q, Ether, ICMPv6TimeExceeded, IPv6, Raw  # type: ignore

from tshark_mcp import models
from tshark_mcp.copies import CopyTracker
from tshark_mcp.limits import ToolError
from tshark_mcp.runner import assert_read_only

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

CLI, SRV = "192.0.2.80", "198.51.100.80"


class Cap:
    """Frames with explicit timestamps and optional on-wire length (for snaplen truncation)."""

    def __init__(self, start: float = 1_700_100_000.0, step: float = 0.010017) -> None:
        self.t = start
        self.step = step
        self.frames: list[tuple[float, bytes, int]] = []
        self.ids = {CLI: 100, SRV: 7000}

    def add(self, pkt, t: float | None = None, orig_len: int | None = None) -> None:
        if t is None:
            self.t = round(self.t + self.step, 6)
            t = self.t
        raw = bytes(pkt)
        self.frames.append((t, raw, orig_len or len(raw)))

    def write(self, path: Path, snaplen: int = 65535, nanoseconds: bool = False, linktype: int = 1) -> Path:
        scale = 1_000_000_000 if nanoseconds else 1_000_000
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B23C4D if nanoseconds else 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
            for t, raw, orig in self.frames:
                if isinstance(t, tuple):  # (seconds, sub-second units) given exactly
                    sec, frac = t
                else:
                    sec = int(t)
                    frac = int(round((t - sec) * scale))
                fh.write(struct.pack("<IIII", sec, frac, len(raw), orig))
                fh.write(raw)
        return path


def seg(src: str, dst: str, seq: int, ack: int, flags: str = "A", payload: int = 0, ip_id: int | None = None,
        chksum: int | None = None, vlan: int | None = None, ttl: int = 64):
    sport, dport = (40000, 443) if src == CLI else (443, 40000)
    tcp = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=4000)
    if chksum is not None:
        tcp.chksum = chksum
    ip = IP(src=src, dst=dst, id=ip_id if ip_id is not None else 1, ttl=ttl, flags="DF")
    eth = Ether(src=g.MAC_A if src == CLI else g.MAC_B, dst=g.MAC_B if src == CLI else g.MAC_A)
    l2 = eth / Dot1Q(vlan=vlan) if vlan is not None else eth
    return l2 / ip / tcp / (Raw(b"d" * payload) if payload else b"")


class Conv:
    """A client downloading from a server, with fresh IP IDs per packet."""

    def __init__(self, cap: Cap) -> None:
        self.cap = cap
        self.cid, self.sid = 100, 7000
        self.cseq, self.sseq = 1000, 50000

    def handshake(self) -> None:
        self.cap.add(seg(CLI, SRV, self.cseq, 0, "S", ip_id=self._c()))
        self.cap.add(seg(SRV, CLI, self.sseq, self.cseq + 1, "SA", ip_id=self._s()))
        self.cseq += 1
        self.sseq += 1
        self.cap.add(seg(CLI, SRV, self.cseq, self.sseq, "A", ip_id=self._c()))

    def data(self, n: int = 1, size: int = 500, ack: bool = True, **kw) -> list:
        sent = []
        for _ in range(n):
            pkt = seg(SRV, CLI, self.sseq, self.cseq, "PA", payload=size, ip_id=self._s(), **kw)
            self.cap.add(pkt)
            sent.append(pkt)
            self.sseq += size
            if ack:
                self.ack()
        return sent

    def ack(self) -> None:
        self.cap.add(seg(CLI, SRV, self.cseq, self.sseq, "A", ip_id=self._c()))

    def _c(self) -> int:
        self.cid += 1
        return self.cid

    def _s(self) -> int:
        self.sid += 1
        return self.sid


def run(configure, tmp_path: Path, cap: Cap, name: str = "q.pcap", **kw):
    srv = configure(allow=[str(tmp_path)])
    out = srv.capture_quality(str(cap.write(tmp_path / name, **kw)))
    TypeAdapter(models.CaptureQualityResult).validate_python(out)  # what the MCP layer checks before replying
    return out


def test_clean_capture_is_trustworthy(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    c.data(10)
    out = run(configure, tmp_path, cap)
    assert out["frames"] == 23 and out["ip_packets"] == 23
    assert out["duplicates"]["copies"] == 0
    gaps = out["tcp_capture_gaps"]
    assert gaps["tcp_data_segments"] == 10
    assert gaps["missed_by_capture"] == 0 and gaps["lost_before_capture"] == 0 and gaps["retransmitted_after_capture"] == 0
    assert out["checksums"]["bad"] == {} and out["checksums"]["validated"]["tcp"] == 23
    assert out["timestamps"]["resolution"] == "microsecond" and out["timestamps"]["backwards_jumps"] == 0
    assert out["verdict"]["loss_conclusions"] == "trustworthy", out["verdict"]


def test_span_copies_on_two_vlans_are_counted_once(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    for _ in range(10):
        pkt = seg(SRV, CLI, c.sseq, c.cseq, "PA", payload=400, ip_id=c._s(), vlan=10)
        cap.add(pkt)
        copy = pkt.copy()
        copy[Dot1Q].vlan = 20
        cap.add(copy, t=cap.t + 0.00002)
        c.sseq += 400
        c.ack()
    out = run(configure, tmp_path, cap)
    dup = out["duplicates"]
    assert dup["copies"] == 10
    assert list(dup["causes"]) == ["seen on two VLANs (SPAN of both ingress and egress)"]
    assert dup["examples"][0]["copy_of"] == 4 and dup["examples"][0]["frame"] == 5
    assert out["encapsulations"]["vlan"] == 20
    # the copies are not mistaken for retransmissions
    assert out["tcp_capture_gaps"]["retransmitted_after_capture"] == 0
    assert out["verdict"]["loss_conclusions"] == "use with care"
    assert any("duplicate copies" in r and "count them once" in r for r in out["verdict"]["reasons"])


def test_udp_without_ip_id_same_size_different_payload_is_not_a_copy(configure, tmp_path: Path):
    cap = Cap(step=0.0005)
    for payload in (b"a" * 40, b"b" * 40, b"b" * 40):  # the third repeats the second byte for byte
        cap.add(Ether() / IP(src=CLI, dst=SRV, id=0) / UDP(sport=4433, dport=443) / Raw(payload))
    out = run(configure, tmp_path, cap)
    assert out["duplicates"]["copies"] == 1 and out["duplicates"]["examples"][0] == {
        "frame": 3, "copy_of": 2, "cause": "identical headers (SPAN or mirror of both directions of a port, or a Linux any capture)"}


def test_linux_any_capture_copy_leaving_and_arriving(configure, tmp_path: Path):
    cap = Cap()
    for i in range(3):
        inner = IP(src=CLI, dst=SRV, id=40 + i) / UDP(sport=5060, dport=5060) / Raw(b"OPTIONS sip:x SIP/2.0")
        cap.add(CookedLinux(pkttype=4, lladdrtype=1, lladdrlen=6, src=b"\x02\x00\x00\x00\x00\x01\x00\x00", proto=0x0800) / inner)
        cap.add(CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=b"\x02\x00\x00\x00\x00\x02\x00\x00", proto=0x0800) / inner,
                t=cap.t + 0.00001)
    out = run(configure, tmp_path, cap, linktype=113)
    assert out["duplicates"]["copies"] == 3
    assert out["duplicates"]["causes"] == {"seen leaving one interface and arriving on another (Linux any capture)": 3}
    assert out["link_types"] == {"sll": 6}


def test_identical_ip_id_far_apart_is_not_a_copy(configure, tmp_path: Path):
    """A retransmission that happens to reuse an IP ID a long time later is not a copy."""
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    first = c.data(1, ack=False)[0]
    cap.add(first, t=cap.t + 5.0)
    cap.t += 5.0
    out = run(configure, tmp_path, cap)
    assert out["duplicates"]["copies"] == 0
    assert out["tcp_capture_gaps"]["retransmitted_after_capture"] == 1


def test_segment_missed_by_the_capture_but_acknowledged(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    c.data(3)
    # segment 4 is never captured, segment 5 is, and the client acknowledges both
    c.sid += 1
    c.sseq += 500
    c.data(1, ack=False)
    c.ack()
    c.data(20)
    out = run(configure, tmp_path, cap)
    gaps = out["tcp_capture_gaps"]
    assert gaps["missed_by_capture"] == 1 and gaps["missed_bytes"] == 500
    assert gaps["lost_before_capture"] == 0 and gaps["unresolved_gaps"] == 0
    assert out["verdict"]["loss_conclusions"] == "not trustworthy"
    assert any("the capture dropped them" in r for r in out["verdict"]["reasons"])


def test_segment_lost_before_the_capture_point_then_retransmitted(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    c.data(2)
    lost_seq = c.sseq
    c.sseq += 500
    c.sid += 1  # the lost segment's IP ID
    c.data(1, ack=False)
    cap.add(seg(CLI, SRV, c.cseq, lost_seq, "A", ip_id=c._c()))  # duplicate ACK for the hole
    cap.add(seg(SRV, CLI, lost_seq, c.cseq, "PA", payload=500, ip_id=c._s()), t=cap.t + 0.2)
    cap.t += 0.2
    c.ack()
    out = run(configure, tmp_path, cap)
    gaps = out["tcp_capture_gaps"]
    assert gaps["lost_before_capture"] == 1 and gaps["missed_by_capture"] == 0 and gaps["out_of_order"] == 0
    assert out["verdict"]["loss_conclusions"] == "trustworthy"
    assert any("1 segment lost before the capture point" in n for n in out["verdict"]["notes"])


def test_reordered_segment_is_not_loss(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    c.data(3)
    a = seg(SRV, CLI, c.sseq, c.cseq, "PA", payload=500, ip_id=c._s())
    b = seg(SRV, CLI, c.sseq + 500, c.cseq, "PA", payload=500, ip_id=c._s())
    cap.add(b)
    cap.add(a)  # sent first (lower IP ID), arrived second
    c.sseq += 1000
    c.ack()
    out = run(configure, tmp_path, cap)
    gaps = out["tcp_capture_gaps"]
    assert gaps["out_of_order"] == 1 and gaps["lost_before_capture"] == 0 and gaps["missed_by_capture"] == 0


@pytest.mark.parametrize("late_tsval, expected", [(105, "out_of_order"), (190, "lost_before_capture")])
def test_ipv6_reordering_versus_loss_by_tcp_timestamp(configure, tmp_path: Path, late_tsval, expected):
    """IPv6 has no IP ID; the TCP timestamp option tells an overtaken segment from a retransmission."""
    a6, b6 = "2001:db8::1", "2001:db8::2"

    def s6(seq, tsval, payload=500):
        return (Ether() / IPv6(src=b6, dst=a6) / TCP(sport=443, dport=40000, seq=seq, ack=1, flags="PA",
                                                      options=[("Timestamp", (tsval, 1))]) / Raw(b"z" * payload))
    cap = Cap()
    cap.add(s6(1000, 100))
    cap.add(s6(2000, 110))  # opens a gap at 1500
    cap.add(s6(1500, late_tsval), t=cap.t + 0.05)
    out = run(configure, tmp_path, cap)
    gaps = out["tcp_capture_gaps"]
    assert gaps[expected] == 1
    assert gaps["lost_before_capture"] + gaps["out_of_order"] == 1


def test_keepalive_on_a_stream_joined_midway_is_not_a_capture_drop(configure, tmp_path: Path):
    cap = Cap()
    # The server's first captured packet is a keep-alive probe one byte below its next sequence number.
    cap.add(seg(SRV, CLI, 59999, 1000, "A", ip_id=1))
    cap.add(seg(CLI, SRV, 1000, 60000, "A", ip_id=2))
    out = run(configure, tmp_path, cap)
    assert out["tcp_capture_gaps"]["missed_by_capture"] == 0


def test_snaplen_truncation(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    for _ in range(4):
        pkt = seg(SRV, CLI, c.sseq, c.cseq, "PA", payload=600, ip_id=c._s())
        raw = bytes(pkt)
        cap.frames.append((cap.t + 0.01, raw[:96], len(raw)))
        cap.t += 0.01
        c.sseq += 600
        c.ack()
    out = run(configure, tmp_path, cap, snaplen=96)
    tr = out["truncated_frames"]
    assert tr["frames"] == 4 and tr["snaplen"] == 96
    assert out["verdict"]["loss_conclusions"] == "use with care"
    assert any("snapshot length of 96" in r for r in out["verdict"]["reasons"])


def test_bad_checksums_from_the_capturing_host_are_offload(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    c.data(6, chksum=0x1234)  # every server segment has a wrong checksum, the client ACKs them all
    out = run(configure, tmp_path, cap)
    ck = out["checksums"]
    assert ck["bad"] == {"tcp": 6}
    assert ck["bad_by_sender"][0]["sender"] == SRV and ck["bad_by_sender"][0]["bad"] == 6
    assert ck["bad_tcp_data_segments"] == 6 and ck["bad_tcp_segments_acknowledged"] == 6
    assert ck["likely_offload"] is True and "offload" in ck["explanation"]
    assert out["verdict"]["loss_conclusions"] == "trustworthy"
    assert any("offload" in n for n in out["verdict"]["notes"])


def test_bad_checksums_never_acknowledged_from_several_senders(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    c.data(4)
    for i in range(3):
        cap.add(seg(SRV, CLI, c.sseq, c.cseq, "PA", payload=300, ip_id=c._s(), chksum=0x1111))
        cap.add(seg(CLI, SRV, c.cseq, c.sseq, "PA", payload=100, ip_id=c._c(), chksum=0x2222))
        c.cseq += 100
    out = run(configure, tmp_path, cap)
    ck = out["checksums"]
    assert ck["bad"] == {"tcp": 6} and ck["likely_offload"] is False
    assert ck["bad_tcp_segments_acknowledged"] < ck["bad_tcp_data_segments"]
    assert out["verdict"]["loss_conclusions"] == "use with care"


def test_one_sided_streams_and_unanswered_syns(configure, tmp_path: Path):
    cap = Cap()
    for i in range(5):  # data from the server only: the client's direction is missing
        cap.add(seg(SRV, CLI, 1000 + i * 100, 9000, "PA", payload=100, ip_id=50 + i))
    for port in (5001, 5002):
        cap.add(Ether() / IP(src=CLI, dst="203.0.113.5", id=port) / TCP(sport=port, dport=80, flags="S"))
    for i in range(6):
        cap.add(Ether() / IP(src=CLI, dst="203.0.113.6", id=300 + i) / UDP(sport=514, dport=514) / Raw(b"log"))
    out = run(configure, tmp_path, cap)
    one = out["one_sided"]
    assert one["tcp_streams"] == 3 and one["tcp_one_direction"] == 1 and one["tcp_syn_unanswered"] == 2
    assert one["udp_one_way_flows"] == 1
    assert one["examples"][0]["from"] == f"{SRV}:443" and one["examples"][0]["kind"] == "one direction only"
    assert out["verdict"]["loss_conclusions"] == "use with care"
    assert any("1 of 3 TCP streams were seen in one direction only" in r for r in out["verdict"]["reasons"])


def test_timestamps_backwards_and_millisecond_resolution(configure, tmp_path: Path):
    cap = Cap(step=0.002)
    c = Conv(cap)
    c.handshake()
    c.data(3)
    cap.add(seg(CLI, SRV, c.cseq, c.sseq, "A", ip_id=c._c()), t=cap.t - 0.5)
    cap.add(seg(CLI, SRV, c.cseq, c.sseq, "A", ip_id=c._c()), t=cap.t + 3.0)
    out = run(configure, tmp_path, cap)
    ts = out["timestamps"]
    assert ts["backwards_jumps"] == 1 and ts["max_backwards_s"] == pytest.approx(0.5, abs=0.001)
    assert ts["first_backwards_frame"] == 10
    assert ts["resolution"] == "millisecond"
    assert ts["largest_gap_s"] == pytest.approx(3.5, abs=0.001)
    reasons = " ".join(out["verdict"]["reasons"])
    assert "go backwards" in reasons and "millisecond resolution" in reasons


def test_sub_microsecond_backwards_step_is_seen(configure, tmp_path: Path):
    """Two stamps 1 ns apart differ only below a float's precision at epoch scale."""
    cap = Cap()
    base = 1_700_100_000
    for i, frac in enumerate((5, 7, 6, 9)):
        cap.frames.append(((base, frac), bytes(seg(CLI, SRV, 1000 + i, 1, "A", ip_id=10 + i)), 0))
    cap.frames = [(t, raw, len(raw)) for t, raw, _ in cap.frames]
    out = run(configure, tmp_path, cap, nanoseconds=True)
    ts = out["timestamps"]
    assert ts["backwards_jumps"] == 1 and ts["first_backwards_frame"] == 3 and ts["resolution"] == "nanosecond"


def test_short_one_direction_stream_is_only_a_note(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    c.data(3)
    cap.add(Ether() / IP(src="192.0.2.99", dst=CLI, id=5) / TCP(sport=5060, dport=41000, flags="PA", seq=9) / Raw(b"x" * 50))
    out = run(configure, tmp_path, cap)
    assert out["one_sided"]["tcp_one_direction"] == 0 and out["one_sided"]["tcp_one_direction_short"] == 1
    assert out["verdict"]["loss_conclusions"] == "trustworthy"
    assert any("fewer than 3 packets" in n for n in out["verdict"]["notes"])


def test_oversized_packets_point_at_segmentation_offload(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    c.data(2, size=8000)
    out = run(configure, tmp_path, cap)
    ov = out["oversized_packets"]
    assert ov["packets"] == 2 and ov["max_ip_len"] == 8040
    assert any("segmentation offload" in r for r in out["verdict"]["reasons"])


def test_rebuilt_copies_with_zeroed_tcp_headers(configure, tmp_path: Path):
    cap = Cap()
    c = Conv(cap)
    c.handshake()
    for _ in range(4):
        c.data(1, ack=False)
        cap.add(Ether() / IP(src=SRV, dst=CLI, id=0) / TCP(sport=443, dport=40000, seq=0, ack=0, flags=0) / Raw(b"d" * 500))
        c.ack()
    out = run(configure, tmp_path, cap)
    assert out["duplicates"]["copies"] == 4
    assert "zeroed TCP header" in next(iter(out["duplicates"]["causes"]))
    assert out["tcp_capture_gaps"]["retransmitted_after_capture"] == 0


def test_frame_cap_is_reported(configure, tmp_path: Path):
    from tshark_mcp.limits import Limits

    cap = Cap()
    c = Conv(cap)
    c.handshake()
    c.data(10)
    path = cap.write(tmp_path / "long.pcap")
    srv = configure(limits=Limits(max_scan_packets=8), allow=[str(tmp_path)])
    out = srv.capture_quality(str(path))
    assert out["truncated"] is True and out["frames"] == 8
    assert any("first 8 frames" in r for r in out["verdict"]["reasons"])


def test_path_outside_the_allowlist_is_refused(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    assert srv.capture_quality("/etc/hosts")["error"]["type"] == "path_not_allowed"


class TestChecksumPreferences:
    def test_only_the_checksum_preferences_pass(self):
        assert_read_only(["-n", "-r", "x.pcap", "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
                          "-o", "ip.check_checksum:TRUE"])

    @pytest.mark.parametrize("value", ["tls.keylog_file:/tmp/k", "tcp.check_checksum:FALSE", "gui.something:1",
                                       "tcp.check_checksum:TRUE ", ""])
    def test_any_other_preference_is_refused(self, value):
        with pytest.raises(ToolError) as exc:
            assert_read_only(["-n", "-r", "x.pcap", "-o", value])
        assert exc.value.type == "forbidden_flag"

    def test_dangling_dash_o_is_refused(self):
        with pytest.raises(ToolError):
            assert_read_only(["-n", "-r", "x.pcap", "-o"])


class TestCopyTracker:
    def test_nonzero_id_copies_within_the_window(self):
        t = CopyTracker(id_window=1.0)
        assert t.check("k", True, 10.0, "first") == (False, None)
        assert t.check("k", True, 10.5, "x") == (True, "first")
        assert t.check("k", True, 12.0, "y")[0] is False

    def test_zero_id_needs_a_few_milliseconds(self):
        t = CopyTracker()
        t.check("k", False, 1.0)
        assert t.check("k", False, 1.004)[0] is True
        assert t.check("k", False, 1.5)[0] is False

    def test_unbounded_window_for_tunnels(self):
        t = CopyTracker()
        t.check("k", True, 1.0)
        assert t.check("k", True, 1000.0)[0] is True


def _in_gtpu(pkt, outer_id: int):
    return (Ether() / IP(src="192.0.2.71", dst="192.0.2.70", id=outer_id) / UDP(sport=2152, dport=2152)
            / Raw(g._gtpu(0x2003, bytes(pkt[IP]))))


def test_tunnelled_retransmission_with_inner_ip_id_zero_is_not_a_copy(configure, tmp_path: Path):
    """Inner IP ID 0 and a new outer ID per packet: a retransmission 300 ms later has the same inner header
    and checksum. Only the inner ID is in the copy key, so only the inner ID chooses the window."""
    cap = Cap()
    c = Conv(cap)
    c._c = c._s = lambda: 0  # every inner packet has IP ID 0
    outer = iter(range(900, 1000))
    add = cap.add
    cap.add = lambda pkt, t=None, orig_len=None: add(_in_gtpu(pkt, next(outer)), t, orig_len)
    c.handshake()
    sent = c.data(3, ack=False)
    cap.add(sent[-1], t=round(cap.t + 0.3, 6))
    cap.t = round(cap.t + 0.3, 6)
    c.ack()
    out = run(configure, tmp_path, cap)
    assert out["duplicates"]["copies"] == 0
    assert out["tcp_capture_gaps"]["retransmitted_after_capture"] == 1


def test_tunnelled_and_decapsulated_copy_with_inner_ip_id_zero(configure, tmp_path: Path):
    """The same inner packet (IP ID 0) seen decapsulated and, 50 us later, in GTP-U is one packet."""
    cap = Cap()
    c = Conv(cap)
    c._c = c._s = lambda: 0
    c.handshake()
    for i in range(4):
        pkt = c.data(1, ack=False)[0]
        cap.add(_in_gtpu(pkt, 800 + i), t=round(cap.t + 0.00005, 6))
    c.ack()
    out = run(configure, tmp_path, cap)
    dup = out["duplicates"]
    assert dup["copies"] == 4 and dup["causes"] == {"seen tunnelled and decapsulated": 4}
    assert out["tcp_capture_gaps"]["retransmitted_after_capture"] == 0


ROUTER, ROUTER6, CLI6, SRV6 = "192.0.2.254", "2001:db8::fe", "2001:db8::80", "2001:db8:1::80"


def _time_exceeded(probe: int, ip_id: int = 0):
    """A router's time-exceeded (IP ID 0, as many routers send it) about one traceroute probe."""
    quoted = IP(src=CLI, dst=SRV, id=0x3000 + probe, ttl=1) / UDP(sport=50000, dport=33434 + probe) / Raw(b"\x00" * 24)
    return Ether() / IP(src=ROUTER, dst=CLI, id=ip_id) / ICMP(type=11, code=0) / quoted


def test_icmp_errors_about_different_probes_are_not_copies(configure, tmp_path: Path):
    """Two time-exceeded from one router 2 ms apart, same size and IP ID 0, quoting two probes."""
    cap = Cap(step=0.002)
    cap.add(_time_exceeded(1))
    cap.add(_time_exceeded(2))
    out = run(configure, tmp_path, cap)
    assert out["duplicates"]["copies"] == 0


def test_icmp_error_seen_twice_is_a_copy(configure, tmp_path: Path):
    cap = Cap()
    cap.add(_time_exceeded(1))
    cap.add(_time_exceeded(1), t=cap.t + 0.00002)
    out = run(configure, tmp_path, cap)
    assert out["duplicates"]["copies"] == 1 and out["duplicates"]["examples"][0]["copy_of"] == 1


def test_icmpv6_errors_about_different_probes_are_not_copies(configure, tmp_path: Path):
    """IPv6 has no IP ID: the ICMPv6 checksum tells two errors from one router apart."""
    cap = Cap(step=0.002)
    for probe in (1, 2):
        quoted = IPv6(src=CLI6, dst=SRV6, hlim=1) / UDP(sport=50000, dport=33434 + probe) / Raw(b"\x00" * 24)
        cap.add(Ether() / IPv6(src=ROUTER6, dst=CLI6) / ICMPv6TimeExceeded() / quoted)
    out = run(configure, tmp_path, cap)
    assert out["duplicates"]["copies"] == 0


def test_icmp_errors_about_echo_probes_differing_only_in_sequence(configure, tmp_path: Path):
    """An ICMP traceroute: the probes differ only in the echo sequence number (the quoted IP ID is 0
    too), so the ICMP checksum of the two errors is the same; the quoted sequence tells them apart."""
    cap = Cap(step=0.002)
    for probe in (12, 13):
        quoted = IP(src=CLI, dst=SRV, id=0, ttl=1) / ICMP(type=8, id=0x77, seq=probe) / Raw(b"\x00" * 24)
        cap.add(Ether() / IP(src=ROUTER, dst=CLI, id=0) / ICMP(type=11, code=0) / quoted)
    out = run(configure, tmp_path, cap)
    assert out["duplicates"]["copies"] == 0

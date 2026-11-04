"""Unanswered requests at the very end of a capture: `near_capture_end`, counted apart.

A request with no answer on any leg stays `unanswered`; when the capture on its
interface stops less than the answer window (2 s) after it, it also gets
`near_capture_end` and a note, and the summary counts it as
`unanswered_near_capture_end`. Requests unanswered earlier keep the plain flag.
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import DNS, DNSQR, IP, UDP, Ether  # type: ignore

from . import pcapgen as g
from .conftest import requires_tshark
from .test_pfcp import N4, SMF, UPF, cause, node_id, pfcp, recovery
from .test_proxy_legs import _echo, _plain

pytestmark = requires_tshark

SGW, PGW = "192.0.2.130", "198.51.100.130"


def _by_frame(rows: list[dict]) -> dict[int, dict]:
    return {r["request_frame"]: r for r in rows if r.get("request_frame")}


def gtp_tail_capture(tmp_path: Path) -> Path:
    """One interface. A Modify Bearer at 1.0 is never answered while the capture runs
    nine more seconds (frame 1). Two more come in the last 15 ms (frames 6 and 7), and
    the capture ends on an Echo Response at 10.015."""
    t0 = 1_700_040_000.0
    frames = [
        (t0 + 1.0, g._udp_frame(SGW, PGW, 2123, 2123, _plain(34, 0x1111, 0x700))),
        (t0 + 5.0, g._udp_frame(SGW, PGW, 2123, 2123, _echo(0x701, False))),
        (t0 + 5.001, g._udp_frame(PGW, SGW, 2123, 2123, _echo(0x701, True))),
        (t0 + 10.0, g._udp_frame(SGW, PGW, 2123, 2123, _plain(34, 0x2222, 0x702))),
        (t0 + 10.005, g._udp_frame(SGW, PGW, 2123, 2123, _plain(34, 0x3333, 0x703))),
        (t0 + 10.014, g._udp_frame(SGW, PGW, 2123, 2123, _echo(0x704, False))),
        (t0 + 10.015, g._udp_frame(PGW, SGW, 2123, 2123, _echo(0x704, True))),
    ]
    return g._frames_to_pcap(tmp_path / "gtp_tail.pcap", frames)


def test_gtp_requests_in_the_last_moments_are_near_capture_end(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(gtp_tail_capture(tmp_path))
    result = srv.gtp_sessions(path)
    rows = _by_frame(result["transactions"])
    early = rows[1]
    assert early["unanswered"] is True and "near_capture_end" not in early and "note" not in early
    for frame in (4, 5):
        late = rows[frame]
        assert late["unanswered"] is True and late["near_capture_end"] is True
        assert "stops at" in late["note"] and "expected within 2 s" in late["note"]
    summary = result["summary"]
    assert summary["unanswered"] == 3 and summary["unanswered_near_capture_end"] == 2
    assert "legs_near_capture_end" not in summary and "legs_without_response" not in summary


def test_window_follows_the_answers_seen(configure, tmp_path: Path):
    """Modify Bearer requests are answered within 20 ms in this capture, so one left
    unanswered 1 s before the end is a real gap; one 10 ms before the end is not."""
    t0 = 1_700_040_500.0
    frames = [
        (t0 + 0.0, g._udp_frame(SGW, PGW, 2123, 2123, _plain(34, 0x1111, 0x720))),
        (t0 + 0.020, g._udp_frame(PGW, SGW, 2123, 2123, _plain(35, 0x9999, 0x720, 16))),
        (t0 + 9.0, g._udp_frame(SGW, PGW, 2123, 2123, _plain(34, 0x2222, 0x721))),
        (t0 + 9.99, g._udp_frame(SGW, PGW, 2123, 2123, _plain(34, 0x3333, 0x722))),
        (t0 + 10.0, g._udp_frame(SGW, PGW, 2123, 2123, _echo(0x723, False))),
        (t0 + 10.001, g._udp_frame(PGW, SGW, 2123, 2123, _echo(0x723, True))),
    ]
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(g._frames_to_pcap(tmp_path / "gtp_fast.pcap", frames)))
    rows = _by_frame(result["transactions"])
    assert rows[1]["answer_frame"] == 2
    assert rows[3]["unanswered"] is True and "near_capture_end" not in rows[3]
    assert rows[4]["unanswered"] is True and rows[4]["near_capture_end"] is True
    assert "took at most 20 ms" in rows[4]["note"]
    assert result["summary"]["unanswered"] == 2 and result["summary"]["unanswered_near_capture_end"] == 1


def test_per_interface_end_decides(configure, tmp_path: Path):
    """Two interfaces. Both see a request at 10.0 that is never answered. Interface 0
    stops right after it; interface 1 goes on for five seconds, so only the request on
    interface 0 is near the end of its capture."""
    t0 = 1_700_041_000.0
    frames = [
        (t0 + 0.0, g._udp_frame(SGW, PGW, 2123, 2123, _echo(0x710, False)), 0),
        (t0 + 0.001, g._udp_frame(PGW, SGW, 2123, 2123, _echo(0x710, True)), 0),
        (t0 + 10.0, g._udp_frame(SGW, PGW, 2123, 2123, _plain(34, 0x4444, 0x711)), 0),
        (t0 + 10.0, g._udp_frame("192.0.2.131", "198.51.100.131", 2123, 2123, _plain(34, 0x5555, 0x712)), 1),
        (t0 + 15.0, g._udp_frame("192.0.2.131", "198.51.100.131", 2123, 2123, _echo(0x713, False)), 1),
        (t0 + 15.001, g._udp_frame("198.51.100.131", "192.0.2.131", 2123, 2123, _echo(0x713, True)), 1),
    ]
    path = g.frames_to_pcapng(tmp_path / "two_ifaces.pcapng", frames, ["side-a", "side-b"])
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(path))
    rows = _by_frame(result["transactions"])
    assert rows[3]["unanswered"] is True and rows[3]["near_capture_end"] is True
    assert rows[4]["unanswered"] is True and "near_capture_end" not in rows[4]
    assert result["summary"]["unanswered"] == 2 and result["summary"]["unanswered_near_capture_end"] == 1


def _diameter_tail_capture(tmp_path: Path) -> Path:
    """An AIR unanswered with eight seconds of capture after it, then an AIR 10 ms
    before the capture ends on a DWR/DWA."""
    mme = "mme01.epc.mnc001.mcc001.3gppnetwork.org"
    realm = "epc.mnc001.mcc001.3gppnetwork.org"
    t0 = 1_700_042_000.0
    frames: list[tuple[float, bytes]] = []
    tsn = [10]

    def send(ts: float, msg: bytes, src: str, dst: str) -> None:
        frames.append((t0 + ts, g._sctp_data(src, dst, 3868, 3868, 0x1111, tsn[0], 46, msg)))
        tsn[0] += 1

    for k, ts in ((1, 1.0), (2, 9.0)):
        sid = f"{mme};1700042000;{k}"
        air = g._diameter(318, 16777251, 0x100 + k, 0x200 + k, True,
                          g._diam_common(sid, mme, realm, realm) + [g._avp(1, g.IMSI.encode())])
        send(ts, air, g.MME_IP, g.HSS_IP)
    dwr = g._diameter(280, 0, 0x300, 0x400, True, [g._avp(264, mme.encode()), g._avp(296, realm.encode())])
    dwa = g._diameter(280, 0, 0x300, 0x400, False, [g._avp(268, (2001).to_bytes(4, "big")),
                                                    g._avp(264, b"hss01." + realm.encode()), g._avp(296, realm.encode())])
    send(9.005, dwr, g.MME_IP, g.HSS_IP)
    send(9.010, dwa, g.HSS_IP, g.MME_IP)
    return g._frames_to_pcap(tmp_path / "diameter_tail.pcap", frames)


def test_diameter_transactions_sessions_and_trace(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(_diameter_tail_capture(tmp_path))
    result = srv.diameter_transactions(path)
    rows = _by_frame(result["transactions"])
    assert rows[1]["unanswered"] is True and "near_capture_end" not in rows[1]
    assert rows[2]["unanswered"] is True and rows[2]["near_capture_end"] is True and "stops at" in rows[2]["note"]
    assert result["summary"]["unanswered"] == 2 and result["summary"]["unanswered_near_capture_end"] == 1

    sessions = srv.diameter_sessions(path)
    assert sessions["summary"]["unanswered"] == 2 and sessions["summary"]["unanswered_near_capture_end"] == 1
    late = next(s for s in sessions["sessions"] if s["session_id"].endswith(";2"))
    early = next(s for s in sessions["sessions"] if s["session_id"].endswith(";1"))
    assert late["unanswered_near_capture_end"] == 1 and late["transactions"][0]["near_capture_end"] is True
    assert "unanswered_near_capture_end" not in early and "near_capture_end" not in early["transactions"][0]

    trace = srv.trace_subscriber(path, imsi=g.IMSI)
    by_frame = {r["request_frame"]: r for r in trace["timeline"]}
    assert by_frame[2]["unanswered"] is True and by_frame[2]["near_capture_end"] is True
    assert "near_capture_end" not in by_frame[1]
    assert trace["failures"] == 2 and trace["unanswered_near_capture_end"] == 1


def test_dns_window_runs_to_the_last_packet_not_the_last_dns_message(configure, tmp_path: Path):
    """A DNS query is never answered and is the last DNS packet, but the capture runs
    five more seconds of other traffic on the same interface: genuinely unanswered.
    A second query asked 0.5 s before the very end is near the end of the capture."""
    t0 = 1_700_043_000.0
    client, resolver = "198.51.100.140", "192.0.2.140"

    def q(qid: int, name: str, sport: int) -> bytes:
        return bytes(Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=client, dst=resolver) / UDP(sport=sport, dport=53)
                     / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))

    other = g._udp_frame("192.0.2.141", "198.51.100.141", 5000, 5001, b"x" * 8)
    frames = [(t0, q(0x10, "gone.example.com", 41000)), (t0 + 5.0, other)]
    path = g._frames_to_pcap(tmp_path / "dns_gap.pcap", frames)
    srv = configure(allow=[str(tmp_path)])
    out = srv.dns_transactions(str(path))
    row = out["transactions"][0]
    assert row["unanswered"] is True and "near_capture_end" not in row
    assert out["summary"]["unanswered_near_capture_end"] == 0

    frames.append((t0 + 4.5, q(0x11, "late.example.com", 41001)))
    frames.sort(key=lambda f: f[0])
    path = g._frames_to_pcap(tmp_path / "dns_tail.pcap", frames)
    out = srv.dns_transactions(str(path))
    late = next(r for r in out["transactions"] if r["name"] == "late.example.com")
    assert late["near_capture_end"] is True and "stops at" in late["note"]
    assert out["summary"]["unanswered"] == 2 and out["summary"]["unanswered_near_capture_end"] == 1


def test_pfcp_heartbeat_at_the_end(configure, tmp_path: Path):
    n4 = N4(1_700_044_000.0)
    n4.cp(0.0, pfcp(1, 0x10, [recovery(1000)]))           # Heartbeat Request, never answered
    n4.cp(6.0, pfcp(5, 0x11, [node_id(SMF), recovery(1000)]))  # Association Setup Request
    n4.up(6.002, pfcp(6, 0x11, [node_id(UPF), cause(1), recovery(2000)]))
    n4.cp(6.010, pfcp(1, 0x12, [recovery(1000)]))         # Heartbeat Request, the last packet
    srv = configure(allow=[str(tmp_path)])
    result = srv.pfcp_sessions(str(n4.write(tmp_path / "n4_tail.pcap")), view="transactions")
    rows = _by_frame(result["transactions"])
    assert rows[1]["unanswered"] is True and "near_capture_end" not in rows[1]
    assert rows[4]["unanswered"] is True and rows[4]["near_capture_end"] is True
    assert result["summary"]["unanswered_near_capture_end"] == 1

"""Requests relayed through GTP proxies: legs without a response and duplicate packets."""

from __future__ import annotations

import struct
from pathlib import Path

from . import pcapgen as g
from .conftest import requires_tshark
from .test_gtpv1 import create_request as v1_create_request
from .test_gtpv1 import create_response as v1_create_response
from .test_gtpv1 import gtpv1, tv

pytestmark = requires_tshark

SGW, PROXY_IN, PROXY_OUT, PGW = "192.0.2.90", "192.0.2.91", "198.51.100.91", "198.51.100.92"


def _csr(imsi: str, seq: int, teid: int) -> bytes:
    return g._gtpv2(32, 0, seq, [g._ie(1, g._tbcd(imsi)), g._ie(82, bytes([6])), g._ie(87, g._fteid(6, teid, SGW)),
                                 g._apn_ie(g.APN), g._ie(99, bytes([1]))])


def _csresp(teid: int, seq: int, cause: int) -> bytes:
    return g._gtpv2(33, teid, seq, [g._ie(2, bytes([cause, 0]))])


class Cap:
    def __init__(self, t0: float) -> None:
        self.t0 = t0
        self.frames: list[tuple[float, bytes]] = []

    def send(self, dt: float, src: str, dst: str, msg: bytes) -> None:
        self.frames.append((self.t0 + dt, g._udp_frame(src, dst, 2123, 2123, msg)))

    def write(self, path: Path) -> Path:
        self.frames.sort(key=lambda f: f[0])
        return g._frames_to_pcap(path, self.frames)


def proxy_capture(tmp_path: Path) -> Path:
    """Four Create Session procedures through one proxy (the proxy renumbers the sequence):
    1. answered on both legs;
    2. the PGW answers the proxy, the proxy never answers the SGW;
    3. the PGW never answers; the proxy rejects towards the SGW on its own (cause 94);
    4. nobody answers.
    Plus one request captured twice."""
    c = Cap(1_700_030_000.0)
    for k, (outer, inner) in enumerate([(0x100, 0x9100), (0x101, 0x9101), (0x102, 0x9102), (0x103, 0x9103)]):
        t = 10.0 * k
        imsi = g.IMSI if k < 3 else g.IMSI_OTHER
        c.send(t, SGW, PROXY_IN, _csr(imsi, outer, 0xA0 + k))
        c.send(t + 0.002, PROXY_OUT, PGW, _csr(imsi, inner, 0xA0 + k))
        if k in (0, 1):
            c.send(t + 0.05, PGW, PROXY_OUT, _csresp(0xA0 + k, inner, 16))
        if k == 0:
            c.send(t + 0.052, PROXY_IN, SGW, _csresp(0xA0 + k, outer, 16))
        if k == 2:
            c.send(t + 8.0, PROXY_IN, SGW, _csresp(0xA0 + k, outer, 94))
    # A Delete Session Request seen twice 0.3 ms apart (one packet on two interfaces).
    dsr = g._gtpv2(36, 0xC0, 0x200, [g._ie(73, bytes([5]))])
    c.send(50.0, SGW, PGW, dsr)
    c.send(50.0003, SGW, PGW, dsr)
    c.send(50.02, PGW, SGW, g._gtpv2(37, 0xA0, 0x200, [g._ie(2, bytes([16, 0]))]))
    return c.write(tmp_path / "proxy.pcap")


def _by_frame(rows: list[dict]) -> dict[int, dict]:
    return {r["request_frame"]: r for r in rows if r.get("request_frame")}


def test_upstream_leg_without_response(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(proxy_capture(tmp_path)))
    rows = _by_frame(result["transactions"])
    # Procedure 1: fully answered, no chain annotation.
    assert "chain" not in rows[1] and "chain" not in rows[2]
    # Procedure 2 (frames 5, 6): the PGW answered the inner leg, the SGW never got a response.
    outer, inner = rows[5], rows[6]
    assert inner["answer_frame"] == 7 and "chain" in inner
    assert "unanswered" not in outer and outer["leg_without_response"] is True
    assert outer["chain"] == {"leg": 1, "legs": 2, "answered_legs": 1, "answered_on_frames": [7]}
    assert "further along the chain" in outer["note"] and "not relayed back" in outer["note"]
    assert result["summary"]["legs_without_response"] == 2


def test_proxy_answered_on_its_own(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    rows = _by_frame(srv.gtp_sessions(str(proxy_capture(tmp_path)))["transactions"])
    outer, inner = rows[8], rows[9]
    assert outer["cause"] == 94 and outer["chain"]["leg"] == 1
    assert inner["leg_without_response"] is True and "unanswered" not in inner
    assert "before it was answered" in inner["note"] and "cause 94" in inner["note"]


def test_no_leg_answered_stays_unanswered(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(proxy_capture(tmp_path)))
    rows = _by_frame(result["transactions"])
    outer, inner = rows[11], rows[12]
    for leg, row in ((1, outer), (2, inner)):
        assert row["unanswered"] is True and "leg_without_response" not in row
        assert row["chain"] == {"leg": leg, "legs": 2, "answered_legs": 0}
    assert result["summary"]["unanswered"] == 2


def test_duplicate_packet_is_not_unanswered(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(proxy_capture(tmp_path)))
    rows = _by_frame(result["transactions"])
    assert rows[13]["answer_frame"] == 15
    assert rows[14]["duplicate_of_frame"] == 13 and "unanswered" not in rows[14]
    assert result["summary"]["duplicates"] == 1


def test_trace_carries_the_leg_annotations(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.trace_subscriber(str(proxy_capture(tmp_path)), imsi=g.IMSI)
    legs = [r for r in result["timeline"] if r.get("leg_without_response")]
    assert {r["request_frame"] for r in legs} == {5, 9}
    assert all(r["note"] and r["chain"]["legs"] == 2 for r in legs)
    assert not any(r.get("unanswered") for r in result["timeline"])


def test_gtpv1_upstream_leg(configure, tmp_path: Path):
    c = Cap(1_700_031_000.0)
    c.send(0.0, SGW, PROXY_IN, v1_create_request(g.IMSI, 0x10, 0x111, 0x112, "internet.test"))
    c.send(0.003, PROXY_OUT, PGW, v1_create_request(g.IMSI, 0x7710, 0x111, 0x112, "internet.test"))
    c.send(0.04, PGW, PROXY_OUT, v1_create_response(0x111, 0x7710, 128, 0x221, 0x222))
    # The capture runs on past the relay (an Echo on the SGW side), so the missing response is a real gap.
    c.send(5.0, SGW, PROXY_IN, gtpv1(1, 0, 0x50, b""))
    c.send(5.001, PROXY_IN, SGW, gtpv1(2, 0, 0x50, tv(14, bytes([0]))))
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtpv1_sessions(str(c.write(tmp_path / "gn_proxy.pcap")))
    rows = _by_frame(result["transactions"])
    assert rows[1]["leg_without_response"] is True and rows[2]["answer_frame"] == 3
    assert result["summary"]["unanswered"] == 0 and result["summary"]["legs_without_response"] == 1


# --------------------------------------------- legs of later procedures (no IMSI)
SGW_B = "192.0.2.93"


def _csr_from(imsi: str, seq: int, teid: int, addr: str) -> bytes:
    return g._gtpv2(32, 0, seq, [g._ie(1, g._tbcd(imsi)), g._ie(82, bytes([6])), g._ie(87, g._fteid(6, teid, addr)),
                                 g._apn_ie(g.APN), g._ie(99, bytes([1]))])


def _csresp_from(header: int, seq: int, teid: int, addr: str) -> bytes:
    return g._gtpv2(33, header, seq, [g._ie(2, bytes([16, 0])), g._ie(87, g._fteid(7, teid, addr))])


def _plain(msg_type: int, header: int, seq: int, cause: int | None = None) -> bytes:
    return g._gtpv2(msg_type, header, seq, [g._ie(2, bytes([cause, 0])) if cause is not None else g._ie(73, bytes([5]))])


def lifecycle_capture(tmp_path: Path) -> Path:
    """One session set up through a proxy that renumbers sequence numbers and has its own
    TEIDs on each leg, then:
    - a Modify Bearer the PGW answers, which the proxy never relays back to the SGW;
    - a Delete Session the PGW never answers, rejected by the proxy on its own (cause 94).
    A second subscriber's session, set up directly (no proxy), sends a Modify Bearer at
    the same time that nobody answers: it is not a leg of the first chain."""
    c = Cap(1_700_032_000.0)
    c.send(0.0, SGW, PROXY_IN, _csr_from(g.IMSI, 0x300, 0xA1, SGW))
    c.send(0.002, PROXY_OUT, PGW, _csr_from(g.IMSI, 0x9300, 0xB1, PROXY_OUT))
    c.send(0.04, PGW, PROXY_OUT, _csresp_from(0xB1, 0x9300, 0xC1, PGW))
    c.send(0.042, PROXY_IN, SGW, _csresp_from(0xA1, 0x300, 0xD1, PROXY_IN))
    c.send(1.0, SGW_B, PGW, _csr_from(g.IMSI_OTHER, 0x400, 0xA2, SGW_B))
    c.send(1.03, PGW, SGW_B, _csresp_from(0xA2, 0x400, 0xC2, PGW))
    # Modify Bearer: frames 7 (SGW leg) and 8 (PGW leg), answered on frame 9 only.
    c.send(5.0, SGW, PROXY_IN, _plain(34, 0xD1, 0x301))
    c.send(5.002, PROXY_OUT, PGW, _plain(34, 0xC1, 0x9301))
    c.send(5.03, PGW, PROXY_OUT, _plain(35, 0xB1, 0x9301, 16))
    # The other subscriber's Modify Bearer, frame 10: no response at all.
    c.send(5.1, SGW_B, PGW, _plain(34, 0xC2, 0x401))
    # Delete Session: frames 11 (SGW leg) and 12 (PGW leg); the proxy answers frame 11 on its own.
    c.send(9.0, SGW, PROXY_IN, _plain(36, 0xD1, 0x302))
    c.send(9.002, PROXY_OUT, PGW, _plain(36, 0xC1, 0x9302))
    c.send(9.5, PROXY_IN, SGW, _plain(37, 0xA1, 0x302, 94))
    return c.write(tmp_path / "lifecycle.pcap")


def test_modify_bearer_not_relayed_back(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(lifecycle_capture(tmp_path)))
    rows = _by_frame(result["transactions"])
    outer, inner = rows[7], rows[8]
    assert inner["answer_frame"] == 9 and inner["chain"]["leg"] == 2
    assert outer["leg_without_response"] is True and "unanswered" not in outer
    assert outer["chain"] == {"leg": 1, "legs": 2, "answered_legs": 1, "answered_on_frames": [9]}
    assert "not relayed back" in outer["note"]


def test_delete_session_answered_by_the_proxy(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    rows = _by_frame(srv.gtp_sessions(str(lifecycle_capture(tmp_path)))["transactions"])
    outer, inner = rows[11], rows[12]
    assert outer["answer_frame"] == 13 and outer["cause"] == 94
    assert inner["leg_without_response"] is True and "unanswered" not in inner
    assert "before it was answered" in inner["note"] and "cause 94" in inner["note"]


def test_other_session_is_not_a_leg(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(lifecycle_capture(tmp_path)))
    other = _by_frame(result["transactions"])[10]
    assert other["unanswered"] is True and "chain" not in other and "leg_without_response" not in other
    assert result["summary"]["unanswered"] == 1 and result["summary"]["legs_without_response"] == 2


def test_trace_carries_later_legs(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.trace_subscriber(str(lifecycle_capture(tmp_path)), imsi=g.IMSI)
    legs = {r["request_frame"]: r for r in result["timeline"] if r.get("leg_without_response")}
    assert set(legs) == {7, 12}
    assert not any(r.get("unanswered") for r in result["timeline"])


def test_transparent_proxy_without_the_create(configure, tmp_path: Path):
    """A proxy that keeps the sequence number and TEID, on a session set up before the
    capture: the Delete Session legs share both. The PGW answers 'Context Not Found' and
    the proxy does not relay it. A Modify Bearer with the same sequence number but another
    TEID is a different procedure."""
    c = Cap(1_700_033_000.0)
    c.send(0.0, SGW, PROXY_IN, _plain(36, 0x7777, 0x500))
    c.send(0.0001, PROXY_OUT, PGW, _plain(36, 0x7777, 0x500))
    c.send(0.02, PGW, PROXY_OUT, _plain(37, 0, 0x500, 64))
    c.send(0.3, SGW, PROXY_IN, _plain(34, 0x8888, 0x600))
    c.send(0.3001, PROXY_OUT, PGW, _plain(34, 0x9999, 0x600))
    c.send(0.33, PGW, PROXY_OUT, _plain(35, 0x1234, 0x600, 16))
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(c.write(tmp_path / "transparent.pcap")))
    rows = _by_frame(result["transactions"])
    assert rows[1]["leg_without_response"] is True and "cause 64" in rows[1]["note"]
    assert rows[2]["answer_frame"] == 3
    assert rows[4]["unanswered"] is True and "chain" not in rows[4]
    assert result["summary"]["unanswered"] == 1 and result["summary"]["legs_without_response"] == 1


def test_gtpv1_update_and_delete_legs(configure, tmp_path: Path):
    """GTPv1 through a proxy with its own TEID-C on each leg: the Update PDP Context the
    GGSN answers is not relayed back; the Delete PDP Context gets no response on any leg."""
    proxy_out = "198.51.100.93"
    c = Cap(1_700_034_000.0)
    c.send(0.0, SGW, PROXY_IN, v1_create_request(g.IMSI, 0x10, 0x111, 0x112, "internet.test"))
    c.send(0.003, proxy_out, PGW, v1_create_request(g.IMSI, 0x7710, 0x511, 0x512, "internet.test"))
    c.send(0.04, PGW, proxy_out, v1_create_response(0x511, 0x7710, 128, 0x221, 0x222))
    c.send(0.042, PROXY_IN, SGW, v1_create_response(0x111, 0x10, 128, 0x611, 0x612))
    c.send(5.0, SGW, PROXY_IN, v1_update(0x611, 0x20, 0x111))
    c.send(5.002, proxy_out, PGW, v1_update(0x221, 0x7720, 0x511))
    c.send(5.03, PGW, proxy_out, gtpv1(19, 0x511, 0x7720, tv(1, bytes([128]))))
    c.send(9.0, SGW, PROXY_IN, gtpv1(20, 0x611, 0x30, tv(20, bytes([5]))))
    c.send(9.002, proxy_out, PGW, gtpv1(20, 0x221, 0x7730, tv(20, bytes([5]))))
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtpv1_sessions(str(c.write(tmp_path / "gn_lifecycle.pcap")))
    rows = _by_frame(result["transactions"])
    assert rows[5]["leg_without_response"] is True and "not relayed back" in rows[5]["note"]
    assert rows[6]["answer_frame"] == 7
    for leg, frame in ((1, 8), (2, 9)):
        assert rows[frame]["unanswered"] is True
        assert rows[frame]["chain"] == {"leg": leg, "legs": 2, "answered_legs": 0}
    assert result["summary"]["legs_without_response"] == 1 and result["summary"]["unanswered"] == 2


def v1_update(header: int, seq: int, teid_c: int) -> bytes:
    return gtpv1(18, header, seq, tv(17, struct.pack("!I", teid_c)) + tv(20, bytes([5])))


# --------------------------------------------- legs on an interface that stopped capturing
def _echo(seq: int, response: bool) -> bytes:
    return g._gtpv2(2 if response else 1, None, seq, [g._ie(3, bytes([0]))])


def stopped_side_capture(tmp_path: Path) -> Path:
    """A transparent proxy (same sequence number and TEID on both legs) captured on two
    interfaces: 0 faces the SGW, 1 faces the PGW.
    - Frames 1-3: a Delete Session the PGW answers with cause 64, never relayed back to
      the SGW while both interfaces keep capturing: a real leg without response.
    - Interface 0 stops at 10.002, right after it sees a Modify Bearer (frame 8); the
      PGW answers the other leg at 10.03, and interface 1 keeps capturing until 10.501.
      The response to the SGW would have come after interface 0 stopped."""
    frames: list[tuple[float, bytes, int]] = []
    t0 = 1_700_035_000.0

    def send(dt: float, src: str, dst: str, msg: bytes, iface: int) -> None:
        frames.append((t0 + dt, g._udp_frame(src, dst, 2123, 2123, msg), iface))

    send(0.0, SGW, PROXY_IN, _plain(36, 0x7777, 0x500), 0)
    send(0.0001, PROXY_OUT, PGW, _plain(36, 0x7777, 0x500), 1)
    send(0.02, PGW, PROXY_OUT, _plain(37, 0, 0x500, 64), 1)
    send(5.0, SGW, PROXY_IN, _echo(0x510, False), 0)
    send(5.001, PROXY_IN, SGW, _echo(0x510, True), 0)
    send(10.0, SGW, PROXY_IN, _echo(0x520, False), 0)
    send(10.001, PROXY_IN, SGW, _echo(0x520, True), 0)
    send(10.002, SGW, PROXY_IN, _plain(34, 0x8888, 0x600), 0)
    send(10.0021, PROXY_OUT, PGW, _plain(34, 0x8888, 0x600), 1)
    send(10.03, PGW, PROXY_OUT, _plain(35, 0x1234, 0x600, 16), 1)
    send(10.5, PROXY_OUT, PGW, _echo(0x530, False), 1)
    send(10.501, PGW, PROXY_OUT, _echo(0x530, True), 1)
    return g.frames_to_pcapng(tmp_path / "two_sides.pcapng", frames, ["sgw-side", "pgw-side"])


def test_leg_on_a_stopped_interface_is_near_capture_end(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(stopped_side_capture(tmp_path)))
    rows = _by_frame(result["transactions"])
    assert rows[1]["leg_without_response"] is True and "cause 64" in rows[1]["note"]
    late = rows[8]
    assert late["near_capture_end"] is True
    assert "leg_without_response" not in late and "unanswered" not in late
    assert late["chain"] == {"leg": 1, "legs": 2, "answered_legs": 1, "answered_on_frames": [10]}
    assert "stops at" in late["note"] and "frame 10" in late["note"]
    assert rows[9]["answer_frame"] == 10
    summary = result["summary"]
    assert summary["legs_without_response"] == 1 and summary["legs_near_capture_end"] == 1
    assert summary["unanswered"] == 0


def test_relay_after_the_capture_ended(configure, tmp_path: Path):
    """One interface: the capture ends on the answer to the inner leg, before the proxy
    could relay it. gtpv1_sessions and trace_subscriber mark the outer leg."""
    c = Cap(1_700_036_000.0)
    c.send(0.0, SGW, PROXY_IN, v1_create_request(g.IMSI, 0x10, 0x111, 0x112, "internet.test"))
    c.send(0.003, PROXY_OUT, PGW, v1_create_request(g.IMSI, 0x7710, 0x111, 0x112, "internet.test"))
    c.send(0.04, PGW, PROXY_OUT, v1_create_response(0x111, 0x7710, 128, 0x221, 0x222))
    path = str(c.write(tmp_path / "gn_cut.pcap"))
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtpv1_sessions(path)
    rows = _by_frame(result["transactions"])
    assert rows[1]["near_capture_end"] is True and "leg_without_response" not in rows[1]
    assert result["summary"]["legs_near_capture_end"] == 1 and "legs_without_response" not in result["summary"]
    timeline = srv.trace_subscriber(path, imsi=g.IMSI)["timeline"]
    outer = next(r for r in timeline if r.get("request_frame") == 1)
    assert outer["near_capture_end"] is True and "stops at" in outer["note"] and not outer.get("unanswered")


def test_interface_listed_twice_in_a_merge(configure, tmp_path: Path):
    """A merged capture lists the SGW-side interface once per input file (ids 0 and 2,
    one name). It stops on id 0 but goes on on id 2 well past the relay, so the missing
    response is a real gap, not the end of the capture."""
    frames: list[tuple[float, bytes, int]] = []
    t0 = 1_700_037_000.0

    def send(dt: float, src: str, dst: str, msg: bytes, iface: int) -> None:
        frames.append((t0 + dt, g._udp_frame(src, dst, 2123, 2123, msg), iface))

    send(0.0, SGW, PROXY_IN, _plain(34, 0x8888, 0x600), 0)
    send(0.0001, PROXY_OUT, PGW, _plain(34, 0x8888, 0x600), 1)
    send(0.03, PGW, PROXY_OUT, _plain(35, 0x1234, 0x600, 16), 1)
    send(2.0, SGW, PROXY_IN, _echo(0x610, False), 2)
    send(2.001, PROXY_IN, SGW, _echo(0x610, True), 2)
    path = g.frames_to_pcapng(tmp_path / "merged.pcapng", frames, ["sgw-side", "pgw-side", "sgw-side"])
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtp_sessions(str(path))
    row = _by_frame(result["transactions"])[1]
    assert row["leg_without_response"] is True and "near_capture_end" not in row
    assert result["summary"]["legs_without_response"] == 1 and "legs_near_capture_end" not in result["summary"]

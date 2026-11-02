"""Requests relayed through GTP proxies: legs without a response and duplicate packets."""

from __future__ import annotations

from pathlib import Path

from . import pcapgen as g
from .conftest import requires_tshark
from .test_gtpv1 import create_request as v1_create_request
from .test_gtpv1 import create_response as v1_create_response

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
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtpv1_sessions(str(c.write(tmp_path / "gn_proxy.pcap")))
    rows = _by_frame(result["transactions"])
    assert rows[1]["leg_without_response"] is True and rows[2]["answer_frame"] == 3
    assert result["summary"]["unanswered"] == 0 and result["summary"]["legs_without_response"] == 1

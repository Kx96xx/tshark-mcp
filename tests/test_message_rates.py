"""message_rates: per-interval counts, bursts and subscriber loops, on synthetic captures."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

MME = "mme01.epc.mnc001.mcc001.3gppnetwork.org"
HSS = "hss01.epc.mnc001.mcc001.3gppnetwork.org"
DRA_IP = "192.0.2.25"
REALM = "epc.mnc001.mcc001.3gppnetwork.org"


class Diam:
    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.tsn = 1
        self.hbh = 0x100

    def send(self, ts: float, src: str, dst: str, msg: bytes) -> None:
        self.frames.append((ts, g._sctp_data(src, dst, 3868, 3868, 0x40, self.tsn, 46, msg)))
        self.tsn += 1

    def request(self, ts: float, cmd: int, imsi: str, e2e: int, relayed: bool = True, answered: bool = True) -> None:
        sid = f"{MME};{e2e}"
        self.hbh += 1
        req = g._diameter(cmd, g.S6A, self.hbh, e2e, True, g._diam_common(sid, MME, REALM, REALM) + [g._avp(1, imsi.encode())])
        self.send(ts, g.MME_IP, DRA_IP, req)
        if relayed:  # the DRA forwards it with a new Hop-by-Hop id and the same End-to-End id
            self.hbh += 1
            fwd = g._diameter(cmd, g.S6A, self.hbh, e2e, True, g._diam_common(sid, MME, REALM, REALM) + [g._avp(1, imsi.encode())])
            self.send(ts + 0.002, DRA_IP, g.HSS_IP, fwd)
        if answered:
            ans = g._diameter(cmd, g.S6A, self.hbh, e2e, False, [g._avp(263, sid.encode()), g._avp(268, struct.pack("!I", 2001)),
                                                                  g._avp(264, HSS.encode()), g._avp(296, REALM.encode())])
            self.send(ts + 0.01, g.HSS_IP, DRA_IP, ans)

    def write(self, path: Path) -> Path:
        self.frames.sort(key=lambda f: f[0])
        return g._frames_to_pcap(path, self.frames)


def purge_loop(tmp_path: Path) -> Path:
    """One subscriber's ULR then PUR every 10 s, six times, each request seen on both
    DRA legs; another subscriber attaches once."""
    d = Diam()
    t0 = 1_700_010_000.0
    for k in range(6):
        d.request(t0 + 10 * k, 316, g.IMSI, 0x1000 + k)
        d.request(t0 + 10 * k + 1, 321, g.IMSI, 0x2000 + k)
    d.request(t0 + 3, 316, g.IMSI_OTHER, 0x3000)
    return d.write(tmp_path / "loop.pcap")


def air_burst(tmp_path: Path) -> Path:
    """One AIR a second for 20 s, then 30 AIRs within one second."""
    d = Diam()
    t0 = 1_700_011_000.0
    for k in range(20):
        d.request(t0 + k + 0.5, 318, g.IMSI_OTHER, 0x4000 + k, relayed=False)
    for k in range(30):
        d.request(t0 + 20.55 + k * 0.03, 318, g.IMSI, 0x5000 + k, relayed=False, answered=False)
    return d.write(tmp_path / "burst.pcap")


def _row(result: dict, message: str) -> dict:
    return next(r for r in result["by_message"] if r["message"] == message)


def test_relayed_copies_count_once_and_the_loop_is_found(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.message_rates(str(purge_loop(tmp_path)))
    ulr = _row(result, "ULR")
    assert ulr["total"] == 14 and ulr["distinct"] == 7 and ulr["request"] is True
    assert _row(result, "PUA")["distinct"] == 6
    assert result["copies"] == 13 and result["distinct_messages"] == result["messages"] - 13
    loops = {(lp["subscriber"], lp["message"]): lp for lp in result["subscriber_loops"]}
    assert set(loops) == {(g.IMSI, "ULR"), (g.IMSI, "PUR")}
    pur = loops[(g.IMSI, "PUR")]
    assert pur["count"] == 6 and pur["median_gap_s"] == 10.0 and pur["regular"] is True
    assert f"{g.IMSI} sent 6 ULR over 50.0 s, about every 10.0 s" in result["storms"]


def test_burst_against_the_usual_rate(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.message_rates(str(air_burst(tmp_path)))
    air = _row(result, "AIR")
    assert air["total"] == 50 and air["peak"] == 30 and air["bursts"] == 1
    burst = result["bursts"][0]
    assert burst["message"] == "AIR" and burst["messages"] == 30 and burst["baseline_per_interval"] == 1
    assert result["storms"][0].startswith("30 AIR in 1.0 s")


def test_imsi_keeps_that_subscriber_only(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.message_rates(str(purge_loop(tmp_path)), imsi=g.IMSI_OTHER)
    assert [(r["message"], r["distinct"]) for r in result["by_message"]] == [("ULR", 1)]


def test_wide_captures_merge_timeline_bins(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.message_rates(str(purge_loop(tmp_path)), interval=0.01)
    assert result["timeline_interval_s"] > 0.01 and len(result["timeline"]) <= 500
    assert sum(r["total"] for r in result["timeline"]) == result["distinct_messages"]


def test_sip_retransmissions_and_response_classes(configure, tmp_path: Path):
    from .test_regressions import _sip_challenge

    srv = configure(allow=[str(tmp_path)])
    result = srv.message_rates(str(_sip_challenge(tmp_path)), protocol="sip")
    reg = _row(result, "REGISTER")
    assert reg["total"] == 4 and reg["distinct"] == 3  # one retransmission
    assert _row(result, "4xx REGISTER")["distinct"] == 1 and _row(result, "2xx REGISTER")["distinct"] == 2
    assert _row(result, "4xx INVITE")["distinct"] == 1


def test_gtp_and_map_names(server, pcap_dir: Path):
    gtp = server.message_rates(str(pcap_dir / "all.pcap"), protocol="gtpv2")
    assert {r["message"] for r in gtp["by_message"]} >= {"Create Session Request", "Create Session Response"}
    assert all(r["protocol"] == "gtpv2" for r in gtp["by_message"])
    mapr = server.message_rates(str(pcap_dir / "sigtran.pcap"), protocol="map")
    names = {r["message"] for r in mapr["by_message"]}
    assert "updateLocation" in names and "mo-forwardSM" in names


@pytest.mark.parametrize("kwargs", [{"protocol": "ss7"}, {"interval": 0}, {"interval": "fast"}])
def test_invalid_arguments(server, pcap_dir: Path, kwargs):
    assert server.message_rates(str(pcap_dir / "all.pcap"), **kwargs)["error"]["type"] == "invalid_argument"

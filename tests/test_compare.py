"""compare_captures: align the ladders of a working and a failing capture."""

from __future__ import annotations

import struct
from pathlib import Path

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

V = g.VENDOR_3GPP
MME = "mme01.epc.mnc001.mcc001.3gppnetwork.org"
HSS = "hss01.epc.mnc001.mcc001.3gppnetwork.org"
REALM = "epc.mnc001.mcc001.3gppnetwork.org"


def u32(code: int, value: int, vendor: int | None = V) -> bytes:
    return g._avp(code, struct.pack("!I", value), vendor=vendor)


def grouped(code: int, members: list[bytes], vendor: int | None = V) -> bytes:
    return g._avp(code, b"".join(members), vendor=vendor)


def subscription(apns: list[str]) -> bytes:
    configs = [grouped(1430, [u32(1423, i + 1), g._avp(493, apn.encode()), u32(1456, 0)]) for i, apn in enumerate(apns)]
    return grouped(1400, [u32(1424, 0), grouped(1429, [u32(1423, 1), u32(1428, 0)] + configs)])


def attach(path: Path, imsi: str, apns: list[str], cause: int, purges: int = 0, extra_clr: bool = False,
           ula_delay: float = 0.03, keepalive: bool = False) -> Path:
    """ULR/ULA with a profile of ``apns``, optional PURs, optional CLR, then a Create
    Session answered with ``cause``."""
    frames: list[tuple[float, bytes]] = []
    t = 1_700_007_000.0
    tsn = 1

    def diam(ts: float, msg: bytes, from_mme: bool) -> None:
        nonlocal tsn
        src, dst = (g.MME_IP, g.HSS_IP) if from_mme else (g.HSS_IP, g.MME_IP)
        frames.append((ts, g._sctp_data(src, dst, 3868, 3868, 0x30, tsn, 46, msg)))
        tsn += 1

    def ans(cmd: int, hbh: int, sid: str, extra: list[bytes]) -> bytes:
        return g._diameter(cmd, g.S6A, hbh, hbh, False, [g._avp(263, sid.encode()), g._avp(264, HSS.encode()),
                                                         g._avp(296, REALM.encode()), u32(268, 2001, vendor=None)] + extra)

    if keepalive:
        dwr = g._diameter(280, 0, 0x99, 0x99, True, [g._avp(264, MME.encode()), g._avp(296, REALM.encode())])
        diam(t - 1.0, dwr, True)
    sid = f"{MME};{imsi};ulr"
    diam(t, g._diameter(316, g.S6A, 0x41, 0x41, True, g._diam_common(sid, MME, REALM, REALM) + [
        g._avp(1, imsi.encode()), u32(1405, 0x22)]), True)
    diam(t + ula_delay, ans(316, 0x41, sid, [u32(1406, 1), subscription(apns)]), False)
    for k in range(purges):
        sid = f"{MME};{imsi};pur{k}"
        diam(t + 0.5 + k * 0.1, g._diameter(321, g.S6A, 0x50 + k, 0x50 + k, True, g._diam_common(sid, MME, REALM, REALM) + [
            g._avp(1, imsi.encode())]), True)
        diam(t + 0.52 + k * 0.1, ans(321, 0x50 + k, sid, [u32(1442, 1)]), False)
    if extra_clr:
        sid = f"{HSS};{imsi};clr"
        diam(t + 0.9, g._diameter(317, g.S6A, 0x60, 0x60, True, g._diam_common(sid, HSS, REALM, REALM, MME) + [
            g._avp(1, imsi.encode()), u32(1420, 2)]), False)
        diam(t + 0.92, g._diameter(317, g.S6A, 0x60, 0x60, False, [g._avp(263, sid.encode()), g._avp(264, MME.encode()),
                                                                    g._avp(296, REALM.encode()), u32(268, 2001, vendor=None)]), True)
    csr = g._gtpv2(32, 0, 0x70, [g._ie(1, g._tbcd(imsi)), g._ie(82, bytes([6])), g._ie(87, g._fteid(6, 0xA1, g.SGW_IP)),
                                 g._apn_ie(apns[0]), g._ie(99, bytes([1]))])
    resp_ies = [g._ie(2, bytes([cause, 0]))]
    if cause == 16:
        resp_ies += [g._ie(87, g._fteid(7, 0xC1, g.PGW_IP), instance=1), g._ie(79, bytes([1]) + g._ipv4(g.UE_IP))]
    frames.append((t + 1.0, g._udp_frame(g.SGW_IP, g.PGW_IP, 2123, 2123, csr)))
    frames.append((t + 1.05, g._udp_frame(g.PGW_IP, g.SGW_IP, 2123, 2123, g._gtpv2(33, 0xA1, 0x70, resp_ies))))
    return g._frames_to_pcap(path, frames)


def _pair(tmp_path: Path, **failing) -> tuple[str, str]:
    work = attach(tmp_path / "working.pcap", g.IMSI, ["internet.test", "ims"], 16)
    fail = attach(tmp_path / "failing.pcap", failing.pop("imsi", g.IMSI), failing.pop("apns", ["internet.test"]),
                  failing.pop("cause", 78), **failing)
    return str(work), str(fail)


def test_identical_captures(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    a, _ = _pair(tmp_path)
    result = srv.compare_captures(a, a, imsi=g.IMSI)
    assert result["identical"] is True and result["first_divergence"] is None
    assert result["summary"]["same"] == 2 and result["a"]["steps"] == 2


def test_first_divergence_is_the_subscription_then_the_cause(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    a, b = _pair(tmp_path)
    result = srv.compare_captures(a, b, imsi=g.IMSI)
    first = result["first_divergence"]
    assert first["op"] == "changed" and first["a"]["message"] == "ULR/ULA"
    assert first["differences"] == {"answer_avps.subscription.apns[ims].apn": {"a": "ims", "b": None},
                                    "answer_avps.subscription.apns[ims].context": {"a": 2, "b": None},
                                    "answer_avps.subscription.apns[ims].pdn_type": {"a": "IPv4 (0)", "b": None}}
    csr = result["ladder"][1]
    assert csr["op"] == "changed" and csr["a"]["message"] == "Create Session Request"
    assert csr["differences"]["result"] == {"a": "Request accepted", "b": "Missing or unknown APN"}
    assert csr["differences"]["paa_allocated"] == {"a": True, "b": False}
    assert csr["differences"]["response_fteids"] == {"a": ["S5/S8 PGW GTP-C"], "b": None}
    assert result["b"]["failed"] == 1 and result["a"]["failed"] == 0


def test_a_storm_of_identical_retries_is_one_step_with_a_count(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    a, b = _pair(tmp_path, apns=["internet.test", "ims"], cause=16, purges=3)
    result = srv.compare_captures(a, b, imsi=g.IMSI)
    only_b = [e for e in result["ladder"] if e["op"] == "only_b"]
    assert len(only_b) == 1 and only_b[0]["b"]["message"] == "PUR/PUA" and only_b[0]["b"]["repeat"] == 3
    assert result["b"]["messages"] == 5 and result["b"]["steps"] == 3
    assert result["first_divergence"]["op"] == "only_b"
    assert result["first_divergence"]["after"] == ["ULR/ULA"]
    raw = srv.compare_captures(a, b, imsi=g.IMSI, collapse_repeats=False)
    assert raw["summary"]["only_b"] == 3


def test_missing_message_and_timing(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    a, b = _pair(tmp_path, apns=["internet.test", "ims"], cause=16, extra_clr=True, ula_delay=0.5)
    result = srv.compare_captures(a, b, imsi=g.IMSI)
    assert [e["op"] for e in result["ladder"]] == ["same", "only_b", "same"]
    assert result["ladder"][1]["b"]["message"] == "CLR/CLA"
    rtt = result["timing"]["largest_rtt_differences"][0]
    assert rtt["message"] == "ULR/ULA" and rtt["a_ms"] == 30.0 and rtt["b_ms"] == 500.0


def test_two_subscribers_compare_without_identity_noise(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    a, b = _pair(tmp_path, imsi=g.IMSI_OTHER, apns=["internet.test", "ims"], cause=16)
    result = srv.compare_captures(a, b, imsi=g.IMSI, imsi_b=g.IMSI_OTHER)
    assert result["identical"] is True
    assert result["b"]["identity"] == {"imsi": g.IMSI_OTHER}
    same_imsi = srv.compare_captures(a, b, imsi=g.IMSI)
    assert same_imsi["b"]["steps"] == 0 and same_imsi["summary"]["only_a"] == 2
    assert same_imsi["notes"][0].startswith("capture B has no Diameter")


def test_whole_capture_mode_drops_keepalives(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    work = attach(tmp_path / "w.pcap", g.IMSI, ["internet.test", "ims"], 16, keepalive=True)
    fail = attach(tmp_path / "f.pcap", g.IMSI, ["internet.test", "ims"], 73)
    result = srv.compare_captures(str(work), str(fail))
    assert result["a"]["identity"] is None and result["a"]["steps"] == 2
    assert result["first_divergence"]["differences"]["result"] == {"a": "Request accepted", "b": "No resources available"}


def test_imsi_b_needs_an_identity_for_a(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    a, b = _pair(tmp_path)
    assert srv.compare_captures(a, b, imsi_b=g.IMSI)["error"]["type"] == "invalid_argument"

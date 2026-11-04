"""roaming_attach_check: one roamer's attach and PDN attempts held against the subscription."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from tshark_mcp import roaming

from . import pcapgen as g
from .conftest import requires_tshark

V = g.VENDOR_3GPP
GX = 16777238
MME = "mme01.epc.mnc002.mcc001.3gppnetwork.org"   # the visited network, PLMN 001-02
HSS = "hss01.epc.mnc001.mcc001.3gppnetwork.org"   # the home network, PLMN 001-01
VREALM = "epc.mnc002.mcc001.3gppnetwork.org"
HREALM = "epc.mnc001.mcc001.3gppnetwork.org"
PCEF = "pgw01.epc.mnc002.mcc001.3gppnetwork.org"
VISITED = bytes([0x00, 0xF1, 0x20])  # 001-02 (TS 24.008 PLMN encoding)
RAND = bytes.fromhex("5a5a5a5a0123456789abcdef5a5a5a5a")  # must never be returned
RAND_HEX = RAND.hex()


def u32(code: int, value: int, vendor: int | None = V) -> bytes:
    return g._avp(code, struct.pack("!I", value), vendor=vendor)


def grouped(code: int, members: list[bytes], vendor: int | None = V) -> bytes:
    return g._avp(code, b"".join(members), vendor=vendor)


def subscription(odb: int = 0) -> bytes:
    """One APN, data.test, IPv4 only, local breakout not allowed; LTE-M restricted."""
    apn = grouped(1430, [
        u32(1423, 1), g._avp(493, b"data.test"), u32(1456, 0),  # PDN-Type IPv4
        grouped(1431, [u32(1028, 9), grouped(1034, [u32(1046, 15), u32(1047, 1), u32(1048, 0)])]),
        grouped(1435, [u32(516, 10_000_000), u32(515, 20_000_000)]),
        u32(1432, 0),  # VPLMN-Dynamic-Address-Allowed NOTALLOWED
    ])
    return grouped(1400, [
        g._avp(701, g._tbcd(g.MSISDN), vendor=V), u32(1424, 0), u32(1417, 2), u32(1426, 1 << 11),
        u32(1425, odb),
        grouped(1435, [u32(516, 20_000_000), u32(515, 40_000_000)]),
        grouped(1429, [u32(1423, 1), u32(1428, 0), apn]),
    ])


def _csr(seq: int, apn: str, pdn_type: int, sgw_teid: int) -> bytes:
    return g._gtpv2(32, 0, seq, [
        g._ie(1, g._tbcd(g.IMSI)), g._ie(76, g._tbcd(g.MSISDN)), g._ie(83, VISITED), g._ie(82, bytes([6])),
        g._ie(87, g._fteid(10, sgw_teid, g.MME_IP)), g._apn_ie(apn), g._ie(128, bytes([0])),
        g._ie(99, bytes([pdn_type])), g._ie(72, struct.pack("!II", 50_000, 100_000)),
        g._ie(93, g._ie(73, bytes([5]))),
    ])


def roaming_capture(tmp_path: Path) -> Path:
    """Three attempts of one roamer (home 001-01) in the visited PLMN 001-02:
    1. AIR/AIA with a vector, ULR/ULA with the subscription, Create Session for an APN the
       subscription does not hold (IPv4v6 asked) rejected 78.
    2. ULR/ULA again, Create Session for data.test with the visited PLMN as operator
       identifier (local breakout, not allowed), accepted; a Gx CCR-I/CCA-I.
    3. ULR answered 5004 ROAMING_NOT_ALLOWED with Error-Diagnostic ODB-ALL-APN."""
    t0 = 1_700_070_000.0
    frames: list[tuple[float, bytes]] = []
    tsn = [1]

    def dia(ts: float, msg: bytes, src: str, dst: str) -> None:
        frames.append((ts, g._sctp_data(src, dst, 3868, 3868, 0x77, tsn[0], 46, msg)))
        tsn[0] += 1

    def gtp(ts: float, msg: bytes, src: str, dst: str) -> None:
        frames.append((ts, g._udp_frame(src, dst, 2123, 2123, msg)))

    def answer(cmd: int, hbh: int, sid: str, extra: list[bytes]) -> bytes:
        return g._diameter(cmd, g.S6A, hbh, hbh, False, [g._avp(263, sid.encode()), g._avp(264, HSS.encode()),
                                                         g._avp(296, HREALM.encode())] + extra)

    def ulr(ts: float, hbh: int, sid: str) -> None:
        dia(ts, g._diameter(316, g.S6A, hbh, hbh, True, g._diam_common(sid, MME, VREALM, HREALM) + [
            g._avp(1, g.IMSI.encode()), u32(1032, 1004), u32(1405, 0x22), g._avp(1407, VISITED, vendor=V)]),
            g.MME_IP, g.HSS_IP)

    # Attempt 1
    sid = f"{MME};1;air"
    dia(t0, g._diameter(318, g.S6A, 0x31, 0x31, True, g._diam_common(sid, MME, VREALM, HREALM) + [
        g._avp(1, g.IMSI.encode()), g._avp(1407, VISITED, vendor=V), grouped(1408, [u32(1410, 1), u32(1412, 0)])]),
        g.MME_IP, g.HSS_IP)
    vector = grouped(1413, [grouped(1414, [g._avp(1447, RAND, vendor=V), g._avp(1448, RAND, vendor=V),
                                           g._avp(1449, RAND, vendor=V), g._avp(1450, RAND + RAND, vendor=V)])])
    dia(t0 + 0.02, answer(318, 0x31, sid, [u32(268, 2001, vendor=None), vector]), g.HSS_IP, g.MME_IP)
    ulr(t0 + 0.1, 0x32, f"{MME};1;ulr1")
    dia(t0 + 0.13, answer(316, 0x32, f"{MME};1;ulr1", [u32(268, 2001, vendor=None), u32(1406, 1), subscription()]),
        g.HSS_IP, g.MME_IP)
    gtp(t0 + 0.2, _csr(0x41, "internet", 3, 0x1001), g.MME_IP, g.SGW_IP)
    gtp(t0 + 0.25, g._gtpv2(33, 0x1001, 0x41, [g._ie(2, bytes([78, 0]))]), g.SGW_IP, g.MME_IP)

    # Attempt 2
    ulr(t0 + 5.0, 0x33, f"{MME};1;ulr2")
    dia(t0 + 5.03, answer(316, 0x33, f"{MME};1;ulr2", [u32(268, 2001, vendor=None), u32(1406, 1), subscription()]),
        g.HSS_IP, g.MME_IP)
    gtp(t0 + 5.1, _csr(0x42, "data.test.mnc002.mcc001.gprs", 1, 0x1002), g.MME_IP, g.SGW_IP)
    gx_sid = f"{PCEF};1;gx"
    gx_common = [g._avp(263, gx_sid.encode()), g._avp(264, PCEF.encode()), g._avp(296, VREALM.encode()),
                 g._avp(258, struct.pack("!I", GX))]
    dia(t0 + 5.12, g._diameter(272, GX, 0x34, 0x34, True, gx_common + [
        g._avp(283, VREALM.encode()), u32(416, 1, vendor=None), u32(415, 0, vendor=None),
        grouped(443, [u32(450, 1, vendor=None), g._avp(444, g.IMSI.encode())], vendor=None),
        g._avp(30, b"data.test", vendor=None)]), g.PGW_IP, g.HSS_IP)
    dia(t0 + 5.14, g._diameter(272, GX, 0x34, 0x34, False, gx_common + [u32(268, 2001, vendor=None),
                                                                     u32(416, 1, vendor=None), u32(415, 0, vendor=None)]),
        g.HSS_IP, g.PGW_IP)
    gtp(t0 + 5.2, g._gtpv2(33, 0x1002, 0x42, [g._ie(2, bytes([16, 0])), g._ie(79, bytes([1]) + g._ipv4(g.UE_IP))]),
        g.SGW_IP, g.MME_IP)

    # Attempt 3
    ulr(t0 + 9.0, 0x35, f"{MME};1;ulr3")
    dia(t0 + 9.02, answer(316, 0x35, f"{MME};1;ulr3", [
        grouped(297, [u32(266, V, vendor=None), u32(298, 5004, vendor=None)], vendor=None), u32(1614, 2)]),
        g.HSS_IP, g.MME_IP)
    return g._frames_to_pcap(tmp_path / "roaming.pcap", frames)


def map_capture(tmp_path: Path) -> Path:
    """A 3G roamer: sendAuthenticationInfo answered, updateGprsLocation refused with
    roamingNotAllowed."""
    t0 = 1_700_071_000.0
    frames: list[tuple[float, bytes]] = []
    sgsn_gt, hlr_gt = "15550109011", "15550109012"
    tsn = [1]

    def send(ts: float, payload: bytes, forward: bool) -> None:
        src, dst = (g.STP_A, g.STP_B) if forward else (g.STP_B, g.STP_A)
        frames.append((ts, g._sctp_data(src, dst, 2905, 2905, 0x55, tsn[0], 3, payload)))
        tsn[0] += 1

    def sccp(data: bytes, forward: bool) -> bytes:
        called, calling = (g._sccp_gt(hlr_gt, 6), g._sccp_gt(sgsn_gt, 149)) if forward else \
            (g._sccp_gt(sgsn_gt, 149), g._sccp_gt(hlr_gt, 6))
        return g._m3ua_data(100, 200, g._sccp_udt(called, calling, data)) if forward else \
            g._m3ua_data(200, 100, g._sccp_udt(called, calling, data))

    sai = g._ber(0x30, g._ber(0x80, g._tbcd(g.IMSI)) + g._ber(0x02, b"\x01"))
    send(t0, sccp(g._tcap_begin(b"\x00\x00\x01\x01", g._invoke(1, 56, sai)), True), True)
    sai_res = g._ber(0x30, g._ber(0xA0, g._ber(0x30, g._ber(0x04, RAND))))
    send(t0 + 0.1, sccp(g._tcap_end(b"\x00\x00\x01\x01", g._return_result_last(1, 56, sai_res)), False), False)

    ugl = g._ber(0x30, g._ber(0x04, g._tbcd(g.IMSI)) + g._ber(0x04, g._addr_string(sgsn_gt))
                 + g._ber(0x04, bytes([0x04]) + g._ipv4("192.0.2.90")))
    send(t0 + 1.0, sccp(g._tcap_begin(b"\x00\x00\x01\x02", g._invoke(1, 23, ugl)), True), True)
    error = g._ber(0xA3, g._ber(0x02, b"\x01") + g._ber(0x02, b"\x08"))  # roamingNotAllowed
    send(t0 + 1.1, sccp(g._tcap_end(b"\x00\x00\x01\x02", error), False), False)
    return g._frames_to_pcap(tmp_path / "map_roaming.pcap", frames)


# ----------------------------------------------------------------- pure logic
def test_plmn_helpers():
    assert roaming.parse_plmn("001-01") == ("001", "01") and roaming.parse_plmn("310410") == ("310", "410")
    assert roaming.parse_plmn("x") is None
    assert roaming.home_from_imsi("001010123456789") == ("001", "01")
    assert roaming.home_from_imsi("310410123456789") == ("310", "410")
    assert roaming.apn_operator("Data.Test.mnc002.mcc001.gprs") == ("data.test", ("001", "002"))
    assert roaming.oi_matches(("001", "002"), ("001", "02"))
    assert roaming.bits_of("2048 [LTE-M-Not-Allowed]") == ["LTE-M-Not-Allowed"]


@pytest.mark.parametrize("requested,subscribed,result", [
    (1, 0, "pass"), (3, 2, "pass"), (3, 0, "warn"), (2, 0, "fail"), (1, 3, "pass"), (None, 0, "unknown")])
def test_pdn_type_check(requested, subscribed, result):
    assert roaming.pdn_type_check(requested, subscribed)[0] == result


def test_attempt_grouping():
    steps = [{"phase": "auth", "kind": "air"}, {"phase": "location", "kind": "ulr"},
             {"phase": "pdn", "kind": "create_session", "apn": "a"}, {"phase": "pdn", "kind": "create_session", "apn": "b"},
             {"phase": "pdn", "kind": "create_session", "apn": "a"}, {"phase": "location", "kind": "ulr"}]
    assert [len(a) for a in roaming.group_attempts(steps)] == [4, 1, 1]


# ----------------------------------------------------------------- through tshark
@requires_tshark
class TestRoamingAttachCheck:
    @pytest.fixture
    def srv(self, configure, tmp_path: Path):
        return configure(allow=[str(tmp_path)])

    def test_three_attempts(self, srv, tmp_path: Path):
        out = srv.roaming_attach_check(str(roaming_capture(tmp_path)), imsi=g.IMSI)
        assert out["home_plmn"] == "001-01" and out["summary"]["attempts"] == 3
        first, second, third = out["attempts"]

        assert first["visited_plmn"] == "001-02" and first["roaming"] is True
        assert [s["step"] for s in first["steps"]] == ["AIR/AIA", "ULR/ULA", "Create Session"]
        assert first["steps"][0]["vectors_returned"] == 1
        assert first["subscription"]["apns"][0]["apn"] == "data.test"
        assert first["request"]["apn"] == "internet" and first["request"]["pdn_type"].startswith("IPv4v6")
        checks = {c["check"]: c for c in first["checks"]}
        assert checks["apn_subscribed"]["result"] == "fail" and "data.test" in checks["apn_subscribed"]["detail"]
        assert checks["rat_allowed"]["result"] == "pass" and checks["odb"]["result"] == "pass"
        ff = first["first_failure"]
        assert ff["step"] == "Create Session" and ff["code"] == 78 and ff["ref"].startswith("TS 29.274")
        assert ff["cause_lookup"] == "cause_lookup(protocol='gtpv2', code=78)"
        assert "Create Session failed" in first["verdict"] and "'internet' requested" in first["verdict"]

        steps2 = [s["step"] for s in second["steps"]]
        assert steps2 == ["ULR/ULA", "Create Session", "Gx CCR-I/CCA-I"]
        checks = {c["check"]: c for c in second["checks"]}
        assert checks["apn_subscribed"]["result"] == "pass" and checks["pdn_type_allowed"]["result"] == "pass"
        assert checks["routing"]["result"] == "fail" and "VPLMN-Dynamic-Address-Allowed" in checks["routing"]["detail"]
        assert checks["ambr_within_subscription"]["result"] == "warn"
        assert second["first_failure"]["check"] == "routing"
        assert second["verdict"].startswith("no step was rejected, but routing fails")

        ff = third["first_failure"]
        assert ff["step"] == "ULR/ULA" and ff["code"] == 5004 and ff["ref"].startswith("TS 29.272")
        assert ff["error_diagnostic"] == "ODB-ALL-APN (2)"
        assert third["subscription_from_earlier_attempt"] is True
        assert out["verdict"].startswith("3 attempt(s), 3 with a failure; latest: ULR/ULA failed")

    def test_home_plmn_override(self, srv, tmp_path: Path):
        path = str(roaming_capture(tmp_path))
        # As if the SIM's home were the visited network: no longer roaming.
        out = srv.roaming_attach_check(path, imsi=g.IMSI, home_plmn="001-02")
        assert out["home_plmn_source"] == "home_plmn argument"
        assert all(a.get("roaming") is False for a in out["attempts"])
        assert "routing" not in {c["check"] for c in out["attempts"][1]["checks"]}

    def test_authentication_vectors_never_returned(self, srv, tmp_path: Path):
        for path in (roaming_capture(tmp_path), map_capture(tmp_path)):
            text = json.dumps(srv.roaming_attach_check(str(path), imsi=g.IMSI)).lower()
            assert RAND_HEX not in text and "5a:5a:5a:5a" not in text

    def test_map_roamer(self, srv, tmp_path: Path):
        out = srv.roaming_attach_check(str(map_capture(tmp_path)), imsi=g.IMSI)
        (attempt,) = out["attempts"]
        assert [s["step"] for s in attempt["steps"]] == ["MAP sendAuthenticationInfo", "MAP updateGprsLocation"]
        assert attempt["steps"][0]["success"] is True
        ff = attempt["first_failure"]
        assert ff["result"] == "roamingNotAllowed" and ff["code"] == 8 and ff["ref"].startswith("TS 29.002")
        assert attempt["visited_plmn"] == "GT 15550109011"

    def test_unknown_imsi_and_bad_arguments(self, srv, tmp_path: Path):
        path = str(roaming_capture(tmp_path))
        out = srv.roaming_attach_check(path, imsi="001019999999999")
        assert out["attempts"] == [] and out["verdict"].startswith("no attach or PDN step")
        assert srv.roaming_attach_check(path, imsi="12ab")["error"]["type"] == "invalid_argument"
        assert srv.roaming_attach_check(path, imsi=g.IMSI, home_plmn="nowhere")["error"]["type"] == "invalid_argument"

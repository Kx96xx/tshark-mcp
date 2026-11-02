"""diameter_avps: AVP detail per transaction, on synthetic S6a and Gx captures."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from tshark_mcp.limits import Limits

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

V = g.VENDOR_3GPP
GX = 16777238
MME = "mme01.epc.mnc001.mcc001.3gppnetwork.org"
HSS = "hss01.epc.mnc001.mcc001.3gppnetwork.org"
REALM = "epc.mnc001.mcc001.3gppnetwork.org"
PCEF = "pgw01.epc.mnc001.mcc001.3gppnetwork.org"
PCRF = "pcrf01.epc.mnc001.mcc001.3gppnetwork.org"
IMSI_ZERO = "001019000000001"  # leading zeros must survive


def u32(code: int, value: int, vendor: int | None = V) -> bytes:
    return g._avp(code, struct.pack("!I", value), vendor=vendor)


def grouped(code: int, members: list[bytes], vendor: int | None = V) -> bytes:
    return g._avp(code, b"".join(members), vendor=vendor)


def apn_config(ctx: int, apn: str, qci: int, prio: int, pgw_ip: str | None = None, served: str | None = None) -> bytes:
    members = [
        u32(1423, ctx),
        g._avp(493, apn.encode()),
        u32(1456, 2),  # PDN-Type IPv4v6
        grouped(1431, [u32(1028, qci), grouped(1034, [u32(1046, prio), u32(1047, 1), u32(1048, 0)])]),
        grouped(1435, [u32(516, 50_000_000), u32(515, 100_000_000)]),
    ]
    if pgw_ip:
        members.append(grouped(486, [g._avp(334, b"\x00\x01" + g._ipv4(pgw_ip))], vendor=None))
    if served:
        members.append(g._avp(848, b"\x00\x01" + g._ipv4(served), vendor=V))
    return grouped(1430, members)


def s6a_capture(tmp_path: Path) -> Path:
    t0 = 1_700_005_000.0
    frames: list[tuple[float, bytes]] = []
    tsn = 1

    def send(ts: float, msg: bytes, from_mme: bool) -> None:
        nonlocal tsn
        src, dst = (g.MME_IP, g.HSS_IP) if from_mme else (g.HSS_IP, g.MME_IP)
        frames.append((ts, g._sctp_data(src, dst, 3868, 3868, 0x10, tsn, 46, msg)))
        tsn += 1

    def answer(cmd: int, hbh: int, sid: str, extra: list[bytes]) -> bytes:
        return g._diameter(cmd, g.S6A, hbh, hbh, False, [g._avp(263, sid.encode()), g._avp(264, HSS.encode()),
                                                         g._avp(296, REALM.encode())] + extra)

    # ULR with flags, answered with a subscription profile of two APNs.
    sid = f"{MME};1;ulr"
    send(t0, g._diameter(316, g.S6A, 0x11, 0x11, True, g._diam_common(sid, MME, REALM, REALM) + [
        g._avp(1, IMSI_ZERO.encode()), u32(1032, 1004), u32(1405, 0x22), g._avp(1407, bytes([0x00, 0xF1, 0x10]), vendor=V),
    ]), True)
    subscription = grouped(1400, [
        g._avp(701, g._tbcd(g.MSISDN), vendor=V),
        u32(1424, 0), u32(1417, 2), u32(1426, 0x21),
        grouped(1435, [u32(516, 20_000_000), u32(515, 40_000_000)]),
        grouped(1429, [u32(1423, 1), u32(1428, 0),
                       apn_config(1, "internet.test", 9, 15),
                       apn_config(2, "ims", 5, 1, pgw_ip="192.0.2.41", served="100.64.9.9")]),
    ])
    send(t0 + 0.03, answer(316, 0x11, sid, [u32(268, 2001, vendor=None), u32(1406, 1), subscription]), False)

    # CLR for subscription withdrawal, with Reattach-Required.
    sid = f"{HSS};1;clr"
    send(t0 + 1.0, g._diameter(317, g.S6A, 0x12, 0x12, True, g._diam_common(sid, HSS, REALM, REALM, MME) + [
        g._avp(1, IMSI_ZERO.encode()), u32(1420, 2), u32(1638, 0x2)]), False)
    send(t0 + 1.02, g._diameter(317, g.S6A, 0x12, 0x12, False, [g._avp(263, sid.encode()), g._avp(264, MME.encode()),
                                                               g._avp(296, REALM.encode()), u32(268, 2001, vendor=None)]), True)

    # PUR / PUA with purge flags.
    sid = f"{MME};1;pur"
    send(t0 + 2.0, g._diameter(321, g.S6A, 0x13, 0x13, True, g._diam_common(sid, MME, REALM, REALM) + [
        g._avp(1, IMSI_ZERO.encode()), u32(1635, 1)]), True)
    send(t0 + 2.01, answer(321, 0x13, sid, [u32(268, 2001, vendor=None), u32(1442, 1)]), False)

    # AIR for another subscriber refused with Experimental-Result 5420.
    sid = f"{MME};1;air"
    send(t0 + 3.0, g._diameter(318, g.S6A, 0x14, 0x14, True, g._diam_common(sid, MME, REALM, REALM) + [
        g._avp(1, g.IMSI_OTHER.encode()), grouped(1408, [u32(1410, 3), u32(1412, 0)])]), True)
    send(t0 + 3.02, answer(318, 0x14, sid, [grouped(297, [u32(266, V, vendor=None), u32(298, 5420, vendor=None)], vendor=None)]),
         False)
    return g._frames_to_pcap(tmp_path / "s6a_avps.pcap", frames)


def gx_capture(tmp_path: Path) -> Path:
    t0 = 1_700_006_000.0
    sid = f"{PCEF};1;gx"

    def common(origin: str) -> list[bytes]:
        return [g._avp(263, sid.encode()), g._avp(264, origin.encode()), g._avp(296, REALM.encode()),
                g._avp(258, struct.pack("!I", GX))]

    ccr = g._diameter(272, GX, 0x21, 0x21, True, common(PCEF) + [
        g._avp(283, REALM.encode()), u32(416, 1, vendor=None), u32(415, 0, vendor=None),
        g._avp(8, g._ipv4(g.UE_IP), vendor=None), g._avp(30, b"internet.test", vendor=None),
        u32(1027, 5), u32(1006, 13)])
    cca = g._diameter(272, GX, 0x21, 0x21, False, common(PCRF) + [
        u32(268, 2001, vendor=None), u32(416, 1, vendor=None), u32(415, 0, vendor=None), u32(1006, 2), u32(1006, 13)])
    ccru = g._diameter(272, GX, 0x22, 0x22, True, common(PCEF) + [
        g._avp(283, REALM.encode()), u32(416, 2, vendor=None), u32(415, 1, vendor=None),
        grouped(1018, [g._avp(1005, b"rule-video", vendor=V), u32(1019, 1), u32(1031, 10)])])
    frames = [
        (t0, g._sctp_data(g.PGW_IP, g.HSS_IP, 3868, 3868, 0x20, 1, 46, ccr)),
        (t0 + 0.02, g._sctp_data(g.HSS_IP, g.PGW_IP, 3868, 3868, 0x21, 1, 46, cca)),
        (t0 + 5.0, g._sctp_data(g.PGW_IP, g.HSS_IP, 3868, 3868, 0x20, 2, 46, ccru)),
    ]
    return g._frames_to_pcap(tmp_path / "gx_avps.pcap", frames)


def _tx(result: dict, request: str) -> dict:
    return next(t for t in result["transactions"] if t["request"] == request)


class TestKeyView:
    def test_ulr_flags_and_identities(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.diameter_avps(str(s6a_capture(tmp_path)), command_code=316)
        assert result["count"] == 1 and result["detail"] == "key"
        req = result["transactions"][0]["request_avps"]
        assert req["User-Name"] == IMSI_ZERO
        assert req["ULR-Flags"] == "34 [S6a/S6d-Indicator, Initial-Attach-Indicator]"
        assert req["RAT-Type"] == "EUTRAN (1004)"
        assert req["Visited-PLMN-Id"] == "001-01"

    def test_ula_subscription_digest(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        ans = srv.diameter_avps(str(s6a_capture(tmp_path)), command_code=316)["transactions"][0]["answer_avps"]
        assert ans["Result-Code"] == 2001
        assert ans["ULA-Flags"] == "1 [Separation-Indication]"
        sub = ans["subscription"]
        assert sub["MSISDN"] == g.MSISDN
        assert sub["Subscriber-Status"] == "SERVICE_GRANTED (0)"
        assert sub["Network-Access-Mode"] == "ONLY_PACKET (2)"
        assert sub["Access-Restriction-Data"] == "33 [UTRAN-Not-Allowed, HO-To-Non-3GPP-Access-Not-Allowed]"
        assert sub["AMBR"] == {"ul": 20_000_000, "dl": 40_000_000}
        assert sub["default_context"] == 1
        assert [a["apn"] for a in sub["apns"]] == ["internet.test", "ims"]
        ims = sub["apns"][1]
        assert ims["qci"] == 5 and ims["arp_priority"] == 1 and ims["pdn_type"] == "IPv4v6 (2)"
        assert ims["pgw"] == {"address": "192.0.2.41"}
        assert ims["served_party_ip"] == "100.64.9.9"
        assert ims["ambr"] == {"ul": 50_000_000, "dl": 100_000_000}

    def test_clr_cancellation_type_and_flags(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        clr = _tx(srv.diameter_avps(str(s6a_capture(tmp_path))), "CLR")
        assert clr["request_avps"]["Cancellation-Type"] == "SUBSCRIPTION_WITHDRAWAL (2)"
        assert clr["request_avps"]["CLR-Flags"] == "2 [Reattach-Required]"
        assert clr["answer_avps"] == {"Result-Code": 2001}

    def test_purge_flags(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        pur = _tx(srv.diameter_avps(str(s6a_capture(tmp_path)), command_code=321), "PUR")
        assert pur["request_avps"]["PUR-Flags"] == "1 [UE-Purged-in-MME]"
        assert pur["answer_avps"]["PUA-Flags"] == "1 [Freeze-M-TMSI]"

    def test_experimental_result(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        air = _tx(srv.diameter_avps(str(s6a_capture(tmp_path)), imsi=g.IMSI_OTHER), "AIR")
        assert air["result"] == "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION"
        assert air["answer_avps"]["Experimental-Result"] == [{"Vendor-Id": V, "Experimental-Result-Code": 5420}]
        assert air["request_avps"]["Number-Of-Requested-Vectors"] == 3

    def test_imsi_selects_only_that_subscriber(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.diameter_avps(str(s6a_capture(tmp_path)), imsi=IMSI_ZERO)
        assert [t["request"] for t in result["transactions"]] == ["ULR", "CLR", "PUR"]

    def test_frame_selects_the_transaction_of_an_answer_frame(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.diameter_avps(str(s6a_capture(tmp_path)), frame=4)  # the CLA
        assert [t["request"] for t in result["transactions"]] == ["CLR"]
        assert result["transactions"][0]["answer_frame"] == 4

    def test_gx_request_type_triggers_and_rule_report(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.diameter_avps(str(gx_capture(tmp_path)))
        first, update = result["transactions"]
        assert first["application"] == "Gx"
        assert first["request_avps"]["CC-Request-Type"] == "INITIAL_REQUEST (1)"
        assert first["request_avps"]["Framed-IP-Address"] == g.UE_IP
        assert first["request_avps"]["Called-Station-Id"] == "internet.test"
        assert first["answer_avps"]["Event-Trigger"] == ["RAT_CHANGE (2)", "USER_LOCATION_CHANGE (13)"]
        assert update["unanswered"] is True
        report = update["request_avps"]["Charging-Rule-Report"]
        assert report[0]["Rule-Failure-Code"] == "RESOURCE_ALLOCATION_FAILURE (10)"
        assert report[0]["Charging-Rule-Name"] == "rule-video"


class TestFullTree:
    def test_full_tree_nests_grouped_and_repeated_avps(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        tx = srv.diameter_avps(str(s6a_capture(tmp_path)), command_code=316, detail="full")["transactions"][0]
        profile = tx["answer_avps"]["Subscription-Data"]["APN-Configuration-Profile"]
        assert [c["Service-Selection"] for c in profile["APN-Configuration"]] == ["internet.test", "ims"]
        assert profile["APN-Configuration"][1]["EPS-Subscribed-QoS-Profile"]["Allocation-Retention-Priority"] == {
            "Priority-Level": 1, "Pre-emption-Capability": "PRE-EMPTION_CAPABILITY_DISABLED (1)",
            "Pre-emption-Vulnerability": "PRE-EMPTION_VULNERABILITY_ENABLED (0)"}
        assert tx["request_avps"]["Session-Id"].endswith(";ulr")
        assert "answer_avps_dropped" not in tx and "truncated" not in tx

    def test_leaf_cap_counts_what_was_left_out(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.diameter_avps(str(s6a_capture(tmp_path)), command_code=316, detail="full", max_avps=10)
        tx = result["transactions"][0]
        assert tx["answer_avps_dropped"] > 0
        assert result["truncated"] is True and "max_avps" in result["truncated_reason"]

    def test_limit_caps_transactions(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.diameter_avps(str(s6a_capture(tmp_path)), limit=2)
        assert result["count"] == 2 and result["total_found"] == 4 and result["truncated"] is True


@pytest.mark.parametrize("kwargs", [{"detail": "everything"}, {"frame": 0}, {"command_code": -1}])
def test_invalid_arguments(configure, tmp_path: Path, kwargs):
    srv = configure(allow=[str(tmp_path)])
    result = srv.diameter_avps(str(s6a_capture(tmp_path)), **kwargs)
    assert result["error"]["type"] == "invalid_argument"


def test_no_match_is_an_empty_result(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)], limits=Limits())
    result = srv.diameter_avps(str(s6a_capture(tmp_path)), imsi="001019999999999")
    assert result["transactions"] == [] and result["total_found"] == 0

"""gtpv1_sessions and the GTPv1-C pass of trace_subscriber, on synthetic Gn captures."""

from __future__ import annotations

import struct
from pathlib import Path

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

SGSN, GGSN, PROXY = "192.0.2.80", "192.0.2.81", "192.0.2.82"


def gtpv1(msg_type: int, teid: int, seq: int, ies: bytes) -> bytes:
    body = struct.pack("!HBB", seq, 0, 0) + ies  # sequence number, N-PDU number, next extension header
    return bytes([0x32, msg_type]) + struct.pack("!HI", len(body), teid) + body


def tv(ie_type: int, data: bytes) -> bytes:
    return bytes([ie_type]) + data


def tlv(ie_type: int, data: bytes) -> bytes:
    return bytes([ie_type]) + struct.pack("!H", len(data)) + data


def apn(name: str) -> bytes:
    return tlv(131, b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")))


def create_request(imsi: str, seq: int, teid_c: int, teid_u: int, apn_name: str) -> bytes:
    return gtpv1(16, 0, seq, b"".join([
        tv(2, g._tbcd(imsi)), tv(14, bytes([1])), tv(15, bytes([0xF0])), tv(16, struct.pack("!I", teid_u)),
        tv(17, struct.pack("!I", teid_c)), tv(20, bytes([5])), tlv(128, bytes([0xF1, 0x21])), apn(apn_name),
        tlv(133, g._ipv4(SGSN)), tlv(133, g._ipv4(SGSN)), tlv(134, bytes([0x91]) + g._tbcd(g.MSISDN)),
        tlv(151, bytes([1])),
    ]))


def create_response(teid: int, seq: int, cause: int, teid_c: int = 0, teid_u: int = 0, eua: str | None = None) -> bytes:
    ies = [tv(1, bytes([cause]))]
    if cause == 128:
        ies += [tv(16, struct.pack("!I", teid_u)), tv(17, struct.pack("!I", teid_c)),
                tlv(128, bytes([0xF1, 0x21]) + g._ipv4(eua or g.UE_IP)), tlv(133, g._ipv4(GGSN)), tlv(133, g._ipv4(GGSN))]
    return gtpv1(17, teid, seq, b"".join(ies))


def gn_capture(tmp_path: Path) -> Path:
    """Create PDP Context accepted, then Update (accepted) and Delete (context not found),
    which carry no IMSI and are only reachable through the TEIDs; another subscriber's
    Create rejected with 219; and an Echo."""
    frames: list[tuple[float, bytes]] = []
    t = 1_700_012_000.0

    def send(dt: float, src: str, dst: str, msg: bytes) -> None:
        frames.append((t + dt, g._udp_frame(src, dst, 2123, 2123, msg)))

    send(0.0, SGSN, GGSN, gtpv1(1, 0, 1, tv(14, bytes([1]))))
    send(0.001, GGSN, SGSN, gtpv1(2, 0, 1, tv(14, bytes([3]))))
    send(1.0, SGSN, GGSN, create_request(g.IMSI, 0x10, 0x111, 0x112, "internet.test"))
    send(1.08, GGSN, SGSN, create_response(0x111, 0x10, 128, 0x221, 0x222))
    send(5.0, SGSN, GGSN, gtpv1(18, 0x221, 0x20, tv(17, struct.pack("!I", 0x111)) + tv(20, bytes([5]))))
    send(5.03, GGSN, SGSN, gtpv1(19, 0x111, 0x20, tv(1, bytes([128]))))
    send(9.0, SGSN, GGSN, gtpv1(20, 0x221, 0x30, tv(20, bytes([5]))))
    send(9.02, GGSN, SGSN, gtpv1(21, 0x111, 0x30, tv(1, bytes([210]))))
    send(12.0, SGSN, GGSN, create_request(g.IMSI_OTHER, 0x40, 0x333, 0x334, "bogus.apn"))
    send(12.01, GGSN, SGSN, create_response(0x333, 0x40, 219))
    return g._frames_to_pcap(tmp_path / "gn.pcap", frames)


def test_pairs_pdp_context_procedures(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.gtpv1_sessions(str(gn_capture(tmp_path)))
    rows = {(r["message"], r.get("imsi")): r for r in result["transactions"]}
    assert result["summary"]["by_message"] == {"Echo Request": 1, "Create PDP Context Request": 2,
                                               "Update PDP Context Request": 1, "Delete PDP Context Request": 1}
    create = rows[("Create PDP Context Request", g.IMSI)]
    assert create["response"] == "Create PDP Context Response" and create["cause_name"] == "Request accepted"
    assert create["accepted"] is True and create["rtt_ms"] == 80.0
    assert create["apn"] == "internet.test" and create["nsapi"] == 5 and create["rat_type"] == "UTRAN"
    assert create["msisdn"] == g.MSISDN and create["end_user_address"] == g.UE_IP
    assert create["request_teid_cp"] == "0x00000111" and create["response_teid_cp"] == "0x00000221"
    assert create["request_gsn"] == SGSN and create["response_gsn"] == GGSN
    rejected = rows[("Create PDP Context Request", g.IMSI_OTHER)]
    assert rejected["cause_name"] == "Missing or unknown APN" and rejected["accepted"] is False
    delete = rows[("Delete PDP Context Request", None)]
    assert delete["cause_name"] == "Context not found" and delete["accepted"] is False
    assert result["summary"]["failed"] == 2 and result["summary"]["unanswered"] == 0


def test_structured_filters(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(gn_capture(tmp_path))
    by_imsi = srv.gtpv1_sessions(path, imsi=g.IMSI_OTHER)
    assert [(r["message"], r["response"]) for r in by_imsi["transactions"]] == [
        ("Create PDP Context Request", "Create PDP Context Response")]
    by_teid = srv.gtpv1_sessions(path, teid="0x221")
    assert [r["message"] for r in by_teid["transactions"]] == [
        "Create PDP Context Request", "Update PDP Context Request", "Delete PDP Context Request"]
    by_apn = srv.gtpv1_sessions(path, apn="Internet.Test")
    assert len(by_apn["transactions"]) == 1


def test_trace_follows_the_pdp_context(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.trace_subscriber(str(gn_capture(tmp_path)), imsi=g.IMSI)
    rows = [r for r in result["timeline"] if r["protocol"] == "gtpv1"]
    assert [(r["message"], r.get("result")) for r in rows] == [
        ("Create PDP Context Request", "Request accepted"), ("Update PDP Context Request", "Request accepted"),
        ("Delete PDP Context Request", "Context not found")]
    assert rows[0]["paa"] == g.UE_IP and rows[2]["failed"] is True
    assert result["passes"]["gtpv1"]["control_teids"] >= 2


def test_trace_without_gtpv1_has_no_gtpv1_pass(server, pcap_dir: Path):
    result = server.trace_subscriber(str(pcap_dir / "all.pcap"), imsi=g.IMSI)
    assert "gtpv1" not in result["passes"] and "gtpv1" not in result["by_protocol"]


def test_response_through_a_proxy(configure, tmp_path: Path):
    t = 1_700_012_500.0
    path = g._frames_to_pcap(tmp_path / "proxy.pcap", [
        (t, g._udp_frame(SGSN, PROXY, 2123, 2123, create_request(g.IMSI, 0x50, 0x511, 0x512, "internet.test"))),
        (t + 0.05, g._udp_frame(PROXY, "198.51.100.80", 2123, 2123, create_response(0x511, 0x50, 128, 0x621, 0x622))),
    ])
    srv = configure(allow=[str(tmp_path)])
    row = srv.gtpv1_sessions(str(path))["transactions"][0]
    assert row["response"] == "Create PDP Context Response" and row["response_path"] == f"{PROXY} > 198.51.100.80"


def test_compare_counts_gtpv1_steps(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(gn_capture(tmp_path))
    result = srv.compare_captures(path, path)
    assert result["identical"] is True and result["a"]["by_protocol"] == {"gtpv1": 4}

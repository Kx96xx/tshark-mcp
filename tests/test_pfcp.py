"""pfcp_sessions and the PFCP pass of trace_subscriber, on synthetic N4 captures."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

SMF, UPF = "192.0.2.100", "192.0.2.101"
UE_A, UE_B = "10.45.0.7", "10.45.0.8"
CP_A, UP_A = 0x0000_0000_0000_A001, 0x0000_0000_0000_B001
CP_B = 0x0000_0000_0000_A002
UP_OLD = 0x0000_0000_0000_B0FF


def ie(ie_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ie_type, len(data)) + data


def pfcp(msg_type: int, seq: int, ies: list[bytes], seid: int | None = None) -> bytes:
    body = b"".join(ies)
    if seid is None:
        head = struct.pack("!I", seq << 8)
        return bytes([0x20, msg_type]) + struct.pack("!H", len(head) + len(body)) + head + body
    head = struct.pack("!Q", seid) + struct.pack("!I", seq << 8)
    return bytes([0x21, msg_type]) + struct.pack("!H", len(head) + len(body)) + head + body


def node_id(ip: str) -> bytes:
    return ie(60, bytes([0]) + g._ipv4(ip))


def f_seid(seid: int, ip: str) -> bytes:
    return ie(57, bytes([0x02]) + struct.pack("!Q", seid) + g._ipv4(ip))


def cause(value: int) -> bytes:
    return ie(19, bytes([value]))


def recovery(stamp: int) -> bytes:
    return ie(96, struct.pack("!I", stamp))


def create_pdr(pdr_id: int, ue_ip: str, far_id: int, source: int) -> bytes:
    pdi = ie(2, ie(20, bytes([source])) + ie(93, bytes([0x02 | (0x04 if source == 1 else 0)]) + g._ipv4(ue_ip)))
    return ie(1, ie(56, struct.pack("!H", pdr_id)) + ie(29, struct.pack("!I", 255)) + pdi + ie(108, struct.pack("!I", far_id)))


def far(ie_type: int, far_id: int, action: int) -> bytes:
    return ie(ie_type, ie(108, struct.pack("!I", far_id)) + ie(44, bytes([action, 0])))


def usage_report(ie_type: int, urr_id: int, total: int, up: int, down: int) -> bytes:
    vol = ie(66, bytes([0x07]) + struct.pack("!QQQ", total, up, down))
    return ie(ie_type, ie(81, struct.pack("!I", urr_id)) + ie(104, struct.pack("!I", 1))
              + ie(63, bytes([0x00, 0x02, 0x00])) + vol + ie(67, struct.pack("!I", 42)))


FORW, BUFF_NOCP = 0x02, 0x0C


class N4:
    def __init__(self, t0: float) -> None:
        self.t0 = t0
        self.frames: list[tuple[float, bytes]] = []

    def cp(self, dt: float, msg: bytes) -> None:
        self.frames.append((self.t0 + dt, g._udp_frame(SMF, UPF, 8805, 8805, msg)))

    def up(self, dt: float, msg: bytes) -> None:
        self.frames.append((self.t0 + dt, g._udp_frame(UPF, SMF, 8805, 8805, msg)))

    def write(self, path: Path) -> Path:
        self.frames.sort(key=lambda f: f[0])
        return g._frames_to_pcap(path, self.frames)


def n4_capture(tmp_path: Path) -> Path:
    """Association and heartbeats (one unanswered, then the UPF's Recovery Time Stamp
    changes); session A: established, downlink buffered, a downlink data report,
    forwarding again, deleted with a usage report; session B: rejected with cause 73;
    a modification of a session from before the capture answered 'Session context not
    found'; an unanswered session report."""
    n = N4(1_700_040_000.0)
    n.cp(0.0, pfcp(5, 1, [node_id(SMF), recovery(3_900_000_000)]))
    n.up(0.002, pfcp(6, 1, [node_id(UPF), cause(1), recovery(3_900_000_100)]))
    n.cp(1.0, pfcp(1, 2, [recovery(3_900_000_000)]))
    n.up(1.001, pfcp(2, 2, [recovery(3_900_000_100)]))
    # Session A
    est = pfcp(50, 10, [node_id(SMF), f_seid(CP_A, SMF), create_pdr(1, UE_A, 1, 0), create_pdr(2, UE_A, 2, 1),
                        far(3, 1, FORW), far(3, 2, FORW)], seid=0)
    n.cp(2.0, est)
    n.up(2.004, pfcp(51, 10, [node_id(UPF), cause(1), f_seid(UP_A, UPF)], seid=CP_A))
    n.cp(5.0, pfcp(52, 11, [far(10, 2, BUFF_NOCP)], seid=UP_A))
    n.up(5.002, pfcp(53, 11, [cause(1)], seid=CP_A))
    n.up(6.0, pfcp(56, 900, [ie(39, bytes([0x01])), ie(83, ie(56, struct.pack("!H", 2)))], seid=CP_A))
    n.cp(6.003, pfcp(57, 900, [cause(1)], seid=UP_A))
    n.cp(7.0, pfcp(52, 12, [far(10, 2, FORW)], seid=UP_A))
    n.up(7.002, pfcp(53, 12, [cause(1)], seid=CP_A))
    n.cp(20.0, pfcp(54, 13, [], seid=UP_A))
    n.up(20.003, pfcp(55, 13, [cause(1), usage_report(79, 1, 3000, 1000, 2000)], seid=CP_A))
    # Session B: rejected
    n.cp(30.0, pfcp(50, 20, [node_id(SMF), f_seid(CP_B, SMF), create_pdr(1, UE_B, 1, 0), far(3, 1, FORW)], seid=0))
    n.up(30.003, pfcp(51, 20, [node_id(UPF), cause(73), ie(40, struct.pack("!H", 1))], seid=CP_B))
    # A session from before the capture
    n.cp(40.0, pfcp(52, 30, [far(10, 9, FORW)], seid=UP_OLD))
    n.up(40.002, pfcp(53, 30, [cause(65)], seid=0))
    # Heartbeat without a response, then the UPF has restarted
    n.cp(50.0, pfcp(1, 40, [recovery(3_900_000_000)]))
    n.cp(60.0, pfcp(1, 41, [recovery(3_900_000_000)]))
    n.up(60.001, pfcp(2, 41, [recovery(3_900_000_555)]))
    # The UPF reports on session A after it was deleted: no response
    n.up(70.0, pfcp(56, 901, [ie(39, bytes([0x02]))], seid=CP_A))
    return n.write(tmp_path / "n4.pcap")


def _session(result: dict, key: str, value: str) -> dict:
    return next(s for s in result["sessions"] if s.get(key) == value)


def test_sessions_view(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.pfcp_sessions(str(n4_capture(tmp_path)))
    a = _session(result, "cp_seid", f"0x{CP_A:016x}")
    assert a["up_seid"] == f"0x{UP_A:016x}" and a["cp"] == SMF and a["up"] == UPF
    assert a["ue_ip"] == [UE_A] and a["establishment"] == "1 Request accepted"
    assert a["modifications"] == 2 and a["reports"]["DLDR"] == 1 and a["reports"]["USAR"] == 1
    assert a["state"] == "deleted" and a["deletion"] == "1 Request accepted"
    assert a["usage"] == {"total_bytes": 3000, "uplink_bytes": 1000, "downlink_bytes": 2000}
    assert any("FAR 2 set to BUFF|NOCP" in i for i in a["issues"])
    assert any("1 request(s) without a response" in i for i in a["issues"])
    b = _session(result, "cp_seid", f"0x{CP_B:016x}")
    assert b["state"] == "rejected" and "establishment rejected: 73 Rule creation/modification Failure" in b["issues"]
    old = _session(result, "up_seid", f"0x{UP_OLD:016x}")
    assert old["established"] == "before the capture" and old["failed_modifications"] == 1
    assert result["summary"]["sessions"] == 3 and result["summary"]["by_state"]["rejected"] == 1
    assert result["sessions"][0].get("issues")  # sessions with issues come first


def test_nodes_show_restart_and_unanswered_heartbeat(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.pfcp_sessions(str(n4_capture(tmp_path)))
    (node,) = result["nodes"]
    assert node["association"] == "1 Request accepted" and node["node_ids"] == {SMF: SMF, UPF: UPF}
    assert node["heartbeats"] == 3 and node["heartbeats_unanswered"] == 1
    assert len(node["restarts"]) == 1 and node["restarts"][0].startswith(f"{UPF} restarted")
    assert result["summary"]["peer_restarts"] == 1


def test_transactions_view(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    rows = srv.pfcp_sessions(str(n4_capture(tmp_path)), view="transactions")["transactions"]
    est = next(r for r in rows if r["message"] == "Session Establishment Request" and r.get("accepted"))
    assert est["cp_f_seid"] == f"0x{CP_A:016x}" and est["up_f_seid"] == f"0x{UP_A:016x}"
    assert est["rules"] == {"create_pdr": 2, "create_far": 2} and est["far_actions"] == {"1": "FORW", "2": "FORW"}
    rej = next(r for r in rows if r.get("cause") == 73)
    assert rej["cause_name"] == "Rule creation/modification Failure" and rej["accepted"] is False and rej["offending_ie"] == 1
    mod = next(r for r in rows if r.get("far_actions") == {"2": "BUFF|NOCP"})
    assert mod["seid"] == f"0x{UP_A:016x}"
    report = next(r for r in rows if r.get("report_types") == ["DLDR"])
    assert report["message"] == "Session Report Request" and report["src"] == UPF
    deletion = next(r for r in rows if r["message"] == "Session Deletion Request")
    assert deletion["response_usage"][0]["downlink_bytes"] == 2000 and deletion["response_usage"][0]["duration_s"] == 42
    assert sum(1 for r in rows if r.get("unanswered")) == 2


def test_selection_by_ue_ip_follows_both_seids(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.pfcp_sessions(str(n4_capture(tmp_path)), ue_ip=UE_A, view="transactions")
    names = [r["message"] for r in result["transactions"]]
    assert names.count("Session Modification Request") == 2 and "Session Report Request" in names
    assert "Session Deletion Request" in names and "Heartbeat Request" not in names
    assert all(r.get("seid") in (None, "0x0000000000000000", f"0x{CP_A:016x}", f"0x{UP_A:016x}")
               for r in result["transactions"])
    by_seid = srv.pfcp_sessions(str(n4_capture(tmp_path)), seid=hex(UP_A))
    assert [s["cp_seid"] for s in by_seid["sessions"]] == [f"0x{CP_A:016x}"]


def test_copies_are_marked(configure, tmp_path: Path):
    n = N4(1_700_041_000.0)
    est = pfcp(50, 10, [node_id(SMF), f_seid(CP_A, SMF), create_pdr(1, UE_A, 1, 0), far(3, 1, FORW)], seid=0)
    n.cp(0.0, est)
    n.cp(0.0004, est)
    n.up(0.004, pfcp(51, 10, [node_id(UPF), cause(1), f_seid(UP_A, UPF)], seid=CP_A))
    n.up(0.0044, pfcp(51, 10, [node_id(UPF), cause(1), f_seid(UP_A, UPF)], seid=CP_A))
    srv = configure(allow=[str(tmp_path)])
    path = str(n.write(tmp_path / "copies.pcap"))
    rows = srv.pfcp_sessions(path, view="transactions")["transactions"]
    assert [r.get("copy_of_frame") for r in rows] == [None, 1]
    (sess,) = srv.pfcp_sessions(path)["sessions"]
    assert sess["copies"] == 1


def test_trace_follows_the_ue_address_into_pfcp(configure, tmp_path: Path):
    """The GTPv2 Create Session Response allocates the UE address; the PFCP session
    carries no IMSI, so the trace finds it through that address."""
    n = N4(1_700_042_000.0)
    csr = g._gtpv2(32, 0, 77, [g._ie(1, g._tbcd(g.IMSI)), g._ie(87, g._fteid(6, 0xA0, g.SGW_IP)), g._apn_ie(g.APN),
                               g._ie(99, bytes([1]))])
    csresp = g._gtpv2(33, 0xA0, 77, [g._ie(2, bytes([16, 0])), g._ie(79, bytes([1]) + g._ipv4(UE_A))])
    n.frames.append((n.t0, g._udp_frame(g.SGW_IP, g.PGW_IP, 2123, 2123, csr)))
    n.cp(0.01, pfcp(50, 10, [node_id(SMF), f_seid(CP_A, SMF), create_pdr(1, UE_A, 1, 0), far(3, 1, FORW)], seid=0))
    n.up(0.012, pfcp(51, 10, [node_id(UPF), cause(1), f_seid(UP_A, UPF)], seid=CP_A))
    n.cp(0.5, pfcp(52, 11, [far(10, 1, FORW)], seid=UP_A))
    n.up(0.502, pfcp(53, 11, [cause(1)], seid=CP_A))
    n.cp(0.6, pfcp(50, 12, [node_id(SMF), f_seid(CP_B, SMF), create_pdr(1, UE_B, 1, 0), far(3, 1, FORW)], seid=0))
    n.frames.append((n.t0 + 0.02, g._udp_frame(g.PGW_IP, g.SGW_IP, 2123, 2123, csresp)))
    srv = configure(allow=[str(tmp_path)])
    result = srv.trace_subscriber(str(n.write(tmp_path / "trace.pcap")), imsi=g.IMSI)
    pf = [r for r in result["timeline"] if r["protocol"] == "pfcp"]
    assert [r["message"] for r in pf] == ["Session Establishment Request", "Session Modification Request"]
    assert pf[0]["up_f_seid"] == f"0x{UP_A:016x}" and pf[0]["ue_ip"] == [UE_A]
    assert result["passes"]["pfcp"]["ue_ips_from_gtp"] == 1


def test_trace_without_pfcp_has_no_pfcp_pass(server, pcap_dir: Path):
    result = server.trace_subscriber(str(pcap_dir / "all.pcap"), imsi=g.IMSI)
    assert "pfcp" not in result["passes"]


@pytest.mark.parametrize("kwargs", [{"seid": "nope"}, {"seid": 0}, {"ue_ip": "10.0.0"}, {"view": "flows"}])
def test_invalid_arguments(server, pcap_dir: Path, kwargs):
    assert server.pfcp_sessions(str(pcap_dir / "all.pcap"), **kwargs)["error"]["type"] == "invalid_argument"


def test_session_from_before_the_capture_gets_both_seids(configure, tmp_path: Path):
    n = N4(1_700_043_000.0)
    n.cp(0.0, pfcp(54, 5, [], seid=UP_OLD))
    n.up(0.003, pfcp(55, 5, [cause(1), usage_report(79, 1, 10, 4, 6)], seid=CP_B))
    srv = configure(allow=[str(tmp_path)])
    (sess,) = srv.pfcp_sessions(str(n.write(tmp_path / "old.pcap")))["sessions"]
    assert sess["up_seid"] == f"0x{UP_OLD:016x}" and sess["cp_seid"] == f"0x{CP_B:016x}"
    assert sess["established"] == "before the capture" and sess["state"] == "deleted"
    assert sess["usage"]["total_bytes"] == 10

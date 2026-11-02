"""Regression tests for bugs found by running the tools against long, real-world
captures. Every capture here is synthetic and built from made-up values."""

from __future__ import annotations

import struct
from pathlib import Path

from tshark_mcp.limits import Limits

from . import pcapgen
from .conftest import requires_tshark

pytestmark = requires_tshark


# ------------------------------------------------- captures that end mid-packet
def _cut_short(tmp_path: Path) -> Path:
    """A Diameter capture whose last record is cut in half, like a ring-buffer
    file copied while tshark was still writing it."""
    full = pcapgen.write_diameter_pcap(tmp_path / "full.pcap")
    data = full.read_bytes()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(data[:-20])
    return cut


class TestCutShortCapture:
    def test_packets_before_the_damage_are_returned_with_a_warning(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.diameter_transactions(str(_cut_short(tmp_path)))
        assert "error" not in result, result
        # ULR/ULA, AIR/AIA and the unanswered AIR survive; the DWR/DWA pair is damaged.
        assert [t["request"] for t in result["transactions"]][:3] == ["ULR", "AIR", "AIR"]
        assert len(result["warnings"]) == 1
        assert "cut short" in result["warnings"][0]

    def test_a_filter_matching_nothing_is_an_empty_result_not_an_error(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.gtp_user_plane(str(_cut_short(tmp_path)))
        assert "error" not in result, result
        assert result["tunnels"] == [] and result["warnings"]

    def test_a_clean_capture_has_no_warnings(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.diameter_transactions(str(pcapgen.write_diameter_pcap(tmp_path / "ok.pcap")))
        assert "warnings" not in result


# ------------------------------------------- tshark -c counts frames read, not matched
def _after_filler(tmp_path: Path, source: Path, filler: int, name: str) -> Path:
    """``filler`` unrelated UDP frames (DNS-port noise) followed by every frame of ``source``."""
    from scapy.all import Ether, rdpcap, wrpcap  # type: ignore

    t0 = 1_699_999_000.0
    noise = []
    for i in range(filler):
        p = Ether(pcapgen._udp_frame("192.0.2.200", "192.0.2.201", 40000 + i, 9, b"noise" * 4))
        p.time = t0 + i * 0.001
        noise.append(p)
    path = tmp_path / name
    wrpcap(str(path), noise + list(rdpcap(str(source))))
    return path


class TestFrameReadCap:
    def test_matches_after_the_first_max_packets_frames_are_found(self, configure, tmp_path: Path):
        diam = pcapgen.write_diameter_pcap(tmp_path / "d.pcap")
        padded = _after_filler(tmp_path, diam, 50, "padded.pcap")
        srv = configure(allow=[str(tmp_path)], limits=Limits(max_packets=20))
        result = srv.diameter_transactions(str(padded))
        # Before the fix tshark -c 20 stopped inside the noise and nothing was found.
        assert result["summary"]["by_message"] == {"ULR": 1, "AIR": 2, "DWR": 1}
        assert result["packets_scanned"] == 7
        assert "truncated" not in result

    def test_match_cap_counts_matching_packets(self, configure, tmp_path: Path):
        diam = pcapgen.write_diameter_pcap(tmp_path / "d.pcap")
        padded = _after_filler(tmp_path, diam, 50, "padded.pcap")
        srv = configure(allow=[str(tmp_path)], limits=Limits(max_packets=3))
        result = srv.diameter_transactions(str(padded))
        assert result["packets_scanned"] == 3
        assert result["truncated"] is True
        assert "first 3 matching packets" in result["truncated_reason"]

    def test_frame_cap_reports_an_unread_tail(self, configure, tmp_path: Path):
        diam = pcapgen.write_diameter_pcap(tmp_path / "d.pcap")
        padded = _after_filler(tmp_path, diam, 50, "padded.pcap")
        srv = configure(allow=[str(tmp_path)], limits=Limits(max_scan_packets=30))
        for result in (srv.diameter_transactions(str(padded)),
                       srv.sctp_associations(str(padded)),
                       srv.filter_packets(str(padded), "diameter", fields=["frame.number"])):
            assert result["total_found"] == 0
            assert result["truncated"] is True
            assert "first 30 frames" in result["truncated_reason"]

    def test_frame_cap_not_reported_when_the_file_fits(self, configure, tmp_path: Path):
        diam = pcapgen.write_diameter_pcap(tmp_path / "d.pcap")
        padded = _after_filler(tmp_path, diam, 3, "padded.pcap")  # exactly 10 frames
        srv = configure(allow=[str(tmp_path)], limits=Limits(max_scan_packets=10))
        result = srv.diameter_transactions(str(padded))
        assert result["summary"]["by_message"] == {"ULR": 1, "AIR": 2, "DWR": 1}
        assert "truncated" not in result

    def test_caller_frame_number_column_is_kept(self, configure, tmp_path: Path):
        # tshark prints a field asked for twice in one column only, so the hidden
        # frame-number column must reuse the caller's own frame.number.
        diam = pcapgen.write_diameter_pcap(tmp_path / "d.pcap")
        padded = _after_filler(tmp_path, diam, 5, "padded.pcap")
        srv = configure(allow=[str(tmp_path)])
        result = srv.filter_packets(str(padded), "diameter.cmd.code == 318",
                                    fields=["diameter.hopbyhopid", "frame.number", "ip.src"])
        assert [p["frame.number"] for p in result["packets"]] == ["8", "9", "10"]
        assert all("ip.src" in p and "diameter.hopbyhopid" in p for p in result["packets"])


# ------------------------------------------- GTPv2-C seen across a NAT or proxy
def _gtp_behind_nat(tmp_path: Path) -> Path:
    """A Create Session Request sent to the PGW's public address and answered from
    that address towards the SGW's inner (NATed) address, then a request whose
    sequence number collides with a response between two unrelated hosts."""
    sgw_outer, sgw_inner, pgw, other_a, other_b = "192.0.2.30", "198.51.100.30", "192.0.2.40", "203.0.113.1", "203.0.113.2"
    g = pcapgen
    csr = g._gtpv2(32, 0, 0x77, [g._ie(1, g._tbcd(g.IMSI)), g._apn_ie(g.APN), g._ie(87, g._fteid(6, 0xA0A0, sgw_outer))])
    resp = g._gtpv2(33, 0xA0A0, 0x77, [g._ie(2, bytes([16, 0])), g._ie(87, g._fteid(7, 0xB0B0, pgw), instance=1)])
    csr2 = g._gtpv2(32, 0, 0x99, [g._ie(1, g._tbcd(g.IMSI_OTHER))])
    stray = g._gtpv2(33, 0xC0C0, 0x99, [g._ie(2, bytes([16, 0]))])
    t0 = 1_700_000_900.0
    frames = [
        (t0, g._udp_frame(sgw_outer, pgw, 2123, 2123, csr)),
        (t0 + 0.010, g._udp_frame(pgw, sgw_inner, 2123, 2123, resp)),
        (t0 + 1.0, g._udp_frame(sgw_outer, pgw, 2123, 2123, csr2)),
        (t0 + 1.010, g._udp_frame(other_a, other_b, 2123, 2123, stray)),
    ]
    return g._frames_to_pcap(tmp_path / "nat.pcap", frames)


class TestGtpAcrossNat:
    def test_response_from_the_request_target_on_another_path_is_paired(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.gtp_sessions(str(_gtp_behind_nat(tmp_path)))
        rows = {(r.get("seq"), r.get("message")): r for r in result["transactions"]}
        first = rows[(0x77, "Create Session Request")]
        assert first.get("unanswered") is None
        assert first["response"] == "Create Session Response" and first["cause"] == 16
        assert first["response_path"] == "192.0.2.40 > 198.51.100.30"

    def test_unrelated_hosts_reusing_a_sequence_number_are_not_paired(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.gtp_sessions(str(_gtp_behind_nat(tmp_path)))
        second = next(r for r in result["transactions"] if r.get("message") == "Create Session Request" and r.get("seq") == 0x99)
        assert second["unanswered"] is True
        assert any(r.get("unmatched_answer") for r in result["transactions"])
        assert result["summary"]["unanswered"] == 1


# ------------------------------------------- MAP results and errors
def _map_replies(tmp_path: Path) -> Path:
    """sendAuthenticationInfo answered by a returnError (unknownSubscriber), and
    mo-forwardSM answered by a returnResultLast that carries only the invoke id,
    as SMSCs commonly send it."""
    g = pcapgen
    vlr, hlr, smsc = "15550109001", "15550109002", "15550109003"
    frames: list[tuple[float, bytes]] = []
    t0 = 1_700_000_950.0

    def send(ts: float, a_to_b: bool, payload: bytes) -> None:
        src, dst = (g.STP_A, g.STP_B) if a_to_b else (g.STP_B, g.STP_A)
        frames.append((ts, g._sctp_data(src, dst, 2905, 2905, 0x5555, 900 + len(frames), 3, payload)))

    def m3ua(called: bytes, calling: bytes, tcap: bytes) -> bytes:
        return g._m3ua_data(100, 200, g._sccp_udt(called, calling, tcap))

    sai_arg = g._ber(0x30, g._ber(0x80, g._tbcd(g.IMSI)) + g._ber(0x02, b"\x01"))
    send(t0, True, m3ua(g._sccp_gt(hlr, 6), g._sccp_gt(vlr, 7),
                        g._tcap_begin(b"\x00\x00\x00\x10", g._invoke(1, 56, sai_arg))))
    error = g._ber(0xA3, g._ber(0x02, b"\x01") + g._ber(0x02, b"\x01"))  # returnError unknownSubscriber
    send(t0 + 0.05, False, m3ua(g._sccp_gt(vlr, 7), g._sccp_gt(hlr, 6), g._tcap_end(b"\x00\x00\x00\x10", error)))

    tpdu = bytes.fromhex("01000B915155101055F500000AE8329BFD4697D9EC37")
    mo_arg = g._ber(0x30, g._ber(0x84, g._addr_string(smsc)) + g._ber(0x82, g._addr_string(g.MSISDN)) + g._ber(0x04, tpdu))
    send(t0 + 1.0, True, m3ua(g._sccp_gt(smsc, 8), g._sccp_gt(vlr, 8),
                              g._tcap_begin(b"\x00\x00\x00\x11", g._invoke(1, 46, mo_arg))))
    bare_result = g._ber(0xA2, g._ber(0x02, b"\x01"))  # returnResultLast, invoke id only
    send(t0 + 1.2, False, m3ua(g._sccp_gt(vlr, 8), g._sccp_gt(smsc, 8), g._tcap_end(b"\x00\x00\x00\x11", bare_result)))
    return g._frames_to_pcap(tmp_path / "map_replies.pcap", frames)


def _components_by_frame(result: dict) -> dict[int, list[dict]]:
    return {r["frame"]: r.get("components", []) for r in result["messages"]}


class TestMapReplies:
    def test_return_error_reports_the_error_code_not_the_choice_index(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        comps = _components_by_frame(srv.sigtran_messages(str(_map_replies(tmp_path))))
        error = comps[2][0]
        assert error["type"] == "returnError"
        assert error["error_code"] == 1 and error["error"] == "unknownSubscriber"
        assert error.get("opcode") != 1

    def test_replies_are_named_after_the_invoke_they_answer(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.sigtran_messages(str(_map_replies(tmp_path)))
        comps = _components_by_frame(result)
        assert comps[2][0]["operation"] == "sendAuthenticationInfo"
        assert comps[4][0]["type"] == "returnResultLast"
        assert comps[4][0]["operation"] == "mo-forwardSM" and comps[4][0]["opcode"] == 46
        # Errors are counted by error, results by the operation they answer.
        assert result["summary"]["by_operation"] == {"sendAuthenticationInfo": 1, "unknownSubscriber": 1, "mo-forwardSM": 2}


# ------------------------------------------- SIP dialogs with challenges and retransmissions
def _sip_challenge(tmp_path: Path) -> Path:
    """REGISTER challenged with 401, retried with credentials (sent twice, a UDP
    retransmission) and accepted with 200, then refreshed; and an INVITE answered
    200 whose later re-INVITE is refused with 491."""
    g = pcapgen
    ue, pcscf = g.UE_SIP_IP, g.PCSCF_IP
    dom = "ims.mnc001.mcc001.3gppnetwork.org"
    aor = f"<sip:+{g.MSISDN}@{dom}>"
    via = "Via: SIP/2.0/UDP 198.51.100.9:5060;branch=z9hG4bK"
    frames: list[tuple[float, bytes]] = []
    t0 = 1_700_001_000.0

    def up(ts: float, lines: list[str]) -> None:
        frames.append((ts, g._udp_frame(ue, pcscf, 5060, 5060, g._sip(lines))))

    def down(ts: float, lines: list[str]) -> None:
        frames.append((ts, g._udp_frame(pcscf, ue, 5060, 5060, g._sip(lines))))

    def register(cseq: int, branch: str) -> list[str]:
        return [f"REGISTER sip:{dom} SIP/2.0", via + branch, f"From: {aor};tag=r1", f"To: {aor}",
                "Call-ID: reg-1@ue.example", f"CSeq: {cseq} REGISTER", "Contact: <sip:198.51.100.9:5060>"]

    def reply(code: int, reason: str, cseq: int, method: str, branch: str, call_id: str) -> list[str]:
        return [f"SIP/2.0 {code} {reason}", via + branch, f"From: {aor};tag=r1", f"To: {aor};tag=n1",
                f"Call-ID: {call_id}", f"CSeq: {cseq} {method}"]

    up(t0, register(1, "a1"))
    down(t0 + 0.02, reply(401, "Unauthorized", 1, "REGISTER", "a1", "reg-1@ue.example"))
    up(t0 + 0.10, register(2, "a2"))
    up(t0 + 0.60, register(2, "a2"))  # retransmission
    down(t0 + 0.70, reply(200, "OK", 2, "REGISTER", "a2", "reg-1@ue.example"))
    up(t0 + 60.0, register(3, "a3"))
    down(t0 + 60.02, reply(200, "OK", 3, "REGISTER", "a3", "reg-1@ue.example"))

    def invite(cseq: int, branch: str) -> list[str]:
        return [f"INVITE sip:+15550100555@{dom} SIP/2.0", via + branch, f"From: {aor};tag=r1",
                f"To: <sip:+15550100555@{dom}>", "Call-ID: call-1@ue.example", f"CSeq: {cseq} INVITE"]

    up(t0 + 100.0, invite(1, "i1"))
    down(t0 + 101.0, reply(200, "OK", 1, "INVITE", "i1", "call-1@ue.example"))
    up(t0 + 130.0, invite(2, "i2"))
    down(t0 + 130.1, reply(491, "Request Pending", 2, "INVITE", "i2", "call-1@ue.example"))
    return g._frames_to_pcap(tmp_path / "sip_challenge.pcap", frames)


class TestSipOutcome:
    def test_register_challenged_then_accepted_is_not_a_failure(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.sip_dialogs(str(_sip_challenge(tmp_path)))
        reg = next(d for d in result["dialogs"] if d["initial_method"] == "REGISTER")
        assert reg["final_status"] == 401  # the first transaction's answer is still reported
        assert reg["outcome_status"] == 200
        assert reg["attempts"] == 3
        assert result["summary"]["failed"] == 0

    def test_a_refused_reinvite_does_not_fail_an_established_call(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.sip_dialogs(str(_sip_challenge(tmp_path)))
        call = next(d for d in result["dialogs"] if d["initial_method"] == "INVITE")
        assert call["outcome_status"] == 200

    def test_retransmissions_are_counted_not_listed_as_methods(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.sip_dialogs(str(_sip_challenge(tmp_path)))
        reg = next(d for d in result["dialogs"] if d["initial_method"] == "REGISTER")
        assert reg["resent_messages"] == 1
        assert reg["methods"] == ["REGISTER", "REGISTER", "REGISTER"]
        assert reg["message_count"] == 7

    def test_trace_uses_the_outcome(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.trace_subscriber(str(_sip_challenge(tmp_path)), msisdn=pcapgen.MSISDN)
        rows = [r for r in result["timeline"] if r["protocol"] == "sip"]
        assert {r["message"] for r in rows} == {"REGISTER -> 200", "INVITE -> 200"}
        assert result["failures"] == 0


# ------------------------------------------- several Diameter messages in one SCTP packet
def _bundled_diameter(tmp_path: Path) -> Path:
    """Two AIRs bundled in one SCTP packet, the other subscriber's first, then
    their answers bundled the same way."""
    from scapy.all import IP, SCTP, Ether  # type: ignore
    from scapy.layers.sctp import SCTPChunkData  # type: ignore

    g = pcapgen
    mme = "mme01.epc.mnc001.mcc001.3gppnetwork.org"
    realm = "epc.mnc001.mcc001.3gppnetwork.org"
    sid_other, sid_mine = f"{mme};1;other", f"{mme};1;mine"

    def air(sid: str, imsi: str, hbh: int) -> bytes:
        return g._diameter(318, g.S6A, hbh, hbh, True, g._diam_common(sid, mme, realm, realm) + [g._avp(1, imsi.encode())])

    def aia(sid: str, hbh: int) -> bytes:
        return g._diameter(318, g.S6A, hbh, hbh, False, [g._avp(263, sid.encode()), g._avp(268, struct.pack("!I", 2001)),
                                                         g._avp(264, b"hss01." + realm.encode()), g._avp(296, realm.encode())])

    def bundle(src: str, dst: str, tsn: int, payloads: list[bytes]) -> bytes:
        pkt = Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=src, dst=dst) / SCTP(sport=3868, dport=3868, tag=0x77)
        for i, data in enumerate(payloads):
            pkt = pkt / SCTPChunkData(beginning=1, ending=1, tsn=tsn + i, stream_id=0, stream_seq=tsn + i, proto_id=46, data=data)
        return bytes(pkt)

    t0 = 1_700_002_000.0
    frames = [
        (t0, bundle(g.MME_IP, g.HSS_IP, 10, [air(sid_other, g.IMSI_OTHER, 0x51), air(sid_mine, g.IMSI, 0x52)])),
        (t0 + 0.02, bundle(g.HSS_IP, g.MME_IP, 20, [aia(sid_other, 0x51), aia(sid_mine, 0x52)])),
    ]
    return g._frames_to_pcap(tmp_path / "bundled.pcap", frames)


class TestBundledDiameter:
    def test_imsi_selects_only_its_own_session(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.diameter_sessions(str(_bundled_diameter(tmp_path)), imsi=pcapgen.IMSI)
        assert [s["session_id"].rsplit(";", 1)[1] for s in result["sessions"]] == ["mine"]
        assert result["sessions"][0]["answer_codes"] == [318]

    def test_trace_keeps_only_the_subscriber_transactions(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        result = srv.trace_subscriber(str(_bundled_diameter(tmp_path)), imsi=pcapgen.IMSI)
        rows = [r for r in result["timeline"] if r["protocol"] == "diameter"]
        assert len(rows) == 1 and rows[0]["identity"] == pcapgen.IMSI
        assert result["passes"]["diameter"]["sessions"] == 1


# ------------------------------------------- find_identifier on files longer than the frame cap
class TestFindIdentifierFrameCap:
    def test_a_file_read_only_in_part_is_not_reported_as_clean(self, configure, tmp_path: Path):
        diam = pcapgen.write_diameter_pcap(tmp_path / "d.pcap")
        padded = _after_filler(tmp_path, diam, 50, "padded.pcap")
        diam.unlink()
        srv = configure(allow=[str(tmp_path)], limits=Limits(max_scan_packets=30))
        result = srv.find_identifier(str(tmp_path), pcapgen.IMSI)
        assert result["files_with_hits"] == 0
        assert result["partially_scanned"] == [str(padded.resolve())]
        assert result["truncated"] is True and "frame cap of 30" in result["truncated_reason"]

    def test_a_file_read_in_full_without_hits_is_not_flagged(self, configure, tmp_path: Path):
        padded = _after_filler(tmp_path, pcapgen.write_diameter_pcap(tmp_path / "d.pcap"), 50, "padded.pcap")
        srv = configure(allow=[str(tmp_path)])
        result = srv.find_identifier(str(padded), "001019999999999")
        assert "partially_scanned" not in result and "truncated" not in result


# ------------------------------------------- find_identifier keeps to its shared time budget
def test_find_identifier_does_not_overrun_the_shared_time_budget(tmp_path: Path):
    import sys
    import textwrap
    import time

    from tshark_mcp import server as server_module

    caps = tmp_path / "caps"
    caps.mkdir()
    for name in ("a.pcap", "b.pcap"):
        (caps / name).write_bytes(b"\x00" * 64)
    fake = tmp_path / "fake-tshark"
    # The filter dry run and the field list return at once; a.pcap takes 1.5 s, b.pcap hangs.
    fake.write_text(f"#!{sys.executable}\nimport sys, time\n" + textwrap.dedent("""
        argv = sys.argv[1:]
        if "-G" in argv or "-" in argv:
            sys.exit(0)
        time.sleep(1.5 if any(a.endswith("a.pcap") for a in argv) else 30)
    """))
    fake.chmod(0o755)
    server_module.configure([str(caps)], limits=Limits(timeout_seconds=3.0), tshark=str(fake))
    try:
        started = time.monotonic()
        result = server_module.find_identifier(str(caps), "001010123456789")
        elapsed = time.monotonic() - started
    finally:
        server_module._STATE = None
    # Before the fix b.pcap got a fresh 3 s and the call took about 4.5 s.
    assert elapsed < 3.8, elapsed
    assert result["files_scanned"] == 2
    assert [e["error"] for e in result["errors"]] == ["timeout"]
    assert result["truncated"] is True and "time budget" in result["truncated_reason"]

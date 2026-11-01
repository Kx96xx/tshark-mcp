"""End-to-end tests: every tool against the synthetic captures through the real tshark."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tshark_mcp.limits import Limits
from tshark_mcp.server import _fit, _parse_conversations, _parse_phs

from . import pcapgen
from .conftest import requires_tshark, tshark_version

pytestmark = requires_tshark


# ----------------------------------------------------------------- guard rails
class TestGuardRails:
    def test_path_outside_allowlist_is_a_structured_error(self, server, tmp_path: Path):
        outside = tmp_path / "x.pcap"
        outside.write_bytes(b"\x00" * 24)
        result = server.pcap_info(str(outside))
        assert result["error"]["type"] == "path_not_allowed"
        assert "allowed_dirs" in result["error"]

    def test_filter_metacharacters_are_rejected_before_tshark(self, server, pcap_dir):
        result = server.filter_packets(str(pcap_dir / "diameter.pcap"), "diameter; rm -rf /")
        assert result["error"]["type"] == "invalid_filter"

    def test_invalid_filter_syntax_is_reported_from_dry_run(self, server, pcap_dir):
        result = server.diameter_transactions(str(pcap_dir / "diameter.pcap"), filter="nosuch.field == 1")
        assert result["error"]["type"] == "invalid_filter"
        assert "nosuch.field" in result["error"]["message"]

    def test_unknown_field_name_is_rejected(self, server, pcap_dir):
        result = server.filter_packets(str(pcap_dir / "diameter.pcap"), "diameter", fields=["diameter.nosuch"])
        assert result["error"]["type"] == "unknown_field"
        assert result["error"]["unknown_fields"] == ["diameter.nosuch"]

    def test_packet_cap_marks_truncation(self, configure, pcap_dir):
        srv = configure(Limits(max_packets=3))
        result = srv.diameter_transactions(str(pcap_dir / "diameter.pcap"))
        assert result["packets_scanned"] == 3
        assert result["truncated"] is True
        assert "narrow" in result["truncated_reason"]

    def test_row_limit_is_clamped_to_max_packets(self, configure, pcap_dir):
        srv = configure(Limits(max_packets=2))
        result = srv.filter_packets(str(pcap_dir / "sip.pcap"), "sip", limit=1000)
        assert result["count"] == 2

    def test_file_too_large_is_refused(self, configure, pcap_dir):
        srv = configure(Limits(max_file_bytes=100))
        result = srv.pcap_info(str(pcap_dir / "diameter.pcap"))
        assert result["error"]["type"] == "file_too_large"

    def test_output_cap_drops_rows(self, configure, pcap_dir):
        srv = configure(Limits(max_output_bytes=600))
        result = srv.sip_dialogs(str(pcap_dir / "sip.pcap"))
        assert result["truncated"] is True
        assert len(json.dumps(result, separators=(",", ":"))) <= 600 or "even after" in result["truncated_reason"]

    def test_fit_halves_largest_list(self):
        big = {"rows": [{"k": "v" * 50} for _ in range(100)], "other": [1, 2]}
        out = _fit(big, 2000)
        assert out["truncated"] is True and len(out["rows"]) < 100 and out["other"] == [1, 2]

    def test_audit_log_written(self, configure, pcap_dir, tmp_path: Path):
        srv = configure(log=True)
        srv.pcap_info(str(pcap_dir / "sip.pcap"))
        srv.pcap_info("/definitely/not/allowed.pcap")
        lines = [json.loads(ln) for ln in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert [ln["tool"] for ln in lines] == ["pcap_info", "pcap_info"]
        assert lines[0]["status"] == "ok" and lines[1]["status"] == "path_not_allowed"
        assert all({"ts", "args", "duration_ms", "bytes"} <= set(ln) for ln in lines)

    def test_unconfigured_server_errors_cleanly(self, pcap_dir):
        from tshark_mcp import server as srv
        srv._STATE = None
        result = srv.pcap_info(str(pcap_dir / "sip.pcap"))
        assert result["error"]["type"] == "not_configured"

    def test_internal_errors_are_not_raised(self, server, pcap_dir, monkeypatch):
        from tshark_mcp import server as srv
        monkeypatch.setattr(srv.diameter, "pair", lambda *_: 1 / 0)
        result = srv.diameter_transactions(str(pcap_dir / "diameter.pcap"))
        assert result["error"]["type"] == "internal_error" and "ZeroDivisionError" in result["error"]["message"]


# ----------------------------------------------------------------- generic tools
class TestGenericTools:
    def test_pcap_info(self, server, pcap_dir):
        info = server.pcap_info(str(pcap_dir / "diameter.pcap"))
        assert info["packets"] == 7
        assert info["link_type"] == "ether"
        assert info["first_packet"].startswith("2023-11-14T22:13:20")
        assert info["duration_s"] == pytest.approx(3.004)
        protos = {r["protocol"] for r in info["protocol_hierarchy"]}
        assert "eth/ip/sctp/diameter" in protos
        assert info["limits"]["max_packets"] == 500

    def test_conversations(self, server, pcap_dir):
        result = server.conversations(str(pcap_dir / "gtpv2.pcap"), layer="udp")
        row = result["conversations"][0]
        assert {row["a"], row["b"]} == {f"{pcapgen.SGW_IP}:2123", f"{pcapgen.PGW_IP}:2123"}
        assert row["frames_total"] == 7
        assert row["frames_a_to_b"] + row["frames_b_to_a"] == 7

    def test_conversations_bad_layer(self, server, pcap_dir):
        assert server.conversations(str(pcap_dir / "gtpv2.pcap"), layer="quic")["error"]["type"] == "invalid_argument"

    def test_filter_packets_default_fields(self, server, pcap_dir):
        result = server.filter_packets(str(pcap_dir / "diameter.pcap"), "diameter.cmd.code == 318")
        assert result["count"] == 3
        assert result["packets"][0]["frame.number"] == "3"
        assert "Authentication-Information" in result["packets"][0]["_ws.col.info"]

    def test_filter_packets_custom_fields(self, server, pcap_dir):
        result = server.filter_packets(str(pcap_dir / "gtpv2.pcap"), "gtpv2.message_type == 32",
                                       fields=["frame.number", "e212.imsi", "gtpv2.apn"], limit=10)
        assert [r["e212.imsi"] for r in result["packets"]] == [pcapgen.IMSI, pcapgen.IMSI_OTHER]
        assert result["packets"][0]["gtpv2.apn"] == pcapgen.APN

    def test_parse_phs_builds_paths(self):
        text = "frame   frames:3 bytes:300\n  eth    frames:3 bytes:300\n    ip   frames:3 bytes:300\n      udp frames:2 bytes:200\n      tcp frames:1 bytes:100\n"
        rows = _parse_phs(text)
        assert [r["protocol"] for r in rows] == ["eth", "eth/ip", "eth/ip/udp", "eth/ip/tcp"]
        # tshark 4.2 prints the same tree without the frame root
        assert _parse_phs(text.replace("frame   frames:3 bytes:300\n", "")) == rows

    def test_parse_conversations_handles_units(self):
        line = "10.0.0.1:1  <->  10.0.0.2:2   3 1 kB   4 2 MB   7 3 bytes   0.000000000   3.0000"
        row = _parse_conversations("header\n" + line)[0]
        assert row["bytes_b_to_a"] == 1000 and row["bytes_a_to_b"] == 2_000_000 and row["bytes_total"] == 3


# ----------------------------------------------------------------- Diameter
class TestDiameter:
    def test_transactions(self, server, pcap_dir):
        result = server.diameter_transactions(str(pcap_dir / "diameter.pcap"))
        txs = result["transactions"]
        assert [t["request"] for t in txs] == ["ULR", "AIR", "AIR", "DWR"]

        ulr = txs[0]
        assert ulr["answer"] == "ULA" and ulr["command"] == "Update-Location"
        assert ulr["application"] == "S6a/S6d" and ulr["application_id"] == 16777251
        assert ulr["user_name"] == pcapgen.IMSI
        assert ulr["result_code"] == 2001 and ulr["result"] == "DIAMETER_SUCCESS" and ulr["success"] is True
        assert ulr["rtt_ms"] == pytest.approx(48.0)
        assert ulr["origin_host"].startswith("mme01") and ulr["answer_origin_host"].startswith("hss01")
        assert ulr["hop_by_hop"] == "0x00001001" and ulr["end_to_end"] == "0x0000a001"

        aia = txs[1]
        assert aia["user_name"] == pcapgen.IMSI_OTHER
        assert aia["experimental_result_code"] == 5001
        assert aia["result"] == "DIAMETER_ERROR_USER_UNKNOWN" and aia["success"] is False

        unanswered = txs[2]
        assert unanswered["unanswered"] is True and "answer_frame" not in unanswered

        dwr = txs[3]
        assert dwr["application"] == "Base" and dwr["answer"] == "DWA"
        assert result["summary"] == {"by_message": {"ULR": 1, "AIR": 2, "DWR": 1}, "unanswered": 1, "failed": 1}

    def test_filter_is_anded_with_diameter(self, server, pcap_dir):
        result = server.diameter_transactions(str(pcap_dir / "diameter.pcap"), filter="diameter.cmd.code == 316")
        assert [t["request"] for t in result["transactions"]] == ["ULR"]


# ----------------------------------------------------------------- GTP
class TestGtp:
    def test_sessions(self, server, pcap_dir):
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"))
        txs = result["transactions"]
        assert [t["message"] for t in txs] == ["Echo Request", "Create Session Request", "Create Session Request",
                                               "Delete Session Request"]
        echo = txs[0]
        assert echo["response"] == "Echo Response" and echo["rtt_ms"] == pytest.approx(2.0)

        csr = txs[1]
        assert csr["imsi"] == pcapgen.IMSI and csr["msisdn"] == pcapgen.MSISDN and csr["apn"] == pcapgen.APN
        assert csr["cause"] == 16 and csr["cause_name"] == "Request accepted" and csr["accepted"] is True
        assert csr["paa"] == pcapgen.UE_IP
        assert {f["interface"] for f in csr["request_fteids"]} == {"S5/S8 SGW GTP-C", "S5/S8 SGW GTP-U"}
        pgw_c = next(f for f in csr["response_fteids"] if f["interface"] == "S5/S8 PGW GTP-C")
        assert pgw_c["teid"] == "0x0000c001" and pgw_c["ipv4"] == pcapgen.PGW_IP

        rejected = txs[2]
        assert rejected["imsi"] == pcapgen.IMSI_OTHER
        assert rejected["cause"] == 78 and rejected["cause_name"] == "Missing or unknown APN" and rejected["accepted"] is False
        assert "paa" not in rejected

        dsr = txs[3]
        assert dsr["unanswered"] is True and dsr["teid"] == "0x0000c001"
        assert result["summary"]["unanswered"] == 1 and result["summary"]["failed"] == 1

    def test_sessions_filter(self, server, pcap_dir):
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), filter="gtpv2.seq == 11")
        assert len(result["transactions"]) == 1 and result["transactions"][0]["cause"] == 78

    def test_identity_filter_only_matches_requests(self, server, pcap_dir):
        # Responses carry no IMSI IE, so an IMSI filter leaves the request looking unanswered.
        # trace_subscriber exists precisely to correlate the pair; this tool stays literal.
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), filter=f'e212.imsi == "{pcapgen.IMSI_OTHER}"')
        assert len(result["transactions"]) == 1 and result["transactions"][0]["unanswered"] is True

    def test_user_plane(self, server, pcap_dir):
        result = server.gtp_user_plane(str(pcap_dir / "gtpu.pcap"))
        by_teid = {t["teid"]: t for t in result["tunnels"]}
        assert set(by_teid) == {"0x0000d001", "0x0000b001"}
        up = by_teid["0x0000d001"]
        assert up["packets"] == 3 and up["outer_src"] == pcapgen.SGW_IP and up["outer_dst"] == pcapgen.PGW_IP
        assert up["inner_src"][0]["addr"] == pcapgen.UE_IP and up["inner_dst"][0]["addr"] == pcapgen.SERVER_IP
        assert up["duration_s"] == pytest.approx(2.0)
        assert result["total_packets"] == 6

    def test_user_plane_single_teid_accepts_hex_and_decimal(self, server, pcap_dir):
        hex_result = server.gtp_user_plane(str(pcap_dir / "gtpu.pcap"), teid="0xb001")
        dec_result = server.gtp_user_plane(str(pcap_dir / "gtpu.pcap"), teid=0xB001)
        assert hex_result["tunnels"] == dec_result["tunnels"]
        assert hex_result["tunnels"][0]["payload_bytes"] == 3 * 148

    def test_user_plane_bad_teid(self, server, pcap_dir):
        assert server.gtp_user_plane(str(pcap_dir / "gtpu.pcap"), teid="lots")["error"]["type"] == "invalid_argument"


# ----------------------------------------------------------------- SIP
class TestSip:
    def test_dialogs(self, server, pcap_dir):
        result = server.sip_dialogs(str(pcap_dir / "sip.pcap"))
        dialogs = {d["call_id"]: d for d in result["dialogs"]}
        call = dialogs["a1b2c3d4@ue.example"]
        assert call["initial_method"] == "INVITE" and call["final_status"] == 200
        assert call["time_to_final_ms"] == pytest.approx(3500.0)
        assert call["p_asserted_identity"] == f"<tel:+{pcapgen.MSISDN}>"
        assert call["methods"] == ["INVITE", "ACK", "BYE"]
        assert [m.get("status") or m.get("method") for m in call["messages"]] == ["INVITE", 100, 180, 200, "ACK", "BYE", 200]
        reg = dialogs["reg-77@ue.example"]
        assert reg["initial_method"] == "REGISTER" and reg["final_status"] == 401
        assert result["summary"]["failed"] == 1

    def test_dialogs_filter(self, server, pcap_dir):
        result = server.sip_dialogs(str(pcap_dir / "sip.pcap"), filter='sip.Method == "REGISTER"')
        assert [d["call_id"] for d in result["dialogs"]] == ["reg-77@ue.example"]
        assert result["dialogs"][0]["no_final_response"] is True  # the 401 is excluded by the filter


# ----------------------------------------------------------------- SCTP / SIGTRAN
class TestSigtran:
    def test_sctp_associations(self, server, pcap_dir):
        result = server.sctp_associations(str(pcap_dir / "sctp.pcap"))
        assoc = result["associations"][0]
        assert {assoc["endpoint_a"], assoc["endpoint_b"]} == {f"{pcapgen.STP_A}:2905", f"{pcapgen.STP_B}:2905"}
        assert assoc["handshake"] == "complete" and assoc["init_frame"] == 1 and assoc["init_ack_frame"] == 2
        assert assoc["initiate_tags"] == {pcapgen.STP_A: "0xaaaa0001", pcapgen.STP_B: "0xbbbb0002"}
        assert assoc["heartbeats_sent"] == 3 and assoc["heartbeats_acked"] == 2 and assoc["heartbeats_unacked"] == 1
        assert assoc["abort_seen"] is False and assoc["shutdown_seen"] is False
        assert assoc["chunk_counts"]["COOKIE_ECHO"] == 1

    def test_sigtran_messages(self, server, pcap_dir):
        result = server.sigtran_messages(str(pcap_dir / "sigtran.pcap"))
        msgs = result["messages"]
        assert len(msgs) == 4

        ul_begin = msgs[0]
        assert ul_begin["m3ua"] == "DATA" and ul_begin["opc"] == 100 and ul_begin["dpc"] == 200
        assert ul_begin["sccp"] == "UDT" and ul_begin["called_ssn"] == 6 and ul_begin["calling_ssn"] == 7
        assert ul_begin["called_gt"] == "15550109002" and ul_begin["calling_gt"] == "15550109001"
        assert ul_begin["tcap"] == "begin" and ul_begin["otid"] == "00000001"
        assert ul_begin["components"] == [{"type": "invoke", "invoke_id": 1, "opcode": 2, "operation": "updateLocation"}]
        assert ul_begin["imsi"] == pcapgen.IMSI and "msisdn" not in ul_begin
        assert ul_begin["answered_in_frame"] == 2

        ul_end = msgs[1]
        assert ul_end["tcap"] == "end" and ul_end["components"][0]["type"] == "returnResultLast"
        assert ul_end["in_response_to_frame"] == 1 and ul_end["rtt_ms"] == pytest.approx(200.0)

        mo_fsm = msgs[2]
        assert mo_fsm["components"][0]["operation"] == "mo-forwardSM"
        assert mo_fsm["msisdn"] == pcapgen.MSISDN
        # The optional trailing imsi in MO-ForwardSM-Arg (TS 29.002) is only in the MAP
        # ASN.1 of newer Wireshark releases; 4.2 reports it as beyond the sequence.
        if tshark_version() >= (4, 6):
            assert mo_fsm["imsi"] == pcapgen.IMSI
        else:
            assert mo_fsm.get("imsi") in (pcapgen.IMSI, None)
        assert mo_fsm["sms"]["tp_da"] == "15550101555"
        assert mo_fsm["unanswered"] is True

        xudt = msgs[3]
        assert xudt["sccp"] == "XUDT"
        assert xudt["segmentation"] == {"first_segment": True, "remaining_segments": 1, "local_reference": "0x420000"}
        assert "tcap" not in xudt and "segmented" in xudt["note"]

        assert result["summary"]["by_operation"] == {"updateLocation": 2, "mo-forwardSM": 1}
        assert result["summary"]["unanswered_begins"] == 1 and result["summary"]["segmented"] == 1

    def test_tbcd_fallback_decoder(self):
        from tshark_mcp.sigtran import decode_tbcd
        assert decode_tbcd("00:01:01:21:43:65:87:f9") == pcapgen.IMSI
        assert decode_tbcd("91:51:55:10:00:21:f3", address_string=True) == pcapgen.MSISDN
        assert decode_tbcd(None) is None and decode_tbcd("zz") is None

    def test_sigtran_filter(self, server, pcap_dir):
        result = server.sigtran_messages(str(pcap_dir / "sigtran.pcap"), filter="gsm_old.localValue == 46")
        assert len(result["messages"]) == 1 and result["messages"][0]["components"][0]["opcode"] == 46

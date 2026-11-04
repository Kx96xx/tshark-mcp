"""diameter_sessions, find_identifier, the structured filters on gtp_sessions and
sip_dialogs, and the filtered conversations view, all against the synthetic captures."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path

import pytest

from tshark_mcp import search
from tshark_mcp.limits import (
    Allowlist, Limits, ToolError, lint_apn, lint_quoted_value, lint_sip_method, lint_teid,
)

from . import pcapgen
from .conftest import requires_tshark, tshark_version

SID1 = "mme01.epc.mnc001.mcc001.3gppnetwork.org;1700000000;1"
SID2 = "mme01.epc.mnc001.mcc001.3gppnetwork.org;1700000000;2"
SID3 = "mme01.epc.mnc001.mcc001.3gppnetwork.org;1700000000;3"
CALL_ID = "a1b2c3d4@ue.example"
REG_CALL_ID = "reg-77@ue.example"


# ----------------------------------------------------------------- pure helpers (no tshark)
class TestLints:
    def test_quoted_value_accepts_session_and_call_ids(self):
        assert lint_quoted_value(SID1, "session_id") == SID1
        assert lint_quoted_value(" a|b&c;d@example ", "call_id") == "a|b&c;d@example"

    @pytest.mark.parametrize("bad", ['x" || diameter', "back\\slash", "tab\there", "nl\nhere", "", "   ", "x" * 600])
    def test_quoted_value_rejects_escapes(self, bad):
        with pytest.raises(ToolError) as exc:
            lint_quoted_value(bad, "session_id")
        assert exc.value.type == "invalid_argument"

    def test_apn(self):
        assert lint_apn("internet.test.apn") == "internet.test.apn"
        assert lint_apn("ims") == "ims"
        for bad in ("bad;apn", 'x" || gtpv2', "", ".leading", "a" * 120):
            with pytest.raises(ToolError):
                lint_apn(bad)

    def test_sip_method(self):
        assert lint_sip_method("register") == "REGISTER"
        for bad in ("INVITE; x", "", "I", 'x"'):
            with pytest.raises(ToolError):
                lint_sip_method(bad)

    def test_teid(self):
        assert lint_teid("0xc001") == 0xC001 and lint_teid(49153) == 0xC001 and lint_teid("49153") == 0xC001
        for bad in ("lots", -1, 0x1_0000_0000, ""):
            with pytest.raises(ToolError):
                lint_teid(bad)


class TestMaxFilesLimit:
    def test_default_env_and_describe(self):
        assert Limits().max_files == 50
        assert Limits.from_env({"TSHARK_MCP_MAX_FILES": "7"}).max_files == 7
        assert Limits().describe()["max_files"] == 50
        with pytest.raises(ValueError):
            Limits(max_files=0)

    def test_cli_flag(self):
        from tshark_mcp.server import build_parser
        args = build_parser().parse_args(["--max-files", "3", "--max-scan-packets", "900"])
        assert args.max_files == 3 and args.max_scan_packets == 900


class TestAllowlistDirectories:
    def test_resolve_dir_inside_root(self, tmp_path: Path):
        sub = tmp_path / "caps"
        sub.mkdir()
        assert Allowlist.from_strings([str(tmp_path)]).resolve_dir(str(sub)) == sub.resolve()

    def test_resolve_dir_rejects_files_and_outsiders(self, tmp_path: Path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        f = allowed / "x.pcap"
        f.write_bytes(b"\x00" * 10)
        al = Allowlist.from_strings([str(allowed)])
        with pytest.raises(ToolError) as exc:
            al.resolve_dir(str(f))
        assert exc.value.type == "not_a_directory"
        with pytest.raises(ToolError) as exc:
            al.resolve_dir(str(tmp_path))
        assert exc.value.type == "path_not_allowed"


class TestSearchHelpers:
    @pytest.mark.parametrize("value, kind", [
        ("192.0.2.1", "ip"), ("2001:db8::1", "ip"), ("001010123456789", "subscriber"), ("+1 555 0100123", "subscriber"),
        (SID1, "session_id"), (CALL_ID, "call_id"),
    ])
    def test_classify(self, value, kind):
        assert search.classify(value) == kind

    def test_classify_unknown(self):
        with pytest.raises(ToolError):
            search.classify("hello world")

    def test_build_filter_shapes(self):
        assert search.build_filter("192.0.2.1", "auto") == ("ip", "ip.addr == 192.0.2.1")
        assert search.build_filter("2001:db8::1", "ip") == ("ip", "ipv6.addr == 2001:db8::1")
        kind, flt = search.build_filter(pcapgen.IMSI, "imsi")
        assert kind == "imsi" and flt.startswith(f'e212.imsi == "{pcapgen.IMSI}"') and "e164.msisdn" not in flt
        kind, flt = search.build_filter(pcapgen.MSISDN, "msisdn")
        assert kind == "msisdn" and "e164.msisdn" in flt and "diameter.MSISDN == 51:55:10:00:21:f3" in flt
        kind, flt = search.build_filter(pcapgen.MSISDN, "auto")
        assert kind == "subscriber" and "e212.imsi" in flt and "e164.msisdn" in flt
        assert search.build_filter(CALL_ID, "auto") == ("call_id", f'sip.Call-ID == "{CALL_ID}"')
        assert search.build_filter(SID1, "session_id") == ("session_id", f'diameter.Session-Id == "{SID1}"')

    def test_build_filter_rejects_bad_input(self):
        for value, kind in (("not-an-ip", "ip"), ("12ab", "imsi"), ('x" || sip', "call_id"), ("x", "nosuch")):
            with pytest.raises(ToolError):
                search.build_filter(value, kind)

    def test_list_captures_skips_non_captures_and_dotfiles(self, tmp_path: Path):
        for name in ("b.pcap", "a.pcapng", "c.cap", "notes.txt", ".hidden.pcap", "d.PCAP"):
            (tmp_path / name).write_bytes(b"\x00")
        (tmp_path / "sub.pcap").mkdir()
        assert [p.name for p in search.list_captures(tmp_path)] == ["a.pcapng", "b.pcap", "c.cap", "d.PCAP"]

    def test_summarise_hits(self):
        text = "1.0\t1\tDIAMETER\n2.5\t2\tGTPv2\n\n0.5\t3\tDIAMETER\njunk\n"
        out = search.summarise_hits(text, protocol_col=True)
        assert out == {"hits": 3, "first": 0.5, "last": 2.5, "first_frame": 3, "last_frame": 2,
                       "protocols": {"DIAMETER": 2, "GTPv2": 1}}
        assert search.summarise_hits("1.0\t1\n", protocol_col=False)["protocols"] == {}


# ----------------------------------------------------------------- tools through tshark
@requires_tshark
class TestRegistration:
    def test_every_tool_is_registered(self):
        from tshark_mcp.server import app
        tools = asyncio.run(app.list_tools())
        names = sorted(t.name for t in tools)
        assert names == sorted([
            "pfcp_sessions",
            "tcp_connections",
            "icmp_errors",
            "pcap_info", "conversations", "filter_packets", "diameter_transactions", "diameter_sessions",
            "gtp_sessions", "gtp_user_plane", "sip_dialogs", "sctp_associations", "sigtran_messages",
            "trace_subscriber", "find_identifier", "diameter_avps", "compare_captures", "gtp_tunnel_health", "message_rates", "gtpv1_sessions",
            "dns_transactions", "tls_handshakes", "capture_quality", "rtp_streams", "tcp_health", "sip_call_detail", "packet_detail", "response_times", "expert_info", "media_path_check", "dtmf_events", "ims_registration", "sms_over_ims", "find_fields", "check_filter",
        ])
        by_name = {t.name: t for t in tools}

        def params(name: str) -> set[str]:
            tool = by_name[name]
            schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema")
            return set(schema["properties"])

        assert {"session_id", "imsi", "command_code", "filter", "limit"} <= params("diameter_sessions")
        assert {"imsi", "apn", "teid", "filter"} <= params("gtp_sessions")
        assert {"call_id", "number", "method", "filter"} <= params("sip_dialogs")
        assert {"identifier", "kind", "max_files"} <= params("find_identifier")
        assert "filter" in params("conversations")


@requires_tshark
class TestDiameterSessions:
    def test_groups_by_session_id(self, server, pcap_dir):
        result = server.diameter_sessions(str(pcap_dir / "diameter.pcap"))
        assert [s["session_id"] for s in result["sessions"]] == [SID1, SID2, SID3]
        assert result["summary"] == {"sessions": 3, "unanswered": 1, "failed": 1, "without_session_id": 1,
                                     "by_application": {"S6a/S6d": 3}}

        ulr = result["sessions"][0]
        assert ulr["application"] == "S6a/S6d" and ulr["user_name"] == pcapgen.IMSI
        assert ulr["origin_host"].startswith("mme01") and ulr["destination_host"].startswith("hss01")
        assert ulr["request_codes"] == [316] and ulr["answer_codes"] == [316] and ulr["result_codes"] == [2001]
        assert ulr["duration_ms"] == pytest.approx(48.0) and ulr["max_rtt_ms"] == pytest.approx(48.0)
        assert ulr["first_time"] == "2023-11-14T22:13:20.000Z" and ulr["last_time"] == "2023-11-14T22:13:20.048Z"
        tx = ulr["transactions"][0]
        assert tx["request"] == "ULR" and tx["answer"] == "ULA" and tx["hop_by_hop"] == "0x00001001"
        assert tx["result"] == "DIAMETER_SUCCESS" and tx["success"] is True and tx["rtt_ms"] == pytest.approx(48.0)

        rejected = result["sessions"][1]
        assert rejected["failed"] == 1 and rejected["result_codes"] == [5001]
        assert rejected["transactions"][0]["result"] == "DIAMETER_ERROR_USER_UNKNOWN"

        pending = result["sessions"][2]
        assert pending["unanswered"] == 1 and "answer_codes" not in pending and "max_rtt_ms" not in pending
        assert pending["transactions"][0]["unanswered"] is True

    def test_imsi_selects_whole_sessions(self, server, pcap_dir):
        result = server.diameter_sessions(str(pcap_dir / "diameter.pcap"), imsi=pcapgen.IMSI)
        assert [s["session_id"] for s in result["sessions"]] == [SID1, SID3]
        # The ULA carries no User-Name yet is present because the whole session was fetched.
        assert result["sessions"][0]["answer_codes"] == [316]
        assert result["selection"] == f'diameter.User-Name == "{pcapgen.IMSI}"'

    def test_command_code_and_session_id(self, server, pcap_dir):
        by_code = server.diameter_sessions(str(pcap_dir / "diameter.pcap"), command_code=318)
        assert [s["session_id"] for s in by_code["sessions"]] == [SID2, SID3]
        exact = server.diameter_sessions(str(pcap_dir / "diameter.pcap"), session_id=SID2)
        assert [s["session_id"] for s in exact["sessions"]] == [SID2]
        assert exact["sessions"][0]["user_name"] == pcapgen.IMSI_OTHER
        both = server.diameter_sessions(str(pcap_dir / "diameter.pcap"), imsi=pcapgen.IMSI, command_code=316)
        assert [s["session_id"] for s in both["sessions"]] == [SID1]

    def test_unknown_imsi_is_empty_not_an_error(self, server, pcap_dir):
        result = server.diameter_sessions(str(pcap_dir / "diameter.pcap"), imsi="999990000000000")
        assert result["sessions"] == [] and result["count"] == 0 and result["summary"]["sessions"] == 0

    def test_arguments_are_linted(self, server, pcap_dir):
        path = str(pcap_dir / "diameter.pcap")
        assert server.diameter_sessions(path, session_id='x" || diameter')["error"]["type"] == "invalid_argument"
        assert server.diameter_sessions(path, imsi="12ab")["error"]["type"] == "invalid_argument"
        assert server.diameter_sessions(path, command_code=-5)["error"]["type"] == "invalid_argument"
        assert server.diameter_sessions(path, filter="nosuch.field == 1")["error"]["type"] == "invalid_filter"

    def test_limit_and_packet_cap(self, configure, pcap_dir):
        srv = configure()
        result = srv.diameter_sessions(str(pcap_dir / "diameter.pcap"), limit=1)
        assert result["count"] == 1 and result["total_found"] == 3 and result["truncated"] is True
        srv = configure(Limits(max_packets=2))
        result = srv.diameter_sessions(str(pcap_dir / "diameter.pcap"))
        assert result["packets_scanned"] == 2 and result["truncated"] is True


@requires_tshark
class TestGtpStructuredFilters:
    def test_imsi_keeps_the_response(self, server, pcap_dir):
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), imsi=pcapgen.IMSI_OTHER)
        txs = result["transactions"]
        assert len(txs) == 1
        assert txs[0]["message"] == "Create Session Request" and txs[0]["response"] == "Create Session Response"
        assert txs[0]["cause"] == 78 and "unanswered" not in txs[0]
        assert result["selection"] == f'e212.imsi == "{pcapgen.IMSI_OTHER}"'

    def test_apn_is_case_insensitive(self, server, pcap_dir):
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), apn="BOGUS.APN")
        assert [t["cause"] for t in result["transactions"]] == [78]
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), apn=pcapgen.APN)
        assert [t["imsi"] for t in result["transactions"]] == [pcapgen.IMSI]

    def test_teid_matches_header_and_fteids(self, server, pcap_dir):
        # 0xC001 is the PGW control TEID: allocated in the Create Session Response, used in the Delete Session header.
        for teid in ("0xc001", 0xC001, "49153"):
            result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), teid=teid)
            assert [t["message"] for t in result["transactions"]] == ["Create Session Request", "Delete Session Request"]
            assert result["transactions"][1]["unanswered"] is True
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), teid="0xa002")
        assert [t["cause"] for t in result["transactions"]] == [78]

    def test_combined_filters_and_misses(self, server, pcap_dir):
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), imsi=pcapgen.IMSI, apn="bogus.apn")
        assert result["transactions"] == [] and result["count"] == 0
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), imsi="999990000000000")
        assert result["transactions"] == []

    def test_arguments_are_linted(self, server, pcap_dir):
        path = str(pcap_dir / "gtpv2.pcap")
        assert server.gtp_sessions(path, apn="bad;apn")["error"]["type"] == "invalid_argument"
        assert server.gtp_sessions(path, teid="lots")["error"]["type"] == "invalid_argument"
        assert server.gtp_sessions(path, imsi="x")["error"]["type"] == "invalid_argument"

    def test_raw_filter_still_works_with_structured_filter(self, server, pcap_dir):
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), imsi=pcapgen.IMSI, filter="gtpv2.message_type == 32")
        # The raw filter is literal: it drops the response (type 33), so the request looks unanswered.
        assert len(result["transactions"]) == 1 and result["transactions"][0]["unanswered"] is True


@requires_tshark
class TestSipStructuredFilters:
    def test_method_keeps_the_final_response(self, server, pcap_dir):
        result = server.sip_dialogs(str(pcap_dir / "sip.pcap"), method="register")
        assert [d["call_id"] for d in result["dialogs"]] == [REG_CALL_ID]
        reg = result["dialogs"][0]
        assert reg["final_status"] == 401 and "no_final_response" not in reg or reg["no_final_response"] is False
        assert reg["duration_ms"] == pytest.approx(40.0)

    def test_number_and_call_id(self, server, pcap_dir):
        by_number = server.sip_dialogs(str(pcap_dir / "sip.pcap"), number=pcapgen.MSISDN)
        assert [d["call_id"] for d in by_number["dialogs"]] == [CALL_ID]
        call = by_number["dialogs"][0]
        assert call["methods"] == ["INVITE", "ACK", "BYE"] and call["final_status"] == 200
        assert call["duration_ms"] == pytest.approx(10030.0) and call["time_to_final_ms"] == pytest.approx(3500.0)
        exact = server.sip_dialogs(str(pcap_dir / "sip.pcap"), call_id=REG_CALL_ID)
        assert [d["call_id"] for d in exact["dialogs"]] == [REG_CALL_ID]
        both = server.sip_dialogs(str(pcap_dir / "sip.pcap"), number=pcapgen.MSISDN, method="REGISTER")
        assert both["dialogs"] == []

    def test_arguments_are_linted(self, server, pcap_dir):
        path = str(pcap_dir / "sip.pcap")
        assert server.sip_dialogs(path, call_id='x" || sip')["error"]["type"] == "invalid_argument"
        assert server.sip_dialogs(path, method="INVITE; x")["error"]["type"] == "invalid_argument"
        assert server.sip_dialogs(path, number="abc")["error"]["type"] == "invalid_argument"

    def test_unknown_call_id_is_empty(self, server, pcap_dir):
        result = server.sip_dialogs(str(pcap_dir / "sip.pcap"), call_id="nobody@nowhere.example")
        assert result["dialogs"] == [] and result["count"] == 0


@requires_tshark
class TestConversationsFilter:
    def test_filter_restricts_counts(self, server, pcap_dir):
        full = server.conversations(str(pcap_dir / "gtpv2.pcap"), layer="udp")
        narrowed = server.conversations(str(pcap_dir / "gtpv2.pcap"), layer="udp", filter="gtpv2.seq == 10")
        assert full["total_frames"] == 7 and narrowed["total_frames"] == 2
        row = narrowed["conversations"][0]
        assert row["frames_a_to_b"] == 1 and row["frames_b_to_a"] == 1 and row["duration_s"] == pytest.approx(0.12)
        assert narrowed["display_filter"] == "gtpv2.seq == 10"

    def test_filter_with_commas_and_lint(self, server, pcap_dir):
        result = server.conversations(str(pcap_dir / "gtpv2.pcap"), layer="udp", filter="frame.number in {1, 2, 3}")
        assert result["total_frames"] == 3
        assert server.conversations(str(pcap_dir / "gtpv2.pcap"), filter="udp; x")["error"]["type"] == "invalid_filter"
        assert server.conversations(str(pcap_dir / "gtpv2.pcap"), filter="nosuch.f == 1")["error"]["type"] == "invalid_filter"

    def test_sctp_layer(self, server, pcap_dir):
        result = server.conversations(str(pcap_dir / "diameter.pcap"), layer="sctp")
        assert result["conversations"][0]["frames_total"] == 7


@requires_tshark
class TestFindIdentifier:
    def _names(self, result):
        return [(Path(f["path"]).name, f["hits"]) for f in result["files"]]

    def test_directory_scan_for_imsi(self, server, pcap_dir):
        result = server.find_identifier(str(pcap_dir), pcapgen.IMSI)
        assert result["kind"] == "subscriber" and result["files_found"] == 7 and result["files_scanned"] == 7
        # tshark 4.2 does not decode the optional trailing imsi of MO-ForwardSM-Arg (see test_sigtran_messages),
        # so the mo-forwardSM Begin counts as a hit only on newer releases.
        map_hits = 2 if tshark_version() >= (4, 6) else 1
        assert self._names(result) == sorted([("all.pcap", 3 + map_hits), ("diameter.pcap", 2), ("sigtran.pcap", map_hits),
                                              ("gtpv2.pcap", 1)], key=lambda r: (-r[1], r[0]))
        assert result["files_with_hits"] == 4 and result["total_hits"] == 6 + 2 * map_hits and result["errors"] == []
        diam = next(f for f in result["files"] if f["path"].endswith("diameter.pcap"))
        assert diam["first"] == "2023-11-14T22:13:20.000Z" and diam["last"] == "2023-11-14T22:13:22.000Z"
        assert diam["protocols"] == {"DIAMETER": 2}
        assert "truncated" not in result

    def test_explicit_kinds(self, server, pcap_dir):
        msisdn = server.find_identifier(str(pcap_dir), pcapgen.MSISDN, kind="msisdn")
        assert msisdn["kind"] == "msisdn"
        assert {n for n, _ in self._names(msisdn)} == {"all.pcap", "sip.pcap", "gtpv2.pcap", "sigtran.pcap"}
        # As an IMSI the number matches nothing in Diameter, GTP or MAP; only the SIP From URI,
        # which is searched for IMSIs because IMS private identities carry them, still contains it.
        imsi_only = server.find_identifier(str(pcap_dir), pcapgen.MSISDN, kind="imsi")
        assert {n for n, _ in self._names(imsi_only)} == {"all.pcap", "sip.pcap"}
        assert "e164.msisdn" not in imsi_only["display_filter"]

    def test_ip_including_inner_gtp_u_addresses(self, server, pcap_dir):
        outer = server.find_identifier(str(pcap_dir), pcapgen.PGW_IP)
        assert outer["kind"] == "ip" and dict(self._names(outer)) == {"all.pcap": 13, "gtpv2.pcap": 7, "gtpu.pcap": 6}
        inner = server.find_identifier(str(pcap_dir), pcapgen.UE_IP)
        assert dict(self._names(inner)) == {"all.pcap": 6, "gtpu.pcap": 6}

    def test_call_id_and_session_id(self, server, pcap_dir):
        call = server.find_identifier(str(pcap_dir), CALL_ID)
        assert call["kind"] == "call_id" and dict(self._names(call)) == {"all.pcap": 7, "sip.pcap": 7}
        sip_row = next(f for f in call["files"] if f["path"].endswith("sip.pcap"))
        assert sip_row["first"] == "2023-11-14T22:18:20.000Z" and sip_row["last"] == "2023-11-14T22:18:30.030Z"
        session = server.find_identifier(str(pcap_dir), SID1)
        assert session["kind"] == "session_id" and dict(self._names(session)) == {"all.pcap": 2, "diameter.pcap": 2}

    def test_single_file(self, server, pcap_dir):
        result = server.find_identifier(str(pcap_dir / "sip.pcap"), pcapgen.MSISDN_OTHER)
        assert result["files_found"] == 1 and self._names(result) == [("sip.pcap", 2)]

    def test_file_cap_truncates(self, configure, pcap_dir):
        srv = configure()
        result = srv.find_identifier(str(pcap_dir), pcapgen.IMSI, max_files=2)
        assert result["files_scanned"] == 2 and result["truncated"] is True and "max_files" in result["truncated_reason"]
        srv = configure(Limits(max_files=3))
        result = srv.find_identifier(str(pcap_dir), pcapgen.IMSI, max_files=1000)
        assert result["files_scanned"] == 3 and result["truncated"] is True

    def test_time_budget_stops_the_scan(self, server, pcap_dir, monkeypatch):
        from tshark_mcp import server as srv
        # Deadline is taken at 0; the first file passes the check at 0, the second sees 1000 s and stops.
        clock = iter([0.0, 0.0] + [1000.0 * n for n in range(1, 100)])
        monkeypatch.setattr(srv, "_now", lambda: next(clock))
        result = srv.find_identifier(str(pcap_dir), pcapgen.IMSI)
        assert result["files_scanned"] == 1 and result["truncated"] is True and "time budget" in result["truncated_reason"]

    def test_oversized_and_unreadable_files_are_reported_per_file(self, configure, pcap_dir, tmp_path: Path):
        allowed = tmp_path / "caps"
        allowed.mkdir()
        shutil.copy(pcap_dir / "diameter.pcap", allowed / "diameter.pcap")
        shutil.copy(pcap_dir / "all.pcap", allowed / "all.pcap")
        (allowed / "garbage.pcap").write_bytes(b"not a capture at all")
        (allowed / "README.txt").write_text("ignored")
        outside = tmp_path / "secret.pcap"
        shutil.copy(pcap_dir / "diameter.pcap", outside)
        os.symlink(outside, allowed / "link.pcap")
        srv = configure(Limits(max_file_bytes=(pcap_dir / "all.pcap").stat().st_size - 1), allow=[str(allowed)])
        result = srv.find_identifier(str(allowed), pcapgen.IMSI)
        assert result["files_found"] == 4 and self._names(result) == [("diameter.pcap", 2)]
        errors = {Path(e["path"]).name: e["error"] for e in result["errors"]}
        assert errors == {"all.pcap": "file_too_large", "garbage.pcap": "tshark_failed", "link.pcap": "path_not_allowed"}

    def test_path_outside_allowlist(self, server, pcap_dir, tmp_path: Path):
        result = server.find_identifier(str(tmp_path), pcapgen.IMSI)
        assert result["error"]["type"] == "path_not_allowed"
        assert server.find_identifier(str(pcap_dir / "missing"), pcapgen.IMSI)["error"]["type"] == "not_found"

    def test_bad_identifiers(self, server, pcap_dir):
        assert server.find_identifier(str(pcap_dir), "hello world")["error"]["type"] == "invalid_argument"
        assert server.find_identifier(str(pcap_dir), "")["error"]["type"] == "invalid_argument"
        assert server.find_identifier(str(pcap_dir), "1.2.3.4", kind="nosuch")["error"]["type"] == "invalid_argument"
        assert server.find_identifier(str(pcap_dir), 'x" || frame', kind="call_id")["error"]["type"] == "invalid_argument"

    def test_no_hits(self, server, pcap_dir):
        result = server.find_identifier(str(pcap_dir), "999990000000000")
        assert result["files"] == [] and result["files_scanned"] == 7 and result["total_hits"] == 0

    def test_read_only_argv(self, server, pcap_dir, monkeypatch):
        from tshark_mcp import server as srv
        seen: list[tuple[str, ...]] = []
        runner = srv.state().runner
        original = runner.read_capture

        def spy(capture, args, **kw):
            result = original(capture, args, **kw)
            seen.append(result.argv)
            return result

        monkeypatch.setattr(runner, "read_capture", spy)
        srv.find_identifier(str(pcap_dir), pcapgen.IMSI)
        assert len(seen) == 7
        for argv in seen:
            assert argv[1:3] == ("-n", "-r") and "-c" in argv and "-w" not in argv and "-i" not in argv


@requires_tshark
class TestAuditLog:
    def test_every_new_tool_writes_one_record(self, configure, pcap_dir, tmp_path: Path):
        srv = configure(log=True)
        srv.diameter_sessions(str(pcap_dir / "diameter.pcap"), imsi=pcapgen.IMSI)
        srv.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), apn=pcapgen.APN)
        srv.sip_dialogs(str(pcap_dir / "sip.pcap"), method="INVITE")
        srv.conversations(str(pcap_dir / "gtpv2.pcap"), layer="udp", filter="gtpv2")
        srv.find_identifier(str(pcap_dir), pcapgen.IMSI, max_files=2)
        srv.find_identifier(str(tmp_path), pcapgen.IMSI)
        lines = [json.loads(ln) for ln in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert [ln["tool"] for ln in lines] == ["diameter_sessions", "gtp_sessions", "sip_dialogs", "conversations",
                                                "find_identifier", "find_identifier"]
        assert [ln["status"] for ln in lines] == ["ok"] * 5 + ["path_not_allowed"]
        assert lines[0]["args"]["imsi"] == pcapgen.IMSI and "session_id" not in lines[0]["args"]
        assert lines[4]["args"]["max_files"] == 2
        assert all({"ts", "duration_ms", "bytes"} <= set(ln) for ln in lines)

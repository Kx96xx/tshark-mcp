"""The output contract every list tool shares: totals, paging with offset, and an
output cap that says exactly how to fetch what it left out."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tshark_mcp.limits import Limits
from tshark_mcp.server import _envelope, _fit, _ROWS_KEY

from . import pcapgen
from .conftest import requires_tshark


def _size(obj) -> int:
    return len(json.dumps(obj, separators=(",", ":"), default=str).encode())


# ----------------------------------------------------------------- pure helpers
class TestEnvelope:
    def test_page_counts_and_next_offset(self):
        rows = [{"n": i} for i in range(10)]
        out = _envelope("rows", rows, 3, offset=3)
        assert out["rows"] == rows[3:6]
        assert (out["total_matched"], out["returned"], out["dropped"], out["offset"], out["next_offset"]) == (10, 3, 4, 3, 6)
        assert out["count"] == 3 and out["total_found"] == 10  # backward-compatible names
        assert out["truncated"] is True and "offset=6" in out["truncated_reason"]
        assert out[_ROWS_KEY] == "rows"

    def test_last_page_has_no_next_offset(self):
        out = _envelope("rows", [{"n": i} for i in range(5)], 3, offset=3)
        assert out["returned"] == 2 and out["dropped"] == 0
        assert "next_offset" not in out and "truncated" not in out

    def test_more_flag_marks_totals_as_lower_bound(self):
        out = _envelope("rows", [{"n": 1}, {"n": 2}], 2, more=True)
        assert out["next_offset"] == 2 and out["total_is_lower_bound"] is True and out["truncated"] is True

    def test_offset_past_the_end_is_explained(self):
        out = _envelope("rows", [{"n": 1}], 5, offset=7)
        assert out["rows"] == [] and out["returned"] == 0 and "past the last row" in out["truncated_reason"]

    @pytest.mark.parametrize("bad", [-1, "x", 1.5j])
    def test_bad_offset_is_rejected(self, bad):
        from tshark_mcp.limits import ToolError
        with pytest.raises(ToolError) as exc:
            _envelope("rows", [], 5, offset=bad)
        assert exc.value.type == "invalid_argument"


class TestFit:
    def test_rows_are_cut_to_an_exact_prefix_with_next_offset(self):
        rows = [{"k": "v" * 50, "n": i} for i in range(100)]
        result = _envelope("rows", rows, 100, offset=0)
        out = _fit(result, 2000)
        assert _size(out) <= 2000 and _ROWS_KEY not in out
        kept = out["returned"]
        assert 1 <= kept < 100 and out["rows"] == rows[:kept] and out["count"] == kept
        assert out["next_offset"] == kept and out["dropped"] == 100 - kept
        assert f"offset={kept}" in out["truncated_reason"] and "output cap of 2000 bytes" in out["truncated_reason"]

    def test_fit_after_an_offset_continues_from_it(self):
        rows = [{"k": "v" * 50, "n": i} for i in range(100)]
        out = _fit(_envelope("rows", rows, 50, offset=20), 2000)
        kept = out["returned"]
        assert out["rows"][0]["n"] == 20 and out["next_offset"] == 20 + kept and out["dropped"] == 80 - kept
        # The page-level note ("N more rows after this page") is replaced, not repeated.
        assert out["truncated_reason"].count("offset=") == 1

    def test_inner_lists_are_trimmed_and_recorded(self):
        result = _envelope("sessions", [{"id": 1, "transactions": [{"x": "y" * 40} for _ in range(200)]}], 10)
        out = _fit(result, 3000)
        assert _size(out) <= 3000
        trimmed = {t["path"]: t for t in out["trimmed"]}
        assert trimmed["sessions[0].transactions"]["of"] == 200
        assert trimmed["sessions[0].transactions"]["kept"] == len(out["sessions"][0]["transactions"]) < 200

    def test_side_list_larger_than_rows_is_trimmed_before_rows(self):
        result = _envelope("rows", [{"n": 1}, {"n": 2}], 10, side=[{"z": "q" * 40} for _ in range(100)])
        out = _fit(result, 1500)
        assert len(out["rows"]) == 2 and out["trimmed"][0]["path"] == "side"

    def test_small_result_is_untouched(self):
        result = _envelope("rows", [{"n": 1}], 10)
        out = _fit(result, 10_000)
        assert out == {k: v for k, v in result.items() if k != _ROWS_KEY}

    def test_legacy_halving_without_a_row_key(self):
        big = {"rows": [{"k": "v" * 50} for _ in range(100)], "other": [1, 2]}
        out = _fit(big, 2000)
        assert out["truncated"] is True and len(out["rows"]) < 100 and out["other"] == [1, 2]
        assert out["trimmed"][0] == {"path": "rows", "kept": len(out["rows"]), "of": 100}


def test_default_output_cap_is_context_sized():
    assert Limits().max_output_bytes == 30 * 1024
    assert Limits.from_env({"TSHARK_MCP_MAX_OUTPUT_KB": "64"}).max_output_bytes == 64 * 1024


# ----------------------------------------------------------------- through the tools


@requires_tshark
class TestPaging:
    def test_pages_of_diameter_transactions_add_up(self, server, pcap_dir: Path):
        path = str(pcap_dir / "diameter.pcap")
        full = server.diameter_transactions(path)
        total = full["total_matched"]
        assert total >= 2 and full["returned"] == total and "next_offset" not in full
        seen, offset = [], 0
        while True:
            page = server.diameter_transactions(path, limit=1, offset=offset)
            assert page["total_matched"] == total and page["returned"] == 1
            seen += page["transactions"]
            if "next_offset" not in page:
                break
            assert page["dropped"] == total - offset - 1 and "offset=" in page["truncated_reason"]
            offset = page["next_offset"]
        assert seen == full["transactions"]

    def test_filter_packets_pages_through_the_matches(self, server, pcap_dir: Path):
        path = str(pcap_dir / "sip.pcap")
        full = server.filter_packets(path, "sip", fields=["frame.number"])
        frames = [p["frame.number"] for p in full["packets"]]
        assert len(frames) >= 3
        first = server.filter_packets(path, "sip", fields=["frame.number"], limit=2)
        assert [p["frame.number"] for p in first["packets"]] == frames[:2]
        assert first["next_offset"] == 2 and first["total_matched"] == len(frames) and "total_is_lower_bound" not in first
        rest = server.filter_packets(path, "sip", fields=["frame.number"], limit=500, offset=2)
        assert [p["frame.number"] for p in rest["packets"]] == frames[2:]
        assert "next_offset" not in rest and rest["offset"] == 2

    def test_output_cap_points_at_the_next_page(self, configure, pcap_dir: Path):
        srv = configure(Limits(max_output_bytes=2000))
        path = str(pcap_dir / "sip.pcap")
        first = srv.sip_dialogs(path)
        assert first["truncated"] is True and _size(first) <= 2000
        nxt = first["next_offset"]
        assert nxt == first["returned"] and f"offset={nxt}" in first["truncated_reason"]
        second = srv.sip_dialogs(path, offset=nxt)
        assert second["offset"] == nxt and second["dialogs"][0]["call_id"] != first["dialogs"][0]["call_id"]

    def test_message_rates_pages_by_message(self, server, pcap_dir: Path):
        path = str(pcap_dir / "all.pcap")
        full = server.message_rates(path, interval=10)
        names = [r["message"] for r in full["by_message"]]
        assert full["total_matched"] == len(names) >= 3
        page = server.message_rates(path, interval=10, limit=2, offset=1)
        assert [r["message"] for r in page["by_message"]] == names[1:3] and page["offset"] == 1
        assert page["messages"] == full["messages"]  # the summary does not depend on the page

    def test_find_identifier_pages_over_files(self, server, pcap_dir: Path):
        first = server.find_identifier(str(pcap_dir), pcapgen.IMSI, max_files=2)
        assert first["files_scanned"] == 2 and first["next_offset"] == 2 and first["offset"] == 0
        assert first["files_not_scanned"] == first["files_found"] - 2 and "offset=2" in first["truncated_reason"]
        second = server.find_identifier(str(pcap_dir), pcapgen.IMSI, max_files=50, offset=2)
        assert second["offset"] == 2 and second["files_scanned"] == second["files_found"] - 2
        assert "next_offset" not in second
        paths = {f["path"] for f in first["files"]} | {f["path"] for f in second["files"]}
        everything = server.find_identifier(str(pcap_dir), pcapgen.IMSI, max_files=50)
        assert paths == {f["path"] for f in everything["files"]}

    def test_bad_offset_is_a_structured_error(self, server, pcap_dir: Path):
        result = server.gtp_sessions(str(pcap_dir / "gtpv2.pcap"), offset=-3)
        assert result["error"]["type"] == "invalid_argument" and "offset" in result["error"]["message"]

    @pytest.mark.parametrize("tool,kwargs", [
        ("conversations", {"path": "gtpv2.pcap"}),
        ("diameter_sessions", {"path": "diameter.pcap"}),
        ("diameter_avps", {"path": "diameter.pcap"}),
        ("gtp_sessions", {"path": "gtpv2.pcap"}),
        ("gtpv1_sessions", {"path": "gtpv2.pcap"}),
        ("pfcp_sessions", {"path": "all.pcap"}),
        ("gtp_user_plane", {"path": "gtpu.pcap"}),
        ("gtp_tunnel_health", {"path": "gtpu.pcap"}),
        ("sctp_associations", {"path": "sctp.pcap"}),
        ("sigtran_messages", {"path": "sigtran.pcap"}),
        ("trace_subscriber", {"path": "all.pcap", "imsi": pcapgen.IMSI}),
    ])
    def test_every_list_tool_reports_the_contract(self, server, pcap_dir: Path, tool, kwargs):
        kwargs = dict(kwargs, path=str(pcap_dir / kwargs["path"]))
        out = getattr(server, tool)(**kwargs)
        assert "error" not in out, out
        assert {"total_matched", "returned", "dropped", "offset"} <= set(out), tool
        assert out["returned"] + out["dropped"] + out["offset"] == out["total_matched"] or out["offset"] > out["total_matched"]
        assert _ROWS_KEY not in out


@requires_tshark
def test_packet_cap_reports_how_many_packets_matched(configure, pcap_dir: Path):
    srv = configure(Limits(max_packets=3))
    out = srv.diameter_transactions(str(pcap_dir / "diameter.pcap"))
    assert out["packets_scanned"] == 3 and out["packets_matched"] > 3 and out["total_is_lower_bound"] is True


def test_output_cap_replaces_the_page_note():
    rows = [{"k": "v" * 50, "n": i} for i in range(300)]
    out = _fit(_envelope("rows", rows, 200), 3000)
    assert "more rows after this page" not in out["truncated_reason"]
    assert out["truncated_reason"].count("offset=") == 1 and f"offset={out['returned']}" in out["truncated_reason"]
    assert out["dropped"] == 300 - out["returned"]


@requires_tshark
def test_dns_transactions_pages(configure, tmp_path: Path):
    from .test_dns import scenario
    srv = configure(allow=[str(tmp_path)])
    path = str(scenario(tmp_path / "dns.pcap"))
    full = srv.dns_transactions(path)
    assert full["total_matched"] >= 2
    page = srv.dns_transactions(path, limit=1, offset=1)
    assert page["transactions"] == full["transactions"][1:2] and page["dropped"] == full["total_matched"] - 2

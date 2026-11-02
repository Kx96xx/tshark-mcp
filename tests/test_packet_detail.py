"""packet_detail and the frame numbers every row carries so it can be opened."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tshark_mcp.limits import Limits
from tshark_mcp.server import _bounded_layers

from . import pcapgen
from .conftest import requires_tshark


# ----------------------------------------------------------------- the bounded tree
def test_budget_goes_to_the_innermost_layer_first():
    tree = {"frame": {"a": "1", "b": "2"}, "ip": {"src": "x", "dst": "y"}, "diameter": {"c": ["1", "2", "3"]}}
    out, kept, dropped, shortened = _bounded_layers(tree, 4)
    assert list(out) == ["ip", "diameter"]  # the packet's own order is kept
    assert out["diameter"] == {"c": ["1", "2", "3"]} and out["ip"] == {"src": "x"}
    assert (kept, dropped, shortened) == (4, 3, 0)


def test_long_values_are_cut():
    out, kept, dropped, shortened = _bounded_layers({"data": {"data.data": "ab" * 600}}, 10)
    assert len(out["data"]["data.data"]) == 515 and out["data"]["data.data"].endswith("...") and shortened == 1


def test_whole_tree_within_budget_is_unchanged():
    tree = {"frame": {"a": "1"}, "sctp": [{"x": "1"}, {"x": "2"}]}
    out, kept, dropped, _ = _bounded_layers(tree, 300)
    assert out == tree and kept == 3 and dropped == 0


# ----------------------------------------------------------------- the tool


@requires_tshark
class TestPacketDetail:
    def test_diameter_frame_decodes_the_request(self, server, pcap_dir: Path):
        tx = server.diameter_transactions(str(pcap_dir / "diameter.pcap"))["transactions"][0]
        out = server.packet_detail(str(pcap_dir / "diameter.pcap"), tx["request_frame"])
        assert "error" not in out, out
        assert out["frame"] == tx["request_frame"] and "diameter" in out["protocols"]
        text = json.dumps(out["layers"]["diameter"])
        assert f'"diameter.cmdcode": "{tx["command_code"]}"' in text or str(tx["command_code"]) in text
        assert pcapgen.IMSI in text
        assert out["fields_returned"] <= 300 and out["time"].endswith("Z") and out["length"] > 0

    def test_layers_restrict_the_tree(self, server, pcap_dir: Path):
        out = server.packet_detail(str(pcap_dir / "gtpv2.pcap"), 1, layers=["gtpv2"])
        assert set(out["layers"]) == {"frame", "gtpv2"}

    def test_max_fields_caps_and_says_so(self, server, pcap_dir: Path):
        out = server.packet_detail(str(pcap_dir / "diameter.pcap"), 1, max_fields=5)
        assert out["fields_returned"] == 5 and out["fields_dropped"] > 0
        assert out["truncated"] is True and "max_fields" in out["truncated_reason"]
        assert "diameter" in out["layers"]  # the innermost layer gets the budget

    def test_frame_past_the_end_is_not_found(self, server, pcap_dir: Path):
        out = server.packet_detail(str(pcap_dir / "diameter.pcap"), 99999)
        assert out["error"]["type"] == "not_found"

    @pytest.mark.parametrize("frame", [0, -2, "x"])
    def test_bad_frame_is_rejected(self, server, pcap_dir: Path, frame):
        out = server.packet_detail(str(pcap_dir / "diameter.pcap"), frame)
        assert out["error"]["type"] == "invalid_argument"

    def test_frame_past_the_frame_cap_is_refused(self, configure, pcap_dir: Path):
        srv = configure(Limits(max_scan_packets=3))
        out = srv.packet_detail(str(pcap_dir / "diameter.pcap"), 4)
        assert out["error"]["type"] == "invalid_argument" and "frame cap" in out["error"]["message"]

    def test_unknown_layer_is_rejected(self, server, pcap_dir: Path):
        out = server.packet_detail(str(pcap_dir / "diameter.pcap"), 1, layers=["nosuchproto"])
        assert out["error"]["type"] == "unknown_field"

    def test_outside_the_allowlist_is_refused(self, server, tmp_path: Path):
        out = server.packet_detail(str(tmp_path / "x.pcap"), 1)
        assert out["error"]["type"] == "path_not_allowed"


# ----------------------------------------------------------------- frames on rows
@requires_tshark
class TestFramesOnRows:
    def test_filter_packets_rows_carry_the_frame(self, server, pcap_dir: Path):
        out = server.filter_packets(str(pcap_dir / "sip.pcap"), "sip", fields=["sip.Method"])
        assert out["packets"] and all(isinstance(r["frame"], int) for r in out["packets"])
        # a caller who asked for frame.number keeps its own column and gets no duplicate
        own = server.filter_packets(str(pcap_dir / "sip.pcap"), "sip", fields=["frame.number"])
        assert all("frame" not in r for r in own["packets"])

    def test_aggregates_name_their_first_and_last_frame(self, server, pcap_dir: Path):
        for out, key in ((server.gtp_user_plane(str(pcap_dir / "gtpu.pcap")), "tunnels"),
                         (server.gtp_tunnel_health(str(pcap_dir / "gtpu.pcap")), "tunnels"),
                         (server.sctp_associations(str(pcap_dir / "sctp.pcap")), "associations"),
                         (server.find_identifier(str(pcap_dir), pcapgen.IMSI), "files")):
            for row in out[key]:
                assert 1 <= row["first_frame"] <= row["last_frame"], (key, row)

    def test_message_rates_names_frames(self, server, pcap_dir: Path):
        out = server.message_rates(str(pcap_dir / "all.pcap"), interval=10, storm_min=2)
        assert all(isinstance(r["first_frame"], int) for r in out["by_message"])
        for loop in out["subscriber_loops"]:
            assert loop["first_frame"] <= loop["last_frame"]

    def test_every_trace_row_has_a_frame(self, server, pcap_dir: Path):
        out = server.trace_subscriber(str(pcap_dir / "all.pcap"), imsi=pcapgen.IMSI, msisdn=pcapgen.MSISDN)
        assert out["timeline"]
        for row in out["timeline"]:
            assert row.get("request_frame") or row.get("answer_frame") or row.get("frame"), row

    def test_frames_open_with_packet_detail(self, server, pcap_dir: Path):
        path = str(pcap_dir / "sigtran.pcap")
        row = server.sigtran_messages(path)["messages"][0]
        out = server.packet_detail(path, row["frame"], layers=["sccp"])
        assert out["frame"] == row["frame"] and "sccp" in out["layers"]

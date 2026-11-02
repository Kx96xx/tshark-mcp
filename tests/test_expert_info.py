"""expert_info: tshark's expert warnings and malformed-packet flags, with frames."""

from __future__ import annotations

from pathlib import Path

import pytest

from tshark_mcp import expert
from tshark_mcp.limits import Limits, ToolError
from tshark_mcp.runner import assert_read_only

from . import pcapgen as g
from .conftest import requires_tshark

STAT = """
Errors (4)
=============
   Frequency      Group           Protocol  Summary
           4  Malformed            GSM SMS  Malformed Packet (Exception occurred)

Warns (156)
=============
   Frequency      Group           Protocol  Summary
          78  Undecoded           Diameter  Unknown AVP 494 (vendor=Example), if you know what this is you can add it to dictionary.xml
          78  Undecoded           Diameter  Unknown Vendor, if you know whose this is you can add it to dictionary.xml

Notes (3)
=============
   Frequency      Group           Protocol  Summary
           3   Sequence                TCP  This frame is a (suspected) retransmission
"""


def test_parse_stat_keeps_protocols_with_spaces():
    rows = expert.parse_stat(STAT)
    assert rows[0] == {"severity": "error", "group": "Malformed", "protocol": "GSM SMS",
                       "summary": "Malformed Packet (Exception occurred)", "count": 4}
    assert [r["severity"] for r in rows] == ["error", "warn", "warn", "note"]
    assert rows[1]["summary"].startswith("Unknown AVP 494 (vendor=Example), if you know")
    assert rows[3] == {"severity": "note", "group": "Sequence", "protocol": "TCP",
                       "summary": "This frame is a (suspected) retransmission", "count": 3}


def test_frames_attach_by_severity_group_and_summary():
    a = expert.AGGREGATOR
    fields = (f"7\t{0x800000}\t{0x07000000}\tMalformed Packet (Exception occurred)\n"
              f"9\t{0x600000}{a}{0x800000}\t{0x05000000}{a}{0x07000000}\tUnknown Vendor, if you know whose this is you can"
              f" add it to dictionary.xml{a}Malformed Packet (Exception occurred)\n")
    frames = expert.parse_frames(fields)
    assert frames[("error", "Malformed", "Malformed Packet (Exception occurred)")] == [7, 9]
    rows = expert.merge(expert.parse_stat(STAT), frames)
    assert rows[0]["first_frame"] == 7 and rows[0]["frames"] == [7, 9] and rows[0]["frame_count"] == 2
    summary = expert.summarise(rows, frames)
    assert summary["by_severity"] == {"error": 4, "warn": 156, "note": 3}
    assert summary["malformed_frames"] == 2 and summary["malformed_first_frames"] == [7, 9]


def test_minor_malformed_notes_are_not_malformed_frames():
    frames = {("note", "Malformed", "The padding of this final parameter should be the padding of the chunk."): [3]}
    assert expert.summarise([], frames)["malformed_frames"] == 0


@pytest.mark.parametrize("stat", ["io,phs", "conv,ip", "expert,warn", "expert,error,diameter", "rtp,streams"])
def test_allowlisted_statistics_pass(stat):
    assert_read_only(["-n", "-r", "x.pcap", "-q", "-z", stat])


@pytest.mark.parametrize("stat", ["follow,tcp,ascii,0", "credentials", "", "smb,srt"])
def test_other_statistics_are_refused(stat):
    with pytest.raises(ToolError) as exc:
        assert_read_only(["-n", "-r", "x.pcap", "-q", "-z", stat])
    assert exc.value.type == "forbidden_flag"


def _expert_capture(path: Path) -> Path:
    """A good GTPv2-C Echo, a three-byte GTP-U packet (a dissector exception), a Diameter
    request with an AVP from an unknown vendor (undecoded warning) and one whose AVP
    claims 200 bytes (wrong AVP length)."""
    echo = g._gtpv2(1, None, 1, [g._ie(3, b"\x01")])
    common = g._diam_common("s;1;1", "mme.example", "example", "example")
    unknown = g._diameter(316, 16777251, 7, 7, True, [*common, g._avp(4242, b"\x00\x00\x00\x01", vendor=99999)])
    bad_avp = bytearray(g._avp(1, b"abc"))
    bad_avp[5:8] = (200).to_bytes(3, "big")
    wrong_length = g._diameter(316, 16777251, 8, 8, True, [*common, bytes(bad_avp)])
    frames = [
        (1.0, g._udp_frame("192.0.2.1", "192.0.2.2", 2123, 2123, echo)),
        (2.0, g._udp_frame("192.0.2.1", "192.0.2.2", 2152, 2152, b"\x30\xff\x00")),
        (3.0, g._sctp_data("192.0.2.10", "192.0.2.20", 3868, 3868, 1, 1, 46, unknown)),
        (4.0, g._sctp_data("192.0.2.10", "192.0.2.20", 3868, 3868, 1, 2, 46, wrong_length)),
    ]
    return g._frames_to_pcap(path, frames)


@requires_tshark
class TestExpertInfoTool:
    def test_malformed_and_undecoded_items_with_frames(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        out = srv.expert_info(str(_expert_capture(tmp_path / "expert.pcap")))
        assert "error" not in out, out
        malformed = {r["protocol"]: r for r in out["items"] if r["group"] == "Malformed" and r["severity"] == "error"}
        assert malformed["GTP"]["frames"] == [2] and malformed["GTP"]["count"] == 1
        assert malformed["Diameter"]["first_frame"] == 4 and "AVP" in malformed["Diameter"]["summary"]
        assert out["items"][0]["severity"] == "error" and out["items"][-1]["severity"] == "warn"  # worst first
        assert out["summary"]["malformed_frames"] == 2 and out["summary"]["malformed_first_frames"] == [2, 4]
        assert any(r["protocol"] == "Diameter" and r["severity"] == "warn" and r["first_frame"] == 3 for r in out["items"])
        assert out["total_matched"] == len(out["items"]) and out["severity"] == "warn"

    def test_severity_error_drops_warnings(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        out = srv.expert_info(str(_expert_capture(tmp_path / "expert.pcap")), severity="error")
        assert {r["severity"] for r in out["items"]} == {"error"}

    def test_filter_restricts_packets(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        out = srv.expert_info(str(_expert_capture(tmp_path / "expert.pcap")), filter="diameter")
        assert out["items"] and {r["protocol"] for r in out["items"]} == {"Diameter"}
        assert out["summary"]["malformed_first_frames"] == [4]
        assert out["display_filter"] == "diameter"

    def test_frames_open_with_packet_detail(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        path = str(_expert_capture(tmp_path / "expert.pcap"))
        out = srv.expert_info(path, severity="error")
        detail = srv.packet_detail(path, out["items"][0]["first_frame"])
        assert detail.get("malformed") is True

    def test_bad_severity_and_filter(self, server, pcap_dir: Path):
        assert server.expert_info(str(pcap_dir / "sip.pcap"), severity="loud")["error"]["type"] == "invalid_argument"
        assert server.expert_info(str(pcap_dir / "sip.pcap"), filter="nosuch.field == 1")["error"]["type"] == "invalid_filter"

    def test_clean_capture_has_no_items(self, server, pcap_dir: Path):
        out = server.expert_info(str(pcap_dir / "sip.pcap"))
        assert out["items"] == [] and out["total_matched"] == 0 and out["summary"]["malformed_frames"] == 0

    def test_frame_cap_is_reported(self, configure, tmp_path: Path):
        srv = configure(Limits(max_scan_packets=2), allow=[str(tmp_path)])
        out = srv.expert_info(str(_expert_capture(tmp_path / "expert.pcap")))
        assert out["truncated"] is True and "frame cap" in out["truncated_reason"]

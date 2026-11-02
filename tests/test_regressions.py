"""Regression tests for bugs found by running the tools against long, real-world
captures. Every capture here is synthetic and built from made-up values."""

from __future__ import annotations

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

"""Regression tests for bugs found by running the tools against long, real-world
captures. Every capture here is synthetic and built from made-up values."""

from __future__ import annotations

from pathlib import Path

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

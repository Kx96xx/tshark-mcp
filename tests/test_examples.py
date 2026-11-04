"""The sample captures committed under examples/ stay true to the README.

Two checks: a fresh generation is byte-identical to the committed files (so the files
cannot drift from the generator), and the tools read them as the README says.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from . import pcapgen
from .conftest import requires_tshark

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
FILES = ("sip_one_way_audio.pcap", "diameter_error_answer.pcap", "gtpv2_create_session_rejected.pcap")


@pytest.mark.parametrize("name", FILES)
def test_committed_capture_matches_generator(tmp_path: Path, name: str) -> None:
    generated = pcapgen.write_example_pcaps(tmp_path)[name.removesuffix(".pcap")]
    assert (EXAMPLES / name).read_bytes() == generated.read_bytes(), (
        f"examples/{name} differs from tests/pcapgen.py: run `python examples/generate.py`")


@pytest.fixture
def examples(configure):
    return configure(allow=[str(EXAMPLES)])


@requires_tshark
class TestOneWayAudio:
    path = str(EXAMPLES / "sip_one_way_audio.pcap")

    def test_media_path_check_names_the_missing_direction(self, examples) -> None:
        out = examples.media_path_check(self.path, pcapgen.EXAMPLE_CALL_ID)
        assert out["common_codecs"] == ["PCMA/8000"]
        assert [d["status"] for d in out["directions"]] == ["as negotiated", "missing"]
        assert out["directions"][1]["expected"] == "192.0.2.70:30010 > 198.51.100.9:40010"
        assert [i["kind"] for i in out["issues"]] == ["one_way_media"]
        assert out["verdict"].startswith("no RTP seen answerer to offerer")

    def test_rtp_streams_sees_one_clean_stream(self, examples) -> None:
        out = examples.rtp_streams(self.path)
        assert out["summary"] == {"streams": 1, "one_way": 1, "with_loss": 0, "rtcp_packets": 0,
                                  "lowest_mos_estimate": pytest.approx(4.39)}
        stream = out["streams"][0]
        assert stream["call_id"] == pcapgen.EXAMPLE_CALL_ID and stream["codec"] == "PCMA/8000"
        assert stream["packets"] == 250 and stream["lost"] == 0 and stream["one_way"] is True
        assert stream["mos_estimate"]["estimate"] is True

    def test_sip_call_detail_timing(self, examples) -> None:
        out = examples.sip_call_detail(self.path, pcapgen.EXAMPLE_CALL_ID)
        call = out["call"]
        assert call["outcome"] == "answered" and call["final_status"] == 200
        assert call["timing"]["post_dial_delay_ms"] == 900.0 and call["timing"]["answer_ms"] == 2400.0
        assert call["timing"]["call_duration_s"] == pytest.approx(5.2)
        assert call["ended_by"]["by"] == "caller" and call["media"]["negotiated_codec"] == "PCMA/8000"


@requires_tshark
class TestDiameterErrorAnswer:
    path = str(EXAMPLES / "diameter_error_answer.pcap")

    def test_transactions_name_the_error(self, examples) -> None:
        out = examples.diameter_transactions(self.path)
        assert out["summary"] == {"by_message": {"ULR": 2, "DWR": 1}, "unanswered": 0, "failed": 1}
        failed = [t for t in out["transactions"] if not t["success"]]
        assert len(failed) == 1
        assert failed[0]["user_name"] == pcapgen.EXAMPLE_IMSI_NO_EPS
        assert failed[0]["experimental_result_code"] == 5420
        assert failed[0]["result"] == "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION"
        assert [t["rtt_ms"] for t in out["transactions"]] == [52.0, 37.0, 3.0]

    def test_avps_show_what_the_mme_asked(self, examples) -> None:
        out = examples.diameter_avps(self.path, imsi=pcapgen.EXAMPLE_IMSI_NO_EPS)
        assert out["count"] == 1
        avps = out["transactions"][0]
        assert avps["request_avps"]["ULR-Flags"] == "34 [S6a/S6d-Indicator, Initial-Attach-Indicator]"
        assert avps["request_avps"]["RAT-Type"] == "EUTRAN (1004)"
        assert avps["request_avps"]["Visited-PLMN-Id"] == "001-01"
        assert avps["answer_avps"]["Experimental-Result"][0]["Experimental-Result-Code"] == 5420


@requires_tshark
class TestCreateSessionRejected:
    path = str(EXAMPLES / "gtpv2_create_session_rejected.pcap")

    def test_rejected_session_is_named(self, examples) -> None:
        out = examples.gtp_sessions(self.path)
        assert out["summary"] == {"by_message": {"Echo Request": 1, "Create Session Request": 2,
                                                 "Delete Session Request": 1}, "unanswered": 0, "failed": 1}
        rejected = [t for t in out["transactions"] if t.get("accepted") is False]
        assert len(rejected) == 1
        assert rejected[0]["imsi"] == pcapgen.IMSI_OTHER and rejected[0]["apn"] == "internet.wrong.apn"
        assert rejected[0]["cause"] == 78 and rejected[0]["cause_name"] == "Missing or unknown APN"
        accepted = [t for t in out["transactions"] if t["message"] == "Create Session Request" and t["accepted"]]
        assert accepted[0]["paa"] == pcapgen.UE_IP and accepted[0]["rtt_ms"] == 95.0

    def test_imsi_filter_keeps_both_halves(self, examples) -> None:
        out = examples.gtp_sessions(self.path, imsi=pcapgen.IMSI_OTHER)
        assert out["count"] == 1 and out["transactions"][0]["answer_frame"] == 6

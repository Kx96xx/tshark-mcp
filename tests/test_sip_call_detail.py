"""sip_call_detail against the synthetic voice captures."""

from __future__ import annotations

from pathlib import Path

from tshark_mcp import sip

from . import pcapgen
from .conftest import requires_tshark


def _voice(pcap_dir: Path, name: str) -> str:
    return str(pcap_dir / "voice" / name)


class TestReason:
    def test_q850_named(self):
        assert sip.reason_detail('Q.850;cause=17;text="busy"') == {
            "header": 'Q.850;cause=17;text="busy"', "q850_cause": 17, "q850_name": "User busy"}
        assert sip.reason_detail("SIP;cause=480") == {"header": "SIP;cause=480"}


@requires_tshark
class TestSipCallDetail:
    def test_answered_call(self, server, pcap_dir):
        out = server.sip_call_detail(_voice(pcap_dir, "voice_call.pcap"), pcapgen.CALL_ID_VOICE)
        assert out["found"] is True
        call = out["call"]
        assert call["outcome"] == "answered" and call["caller"] == pcapgen.UE_SIP_IP
        assert call["final_response"] == {"status": 200, "reason_phrase": "OK", "frame": 5}
        assert call["timing"] == {"post_dial_delay_ms": 1200.0, "post_dial_delay_to": 180, "ringing_ms": 1200.0,
                                  "answer_ms": 3000.0, "setup_ms": 3020.0, "call_duration_s": 5.5}
        assert call["retransmissions"] == {"INVITE": 1}
        assert call["ended_by"]["method"] == "BYE" and call["ended_by"]["by"] == "callee"
        assert call["reasons"][0]["q850_cause"] == 16 and call["reasons"][0]["q850_name"] == "Normal call clearing"
        media = call["media"]
        assert [(e["message"], e["role"]) for e in media["sdp"]] == [("INVITE", "offer"), ("200 INVITE", "answer")]
        assert media["common_codecs"] == ["AMR-WB/16000"] and media["negotiated_codec"] == "AMR-WB/16000"
        assert media["sdp"][1]["media"][0]["address"] == pcapgen.MEDIA_GW_IP
        sdp_frames = [m["frame"] for m in call["messages"] if m.get("sdp")]
        assert sdp_frames == [1, 5]
        # The dialog row of sip_dialogs is part of the detail.
        assert call["final_status"] == 200 and call["resent_messages"] == 1 and "methods" not in call

    def test_488_codec_mismatch_and_warning(self, server, pcap_dir):
        call = server.sip_call_detail(_voice(pcap_dir, "voice_problems.pcap"), pcapgen.CALL_ID_488)["call"]
        assert call["outcome"] == "failed 488"
        assert call["final_response"]["reason_phrase"] == "Not Acceptable Here"
        assert call["timing"] == {"post_dial_delay_ms": 300.0, "post_dial_delay_to": 488}
        assert call["warnings"][0]["header"].startswith("305 ")
        assert call["reasons"][0]["header"].startswith("SIP;cause=488")
        media = call["media"]
        assert [e["role"] for e in media["sdp"]] == ["offer", "failure_response"]
        assert media["common_codecs"] == [] and "no codec in common" in media["note"]
        assert "ended_by" not in call

    def test_caller_hangs_up_and_private_sdp_address(self, server, pcap_dir):
        call = server.sip_call_detail(_voice(pcap_dir, "voice_problems.pcap"), pcapgen.CALL_ID_NAT)["call"]
        assert call["ended_by"]["by"] == "caller" and call["timing"]["call_duration_s"] == 3.0
        assert call["media"]["sdp"][0]["media"][0]["private_address"] is True
        assert call["media"]["negotiated_codec"] == "PCMU/8000"

    def test_unknown_call_and_lint(self, server, pcap_dir):
        out = server.sip_call_detail(_voice(pcap_dir, "voice_call.pcap"), "nobody@example.invalid")
        assert {k: v for k, v in out.items() if k != "tokens_estimate"} == {"found": False, "packets_scanned": 0}
        assert server.sip_call_detail(_voice(pcap_dir, "voice_call.pcap"), 'x"y')["error"]["type"] == "invalid_argument"

    def test_existing_sip_capture(self, server, pcap_dir):
        call = server.sip_call_detail(str(pcap_dir / "sip.pcap"), "a1b2c3d4@ue.example")["call"]
        assert call["timing"]["post_dial_delay_ms"] == 900.0 and call["timing"]["answer_ms"] == 3500.0
        assert call["ended_by"]["by"] == "caller" and call["timing"]["call_duration_s"] == 6.5

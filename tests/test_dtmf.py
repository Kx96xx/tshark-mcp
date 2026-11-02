"""dtmf_events: RFC 4733 telephone-events and SIP INFO DTMF."""

from __future__ import annotations

from pathlib import Path

from tshark_mcp import dtmf

from . import pcapgen
from .conftest import requires_tshark


def _voice(pcap_dir: Path, name: str) -> str:
    return str(pcap_dir / "voice" / name)


def _info(frame: int, body: str, ctype: str, cseq: str = "2", method: str = "INFO", status: str = "") -> dict:
    return {"sip.Call-ID": "c1", "frame.number": str(frame), "frame.time_epoch": str(frame), "ip.src": "a", "ip.dst": "b",
            "sip.Method": method, "sip.Status-Code": status, "sip.CSeq.method": "INFO", "sip.CSeq.seq": cseq,
            "sip.resend": "", "sip.Content-Type": ctype, "sip.msg_body": body.encode().hex()}


class TestHelpers:
    def test_info_bodies(self):
        rows = dtmf.info_events([
            _info(1, "Signal=#\r\nDuration=100\r\n", "application/dtmf-relay"),
            _info(2, "", "", method="", status="200"),
            _info(3, '<kpml-response code="200" digits="42"/>', "application/kpml-response+xml", cseq="3"),
            _info(4, "x", "text/plain", cseq="4"),
        ])
        assert [(r["digit"], r.get("response"), r.get("duration_ms")) for r in rows] == [("#", 200, 100), ("42", None, None)]
        assert rows[1]["issues"] == ["no final response to the INFO in the capture"]

    def test_filters(self):
        assert dtmf.rtp_filter(set()) == "rtpevent"
        assert dtmf.rtp_filter({"192.0.2.1"}) == "rtpevent && (ip.addr in {192.0.2.1})"
        assert dtmf.info_filter("c@x") == 'sip.CSeq.method == "INFO" && sip.Call-ID == "c@x"'


@requires_tshark
class TestDtmfEvents:
    def test_both_methods_in_one_call(self, server, pcap_dir):
        out = server.dtmf_events(_voice(pcap_dir, "voice_call.pcap"))
        assert [(e["source"], e["digit"]) for e in out["events"]] == [("sip_info", "7"), ("rfc4733", "5")]
        ev = out["events"][1]
        assert (ev["payload_type"], ev["clock_rate"], ev["packets"], ev["end_packets"]) == (101, 16000, 5, 3)
        assert ev["duration_ms"] == 30.0 and ev["volume_dbm0"] == -10 and "issues" not in ev
        assert out["events"][0]["response"] == 200 and out["events"][0]["duration_ms"] == 160
        (call,) = out["calls"]
        assert (call["rfc4733"], call["sip_info"], call["telephone_event_payload_types"]) == ("5", "7", [101])
        assert "both in RTP and in SIP INFO" in call["note"]

    def test_payload_type_end_packet_and_rejected_info(self, server, pcap_dir):
        out = server.dtmf_events(_voice(pcap_dir, "voice_dtmf.pcap"), call_id=pcapgen.CALL_ID_DTMF)
        digits = {e["digit"]: e for e in out["events"]}
        assert list(digits) == ["1", "#", "9", "*"]
        assert digits["1"]["end_packets"] == 0 and "no end-of-event packet" in digits["1"]["issues"][0]
        assert digits["#"]["payload_type"] == 101 and "not the negotiated telephone-event type (100)" in digits["#"]["issues"][0]
        assert digits["9"]["response"] == 415 and "rejected with 415" in digits["9"]["issues"][0]
        assert digits["*"]["content_type"] == "application/dtmf-relay" and "issues" not in digits["*"]
        assert out["summary"] == {"rfc4733_digits": 2, "sip_info_digits": 2, "with_issues": 3}

    def test_no_dtmf_paging_and_lint(self, server, pcap_dir):
        out = server.dtmf_events(_voice(pcap_dir, "voice_problems.pcap"))
        assert out["count"] == 0 and out["calls"] == []
        page = server.dtmf_events(_voice(pcap_dir, "voice_dtmf.pcap"), limit=1, offset=1)
        assert page["returned"] == 1 and page["events"][0]["digit"] == "#" and page["next_offset"] == 2
        assert server.dtmf_events(_voice(pcap_dir, "voice_call.pcap"), call_id="nobody@example.invalid")["count"] == 0
        assert server.dtmf_events(_voice(pcap_dir, "voice_call.pcap"), call_id='a"b')["error"]["type"] == "invalid_argument"

"""media_path_check: SDP-negotiated media against the RTP seen."""

from __future__ import annotations

from pathlib import Path

from tshark_mcp import media, sip

from . import pcapgen
from .conftest import requires_tshark


def _voice(pcap_dir: Path, name: str) -> str:
    return str(pcap_dir / "voice" / name)


def _sdp(addr: str, port: int, fmts: str, maps: list[str], direction: str = "sendrecv", version: int = 1) -> str:
    lines = ["v=0", f"o=- {port} {version} IN IP4 {addr}", "s=-", f"c=IN IP4 {addr}", "t=0 0", f"m=audio {port} RTP/AVP {fmts}"]
    lines += [f"a=rtpmap:{m}" for m in maps] + [f"a={direction}"]
    return "\r\n".join(lines) + "\r\n"


def _sdps(offer: str, answer: str | None) -> list[dict]:
    def msg(frame, src, body, method="", status=""):
        return {"sip.Call-ID": "c1", "frame.number": str(frame), "frame.time_epoch": str(frame), "ip.src": src,
                "ip.dst": "x", "sip.Method": method, "sip.Status-Code": status, "sip.CSeq.method": "INVITE",
                "sip.CSeq.seq": "1", "sip.resend": "", "sip.msg_body": body.encode().hex()}
    msgs = [msg(1, "192.0.2.1", offer, method="INVITE")]
    if answer:
        msgs.append(msg(2, "192.0.2.2", answer, status="200"))
    return sip.sdp_messages(msgs)


def _stream(src: str, dst: str, pt: int = 0, ssrc: str = "0x1") -> dict:
    return {"ssrc": ssrc, "src": src, "dst": dst, "packets": 10, "payload_type": pt, "codec": "PCMU/8000", "call_id": "c1"}


OFFER = _sdp("198.51.100.1", 4000, "0 8", ["0 PCMU/8000", "8 PCMA/8000"])
ANSWER = _sdp("198.51.100.2", 5000, "0", ["0 PCMU/8000"])


class TestCheck:
    def test_clean_call(self):
        out = media.check("c1", _sdps(OFFER, ANSWER), [_stream("198.51.100.1:4000", "198.51.100.2:5000"),
                                                       _stream("198.51.100.2:5000", "198.51.100.1:4000", ssrc="0x2")])
        assert out["issues"] == [] and out["common_codecs"] == ["PCMU/8000"]
        assert [d["status"] for d in out["directions"]] == ["as negotiated", "as negotiated"]

    def test_no_rtp_wrong_address_and_payload_type(self):
        assert [i["kind"] for i in media.check("c1", _sdps(OFFER, ANSWER), [])["issues"]] == ["no_rtp"]
        out = media.check("c1", _sdps(OFFER, ANSWER), [
            _stream("198.51.100.1:4000", "198.51.100.2:5000", pt=18),
            _stream("198.51.100.2:5000", "198.51.100.9:4000", ssrc="0x2"),
        ])
        kinds = [i["kind"] for i in out["issues"]]
        assert "payload_type_not_negotiated" in kinds and "rtp_to_wrong_address" in kinds
        assert out["directions"][1]["status"] == "sent elsewhere"

    def test_hold_rejected_and_answer_codec_mismatch(self):
        held = _sdp("198.51.100.2", 5000, "0", ["0 PCMU/8000"], direction="sendonly")
        assert "media_direction" in [i["kind"] for i in media.check("c1", _sdps(OFFER, held), [])["issues"]]
        rejected = _sdp("198.51.100.2", 0, "0", ["0 PCMU/8000"])
        assert "media_rejected" in [i["kind"] for i in media.check("c1", _sdps(OFFER, rejected), [])["issues"]]
        g729 = _sdp("198.51.100.2", 5000, "18", ["18 G729/8000"])
        out = media.check("c1", _sdps(OFFER, g729), [])
        assert out["common_codecs"] == [] and out["verdict"].startswith("the answer's codecs (G729/8000)")

    def test_unanswered_offer_and_no_sdp(self):
        out = media.check("c1", _sdps(OFFER, None), [])
        assert [i["kind"] for i in out["issues"]] == ["no_answer"] and "directions" not in out
        assert media.check("c1", [], [])["issues"][0]["kind"] == "no_sdp"


@requires_tshark
class TestMediaPathCheck:
    def test_clean_call(self, server, pcap_dir):
        out = server.media_path_check(_voice(pcap_dir, "voice_call.pcap"), pcapgen.CALL_ID_VOICE)
        assert out["found"] is True and out["issues"] == [] and out["rtp_streams"] == 2
        assert out["offer"]["media_endpoint"] == "198.51.100.9:40000" and out["answer"]["media_endpoint"] == "192.0.2.70:30000"
        assert out["common_codecs"] == ["AMR-WB/16000"] and out["verdict"].startswith("media flows both ways")

    def test_nat_not_latched(self, server, pcap_dir):
        out = server.media_path_check(_voice(pcap_dir, "voice_problems.pcap"), pcapgen.CALL_ID_NAT)
        kinds = [i["kind"] for i in out["issues"]]
        assert kinds == ["private_sdp_address", "source_differs_from_sdp", "nat_not_latched"]
        assert "203.0.113.7:61000" in out["verdict"] and "10.0.0.5:40000" in out["verdict"]
        assert [d["status"] for d in out["directions"]] == ["arrives from another source", "as negotiated"]

    def test_one_way_by_signalling_is_not_one_way_media(self):
        """Offer a=recvonly, answer a=sendonly: only the answerer sends, as negotiated. The
        missing offerer-to-answerer RTP is expected, not a fault (it used to be one_way_media)."""
        offer = _sdp("192.0.2.1", 6000, "0", ["0 PCMU/8000"], direction="recvonly")
        answer = _sdp("192.0.2.2", 7000, "0", ["0 PCMU/8000"], direction="sendonly")
        out = media.check("c1", _sdps(offer, answer), [_stream("192.0.2.2:7000", "192.0.2.1:6000")])
        assert [i["kind"] for i in out["issues"]] == ["media_direction", "media_direction"]
        assert out["directions"][0]["status"] == "not expected (a=recvonly in the offer)"
        assert out["directions"][1]["status"] == "as negotiated"
        assert "one-way audio as captured" not in out["verdict"]
        # the same SDP with the answerer silent too: that one is a real one-way-media finding
        silent = media.check("c1", _sdps(offer, answer), [])
        assert "no_rtp" in [i["kind"] for i in silent["issues"]]
        # inactive on both sides and no RTP: nothing was expected, so no no_rtp either
        hold = media.check("c1", _sdps(_sdp("192.0.2.1", 6000, "0", ["0 PCMU/8000"], direction="inactive"),
                                       _sdp("192.0.2.2", 7000, "0", ["0 PCMU/8000"], direction="inactive")), [])
        assert [i["kind"] for i in hold["issues"]] == ["media_direction", "media_direction"]
        assert all(d["status"].startswith("not expected") for d in hold["directions"])

    def test_one_way(self, server, pcap_dir):
        out = server.media_path_check(_voice(pcap_dir, "voice_problems.pcap"), pcapgen.CALL_ID_ONEWAY)
        assert [i["kind"] for i in out["issues"]] == ["one_way_media"]
        assert out["directions"][1] == {"direction": "answerer to offerer", "expected": "192.0.2.70:30004 > 198.51.100.9:40002",
                                        "streams": [], "status": "missing"}

    def test_488_codec_mismatch(self, server, pcap_dir):
        out = server.media_path_check(_voice(pcap_dir, "voice_problems.pcap"), pcapgen.CALL_ID_488)
        assert [i["kind"] for i in out["issues"]] == ["codec_mismatch"] and out["common_codecs"] == []
        assert out["failure_sdp"]["codecs"] == ["AMR-WB/16000"] and out["verdict"].startswith("488: no codec in common")

    def test_unknown_call_and_lint(self, server, pcap_dir):
        out = server.media_path_check(_voice(pcap_dir, "voice_call.pcap"), "nobody@example.invalid")
        assert out["found"] is False and out["issues"][0]["kind"] == "no_sdp"
        assert server.media_path_check(_voice(pcap_dir, "voice_call.pcap"), "")["error"]["type"] == "invalid_argument"

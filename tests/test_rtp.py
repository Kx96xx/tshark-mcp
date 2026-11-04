"""rtp_streams and the SDP/RTP helpers behind it, against synthetic voice captures,
cross-checked with tshark's own ``-z rtp,streams`` statistics."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from tshark_mcp import rtp, sdp, sip
from tshark_mcp.limits import Limits

from . import pcapgen
from .conftest import TSHARK, requires_tshark

OFFER = (
    "v=0\r\no=- 100 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\n"
    "m=audio 40000 RTP/AVP 96 8 101\r\na=rtpmap:96 AMR-WB/16000\r\na=rtpmap:101 telephone-event/16000\r\n"
    "a=fmtp:101 0-15\r\na=ptime:20\r\na=sendonly\r\n"
    "m=video 0 RTP/AVP 99\r\nc=IN IP4 10.0.0.9\r\na=rtpmap:99 H264/90000\r\n"
)


def _voice(pcap_dir: Path, name: str) -> str:
    return str(pcap_dir / "voice" / name)


# ----------------------------------------------------------------- pure helpers
class TestSdp:
    def test_rtp_without_ip_addresses_is_left_out(self):
        """RTP over Bluetooth AVDTP (or any non-IP transport) has no addresses or ports: it
        used to be merged into one stream keyed ':None' with bogus duplicates and sequence
        errors. The filter keeps RTP over IP and the parser drops anything without addresses."""
        assert "(ip || ipv6)" in rtp.DISPLAY_FILTER
        cols = {f: "" for f in rtp.FIELDS}
        cols.update({"frame.number": "14", "frame.time_epoch": "1700000000.1", "rtp.ssrc": "0x11223344", "rtp.seq": "1",
                     "rtp.timestamp": "0", "rtp.p_type": "96", "rtp.marker": "0"})
        line = "\t".join(cols[f] for f in rtp.FIELDS)
        assert rtp.parse(line + "\n") == ([], [])
        cols.update({"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2", "udp.srcport": "4000", "udp.dstport": "5000"})
        packets, _ = rtp.parse("\t".join(cols[f] for f in rtp.FIELDS) + "\n")
        assert len(packets) == 1 and packets[0]["src"] == "192.0.2.1"

    def test_parse_media_sections_in_order(self):
        parsed = sdp.parse(OFFER)
        audio, video = parsed["media"]
        assert parsed["origin"] == "198.51.100.9" and parsed["origin_version"] == "100/1"
        assert (audio["address"], audio["port"], audio["rtcp_port"]) == ("198.51.100.9", 40000, 40001)
        assert [sdp.codec_label(c) for c in audio["codecs"]] == ["AMR-WB/16000", "PCMA/8000", "telephone-event/16000"]
        assert audio["direction"] == "sendonly" and audio["ptime"] == 20
        assert sdp.telephone_event_pts(audio) == [101]
        assert [c["name"] for c in sdp.voice_codecs(audio)] == ["AMR-WB", "PCMA"]
        assert video["address"] == "10.0.0.9" and video["port"] == 0 and video["direction"] == "sendrecv"
        summary = sdp.summary(video)
        assert summary["rejected"] and summary["private_address"]

    def test_multipart_and_hex_body(self):
        body = ("--b1\r\nContent-Type: application/sdp\r\n\r\n" + OFFER + "--b1\r\nContent-Type: application/x\r\n\r\nx\r\n--b1--")
        hex_body = body.encode().hex()
        text = sdp.extract(sdp.body_text(hex_body))
        assert text.startswith("v=0") and "--b1" not in text
        assert sdp.extract(sdp.body_text(":".join(hex_body[i:i + 2] for i in range(0, len(hex_body), 2)))) == text
        assert sdp.extract("Signal=5\r\nDuration=160") is None
        assert sdp.body_text("") == "" and sdp.body_text("zz") == ""

    def test_common_codecs_ignore_events_and_compare_rate(self):
        a = sdp.parse(OFFER)["media"][0]
        b = sdp.parse(OFFER.replace("96 AMR-WB/16000", "96 AMR-WB/8000"))["media"][0]
        assert sdp.common_codecs(a, b) == ["PCMA/8000"]
        only_events = sdp.parse("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 1 RTP/AVP 101\r\na=rtpmap:101 telephone-event/16000\r\n")
        assert sdp.common_codecs(a, only_events["media"][0]) == []

    @pytest.mark.parametrize("addr,private", [
        ("10.1.2.3", True), ("172.20.0.1", True), ("192.168.1.1", True), ("100.64.0.7", True), ("fd00::1", True),
        ("192.0.2.70", False), ("203.0.113.7", False), ("8.8.8.8", False), ("not-an-ip", False), (None, False),
    ])
    def test_private_addresses(self, addr, private):
        assert sdp.is_private(addr) is private


class TestRtpMath:
    def test_sequence_wrap_loss_duplicates_and_reordering(self):
        seqs = [65533, 65534, 65535, 0, 2, 1, 1, 3]
        stats = rtp.sequence_stats([{"seq": s} for s in seqs])
        assert stats["expected"] == 7 and stats["lost"] == 0
        assert stats["duplicates"] == 1 and stats["out_of_order"] == 1
        stats = rtp.sequence_stats([{"seq": s} for s in (10, 11, 15, 16)])
        assert (stats["expected"], stats["lost"], stats["sequence_errors"]) == (7, 3, 1)

    def test_jitter_is_rfc3550(self):
        # 8 kHz, 20 ms packets; the third arrives 8 ms late, so D = 8 then 8 again.
        pkts = [{"time": t, "ts": i * 160, "pt": 0} for i, t in enumerate([0.0, 0.020, 0.048, 0.060])]
        out = rtp.timing_stats(pkts, 8000, 0)
        assert out["max_jitter_ms"] == pytest.approx(8 / 16 + (8 - 8 / 16) / 16, abs=1e-3)
        assert out["max_delta_ms"] == pytest.approx(28.0) and "max_jitter_ms" not in rtp.timing_stats(pkts, None)

    def test_mos_estimate_is_labelled_and_monotonic(self):
        clean = rtp.mos_estimate("PCMU", 0.0, 0.0, None, 20)
        lossy = rtp.mos_estimate("PCMU", 5.0, 0.0, None, 20)
        slow = rtp.mos_estimate("PCMU", 0.0, 0.0, 600.0, 20)
        g729 = rtp.mos_estimate("G729", 0.0, 0.0, None, 20)
        assert clean["estimate"] is True and "G.107" in clean["method"]
        assert 4.3 <= clean["value"] <= 4.5
        assert lossy["value"] < clean["value"] and slow["value"] < clean["value"] and g729["value"] < clean["value"]
        assert slow["inputs"]["delay_source"] == "half the RTCP round trip"
        assert rtp.mos_estimate("OPUS", 0.0, 0.0, None, 20)["inputs"]["codec_values"].startswith("assumed")
        assert rtp.mos_estimate("PCMU", 100.0, 0.0, None, 20)["value"] < 1.5

    def test_filter_shape(self):
        assert rtp.rtp_filter({"192.0.2.1", "2001:db8::1"}) == \
            "(rtp || rtcp) && (ip.addr in {192.0.2.1} || ipv6.addr in {2001:db8::1})"
        assert rtp.rtp_filter(set()) == rtp.DISPLAY_FILTER

    def test_offer_answer_roles(self):
        def msg(frame, src, body, method="", status="", resend="", cseq="1", cseq_method="INVITE"):
            return {"sip.Call-ID": "c1", "frame.number": str(frame), "frame.time_epoch": str(frame), "ip.src": src,
                    "ip.dst": "x", "sip.Method": method, "sip.Status-Code": status, "sip.CSeq.method": cseq_method,
                    "sip.CSeq.seq": cseq, "sip.resend": resend, "sip.msg_body": body.encode().hex()}
        answer = OFFER.replace("100 1", "200 1")
        rows = sip.sdp_messages([
            msg(1, "a", OFFER, method="INVITE"), msg(2, "a", OFFER, method="INVITE", resend="1"),
            msg(3, "proxy", OFFER, method="INVITE"),  # the same offer forwarded on the proxy's other leg
            msg(4, "b", answer, status="183"), msg(5, "b", answer, status="200"),
            msg(6, "a", OFFER.replace("100 1", "100 2"), method="INVITE", cseq="2"),
            msg(7, "b", answer.replace("200 1", "200 2"), status="200", cseq="2"),
            # A re-INVITE without SDP: the offer comes in the 200 and the answer in the ACK.
            msg(8, "b", answer.replace("200 1", "200 3"), status="200", cseq="3"),
            msg(9, "a", OFFER.replace("100 1", "100 3"), method="ACK", cseq="3", cseq_method="ACK"),
        ])
        assert [(r["frame"], r["role"]) for r in rows] == [
            (1, "offer"), (3, "repeat"), (4, "answer"), (5, "repeat"), (6, "offer"), (7, "answer"), (8, "offer"),
            (9, "answer")]


# ----------------------------------------------------------------- through tshark
def _tshark_rtp_streams(path: str, heuristic: bool = False) -> dict[str, dict[str, float]]:
    """Parse ``tshark -q -z rtp,streams``: per SSRC packets, lost, max delta and max jitter."""
    argv = [TSHARK, "-n", "-r", path, "-q", "-z", "rtp,streams"]
    if heuristic:
        argv[1:1] = ["--enable-heuristic", "rtp_udp"]
    out = subprocess.run(argv, capture_output=True, text=True, check=True).stdout
    rows = {}
    num = r"(-?[\d.]+)"
    pattern = re.compile(r"(0x[0-9a-fA-F]{8})\s+.*?\s(\d+)\s+(-?\d+) \([^)]*\)\s+" + r"\s+".join([num] * 6))
    for line in out.splitlines():
        m = pattern.search(line)
        if m:
            rows[m.group(1).lower()] = {"packets": int(m.group(2)), "lost": int(m.group(3)),
                                        "max_delta_ms": float(m.group(6)), "max_jitter_ms": float(m.group(9))}
    return rows


@requires_tshark
class TestRtpStreams:
    def test_call_streams_link_codec_loss_rtcp_and_mos(self, server, pcap_dir):
        out = server.rtp_streams(_voice(pcap_dir, "voice_call.pcap"))
        assert "error" not in out, out
        assert out["count"] == 2 and out["summary"]["one_way"] == 0 and out["summary"]["rtcp_packets"] == 3
        up = next(s for s in out["streams"] if s["ssrc"] == "0x11111111")
        down = next(s for s in out["streams"] if s["ssrc"] == "0x22222222")
        assert up["call_id"] == down["call_id"] == pcapgen.CALL_ID_VOICE
        assert up["linked_by"] == "sdp_destination" and up["src"] == "198.51.100.9:40000" and up["dst"] == "192.0.2.70:30000"
        assert up["codec"] == "AMR-WB/16000" and up["codec_source"] == "sdp" and up["clock_rate"] == 16000
        assert up["payload_types"] == {"101": 5, "96": 246} and up["telephone_event_packets"] == 5
        assert (up["packets"], up["expected"], up["lost"], up["out_of_order"]) == (251, 254, 3, 1)
        assert up["reverse_ssrc"] == "0x22222222" and down["reverse_ssrc"] == "0x11111111"
        assert down["lost"] == 0 and down["max_jitter_ms"] == 0.0 and down["mean_delta_ms"] == 20.0
        assert any("lost" in i for i in up["issues"]) and "issues" not in down
        # The gateway's report about the uplink: 3 lost, jitter 80 units at 16 kHz, 100 ms round trip.
        assert up["rtcp"]["cumulative_lost_last"] == 3 and up["rtcp"]["jitter_max_ms"] == 5.0
        assert up["rtcp"]["rtt_ms_max"] == pytest.approx(100.0, abs=0.1)
        assert up["mos_estimate"]["estimate"] is True and up["mos_estimate"]["inputs"]["one_way_delay_ms"] == pytest.approx(50.0, abs=0.1)
        assert up["mos_estimate"]["value"] < down["mos_estimate"]["value"]
        assert "Estimate, not a measurement" in out["mos_method"]
        assert out["rtcp_xr"] == [{"frame": out["rtcp_xr"][0]["frame"], "time": out["rtcp_xr"][0]["time"],
                                   "from": "192.0.2.70:30001", "reporter_ssrc": "0x22222222", "r_factor": 88,
                                   "mos_lq": 4.1, "mos_cq": 4.0, "round_trip_ms": 100}]
        roles = [(e["message"], e["role"]) for e in out["calls"][0]["sdp"]]
        assert roles == [("INVITE", "offer"), ("200 INVITE", "answer")]

    def test_matches_tshark_rtp_streams(self, server, pcap_dir):
        for name in ("voice_call.pcap", "voice_problems.pcap"):
            ref = _tshark_rtp_streams(_voice(pcap_dir, name))
            if not ref:
                pytest.skip("could not parse this tshark's rtp,streams output")
            out = server.rtp_streams(_voice(pcap_dir, name))
            mine = {s["ssrc"]: s for s in out["streams"]}
            assert set(mine) == set(ref), name
            for ssrc, r in ref.items():
                s = mine[ssrc]
                assert (s["packets"], s["lost"]) == (r["packets"], r["lost"]), (name, ssrc)
                assert s["max_delta_ms"] == pytest.approx(r["max_delta_ms"], abs=0.01), (name, ssrc)
                assert s["max_jitter_ms"] == pytest.approx(r["max_jitter_ms"], abs=0.01), (name, ssrc)

    def test_nat_one_way_and_call_filter(self, server, pcap_dir):
        out = server.rtp_streams(_voice(pcap_dir, "voice_problems.pcap"))
        by_ssrc = {s["ssrc"]: s for s in out["streams"]}
        assert set(by_ssrc) == {"0x33333333", "0x44444444", "0x55555555"}
        nat_up, nat_down, lone = by_ssrc["0x33333333"], by_ssrc["0x44444444"], by_ssrc["0x55555555"]
        assert nat_up["src"] == "203.0.113.7:61000" and nat_up["call_id"] == pcapgen.CALL_ID_NAT
        assert nat_down["dst"] == "10.0.0.5:40000" and nat_down["reverse_ssrc"] == "0x33333333"
        assert lone["one_way"] is True and lone["call_id"] == pcapgen.CALL_ID_ONEWAY and lone["codec"] == "PCMA/8000"
        one = server.rtp_streams(_voice(pcap_dir, "voice_problems.pcap"), call_id=pcapgen.CALL_ID_NAT)
        assert {s["ssrc"] for s in one["streams"]} == {"0x33333333", "0x44444444"}
        assert "10.0.0.5" in one["display_filter"] and [c["call_id"] for c in one["calls"]] == [pcapgen.CALL_ID_NAT]
        rejected = server.rtp_streams(_voice(pcap_dir, "voice_problems.pcap"), call_id=pcapgen.CALL_ID_488)
        assert rejected["count"] == 0 and rejected["calls"][0]["sdp"][1]["message"] == "488 INVITE"

    def test_ssrc_and_unknown_call(self, server, pcap_dir):
        out = server.rtp_streams(_voice(pcap_dir, "voice_call.pcap"), ssrc="0x22222222")
        assert [s["ssrc"] for s in out["streams"]] == ["0x22222222"]
        assert server.rtp_streams(_voice(pcap_dir, "voice_call.pcap"), ssrc=0x11111111)["count"] == 1
        none = server.rtp_streams(_voice(pcap_dir, "voice_call.pcap"), call_id="nobody@example.invalid")
        assert none["count"] == 0 and "no SDP for this Call-ID" in none["notes"][0]

    def test_heuristic_for_captures_without_sdp(self, server, pcap_dir):
        path = _voice(pcap_dir, "rtp_no_sdp.pcap")
        plain = server.rtp_streams(path)
        assert plain["count"] == 0 and "heuristic=true" in plain["notes"][0]
        out = server.rtp_streams(path, heuristic=True)
        (s,) = out["streams"]
        assert s["codec"] == "PCMU/8000" and s["codec_source"] == "static payload type" and s["packets"] == 50
        assert "not linked to any SDP in the capture" in s["issues"] and s["one_way"] is True
        ref = _tshark_rtp_streams(path, heuristic=True)
        if ref:
            assert ref["0x66666666"]["packets"] == 50

    def test_arguments_are_linted(self, server, pcap_dir):
        path = _voice(pcap_dir, "voice_call.pcap")
        assert server.rtp_streams(path, ssrc="zz")["error"]["type"] == "invalid_argument"
        assert server.rtp_streams(path, ssrc=-1)["error"]["type"] == "invalid_argument"
        assert server.rtp_streams(path, call_id='a"b')["error"]["type"] == "invalid_argument"
        assert server.rtp_streams(path, filter="rtp; rm")["error"]["type"] == "invalid_filter"

    def test_user_filter_and_limits(self, configure, pcap_dir):
        srv = configure(Limits(max_scan_packets=100))
        out = srv.rtp_streams(_voice(pcap_dir, "voice_call.pcap"))
        assert out["truncated"] is True and "frame cap" in out["truncated_reason"]
        srv = configure()
        out = srv.rtp_streams(_voice(pcap_dir, "voice_call.pcap"), filter="udp.srcport == 30000", limit=1)
        assert [s["ssrc"] for s in out["streams"]] == ["0x22222222"]
        first = srv.rtp_streams(_voice(pcap_dir, "voice_call.pcap"), limit=1)
        second = srv.rtp_streams(_voice(pcap_dir, "voice_call.pcap"), limit=1, offset=first["next_offset"])
        assert (first["total_matched"], first["returned"], first["dropped"]) == (2, 1, 1)
        assert {first["streams"][0]["ssrc"], second["streams"][0]["ssrc"]} == {"0x11111111", "0x22222222"}
        assert "next_offset" not in second

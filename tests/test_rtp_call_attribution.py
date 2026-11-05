"""RTP attributed to the right call (public-validation D7), and RTP inside STUN/TURN (D19).

D7: with a Call-ID, rtp_streams and media_path_check read every RTP packet to or from that
call's SDP addresses, which includes the next call when it reuses the offerer's port. Linking
those streams against the call's own SDP only tagged the next call's stream with this Call-ID,
and media_path_check then reported a NAT rewrite and a payload type neither SDP listed. Streams
are now linked against every SDP in the capture, and a call whose BYE came before a stream
started cannot own it.

D19: heuristic RTP enables rtp_stun / rtp_classicstun too, so RTP relayed through TURN (WebRTC)
is found.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

CALL1, CALL2 = "reuse-1@test.invalid", "reuse-2@test.invalid"


def _call(configure, tmp_path: Path, tool: str, path: Path, **kw) -> dict:
    srv = configure(allow=[str(tmp_path)])
    out = getattr(srv, tool)(str(path), **kw)
    assert "error" not in out, out
    return out


def test_streams_of_a_reused_port_go_to_their_own_call(configure, tmp_path):
    cap = g.write_port_reuse_calls_pcap(tmp_path / "reuse.pcap")
    every = _call(configure, tmp_path, "rtp_streams", cap)["streams"]
    assert {(s["ssrc"], s["call_id"]) for s in every} == {("0x0a0a0001", CALL1), ("0x0a0a0002", CALL2)}
    one = _call(configure, tmp_path, "rtp_streams", cap, call_id=CALL1)["streams"]
    assert [s["ssrc"] for s in one] == ["0x0a0a0001"]
    two = _call(configure, tmp_path, "rtp_streams", cap, call_id=CALL2)["streams"]
    assert [s["ssrc"] for s in two] == ["0x0a0a0002"]


def test_media_path_check_sees_no_nat_from_the_next_call(configure, tmp_path):
    cap = g.write_port_reuse_calls_pcap(tmp_path / "reuse.pcap")
    out = _call(configure, tmp_path, "media_path_check", cap, call_id=CALL1)
    kinds = {i["kind"] for i in out["issues"]}
    assert not kinds & {"source_differs_from_sdp", "payload_type_not_negotiated", "nat_not_latched"}, out["issues"]


def test_a_stream_after_the_bye_is_not_the_call_even_without_the_next_calls_sdp(configure, tmp_path):
    cap = g.write_port_reuse_calls_pcap(tmp_path / "reuse.pcap", second_signalled=False)
    one = _call(configure, tmp_path, "rtp_streams", cap, call_id=CALL1)["streams"]
    assert [s["ssrc"] for s in one] == ["0x0a0a0001"]
    out = _call(configure, tmp_path, "media_path_check", cap, call_id=CALL1)
    assert not {i["kind"] for i in out["issues"]} & {"source_differs_from_sdp", "payload_type_not_negotiated"}


def test_heuristic_rtp_inside_turn(configure, tmp_path):
    cap = g.write_rtp_over_stun_pcap(tmp_path / "turn.pcap")
    out = _call(configure, tmp_path, "rtp_streams", cap, heuristic=True)
    assert [(s["ssrc"], s["packets"]) for s in out["streams"]] == [("0x0b0b0001", 20)]


def test_attribution_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = g.write_port_reuse_calls_pcap(tmp_path / "reuse.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("rtp_streams", {"path": str(cap), "call_id": CALL1})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    out = asyncio.run(go())
    assert [s["ssrc"] for s in out["streams"]] == ["0x0a0a0001"]

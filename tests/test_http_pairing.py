"""http_transactions pairing and time to first byte (public-validation D9a, D9b, D9c, D11).

D9a: a response tshark cannot reassemble in one pass never gets ``http.response``, so its
request was "unanswered". A second pass with TCP reassembly off reads the status line from the
response's first segment.
D9b: a response without ``http.request_in`` answers the oldest open request on its connection.
D9c: an HTTP/2 header block whose HPACK count includes a dynamic table size update was dropped.
D11: ``response_ms`` runs to the LAST segment of a response, so a large body read slowly looked
like a slow server; ``ttfb_ms`` is the time to the first segment and drives the slow issue.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from pydantic import TypeAdapter

from tshark_mcp import httptx, models

from .conftest import requires_tshark
from .test_http_transactions import req
from .test_response_times import Capture
from .test_response_times_http2 import END_HEADERS, HEADERS, block, data, frame, request, start

pytestmark = requires_tshark

WEB, BULK, H2 = "203.0.113.110", "203.0.113.111", "203.0.113.112"


def split_response(path: Path) -> Path:
    """An HTTP/1.0 response with no Content-Length (the body runs to the close), its header split over
    three segments and no FIN in the capture: tshark waits for the end of the body and never shows the
    response. The capture goes on 10 s after it on another connection."""
    cap = Capture()
    c = cap.conn(WEB, sport=80).open()
    c.send("c", payload=req("GET", "/page", host="www.example.com"), dt=0.001)
    c.send("s", payload=b"HTTP/1.0 200 OK\r\n", dt=0.030)
    c.send("s", payload=b"Content-Type: text/html\r\n", dt=0.001)
    c.send("s", payload=b"\r\n<html>", dt=0.001)
    other = cap.conn(BULK, sport=80).open()
    other.send("c", flags="A", dt=10.0)
    return cap.write(path)


def slow_transfer(path: Path) -> Path:
    """The server answers in 50 ms, then the 6,000-byte body trickles in over 3 s (a slow reader)."""
    cap = Capture()
    c = cap.conn(BULK, sport=80).open()
    c.send("c", payload=req("GET", "/report", host="files.example.com"), dt=0.001)
    body = b"x" * 6000
    head = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    whole = head + body
    c.send("s", payload=whole[:1000], dt=0.050)
    for i in range(1000, len(whole), 1000):
        c.send("s", payload=whole[i:i + 1000], dt=0.600)
    c.send("c", flags="A", dt=0.001)
    return cap.write(path)


def h2_table_size_update(path: Path) -> Path:
    """An h2c response whose header block starts with an HPACK dynamic table size update (RFC 7541 6.3)."""
    cap = Capture()
    c = start(cap, H2)
    c.send("c", payload=request(1, "/index"), dt=0.001)
    resize = b"\x3f\xe1\x1f"  # size update to 4096
    c.send("s", payload=frame(HEADERS, END_HEADERS, 1, resize + block((":status", "200"), ("content-type", "text/html")))
           + data(1, 30), dt=0.040)
    return cap.write(path)


def _run(configure, tmp_path: Path, path: Path, **kw) -> dict:
    srv = configure(allow=[str(tmp_path)])
    out = srv.http_transactions(str(path), **kw)
    assert "error" not in out, out
    TypeAdapter(models.HttpTransactionsResult).validate_python(out)
    return out


def test_unreassembled_response_is_read_from_its_first_segment(configure, tmp_path):
    out = _run(configure, tmp_path, split_response(tmp_path / "split.pcap"))
    [row] = out["requests"]
    assert row["status"] == 200 and row["reason"] == "OK" and "unanswered" not in row
    assert row["response_decoded_from"] == "first_segment"
    assert row["ttfb_ms"] > 0
    assert out["summary"]["unanswered"] == 0 and out["summary"]["responses_from_first_segment"] == 1
    assert not any("no response" in i for i in out["summary"]["issues"])


def test_slow_transfer_is_not_a_slow_server(configure, tmp_path):
    out = _run(configure, tmp_path, slow_transfer(tmp_path / "slow.pcap"))
    [row] = out["requests"]
    assert row["response_ms"] > 2900 and 40 <= row["ttfb_ms"] <= 60
    issues = out["summary"]["issues"]
    assert any(i.startswith("p99 transfer") and "first byte came within" in i for i in issues), issues
    assert not any(i.startswith("p99 response") for i in issues)
    srv_out = _run(configure, tmp_path, tmp_path / "slow.pcap", view="endpoints")
    assert srv_out["endpoints"][0]["ttfb_ms"]["p99"] < 100


def test_incident_summary_does_not_call_a_slow_transfer_a_slow_server(configure, tmp_path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.incident_summary(str(slow_transfer(tmp_path / "slow.pcap")))
    assert "http_slow" not in {f["kind"] for f in out["findings"]}


def test_http2_header_block_with_table_size_update(configure, tmp_path):
    out = _run(configure, tmp_path, h2_table_size_update(tmp_path / "h2.pcap"))
    [row] = out["requests"]
    assert row["status"] == 200 and row["content_type"] == "text/html" and "unanswered" not in row


def _line(values: dict[str, str]) -> str:
    return "\t".join(values.get(f, "") for f in httptx.FIELDS)


def test_response_without_request_in_answers_the_oldest_open_request():
    base = {"frame.protocols": "eth:ethertype:ip:tcp:http", "ip.id": "0x0001", "ip.len": "200", "ip.ttl": "64",
            "tcp.stream": "0", "tcp.seq_raw": "1", "tcp.ack_raw": "1", "tcp.flags": "0x018", "tcp.checksum": "0x1"}
    c2s = {**base, "ip.src": "192.0.2.1", "ip.dst": "192.0.2.2", "tcp.srcport": "40000", "tcp.dstport": "80"}
    s2c = {**base, "ip.src": "192.0.2.2", "ip.dst": "192.0.2.1", "tcp.srcport": "80", "tcp.dstport": "40000"}
    lines = [
        _line({**c2s, "frame.number": "1", "frame.time_epoch": "100.0", "ip.id": "0x0001", "tcp.seq_raw": "1",
               "http.request.method": "GET", "http.request.uri": "/a", "http.host": "h"}),
        _line({**c2s, "frame.number": "2", "frame.time_epoch": "100.1", "ip.id": "0x0002", "tcp.seq_raw": "50",
               "http.request.method": "GET", "http.request.uri": "/b", "http.host": "h"}),
        # Answers /a but tshark linked no request (a malformed header).
        _line({**s2c, "frame.number": "3", "frame.time_epoch": "100.3", "ip.id": "0x0101", "tcp.seq_raw": "1",
               "http.response.code": "206", "http.response.phrase": "Partial Content"}),
        _line({**s2c, "frame.number": "4", "frame.time_epoch": "100.4", "ip.id": "0x0102", "tcp.seq_raw": "90",
               "http.response.code": "200", "http.response.phrase": "OK", "http.request_in": "2", "http.time": "0.3"}),
    ]
    rows, _ = httptx.analyse(httptx.parse("\n".join(lines)))
    by_uri = {r["uri"]: r for r in rows}
    assert by_uri["/a"]["status"] == 206 and by_uri["/a"]["paired_by"] == "stream_order"
    assert by_uri["/a"]["response_frame"] == 3
    assert by_uri["/b"]["status"] == 200 and by_uri["/b"].get("paired_by") is None


def test_first_segment_pass_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = split_response(tmp_path / "split.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("http_transactions", {"path": str(cap)})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    out = asyncio.run(go())
    assert out["requests"][0]["status"] == 200 and out["summary"]["unanswered"] == 0



def test_only_the_reassembly_off_preference_is_allowed():
    import pytest

    from tshark_mcp.limits import ToolError
    from tshark_mcp.runner import assert_read_only

    assert_read_only(["-r", "x.pcap", "-o", "tcp.desegment_tcp_streams:FALSE"])
    for pref in ("tcp.desegment_tcp_streams:TRUE", "http.desegment_body:FALSE", "uat:user_dlts:x"):
        with pytest.raises(ToolError):
            assert_read_only(["-r", "x.pcap", "-o", pref])

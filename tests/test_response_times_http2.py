"""response_times on HTTP/2 (cleartext h2c) and gRPC: one exchange per HTTP/2 stream, on synthetic captures.

Frames are built by hand from RFC 9113; header blocks use HPACK literals without indexing (RFC 7541 6.2.2)
so tshark decodes them without any earlier dynamic-table state.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from .conftest import requires_tshark
from .test_response_times import Capture

pytestmark = requires_tshark

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, RST_STREAM, SETTINGS, PUSH_PROMISE = 0, 1, 3, 4, 5
END_STREAM, END_HEADERS, ACK = 0x1, 0x4, 0x1


def frame(ftype: int, flags: int, stream: int, body: bytes = b"") -> bytes:
    return struct.pack("!I", len(body))[1:] + bytes([ftype, flags]) + struct.pack("!I", stream) + body


def block(*pairs: tuple[str, str]) -> bytes:
    out = b""
    for name, value in pairs:
        n, v = name.encode(), value.encode()
        out += b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v
    return out


def request(stream: int, path: str, method: str = "GET", end: bool = True, extra=()) -> bytes:
    hdr = block((":method", method), (":scheme", "http"), (":path", path), (":authority", "www.example.com"), *extra)
    return frame(HEADERS, END_HEADERS | (END_STREAM if end else 0), stream, hdr)


def status(stream: int, code: str, end: bool = False, extra=()) -> bytes:
    return frame(HEADERS, END_HEADERS | (END_STREAM if end else 0), stream, block((":status", code), *extra))


def data(stream: int, n: int, end: bool = True) -> bytes:
    return frame(DATA, END_STREAM if end else 0, stream, b"d" * n)


def start(cap: Capture, server: str, port: int = 80):
    c = cap.conn(server, sport=port).open()
    c.send("c", payload=PREFACE + frame(SETTINGS, 0, 0), dt=0.001)
    c.send("s", payload=frame(SETTINGS, 0, 0) + frame(SETTINGS, ACK, 0), dt=0.020)
    c.send("c", payload=frame(SETTINGS, ACK, 0), dt=0.001)
    return c


def h2_capture(path: Path) -> Path:
    cap = Capture()
    # Two requests in one segment; the server answers the second after 30 ms and the first after 430 ms.
    c = start(cap, "203.0.113.60")
    c.send("c", payload=request(1, "/slow") + request(3, "/fast"), dt=0.001)
    c.send("s", payload=status(3, "200") + data(3, 100), dt=0.050)
    c.send("s", payload=status(1, "404") + data(1, 50), dt=0.400)
    # A 3000-byte DATA frame over three TCP segments (tshark shows it in the last one), then a request
    # the server refuses with RST_STREAM, and a pushed stream.
    c = start(cap, "203.0.113.61")
    c.send("c", payload=request(1, "/big"), dt=0.001)
    body = status(1, "200") + data(1, 3000)
    c.send("s", payload=body[:1200], dt=0.120)
    c.send("s", payload=body[1200:2400], dt=0.010)
    c.send("s", payload=body[2400:], dt=0.010)
    c.send("c", payload=request(3, "/refused"), dt=0.005)
    c.send("s", payload=frame(RST_STREAM, 0, 3, struct.pack("!I", 7)), dt=0.021)
    c.send("c", payload=request(5, "/page"), dt=0.005)
    c.send("s", payload=frame(PUSH_PROMISE, END_HEADERS, 5, struct.pack("!I", 2) + block(
        (":method", "GET"), (":scheme", "http"), (":path", "/style.css"), (":authority", "www.example.com")))
        + status(5, "200") + data(5, 40) + status(2, "200") + data(2, 60), dt=0.025)
    return cap.write(path)


def grpc_capture(path: Path) -> Path:
    cap = Capture()
    # 8080 is one of tshark's HTTP ports; on 50051 tshark before 4.4 does not find HTTP/2 by itself.
    c = start(cap, "203.0.113.70", port=8080)
    ct = (("content-type", "application/grpc"), ("te", "trailers"))
    msg = b"\x00" + struct.pack("!I", 7) + b"\x0a\x05hello"
    c.send("c", payload=request(1, "/example.v1.Greeter/SayHello", "POST", end=False, extra=ct)
           + frame(DATA, END_STREAM, 1, msg)
           + request(3, "/example.v1.Greeter/SayHello", "POST", end=False, extra=ct)
           + frame(DATA, END_STREAM, 3, msg), dt=0.001)
    c.send("s", payload=status(3, "200", extra=(("content-type", "application/grpc"),))
           + frame(HEADERS, END_HEADERS | END_STREAM, 3, block(("grpc-status", "14"), ("grpc-message", "unavailable"))),
           dt=0.025)
    c.send("s", payload=status(1, "200", extra=(("content-type", "application/grpc"),)) + frame(DATA, 0, 1, msg)
           + frame(HEADERS, END_HEADERS | END_STREAM, 1, block(("grpc-status", "0"))), dt=0.300)
    return cap.write(path)


def upgrade_capture(path: Path) -> Path:
    cap = Capture()
    c = cap.conn("203.0.113.80", sport=80).open()
    c.send("c", payload=b"GET /up HTTP/1.1\r\nHost: www.example.com\r\nConnection: Upgrade, HTTP2-Settings\r\n"
           b"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n", dt=0.001)
    c.send("s", payload=b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n", dt=0.021)
    c.send("c", payload=PREFACE + frame(SETTINGS, 0, 0), dt=0.001)
    c.send("s", payload=frame(SETTINGS, 0, 0) + status(1, "200") + data(1, 20), dt=0.100)
    return cap.write(path)


def _exchanges(flow):
    return {x["h2_stream"]: x for x in flow["slowest_exchanges"]}


def test_each_http2_stream_is_its_own_exchange(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(h2_capture(tmp_path / "h2.pcap")))
    f = next(f for f in out["flows"] if f["server"] == "203.0.113.60:80")
    assert f["http2"] is True and f["exchanges"] == 2 and f["verdict"] == "server-bound"
    x = _exchanges(f)
    assert x[1]["method"] == "GET" and x[1]["uri"] == "/slow" and x[1]["host"] == "www.example.com"
    assert x[1]["status"] == 404 and x[1]["think_ms"] == 450.0 and x[1]["server_ms"] == 430.0
    assert x[3]["uri"] == "/fast" and x[3]["status"] == 200 and x[3]["think_ms"] == 50.0 and x[3]["server_ms"] == 30.0
    # Bytes are the HTTP/2 frames of that stream only: HEADERS 9 + 13, DATA 9 + 100.
    assert x[3]["response_bytes"] == 131
    assert f["max_server_ms"] == 430.0


def test_frame_over_several_segments_reset_stream_and_push(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(h2_capture(tmp_path / "h2.pcap")))
    f = next(f for f in out["flows"] if f["server"] == "203.0.113.61:80")
    assert f["exchanges"] == 3 and f["server_pushes"] == 1 and f["unanswered_requests"] == 1
    x = _exchanges(f)
    # The response starts at the first of the three segments, not where tshark completed the frame.
    assert x[1]["think_ms"] == pytest.approx(120.0, abs=0.01) and x[1]["transfer_ms"] == pytest.approx(20.0, abs=0.01)
    assert x[1]["response_bytes"] == 22 + 3009
    assert x[3]["no_response"] is True and x[3]["stream_reset_by"] == "server" and x[3]["uri"] == "/refused"
    assert x[5]["status"] == 200 and x[5]["response_bytes"] == 22 + 49  # not the pushed stream 2 (nor the PUSH_PROMISE)


def test_grpc_calls_on_one_connection_are_timed_apart(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(grpc_capture(tmp_path / "grpc.pcap")))
    f = out["flows"][0]
    assert f["http2"] is True and f["exchanges"] == 2
    x = _exchanges(f)
    assert x[1]["method"] == "POST" and x[1]["uri"] == "/example.v1.Greeter/SayHello"
    assert x[1]["grpc_status"] == 0 and x[1]["think_ms"] == 325.0
    assert x[3]["grpc_status"] == 14 and x[3]["think_ms"] == 25.0 and x[3]["server_ms"] == 5.0


def test_h2c_upgrade_request_is_stream_1(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(upgrade_capture(tmp_path / "up.pcap")))
    f = out["flows"][0]
    assert f["http2"] is True and f["exchanges"] == 1
    x = f["slowest_exchanges"][0]
    assert x["h2_stream"] == 1 and x["method"] == "GET" and x["uri"] == "/up" and x["status"] == 200
    # Answered on stream 1 after the 101: from the request to the first HTTP/2 response byte.
    assert x["think_ms"] == 122.0


def test_http1_connections_are_not_marked_http2(configure, tmp_path: Path):
    from .test_response_times import build
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(build(tmp_path / "rt.pcap")))
    assert all("http2" not in f for f in out["flows"])
    assert all("h2_stream" not in x for f in out["flows"] for x in f["slowest_exchanges"])


def test_http2_results_match_the_output_schema(configure, tmp_path: Path):
    from pydantic import TypeAdapter

    from tshark_mcp import models
    srv = configure(allow=[str(tmp_path)])
    for out in (srv.response_times(str(h2_capture(tmp_path / "h2.pcap"))),
                srv.response_times(str(grpc_capture(tmp_path / "grpc.pcap")))):
        assert "error" not in out
        TypeAdapter(models.ResponseTimesResult).validate_python(out)

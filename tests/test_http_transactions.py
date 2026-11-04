"""http_transactions: HTTP/1.x pairs, HTTP/2 and gRPC streams, endpoints, on synthetic captures."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from tshark_mcp import models

from .conftest import TSHARK, requires_tshark
from .test_response_times import Capture
from .test_response_times_http2 import grpc_capture, h2_capture

pytestmark = requires_tshark

API, SEARCH, ODD = "203.0.113.10", "203.0.113.20", "203.0.113.30"
ODD_PORT = 9123


def req(method: str, uri: str, host: str = "api.example.com", body: bytes = b"") -> bytes:
    head = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n"
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    return head.encode() + b"\r\n" + body


def resp(code: int, reason: str, body: bytes = b"", ctype: str = "application/json", chunked: bool = False) -> bytes:
    head = f"HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\n"
    if chunked:
        head += "Transfer-Encoding: chunked\r\n\r\n"
        return head.encode() + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    head += f"Content-Length: {len(body)}\r\n\r\n"
    return head.encode() + body


def http1_capture(path: Path) -> Path:
    cap = Capture()
    c = cap.conn(API, sport=80).open()
    c.send("c", payload=req("GET", "/api/orders/123?token=abc&page=2"), dt=0.001, copy=True)
    c.send("s", payload=resp(200, "OK", b"o" * 700), dt=0.040)
    for i in range(3):
        c.send("c", payload=req("POST", "/api/orders", body=b'{"x":1}'), dt=0.010)
        c.send("s", payload=resp(500, "Internal Server Error", b"e" * 20), dt=0.030)
    c.send("c", payload=req("POST", "/api/orders", body=b'{"x":2}'), dt=0.010)
    c.send("s", payload=resp(201, "Created", b"c" * 10), dt=0.030)
    c.send("c", payload=req("GET", "/api/orders/456"), dt=0.010)
    c.send("s", payload=resp(404, "Not Found", b"n"), dt=0.020)
    c.send("c", payload=req("GET", "/api/stream"), dt=0.010)
    c.send("s", payload=resp(200, "OK", b"s" * 300, ctype="text/plain", chunked=True), dt=0.020)
    s = cap.conn(SEARCH, sport=8080).open()
    s.send("c", payload=req("GET", "/search?q=x", host="search.example.com"), dt=0.001)
    s.send("s", payload=resp(200, "OK", b"r" * 50), dt=2.000)
    s.send("c", payload=req("GET", "/hang", host="search.example.com"), dt=0.010)
    # The capture goes on 10 s after /hang, then one last request near the end.
    c.send("c", payload=req("GET", "/late"), dt=10.0)
    c.send("c", flags="A", dt=1.0)
    return cap.write(path)


def run(configure, tmp_path: Path, build=http1_capture, name="http.pcap", **kw):
    srv = configure(allow=[str(tmp_path)])
    out = srv.http_transactions(str(build(tmp_path / name)), **kw)
    assert "error" not in out, out
    TypeAdapter(models.HttpTransactionsResult).validate_python(out)
    return out


def by_uri(out):
    rows: dict[str, list[dict]] = {}
    for r in out["requests"]:
        rows.setdefault(r["uri"], []).append(r)
    return rows


def test_http1_pairs(configure, tmp_path):
    out = run(configure, tmp_path)
    rows = by_uri(out)
    first = rows["/api/orders/123"][0]
    assert first["method"] == "GET" and first["host"] == "api.example.com" and first["query"] == "token=abc&page=2"
    assert first["status"] == 200 and first["reason"] == "OK" and first["response_bytes"] == 700
    assert first["content_type"] == "application/json" and first["response_ms"] == pytest.approx(40.0, abs=0.01)
    assert first["server"] == f"{API}:80" and first["version"] == "HTTP/1.1"
    assert [r["status"] for r in rows["/api/orders"]] == [500, 500, 500, 201]
    assert rows["/api/orders"][0]["request_bytes"] == 7
    assert rows["/api/stream"][0]["status"] == 200 and rows["/api/stream"][0]["content_type"] == "text/plain"
    assert rows["/search"][0]["response_ms"] == pytest.approx(2000.0, abs=0.01)
    hang = rows["/hang"][0]
    assert hang["unanswered"] is True and "near_capture_end" not in hang
    late = rows["/late"][0]
    assert late["unanswered"] is True and late["near_capture_end"] is True
    s = out["summary"]
    # The copied request is not dissected as HTTP again (tshark sees a retransmission), so it is not
    # a second request either way.
    assert len(rows["/api/orders/123"]) == 1 and s["status_mix"] == {"2xx": 4, "4xx": 1, "5xx": 3}
    assert s["unanswered"] == 2 and s["unanswered_near_capture_end"] == 1


def test_counts_match_raw_tshark(configure, tmp_path):
    out = run(configure, tmp_path)
    pcap = str(tmp_path / "http.pcap")

    def count(flt: str) -> int:
        return len(subprocess.run([TSHARK, "-n", "-r", pcap, "-Y", flt, "-T", "fields", "-e", "frame.number"],
                                  capture_output=True, text=True, check=True).stdout.split())
    assert len(out["requests"]) == count("http.request") - out["summary"]["copies_dropped"]
    assert out["summary"]["answered"] == count("http.response")


def test_endpoints_and_issues(configure, tmp_path):
    out = run(configure, tmp_path, view="endpoints")
    eps = {(e["method"], e["uri"]): e for e in out["endpoints"]}
    orders = eps[("POST", "/api/orders")]
    assert orders["count"] == 4 and orders["status"] == {"2xx": 1, "5xx": 3}
    # Numeric ids are collapsed into one endpoint.
    ids = eps[("GET", "/api/orders/{id}")]
    assert ids["count"] == 2 and ids["status"] == {"2xx": 1, "4xx": 1}
    assert eps[("GET", "/search")]["response_ms"]["p99"] == pytest.approx(2000.0, abs=0.01)
    text = " | ".join(out["summary"]["issues"])
    assert "75% of POST api.example.com/api/orders answered 5xx (3 of 4)" in text
    assert "p99 response 2.0 s on GET search.example.com/search" in text


def test_selectors(configure, tmp_path):
    srv = configure(allow=[str(tmp_path)])
    path = str(http1_capture(tmp_path / "http.pcap"))
    assert {r["status"] for r in srv.http_transactions(path, status="5xx")["requests"]} == {500}
    assert [r["uri"] for r in srv.http_transactions(path, status=404)["requests"]] == ["/api/orders/456"]
    assert {r["host"] for r in srv.http_transactions(path, host="example.com")["requests"]} == {
        "api.example.com", "search.example.com"}
    assert [r["uri"] for r in srv.http_transactions(path, host="search.example.com", min_ms=1000)["requests"]] == ["/search"]
    assert {r["method"] for r in srv.http_transactions(path, method="post")["requests"]} == {"POST"}
    assert len(srv.http_transactions(path, path_prefix="/api/orders/")["requests"]) == 2
    page = srv.http_transactions(path, limit=3)
    assert page["returned"] == 3 and page["next_offset"] == 3


@pytest.mark.parametrize("kw,needle", [
    ({"status": "6xx"}, "status"), ({"method": "GET /x"}, "method"), ({"path_prefix": "api"}, "path_prefix"),
    ({"min_ms": "slow"}, "min_ms"), ({"view": "x"}, "view"), ({"host": "a b"}, "host"),
])
def test_bad_arguments(configure, tmp_path, kw, needle):
    srv = configure(allow=[str(tmp_path)])
    out = srv.http_transactions(str(http1_capture(tmp_path / "http.pcap")), **kw)
    assert out["error"]["type"] == "invalid_argument" and needle in out["error"]["message"]


def test_http2_streams(configure, tmp_path):
    out = run(configure, tmp_path, build=h2_capture, name="h2.pcap")
    rows = {(r["server"], r["h2_stream"]): r for r in out["requests"]}
    slow = rows[("203.0.113.60:80", 1)]
    assert slow["uri"] == "/slow" and slow["status"] == 404 and slow["host"] == "www.example.com"
    assert slow["ttfb_ms"] == pytest.approx(450.0, abs=0.01) and slow["response_bytes"] == 50
    fast = rows[("203.0.113.60:80", 3)]
    assert fast["ttfb_ms"] == pytest.approx(50.0, abs=0.01) and fast["response_bytes"] == 100
    big = rows[("203.0.113.61:80", 1)]
    assert big["response_bytes"] == 3000
    refused = rows[("203.0.113.61:80", 3)]
    assert refused["stream_reset_by"] == "server" and refused["reset_error"] == "REFUSED_STREAM"
    assert "unanswered" not in refused
    assert out["summary"]["h2_connections"] == 2
    assert any("reset by the server with REFUSED_STREAM" in i for i in out["summary"]["issues"])


def test_grpc(configure, tmp_path):
    out = run(configure, tmp_path, build=grpc_capture, name="grpc.pcap")
    rows = {r["h2_stream"]: r for r in out["requests"]}
    assert rows[1]["grpc"] is True and rows[1]["grpc_status"] == 0 and rows[1]["grpc_status_name"] == "OK"
    assert rows[3]["grpc_status"] == 14 and rows[3]["grpc_status_name"] == "UNAVAILABLE"
    assert rows[1]["response_ms"] == pytest.approx(325.0, abs=0.01)
    assert out["summary"]["grpc_calls"] == 2
    assert any("returned UNAVAILABLE 1 time" in i for i in out["summary"]["issues"])


def odd_port_capture(path: Path) -> Path:
    cap = Capture()
    o = cap.conn(ODD, sport=ODD_PORT).open()
    o.send("c", payload=req("GET", "/odd", host="odd.example.com"), dt=0.001)
    o.send("s", payload=resp(200, "OK", b"z"), dt=0.010)
    return cap.write(path)


def test_http_on_an_odd_port_is_never_lost_silently(configure, tmp_path):
    # tshark's "HTTP over TCP" heuristic finds it on most versions; when it does not, the
    # second pass must name the port.
    out = run(configure, tmp_path, build=odd_port_capture, name="odd.pcap")
    dissected = any(r["uri"] == "/odd" for r in out["requests"])
    named = any(u["server"] == f"{ODD}:{ODD_PORT}" for u in out.get("undissected_http", []))
    assert dissected != named, out


def test_undissected_parser():
    from tshark_mcp import httptx
    stdout = "7\t3\t203.0.113.30\t\t9123\t80\n9\t3\t203.0.113.30\t\t9123\t80\n11\t4\t\t2001:db8::1\t50051\t24\n"
    out = httptx.undissected(stdout, {4})
    assert out == [{"server": "203.0.113.30:9123", "frames": 2, "first_frame": 7, "kind": "HTTP"}]
    assert "PRI * HTTP/2.0" not in httptx.UNDISSECTED_FILTER and "50:52:49" in httptx.UNDISSECTED_FILTER

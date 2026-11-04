"""http_transactions: HTTP/1.x requests paired with responses, and HTTP/2 / gRPC streams.

HTTP/1.x pairs come from tshark itself (a response's ``http.request_in`` names its
request frame), so pipelining and several messages per segment are handled the way
Wireshark does. Each pair gets the method, host, path (the query string is cut off
and kept apart, capped), status and reason, Content-Type and Content-Length, and
``response_ms``: tshark's ``http.time``, from the request to the frame that completed
the response (the last segment of a reassembled body).

HTTP/2 (cleartext h2c, or TLS with keys) is followed per stream from the frames
tshark dissects: the request HEADERS (:method, :path, :authority), the response
HEADERS (:status), DATA bytes each way, trailers with ``grpc-status``, END_STREAM and
RST_STREAM. ``ttfb_ms`` is request HEADERS to response HEADERS and ``response_ms``
request HEADERS to the server's END_STREAM.

Copies of the same packet are dropped first with the key ``capture_quality`` uses.

tshark dissects HTTP/1.x on its HTTP ports (80, 8080, 3128 and the rest of its
``http.tcp.port`` range) and by heuristics; HTTP/2 in clear only on those ports with
tshark 4.2, on any port from 4.4.0. Traffic on another port stays raw TCP: a second
bounded pass finds TCP payloads that start with an HTTP method or the HTTP/2 preface
on streams tshark left undissected and names the server ports in
``undissected_http``. Decode As is not offered yet, so for those ports use
``response_times`` (timing without HTTP labels) or ``filter_packets``.
"""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from typing import Any, Callable

from .copies import CopyTracker, copy_key, has_ip_id
from .fields import compact, split_fields_line, to_float, to_int
from .packets import record
from .timing import H2_DATA, H2_HEADERS, H2_RST_STREAM, _h2_frames

AGGREGATOR = "|"
FIELDS = [
    "frame.number", "frame.time_epoch", "frame.protocols",
    "ip.src", "ip.dst", "ip.id", "ip.len", "ip.ttl", "ipv6.src", "ipv6.dst", "ipv6.plen", "ipv6.hlim",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags", "tcp.checksum",
    "http.request.method", "http.request.uri", "http.request.version", "http.host", "http.response.code",
    "http.response.phrase", "http.response.version", "http.time", "http.request_in", "http.content_length",
    "http.content_type",
    "http2.streamid", "http2.type", "http2.length", "http2.flags.end_stream", "http2.header.count",
    "http2.header.name", "http2.header.value", "http2.rst_stream.error",
]
BASE_FILTER = "http || http2"

_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ", "OPTIONS ", "CONNECT ")
H2_PREFACE = "PRI * HTTP/2.0"


def _hex(text: str) -> str:
    return ":".join(f"{b:02x}" for b in text.encode())


UNDISSECTED_FILTER = "tcp.len > 0 && !http && !http2 && (" + " || ".join(
    f"tcp.payload[0:{len(t)}] == {_hex(t)}" for t in (*_METHODS, H2_PREFACE)) + ")"
UNDISSECTED_FIELDS = ["frame.number", "tcp.stream", "ip.dst", "ipv6.dst", "tcp.dstport", "tcp.len"]

GRPC_STATUS = {
    0: "OK", 1: "CANCELLED", 2: "UNKNOWN", 3: "INVALID_ARGUMENT", 4: "DEADLINE_EXCEEDED", 5: "NOT_FOUND",
    6: "ALREADY_EXISTS", 7: "PERMISSION_DENIED", 8: "RESOURCE_EXHAUSTED", 9: "FAILED_PRECONDITION", 10: "ABORTED",
    11: "OUT_OF_RANGE", 12: "UNIMPLEMENTED", 13: "INTERNAL", 14: "UNAVAILABLE", 15: "DATA_LOSS", 16: "UNAUTHENTICATED",
}  # gRPC status codes (grpc/doc/statuscodes.md)
H2_ERRORS = {
    0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT",
    5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL", 9: "COMPRESSION_ERROR",
    10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED",
}  # RFC 9113 section 7
QUERY_CAP = 128
NEAR_END_S = 5.0
SLOW_P99_MS = 1000.0
ERROR_SHARE = 0.05
COPY_WINDOW_S = 1.0
_ID = re.compile(r"(?<=/)(?:[0-9]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                 r"|[0-9a-fA-F]{16,})(?=/|$)")


def _nth(values: list[str], n: int) -> str:
    return values[n] if 0 <= n < len(values) else ""


def _side(ip: str, port: str) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def normalise(path: str) -> str:
    """The path with numeric ids, UUIDs and long hex tokens collapsed to ``{id}``."""
    return _ID.sub("{id}", path)


def _split_uri(uri: str) -> tuple[str, str | None]:
    path, sep, query = uri.partition("?")
    if not sep:
        return uri, None
    return path, query[:QUERY_CAP] + ("..." if len(query) > QUERY_CAP else "")


def parse(stdout: str) -> list[tuple[dict[str, Any], dict[str, list[str]]]]:
    out = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        raw = {k: (v.split(AGGREGATOR) if v else []) for k, v in zip(FIELDS, cols)}
        out.append((record(raw), raw))
    return out


class _H2:
    def __init__(self, conn: str, sid: int, rec: dict[str, Any]) -> None:
        self.conn, self.sid = conn, sid
        self.client: tuple | None = None
        self.server: tuple | None = None
        self.start = self.start_frame = None
        self.method = self.path = self.authority = None
        self.status = self.status_time = self.status_frame = None
        self.content_type = None
        self.grpc = None
        self.end_time = None
        self.req_bytes = self.resp_bytes = 0
        self.rst_by = None
        self.rst_error = None
        self.stream = rec["tcp"].get("stream")


def analyse(packets: list[tuple[dict[str, Any], dict[str, list[str]]]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    tracker = CopyTracker(id_window=COPY_WINDOW_S)
    requests: list[dict[str, Any]] = []
    by_frame: dict[int, list[dict[str, Any]]] = defaultdict(list)
    h2: dict[tuple, _H2] = {}
    h2_order: list[_H2] = []
    h2_conns: set = set()
    copies = 0
    for rec, raw in packets:
        tcp = rec.get("tcp")
        if not tcp or not rec.get("src"):
            continue
        has_id = has_ip_id(rec)
        if tracker.check(copy_key(rec, has_id), has_id, rec["time"])[0]:
            copies += 1
            continue
        src, dst = (rec["src"], tcp["sport"]), (rec["dst"], tcp["dport"])
        _http1(rec, raw, src, dst, requests, by_frame)
        frames = _h2_frames(raw)
        if frames:
            h2_conns.add(tcp.get("stream"))
            _http2(rec, raw, frames, src, dst, h2, h2_order)
    rows = [_h1_row(r) for r in requests] + [_h2_row(s) for s in h2_order if s.start is not None]
    rows.sort(key=lambda r: r.get("frame") or 0)
    stats = {"copies_dropped": copies, "h2_connections": len(h2_conns),
             "h2_streams_without_request": sum(1 for s in h2_order if s.start is None) or None}
    return rows, stats


def _http1(rec: dict[str, Any], raw: dict[str, list[str]], src: tuple, dst: tuple,
           requests: list[dict[str, Any]], by_frame: dict[int, list[dict[str, Any]]]) -> None:
    methods = raw.get("http.request.method") or []
    uris = raw.get("http.request.uri") or []
    hosts = raw.get("http.host") or []
    versions = raw.get("http.request.version") or []
    lengths = raw.get("http.content_length") or []
    ctypes = raw.get("http.content_type") or []
    codes = raw.get("http.response.code") or []
    aligned = len(hosts) == len(methods)
    for i, method in enumerate(methods):
        req = {"frame": rec["frame"], "time": rec["time"], "stream": rec["tcp"].get("stream"),
               "client": _side(*src), "server": _side(*dst), "method": method, "uri": _nth(uris, i),
               "host": _nth(hosts, i) if aligned else (hosts[0] if len(hosts) == 1 and len(methods) == 1 else None),
               "version": _nth(versions, i) or None,
               "request_bytes": to_int(_nth(lengths, i)) if not codes and len(lengths) == len(methods) else None}
        requests.append(req)
        by_frame[rec["frame"]].append(req)
    if not codes:
        return
    req_in = raw.get("http.request_in") or []
    phrases = raw.get("http.response.phrase") or []
    times = raw.get("http.time") or []
    rversions = raw.get("http.response.version") or []
    for i, code in enumerate(codes):
        target = to_int(_nth(req_in, i)) if len(req_in) == len(codes) else (to_int(req_in[0]) if len(req_in) == 1 else None)
        if target is None:
            continue
        req = next((r for r in by_frame.get(target, []) if "status" not in r), None)
        if req is None:
            continue
        req["status"] = to_int(code)
        req["reason"] = _nth(phrases, i) if len(phrases) == len(codes) else None
        req["response_frame"] = rec["frame"]
        t = to_float(_nth(times, i)) if len(times) == len(codes) else None
        if t is None and rec["time"] is not None and req["time"] is not None:
            t = rec["time"] - req["time"]
        req["response_ms"] = round(t * 1000, 3) if t is not None else None
        if len(lengths) == len(codes):
            req["response_bytes"] = to_int(lengths[i])
        if len(ctypes) == len(codes):
            req["content_type"] = ctypes[i]
        req["response_version"] = _nth(rversions, i) or None


def _http2(rec: dict[str, Any], raw: dict[str, list[str]], frames: list[dict[str, Any]], src: tuple, dst: tuple,
           h2: dict[tuple, _H2], order: list[_H2]) -> None:
    conn = tuple(sorted([src, dst]))
    errors = raw.get("http2.rst_stream.error") or []
    rst_n = 0
    for f in frames:
        sid = f["stream"]
        if f["type"] == H2_RST_STREAM:
            err = to_int(_nth(errors, rst_n))
            rst_n += 1
        else:
            err = None
        if not sid:
            continue
        s = h2.get((conn, sid))
        if s is None:
            s = h2[(conn, sid)] = _H2(str(conn), sid, rec)
            order.append(s)
        hdr = f.get("headers") or {}
        from_client = s.client == src if s.client is not None else ":method" in hdr
        if f["type"] == H2_HEADERS and ":method" in hdr and s.start is None:
            s.client, s.server = src, dst
            s.start, s.start_frame = rec["time"], rec["frame"]
            s.method, s.path, s.authority = hdr.get(":method"), hdr.get(":path"), hdr.get(":authority")
            from_client = True
        elif f["type"] == H2_HEADERS and not from_client:
            if ":status" in hdr and s.status is None:
                s.status, s.status_time, s.status_frame = to_int(hdr[":status"]), rec["time"], rec["frame"]
                s.content_type = hdr.get("content-type")
            if "grpc-status" in hdr:
                s.grpc = to_int(hdr["grpc-status"])
        elif f["type"] == H2_DATA:
            if from_client:
                s.req_bytes += max(0, f["bytes"] - 9)
            else:
                s.resp_bytes += max(0, f["bytes"] - 9)
        elif f["type"] == H2_RST_STREAM:
            s.rst_by = "client" if from_client else "server"
            s.rst_error = err
        if f.get("end") and not from_client and s.end_time is None:
            s.end_time = rec["time"]


def _ms(a: float | None, b: float | None) -> float | None:
    return round((b - a) * 1000, 3) if a is not None and b is not None and b >= a else None


def _h1_row(r: dict[str, Any]) -> dict[str, Any]:
    path, query = _split_uri(r.get("uri") or "")
    row = {
        "frame": r["frame"], "response_frame": r.get("response_frame"), "stream": r["stream"],
        "client": r["client"], "server": r["server"], "version": r.get("version"), "method": r["method"],
        "host": r.get("host"), "uri": path, "query": query, "status": r.get("status"), "reason": r.get("reason"),
        "content_type": r.get("content_type"), "request_bytes": r.get("request_bytes"),
        "response_bytes": r.get("response_bytes"), "response_ms": r.get("response_ms"),
        "unanswered": True if "status" not in r else None, "_time": r["time"],
    }
    return row


def _h2_row(s: _H2) -> dict[str, Any]:
    path, query = _split_uri(s.path or "")
    grpc = s.grpc is not None or (s.content_type or "").startswith("application/grpc")
    row = {
        "frame": s.start_frame, "response_frame": s.status_frame, "stream": s.stream, "h2_stream": s.sid,
        "client": _side(*s.client) if s.client else None, "server": _side(*s.server) if s.server else None,
        "version": "HTTP/2", "method": s.method, "host": s.authority, "uri": path, "query": query,
        "status": s.status, "content_type": s.content_type, "request_bytes": s.req_bytes or None,
        "response_bytes": s.resp_bytes if s.status is not None else None,
        "ttfb_ms": _ms(s.start, s.status_time), "response_ms": _ms(s.start, s.end_time),
        "grpc": grpc or None,
        "grpc_status": s.grpc, "grpc_status_name": GRPC_STATUS.get(s.grpc) if s.grpc is not None else None,
        "stream_reset_by": s.rst_by,
        "reset_error": H2_ERRORS.get(s.rst_error, s.rst_error) if s.rst_by else None,
        "unanswered": True if s.status is None and s.rst_by is None else None, "_time": s.start,
    }
    return row


def finish(rows: list[dict[str, Any]], capture_end: Callable[[], float | None]) -> list[dict[str, Any]]:
    """Mark unanswered requests near the end of the capture and drop private keys."""
    end: list[float | None] = []
    out = []
    for r in rows:
        t = r.pop("_time", None)
        if r.get("unanswered"):
            if not end:
                end.append(capture_end())
            if end[0] is not None and t is not None and end[0] - t < NEAR_END_S:
                r["near_capture_end"] = True
        out.append(compact(r))
    return out


def status_class(status: int | None) -> str:
    return f"{status // 100}xx" if status is not None and 100 <= status < 600 else "none"


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return round(values[0], 3)
    return round(statistics.quantiles(values, n=100, method="inclusive")[int(q) - 1], 3)


def endpoints(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[(r.get("host") or r.get("server"), r.get("method"), normalise(r.get("uri") or ""))].append(r)
    out = []
    for (host, method, path), rs in groups.items():
        times = sorted(r["response_ms"] for r in rs if r.get("response_ms") is not None)
        sizes = sorted(r["response_bytes"] for r in rs if r.get("response_bytes") is not None)
        classes = Counter(status_class(r.get("status")) for r in rs if not r.get("unanswered"))
        slowest = max((r for r in rs if r.get("response_ms") is not None), key=lambda r: r["response_ms"], default=None)
        servers = Counter(r.get("server") for r in rs)
        grpc = Counter(r["grpc_status_name"] for r in rs if r.get("grpc_status_name"))
        out.append(compact({
            "host": host, "method": method, "uri": path, "count": len(rs),
            "status": dict(sorted(classes.items())) or None,
            "unanswered": sum(1 for r in rs if r.get("unanswered")) or None,
            "response_ms": compact({"p50": _pct(times, 50), "p90": _pct(times, 90), "p99": _pct(times, 99),
                                    "max": round(times[-1], 3) if times else None}) or None,
            "response_bytes": compact({"p50": _pct([float(s) for s in sizes], 50), "max": sizes[-1] if sizes else None})
            or None,
            "grpc_status": dict(grpc.most_common()) or None,
            "servers": [s for s, _ in servers.most_common(3) if s],
            "slowest_frame": slowest["frame"] if slowest else None, "first_frame": min(r["frame"] for r in rs),
        }))
    out.sort(key=lambda e: (-(e.get("status", {}).get("5xx", 0) + (e.get("unanswered") or 0)), -e["count"]))
    return out


def summary(rows: list[dict[str, Any]], eps: list[dict[str, Any]], undissected: list[dict[str, Any]]) -> dict[str, Any]:
    issues: list[str] = []
    for e in eps:
        st = e.get("status") or {}
        answered = sum(st.values())
        bad = st.get("5xx", 0)
        label = f"{e.get('method')} {e.get('host') or ''}{e['uri']}"
        if bad and answered and (bad / answered >= ERROR_SHARE):
            by = ", ".join(e.get("servers") or [])
            issues.append(f"{round(100 * bad / answered)}% of {label} answered 5xx ({bad} of {answered}) by {by}")
        p99 = (e.get("response_ms") or {}).get("p99")
        if p99 is not None and p99 >= SLOW_P99_MS:
            issues.append(f"p99 response {round(p99 / 1000, 2)} s on {label} (slowest frame {e.get('slowest_frame')})")
        if e.get("unanswered"):
            issues.append(f"{e['unanswered']} {label} request{'s' if e['unanswered'] != 1 else ''} got no response "
                          "in the capture")
        bad_grpc = {k: v for k, v in (e.get("grpc_status") or {}).items() if k != "OK"}
        for name, n in bad_grpc.items():
            issues.append(f"gRPC {label} returned {name} {n} time{'s' if n != 1 else ''}")
    resets = Counter((r.get("stream_reset_by"), r.get("reset_error")) for r in rows if r.get("stream_reset_by"))
    for (by, err), n in resets.most_common():
        issues.append(f"{n} HTTP/2 stream{'s' if n != 1 else ''} reset by the {by} with {err}")
    for u in undissected:
        issues.append(f"{u['server']} carries {u['kind']} that tshark did not dissect ({u['frames']} frames, first "
                      f"{u['first_frame']}): this tool cannot read it; use response_times or filter_packets on "
                      f"tcp.port == {u['server'].rsplit(':', 1)[1]}")
    return {
        "requests": len(rows),
        "answered": sum(1 for r in rows if not r.get("unanswered")),
        "unanswered": sum(1 for r in rows if r.get("unanswered")),
        "unanswered_near_capture_end": sum(1 for r in rows if r.get("near_capture_end")),
        "status_mix": dict(sorted(Counter(status_class(r.get("status")) for r in rows if r.get("status")).items())),
        "versions": dict(Counter(r.get("version") or "unknown" for r in rows).most_common()),
        "by_server": dict(Counter(r.get("server") for r in rows).most_common(10)),
        "grpc_calls": sum(1 for r in rows if r.get("grpc")),
        "endpoints": len(eps),
        "issues": issues[:20],
    }


def undissected(stdout: str, http_streams: set) -> list[dict[str, Any]]:
    """Server ports whose TCP payload looks like HTTP that tshark did not dissect. Streams where it
    dissected HTTP are skipped: a retransmitted or copied segment is not dissected again."""
    groups: dict[str, dict[str, Any]] = {}
    for line in stdout.splitlines():
        cols = split_fields_line(line) + [""] * len(UNDISSECTED_FIELDS)
        frame, stream, v4, v6, port = cols[0], cols[1], cols[2], cols[3], cols[4]
        if to_int(stream.split(AGGREGATOR)[-1]) in http_streams:
            continue
        dst = (v6 or v4).split(AGGREGATOR)[-1]
        port = port.split(AGGREGATOR)[-1]
        if not dst or not port:
            continue
        key = _side(dst, port)
        g = groups.setdefault(key, {"server": key, "frames": 0, "first_frame": to_int(frame), "kind": "HTTP"})
        g["frames"] += 1
    return sorted(groups.values(), key=lambda g: -g["frames"])


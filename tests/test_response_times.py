"""response_times: network, server and receiver time per TCP flow, on synthetic captures."""

from __future__ import annotations

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw  # type: ignore

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

CLIENT = "198.51.100.40"


class Capture:
    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.t = 1_700_050_000.0
        self.port = 51000

    def conn(self, server: str, sport: int = 8443) -> "Conn":
        self.port += 1
        return Conn(self, server, sport, self.port)

    def write(self, path: Path) -> Path:
        return g._frames_to_pcap(path, self.frames)


class Conn:
    """One TCP connection seen from a capture point next to the client."""

    def __init__(self, cap: Capture, server: str, sport: int, cport: int) -> None:
        self.cap, self.server, self.sport, self.cport = cap, server, sport, cport
        self.seq = {"c": 1000, "s": 70000}
        self.ip_id = {"c": 100, "s": 900}

    def send(self, side: str, n: int = 0, flags: str = "PA", dt: float = 0.0, window: int = 65000,
             payload: bytes | None = None, seq: int | None = None, copy: bool = False) -> None:
        other = "s" if side == "c" else "c"
        src, dst, sp, dp = ((CLIENT, self.server, self.cport, self.sport) if side == "c"
                            else (self.server, CLIENT, self.sport, self.cport))
        data = payload if payload is not None else b"x" * n
        self.ip_id[side] += 1
        use_seq = self.seq[side] if seq is None else seq
        pkt = Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=src, dst=dst, id=self.ip_id[side]) / TCP(
            sport=sp, dport=dp, flags=flags, seq=use_seq, ack=self.seq[other], window=window) / (Raw(data) if data else b"")
        self.cap.t += dt
        self.cap.frames.append((self.cap.t, bytes(pkt)))
        if copy:
            self.cap.frames.append((self.cap.t + 0.0002, bytes(pkt)))
        if seq is None:
            self.seq[side] += len(data) + (1 if "S" in flags or "F" in flags else 0)

    def open(self, rtt: float = 0.020) -> "Conn":
        self.send("c", flags="S")
        self.send("s", flags="SA", dt=rtt)      # capture near the client: the round trip is SYN to SYN-ACK
        self.send("c", flags="A", dt=0.0002)
        return self


def build(path: Path) -> Path:
    cap = Capture()
    # Server-bound: 20 ms round trip, the server works 500 ms before answering.
    c = cap.conn("203.0.113.10").open()
    c.send("c", 300, dt=0.001)
    c.send("s", 1200, dt=0.520)
    c.send("s", 800, dt=0.001)
    c.send("c", flags="A", dt=0.0005)
    # Network-bound: quick server, a lost segment resent after a 1 s timeout in the middle of the response.
    c = cap.conn("203.0.113.20").open()
    c.send("c", 300, dt=0.001)
    c.send("s", 1000, dt=0.025)
    lost = c.seq["s"]
    c.seq["s"] += 1000            # this segment never reaches the capture point
    c.send("s", 1000, dt=0.001)
    c.send("s", 1000, dt=1.000, seq=lost)  # the retransmission
    c.send("c", flags="A", dt=0.0005)
    # Receiver-bound: the client advertises a zero window and the response waits 2 s.
    c = cap.conn("203.0.113.30").open()
    c.send("c", 300, dt=0.001)
    c.send("s", 1000, dt=0.025)
    c.send("c", flags="A", dt=0.001, window=0)
    c.send("s", 1000, dt=2.000)
    # Fast, HTTP/1.1 on port 80, with one packet captured twice.
    c = cap.conn("203.0.113.40", sport=80).open(rtt=0.010)
    c.send("c", payload=b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", dt=0.001, copy=True)
    c.send("s", payload=b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", dt=0.015)
    # A push channel: the answer comes 30 s after the request.
    c = cap.conn("203.0.113.50").open()
    c.send("c", 100, dt=0.001)
    c.send("s", 100, dt=30.0)
    # SYNs that never get an answer, and one refused with a reset.
    c = cap.conn("203.0.113.60")
    c.send("c", flags="S")
    c.send("c", flags="S", dt=1.0, seq=1000)
    c = cap.conn("203.0.113.70")
    c.send("c", flags="S", dt=0.1)
    c.send("s", flags="RA", dt=0.010)
    return cap.write(path)


def _flow(out, server):
    return next(f for f in out["flows"] if f["server"].startswith(server))


def test_server_bound(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(build(tmp_path / "rt.pcap")))
    f = _flow(out, "203.0.113.10:")
    assert f["verdict"] == "server-bound" and f["rtt_ms"] == 20.2 and f["rtt_source"] == "handshake"
    assert f["capture_near"] == "client"
    x = f["slowest_exchanges"][0]
    assert x["think_ms"] == 520.0 and x["server_ms"] == 500.0 and x["transfer_ms"] == 1.0
    assert x["request_bytes"] == 300 and x["response_bytes"] == 2000


def test_network_bound_retransmission_stall(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(build(tmp_path / "rt.pcap")))
    f = _flow(out, "203.0.113.20:")
    assert f["verdict"] == "network-bound" and f["retransmissions"] == 1
    x = f["slowest_exchanges"][0]
    assert x["stalls"] == [{"at": x["stalls"][0]["at"], "gap_ms": 1000.0, "cause": "retransmission"}]
    assert f["time_split_ms"]["retransmission_stalls"] == 1000.0


def test_receiver_bound_zero_window(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(build(tmp_path / "rt.pcap")))
    f = _flow(out, "203.0.113.30:")
    assert f["verdict"] == "receiver-bound" and f["zero_windows"] == 1
    assert f["slowest_exchanges"][0]["stalls"][0]["cause"] == "zero_window"


def test_fast_http_and_copies(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(build(tmp_path / "rt.pcap")))
    f = _flow(out, "203.0.113.40:80")
    assert f["verdict"] == "fast" and f["duplicate_copies"] == 1 and "retransmissions" not in f
    x = f["slowest_exchanges"][0]
    assert (x["method"], x["uri"], x["host"], x["status"]) == ("GET", "/index.html", "www.example.com", 404)
    assert x["server_ms"] == 5.0


def test_long_wait_and_connections_not_opened(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(build(tmp_path / "rt.pcap")))
    push = _flow(out, "203.0.113.50:")
    assert push["verdict"] == "idle-or-push" and push["long_waits"] == 1
    assert push["slowest_exchanges"][0]["long_wait"] is True and "server" not in push.get("time_split_ms", {})
    not_opened = {n["server"]: n for n in out["not_opened"]}
    assert not_opened["203.0.113.60:8443"]["outcome"] == "no_answer" and not_opened["203.0.113.60:8443"]["syn_attempts"] == 2
    assert not_opened["203.0.113.70:8443"]["outcome"] == "refused"
    assert out["summary"]["connections_not_opened"] == 2
    assert out["summary"]["verdicts"] == {"server-bound": 1, "network-bound": 1, "receiver-bound": 1, "fast": 1,
                                          "idle-or-push": 1}
    # Slowest real problems first, fast and idle flows last.
    assert [f["verdict"] for f in out["flows"]][-2:] in (["fast", "idle-or-push"], ["idle-or-push", "fast"])
    assert any("1 flows are server-bound (203.0.113.10:8443 x1)" == i for i in out["issues"])


def test_filter_and_pages(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(build(tmp_path / "rt.pcap"))
    only = srv.response_times(path, filter="tcp.port == 80")
    assert [f["server"] for f in only["flows"]] == ["203.0.113.40:80"]
    full = srv.response_times(path)
    page = srv.response_times(path, limit=2, offset=1)
    assert page["flows"] == full["flows"][1:3] and page["total_matched"] == 5 and page["next_offset"] == 3


def test_no_handshake_uses_acks_and_split_streams_join(configure, tmp_path: Path):
    cap = Capture()
    c = cap.conn("203.0.113.80")
    c.send("c", 200, dt=0.001)            # the capture started after the handshake
    c.send("s", flags="A", dt=0.030)      # the server's ACK: 30 ms round trip from here
    c.send("s", 500, dt=0.200)
    c.send("c", flags="A", dt=0.001)
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(cap.write(tmp_path / "noh.pcap")))
    f = out["flows"][0]
    assert f["rtt_source"] == "acks" and f["rtt_capture_to_server_ms"] == 30.0
    assert f["slowest_exchanges"][0]["server_ms"] == 200.0


def test_results_match_the_published_output_schemas(configure, tmp_path: Path):
    """The MCP layer validates every result against the tool's outputSchema; a None where an int is
    declared fails the call over stdio even though the direct call returns."""
    from pydantic import TypeAdapter

    from tshark_mcp import models

    from .test_dns import scenario as dns_scenario
    from .test_tls import scenario as tls_scenario
    srv = configure(allow=[str(tmp_path)])
    cap = Capture()
    c = cap.conn("203.0.113.90").open()
    for _ in range(4):  # several exchanges, none with a retransmission
        c.send("c", 100, dt=0.001)
        c.send("s", 300, dt=0.300)
    c.send("c", 100, dt=0.001)  # and a last request that gets no answer
    checks = [
        (models.ResponseTimesResult, srv.response_times(str(build(tmp_path / "rt.pcap")))),
        (models.ResponseTimesResult, srv.response_times(str(cap.write(tmp_path / "many.pcap")))),
        (models.DnsTransactionsResult, srv.dns_transactions(str(dns_scenario(tmp_path / "dns.pcap")))),
        (models.TlsHandshakesResult, srv.tls_handshakes(str(tls_scenario(tmp_path / "tls.pcap")))),
    ]
    for model, out in checks:
        assert "error" not in out
        TypeAdapter(model).validate_python(out)


def test_lossy_handshake_toward_the_client(configure, tmp_path: Path):
    cap = Capture()
    c = cap.conn("203.0.113.95")
    c.send("c", flags="S", seq=5000)
    c.send("s", flags="SA", dt=0.020, seq=80000)
    c.send("c", flags="S", dt=1.000, seq=5000)      # the SYN-ACK never reached the client: it asks again
    c.send("s", flags="SA", dt=0.020, seq=80000)
    c.seq = {"c": 5001, "s": 80001}
    c.send("c", flags="A", dt=0.030)
    c.send("c", 100, dt=0.001)
    c.send("s", 100, dt=0.060)
    srv = configure(allow=[str(tmp_path)])
    out = srv.response_times(str(cap.write(tmp_path / "lossy.pcap")))
    f = out["flows"][0]
    assert f["syn_retransmissions"] == 1 and f["synack_retransmissions"] == 1
    assert f["rtt_ms"] == 50.0 and f["rtt_capture_to_server_ms"] == 20.0 and f["connect_ms"] == 1070.0
    assert any("needed the SYN-ACK more than once" in i for i in out["issues"])

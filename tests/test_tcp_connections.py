"""tcp_connections: per connection attempt outcome, and per destination, on synthetic captures."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import ICMP, IP, TCP, Ether, Raw  # type: ignore

from tshark_mcp import models

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark
from .test_capture_quality import Cap

pytestmark = requires_tshark

CLI, CLI2, CLI3 = "192.0.2.91", "192.0.2.92", "192.0.2.93"
WEB, DB, CLOSED, FW = "198.51.100.10", "198.51.100.20", "198.51.100.30", "198.51.100.40"
ROUTER = "203.0.113.1"


class Wire:
    def __init__(self) -> None:
        self.cap = Cap(step=0.001)
        self.ids: dict[str, int] = {}

    def pkt(self, src: str, dst: str, sport: int, dport: int, flags: str, seq: int, ack: int = 0, payload: int = 0,
            ip_id: int | None = None):
        if ip_id is None:
            self.ids[src] = self.ids.get(src, 100) + 1
            ip_id = self.ids[src]
        return (Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=src, dst=dst, id=ip_id, flags="DF")
                / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / (Raw(b"x" * payload) if payload else b""))

    def add(self, pkt, at: float | None = None):
        if at is not None:
            self.cap.t = at
        self.cap.add(pkt, t=at)
        return pkt

    def full(self, cli: str, srv: str, cport: int, sport: int, at: float, close: str = "client_fin",
             duration: float = 0.2, isn: int = 1000) -> None:
        self.add(self.pkt(cli, srv, cport, sport, "S", isn), at)
        self.add(self.pkt(srv, cli, sport, cport, "SA", 5000, isn + 1), at + 0.02)
        self.add(self.pkt(cli, srv, cport, sport, "A", isn + 1, 5001), at + 0.021)
        self.add(self.pkt(cli, srv, cport, sport, "PA", isn + 1, 5001, payload=100), at + 0.03)
        self.add(self.pkt(srv, cli, sport, cport, "PA", 5001, isn + 101, payload=700), at + 0.05)
        end = at + duration
        if close == "client_fin":
            self.add(self.pkt(cli, srv, cport, sport, "FA", isn + 101, 5701), end)
            self.add(self.pkt(srv, cli, sport, cport, "FA", 5701, isn + 102), end + 0.01)
            self.add(self.pkt(cli, srv, cport, sport, "A", isn + 102, 5702), end + 0.011)
        elif close == "server_rst":
            self.add(self.pkt(srv, cli, sport, cport, "R", 5701), end)

    def write(self, tmp_path: Path) -> Path:
        self.cap.frames.sort(key=lambda f: f[0])
        return self.cap.write(tmp_path / "conns.pcap")


def scenario() -> Wire:
    w = Wire()
    w.full(CLI, WEB, 40001, 443, 1.0, close="client_fin")
    w.full(CLI, WEB, 40002, 443, 2.0, close="server_rst")
    # Refused: RST+ACK to the SYN.
    w.add(w.pkt(CLI, CLOSED, 40003, 8080, "S", 3000), 3.0)
    w.add(w.pkt(CLOSED, CLI, 8080, 40003, "RA", 0, 3001), 3.001)
    # Filtered: SYN retried at 1, 2 and 4 s, never answered.
    for t in (4.0, 5.0, 7.0, 11.0):
        w.add(w.pkt(CLI, DB, 40004, 5432, "S", 4000), t)
    # One copy of the first SYN captured on a second tap: same IP ID, not a retry.
    syn = w.pkt(CLI2, DB, 40010, 5432, "S", 7000, ip_id=777)
    w.add(syn, 4.5)
    w.add(syn, 4.5002)
    # CLI2 and CLI3 connect to DB while CLI is dropped.
    w.add(w.pkt(DB, CLI2, 5432, 40010, "SA", 9000, 7001), 4.52)
    w.add(w.pkt(CLI2, DB, 40010, 5432, "A", 7001, 9001), 4.53)
    w.full(CLI3, DB, 40011, 5432, 6.0)
    # Prohibited: a router answers the SYN with ICMP communication administratively prohibited.
    probe = IP(src=CLI, dst=FW, id=555, flags="DF") / TCP(sport=40005, dport=22, flags="S", seq=1)
    w.add(Ether() / IP(src=CLI, dst=FW, id=555, flags="DF") / TCP(sport=40005, dport=22, flags="S", seq=1), 12.0)
    w.add(Ether() / IP(src=ROUTER, dst=CLI, id=9) / ICMP(type=3, code=13) / bytes(probe)[:28], 12.01)
    # Port reuse: the same addresses and ports, a new ISN, refused this time.
    w.add(w.pkt(CLI, CLOSED, 40003, 8080, "S", 99000), 13.0)
    w.add(w.pkt(CLOSED, CLI, 8080, 40003, "RA", 0, 99001), 13.001)
    # Seen midway: data with no handshake.
    w.add(w.pkt(CLI, WEB, 40020, 443, "PA", 50, 60, payload=10), 14.0)
    # Near the end: one SYN 1 s before the last packet.
    w.add(w.pkt(CLI, DB, 40030, 5432, "S", 123), 20.0)
    w.add(w.pkt(CLI, WEB, 40020, 443, "PA", 60, 60, payload=10), 21.0)
    return w


def run(configure, tmp_path: Path, w: Wire, **kw):
    srv = configure(allow=[str(tmp_path)])
    out = srv.tcp_connections(str(w.write(tmp_path)), **kw)
    TypeAdapter(models.TcpConnectionsResult).validate_python(out)
    assert "error" not in out, out
    return out


def by_port(out) -> dict[int, list[dict]]:
    rows: dict[int, list[dict]] = {}
    for r in out["connections"]:
        rows.setdefault(int(r["client"].rsplit(":", 1)[1]), []).append(r)
    return rows


def test_outcomes(configure, tmp_path):
    out = run(configure, tmp_path, scenario())
    rows = by_port(out)
    assert rows[40001][0]["outcome"] == "connected" and rows[40001][0]["closed_by"] == "client_fin"
    assert rows[40001][0]["bytes_client_to_server"] == 100 and rows[40001][0]["bytes_server_to_client"] == 700
    assert rows[40001][0]["connect_ms"] == 20.0
    assert rows[40001][0]["completeness"] == ["syn", "syn_ack", "data", "fin"]
    assert rows[40002][0]["outcome"] == "connected" and rows[40002][0]["closed_by"] == "server_rst"
    assert [r["outcome"] for r in rows[40003]] == ["refused", "refused"]  # port reuse: two attempts
    assert all(r["closed_by"] == "server_rst" for r in rows[40003])
    filtered = rows[40004][0]
    assert filtered["outcome"] == "filtered" and filtered["syns"] == 4 and filtered["syn_retries"] == 3
    assert filtered["syn_retry_gaps_s"] == [1.0, 2.0, 4.0] and "near_capture_end" not in filtered
    copied = rows[40010][0]
    assert copied["outcome"] == "connected" and copied["syns"] == 1 and copied["copies_dropped"] == 1
    prohibited = rows[40005][0]
    assert prohibited["outcome"] == "prohibited"
    assert prohibited["icmp"][0]["from"] == ROUTER and "prohibited" in prohibited["icmp"][0]["error"]
    assert rows[40020][0]["outcome"] == "seen_midway"
    near = rows[40030][0]
    assert near["outcome"] == "filtered" and near["near_capture_end"] is True
    # Failed attempts come first.
    outcomes = [r["outcome"] for r in out["connections"]]
    assert outcomes.index("connected") > outcomes.index("filtered")
    s = out["summary"]
    assert s["copies_dropped"] == 1 and s["by_outcome"]["refused"] == 2 and s["connections"] == len(out["connections"])


def test_syn_count_matches_raw_tshark(configure, tmp_path):
    out = run(configure, tmp_path, scenario())
    raw = subprocess.run([TSHARK, "-n", "-r", str(tmp_path / "conns.pcap"), "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                          "-T", "fields", "-e", "frame.number"], capture_output=True, text=True, check=True).stdout.split()
    # tshark counts the mirrored SYN copy too; the tool drops it.
    assert sum(r.get("syns", 0) for r in out["connections"]) == len(raw) - out["summary"]["copies_dropped"]


def test_destinations_name_the_dropped_client(configure, tmp_path):
    out = run(configure, tmp_path, scenario(), view="destinations")
    dests = {d["server"]: d for d in out["destinations"]}
    db = dests[f"{DB}:5432"]
    assert db["attempts"] == 4 and db["connected"] == 2 and db["filtered"] == 2 and db["success_rate"] == 0.5
    assert db["clients"] == 3
    assert any(f"from {CLI}" in i and "security group" in i for i in db["issues"]), db["issues"]
    closed = dests[f"{CLOSED}:8080"]
    assert closed["refused"] == 2 and any("refused 2" in i for i in closed["issues"])
    fw = dests[f"{FW}:22"]
    assert any(ROUTER in i and "firewall rejects" in i for i in fw["issues"])
    assert out["summary"]["issues"]


def test_selectors(configure, tmp_path):
    w = scenario()
    srv = configure(allow=[str(tmp_path)])
    path = str(w.write(tmp_path))
    out = srv.tcp_connections(path, server=DB, port=5432)
    assert {r["server"] for r in out["connections"]} == {f"{DB}:5432"} and out["total_matched"] == 4
    out = srv.tcp_connections(path, client=CLI2)
    assert [r["client"] for r in out["connections"]] == [f"{CLI2}:40010"]
    out = srv.tcp_connections(path, outcome="refused")
    assert out["total_matched"] == 2
    out = srv.tcp_connections(path, server=FW)
    assert [r["outcome"] for r in out["connections"]] == ["prohibited"]  # the ICMP error survives the address filter
    out = srv.tcp_connections(path, limit=2)
    assert out["returned"] == 2 and out["next_offset"] == 2


@pytest.mark.parametrize("kw,needle", [
    ({"server": "not-an-ip"}, "server"), ({"client": "1.2.3"}, "client"), ({"port": 70000}, "port"),
    ({"outcome": "maybe"}, "outcome"), ({"view": "x"}, "view"), ({"server": "1.2.3.4 || 1"}, "server"),
])
def test_bad_arguments(configure, tmp_path, kw, needle):
    srv = configure(allow=[str(tmp_path)])
    out = srv.tcp_connections(str(scenario().write(tmp_path)), **kw)
    assert out["error"]["type"] == "invalid_argument" and needle in out["error"]["message"]


def test_churn(configure, tmp_path):
    w = Wire()
    for i in range(60):
        w.full(CLI, WEB, 41000 + i, 443, 1.0 + i, duration=0.1)
    out = run(configure, tmp_path, w, view="destinations")
    web = out["destinations"][0]
    assert web["connected"] == 60 and web["max_concurrent"] == 1
    assert any("60 connections" in i and "keep-alive" in i for i in web["issues"]), web["issues"]

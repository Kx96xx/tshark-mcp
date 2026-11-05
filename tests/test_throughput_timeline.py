"""throughput_timeline: a synthetic transfer with a loss burst, a zero-window stall and an idle gap."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw  # type: ignore

from tshark_mcp import models
from tshark_mcp import server as srv
from tshark_mcp.limits import Limits

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark

T0 = 1_700_300_000.0
CLI, SRV = "192.0.2.31", "198.51.100.41"
SEG = 1400


class Transfer:
    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.seq = 5001    # next server byte
        self.ack = 1001    # next client byte the server expects
        self.ids = {CLI: 100, SRV: 200}

    def pkt(self, t: float, frm: str, flags: str, seq: int, ack: int, payload: int = 0, window: int = 65535) -> None:
        self.ids[frm] += 1
        to = SRV if frm == CLI else CLI
        sport, dport = (50000, 80) if frm == CLI else (80, 50000)
        p = (Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=frm, dst=to, id=self.ids[frm])
             / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=window)
             / (Raw(b"d" * payload) if payload else b""))
        self.frames.append((t, bytes(p)))

    def handshake(self, t: float) -> None:
        self.pkt(t, CLI, "S", 1000, 0)
        self.pkt(t + 0.010, SRV, "SA", 5000, 1001)
        self.pkt(t + 0.011, CLI, "A", 1001, 5001)

    def good(self, t: float, until: float, step: float = 0.010) -> float:
        while t < until - 1e-9:
            self.pkt(t, SRV, "PA", self.seq, self.ack, SEG)
            self.seq += SEG
            self.pkt(t + 0.001, CLI, "A", self.ack, self.seq)
            t += step
        return t

    def lossy(self, t: float, until: float) -> float:
        """Every segment is lost once: a duplicate ACK, then the retransmission 50 ms later is acknowledged."""
        while t < until - 1e-9:
            self.pkt(t, SRV, "PA", self.seq, self.ack, SEG)
            self.pkt(t + 0.001, CLI, "A", self.ack, self.seq)          # acknowledges nothing new
            self.pkt(t + 0.050, SRV, "PA", self.seq, self.ack, SEG)     # retransmission, new IP ID
            self.seq += SEG
            self.pkt(t + 0.051, CLI, "A", self.ack, self.seq)
            t += 0.060
        return t

    def zero_window(self, t: float, until: float) -> float:
        self.pkt(t, SRV, "PA", self.seq, self.ack, SEG)
        self.seq += SEG
        t += 0.001
        while t < until - 1e-9:
            self.pkt(t, CLI, "A", self.ack, self.seq, window=0)
            t += 0.2
        self.pkt(until - 0.005, CLI, "A", self.ack, self.seq)  # window update
        return until

    def write(self, path: Path) -> Path:
        return g._frames_to_pcap(path, sorted(self.frames, key=lambda f: f[0]))


def _dns(tr: Transfer, t: float, n: int) -> None:
    for i in range(n):
        p = Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=CLI, dst="192.0.2.53") / UDP(sport=33000 + i, dport=53) / DNS(
            id=i, rd=1, qd=DNSQR(qname="api.example.com"))
        tr.frames.append((t + i * 0.001, bytes(p)))


@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tr = Transfer()
    tr.handshake(T0)
    tr.good(T0 + 0.1, T0 + 3.0)
    tr.lossy(T0 + 3.0, T0 + 4.0)
    tr.good(T0 + 4.0, T0 + 6.0)
    tr.zero_window(T0 + 6.0, T0 + 7.0)
    tr.good(T0 + 9.0, T0 + 10.0)        # 7 s to 9 s: nothing
    _dns(tr, T0 + 1.5, 1)
    _dns(tr, T0 + 2.5, 1)
    _dns(tr, T0 + 4.5, 1)
    _dns(tr, T0 + 9.2, 20)
    d = tmp_path_factory.mktemp("tput")
    return tr.write(d / "transfer.pcap")


@pytest.fixture
def tput(capture: Path):
    srv.configure([str(capture.parent)], limits=Limits(), tshark=TSHARK)
    yield srv
    srv._STATE = None


def test_intervals_carry_the_loss_burst_the_stall_and_the_gap(tput, capture: Path):
    out = tput.throughput_timeline(str(capture), limit=20)
    assert "error" not in out, out
    TypeAdapter(models.ThroughputTimelineResult).validate_python(out)
    iv = out["intervals"]
    assert len(iv) == 11 and [r["index"] for r in iv] == list(range(11))
    assert iv[1]["goodput_bps"] == 100 * SEG * 8               # 100 segments acknowledged in that second
    assert iv[3]["retransmitted_bytes"] > 0 and iv[3]["goodput_bps"] < iv[1]["goodput_bps"] / 4
    assert "retransmitted_bytes" not in iv[1] and "retransmitted_bytes" not in iv[5]
    assert iv[6]["zero_windows"] >= 4
    assert "packets" not in iv[7] and "packets" not in iv[8] and iv[7]["bps"] == 0
    assert iv[9]["dns_queries"] == 20 and iv[0]["syns"] == 1
    s = out["summary"]
    assert s["idle_intervals"] == 2 and s["tcp_streams"] == 1 and s["peak_goodput_bps"] >= iv[1]["goodput_bps"]


def test_goodput_adds_up_to_the_bytes_acknowledged(tput, capture: Path):
    out = tput.throughput_timeline(str(capture), limit=20)
    acked = sum(r.get("acked_bytes", 0) for r in out["intervals"])
    (stream,) = out["streams"]
    assert acked == stream["data_bytes"] - stream["retransmitted_bytes"]
    assert stream["flow"] == f"{CLI}:50000 -> {SRV}:80" and stream["verdict"] == "loss-limited"
    assert stream["retransmitted_share"] > 0.02 and stream["first_frame"] == 1


def test_counts_match_raw_tshark(tput, capture: Path):
    out = tput.throughput_timeline(str(capture), limit=20)
    raw = subprocess.run([TSHARK, "-n", "-r", str(capture), "-T", "fields", "-e", "frame.len"],
                         capture_output=True, text=True, check=True).stdout.split()
    assert out["summary"]["packets"] == len(raw) and out["summary"]["bytes"] == sum(int(x) for x in raw)
    dns = subprocess.run([TSHARK, "-n", "-r", str(capture), "-Y", "dns.flags.response == 0", "-T", "fields",
                          "-e", "frame.number"], capture_output=True, text=True, check=True).stdout.split()
    assert out["summary"]["dns_queries"] == len(dns) == 23


def test_issues_name_the_cause(tput, capture: Path):
    issues = tput.throughput_timeline(str(capture))["issues"]
    fell = next(i for i in issues if i.startswith("goodput fell"))
    assert "loss on the path" in fell and "1.12 Mbit/s" in fell
    assert any("loss-limited" in i for i in issues)
    assert any(i.startswith("burst of 20 dns queries") for i in issues)


def test_series_per_key_and_paging(tput, capture: Path):
    out = tput.throughput_timeline(str(capture), per="host", top=2, limit=4, offset=2)
    assert [s["key"] for s in out["series"]] == [CLI, SRV]  # each host counts what it sent and received
    assert out["series"][1]["intervals"][1]["bytes_sent"] > 0
    assert [r["index"] for r in out["intervals"]] == [2, 3, 4, 5] and out["next_offset"] == 6
    conv = tput.throughput_timeline(str(capture), per="conversation", top=1)
    assert conv["series"][0]["key"] == f"{CLI} <-> {SRV}"
    assert "series" not in tput.throughput_timeline(str(capture))


def test_window_filter_and_bad_arguments(tput, capture: Path):
    part = tput.throughput_timeline(str(capture), start="+3s", end="+4s")
    assert part["summary"]["first"].startswith("2023-11-18T09:33:23") and len(part["intervals"]) <= 2
    tcp_only = tput.throughput_timeline(str(capture), filter="tcp")
    assert tcp_only["summary"]["dns_queries"] == 0
    assert tput.throughput_timeline(str(capture), per="vlan")["error"]["type"] == "invalid_argument"
    assert tput.throughput_timeline(str(capture), interval=0)["error"]["type"] == "invalid_argument"
    too_many = tput.throughput_timeline(str(capture), interval=0.0005)
    assert too_many["error"]["type"] == "invalid_argument"
    fine = tput.throughput_timeline(str(capture), interval=0.001)
    assert fine["error"]["type"] == "invalid_argument" and "10000 intervals" in fine["error"]["message"]


async def _over_stdio(capture: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "tshark_mcp.server", "--allow-dir", str(capture.parent)],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool("throughput_timeline", {"path": str(capture), "per": "stream"})


def test_throughput_timeline_over_stdio(capture: Path):
    got = asyncio.run(_over_stdio(capture))
    out = got.structured_content
    assert not got.is_error and out["streams"][0]["verdict"] == "loss-limited" and out["series"]

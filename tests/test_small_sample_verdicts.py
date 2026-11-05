"""Verdicts that small samples and fallbacks used to inflate (public-validation D15, D16).

D15: a DNS query lost and sent again 5 s later made the resolver "slow: 90% within 5006 ms",
from 5 answers. The server's time now runs from the last copy of the query, a percentile needs
10 answers, and the lost-and-resent query is reported as a loss.
D16: an IPv6 attempt refused 0.3 ms before the IPv4 connection to the same service worked
(happy eyeballs) was a high connect failure, and SYNs refused with a reset were counted again
as "SYNs without a SYN-ACK".
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark


def _call(configure, tmp_path: Path, tool: str, path: Path, **kw) -> dict:
    srv = configure(allow=[str(tmp_path)])
    out = getattr(srv, tool)(str(path), **kw)
    assert "error" not in out, out
    return out


def test_lost_query_is_a_loss_not_a_slow_server(configure, tmp_path):
    out = _call(configure, tmp_path, "dns_transactions", g.write_dns_lost_query_pcap(tmp_path / "dns.pcap"))
    assert not any("is slow" in i for i in out["issues"])
    assert any("was sent again 5.0 s later and answered 6.0 ms after the resend" in i for i in out["issues"])
    lost = next(t for t in out["transactions"] if t["name"] == "lost.example.com")
    assert lost["rtt_ms"] > 5000 and lost["rtt_after_resend_ms"] == 6.0
    assert out["summary"]["rtt_ms"]["max"] < 1000  # server time from the last copy of the query
    inc = _call(configure, tmp_path, "incident_summary", tmp_path / "dns.pcap")
    assert "dns_slow" not in {f["kind"] for f in inc["findings"]}


def test_few_slow_answers_are_named_without_a_percentile(configure, tmp_path):
    out = _call(configure, tmp_path, "dns_transactions",
                g.write_dns_lost_query_pcap(tmp_path / "dns.pcap", slow_answers=2))
    assert any("took more than 1000 ms on 2 of 5 answers" in i for i in out["issues"])
    assert not any("90% of answers" in i for i in out["issues"])


def test_enough_slow_answers_still_make_a_slow_server(configure, tmp_path):
    path = g.write_dns_lost_query_pcap(tmp_path / "dns.pcap", slow_answers=6, answers=12)
    out = _call(configure, tmp_path, "dns_transactions", path)
    assert any(f"{g.RESOLVER}:53 is slow: 90% of answers" in i or f"{g.RESOLVER} is slow" in i for i in out["issues"]), \
        out["issues"]
    inc = _call(configure, tmp_path, "incident_summary", path)
    assert "dns_slow" in {f["kind"] for f in inc["findings"]}


def test_happy_eyeballs_is_low_and_refused_syns_are_not_unanswered(configure, tmp_path):
    path = g.write_happy_eyeballs_pcap(tmp_path / "he.pcap")
    dests = {d["server"]: d for d in _call(configure, tmp_path, "tcp_connections", path, view="destinations")["destinations"]}
    v6 = dests["[2001:db8::443]:443"]
    assert v6["refused"] == 1 and v6["failed_then_connected_elsewhere"] == 1
    assert any("happy eyeballs" in i for i in v6["issues"])
    assert "failed_then_connected_elsewhere" not in dests["198.51.100.44:445"]
    findings = _call(configure, tmp_path, "incident_summary", path)["findings"]
    connect = [f for f in findings if f["kind"] == "connect_failures"]
    he = next(f for f in connect if "2001:db8::443" in f["text"])
    assert he["severity"] == "low"
    scan = [f for f in connect if "198.51.100.44" in f["text"]]
    assert len(scan) == 2 and all(f["severity"] == "high" for f in scan)
    assert "tcp_unanswered_syn" not in {f["kind"] for f in findings}
    health = _call(configure, tmp_path, "tcp_health", path)
    assert not any("no SYN-ACK" in i for s in health["streams"] for i in s.get("issues", []))


def test_small_samples_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = g.write_dns_lost_query_pcap(tmp_path / "dns.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("dns_transactions", {"path": str(cap)})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    assert not any("is slow" in i for i in asyncio.run(go())["issues"])

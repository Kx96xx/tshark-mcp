"""incident_summary: findings composed from the other tools on synthetic captures."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import rdpcap, wrpcap  # type: ignore

from tshark_mcp import incident, models
from tshark_mcp import server as srv
from tshark_mcp.limits import Limits

from . import pcapgen as g
from . import test_dns, test_http_transactions, test_icmp_errors, test_tcp_connections, test_tls
from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark


def _merge(path: Path, parts: list[Path]) -> Path:
    packets = []
    for p in parts:
        packets.extend(rdpcap(str(p)))
    packets.sort(key=lambda p: float(p.time))
    wrpcap(str(path), packets)
    return path


@pytest.fixture(scope="module")
def caps(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("incident")
    parts = d / "parts"
    parts.mkdir()
    test_dns.scenario(parts / "dns.pcap")
    test_tls.scenario(parts / "tls.pcap")
    test_http_transactions.http1_capture(parts / "http.pcap")
    test_icmp_errors.scenario().write(parts / "icmp.pcap")
    conns = test_tcp_connections.scenario().write(parts)
    _merge(d / "web.pcap", [parts / "dns.pcap", parts / "tls.pcap", parts / "http.pcap", parts / "icmp.pcap", conns])
    test_dns.scenario(d / "dns_only.pcap")
    g.write_all(d / "sig")
    g.write_merged_pcap(d / "signalling.pcap", d / "sig")
    g.write_voice_pcaps(d / "voice")
    return d


@pytest.fixture
def inc(caps: Path):
    srv.configure([str(caps)], limits=Limits(), tshark=TSHARK)
    yield srv
    srv._STATE = None


def _kinds(out) -> list[str]:
    return [f["kind"] for f in out["findings"]]


def test_web_capture_findings_are_ranked_with_evidence(inc, caps: Path):
    out = inc.incident_summary(str(caps / "web.pcap"))
    assert "error" not in out, out
    TypeAdapter(models.IncidentSummaryResult).validate_python(out)
    kinds = _kinds(out)
    for expected in ("connect_failures", "dns_unanswered", "dns_servfail", "tls_failed", "tls_certificate", "http_5xx",
                     "routing_loop", "path_mtu", "prohibited"):
        assert expected in kinds, (expected, kinds)
    severities = [f["severity"] for f in out["findings"]]
    assert severities == sorted(severities, key=incident.SEVERITIES.index)
    http = next(f for f in out["findings"] if f["kind"] == "http_5xx")
    assert http["text"] == "3 of 8 HTTP responses were 5xx (37.5%)" and http["severity"] == "high"
    assert http["evidence"]["tool"] == "http_transactions" and http["evidence"]["frames"]
    assert http["next_call"] == {"tool": "http_transactions", "args": {"path": str(caps / "web.pcap"), "view": "requests",
                                                                       "status": "5xx"}}
    dns = next(f for f in out["findings"] if f["kind"] == "dns_unanswered")
    assert dns["text"] == "3 of 10 DNS queries got no answer (30.0%)"  # none is near the end of the merged file
    conn = [f for f in out["findings"] if f["kind"] == "connect_failures"]
    assert any("filtered" in f["text"] for f in conn) and any("refused" in f["text"] for f in conn)
    assert conn[0]["next_call"]["tool"] == "tcp_connections" and "port" in conn[0]["next_call"]["args"]
    # the "no reply to 1 of 5 echoes" and traceroute sentences are not raised above low
    assert all(f["severity"] == "low" for f in out["findings"] if f["kind"] in ("echo_loss", "port_unreachable"))
    assert "traceroute" not in " ".join(f["text"] for f in out["findings"])


def test_capture_block_top_talkers_and_timeline(inc, caps: Path):
    out = inc.incident_summary(str(caps / "web.pcap"))
    cap = out["capture"]
    assert cap["packets"] > 0 and "tcp" in cap["protocols"] and cap["trust"]["loss_conclusions"]
    assert not any("encrypted" in c for c in cap.get("cannot_show", []))  # HTTP is in clear here
    assert 1 <= len(out["top_talkers"]) <= 5 and out["top_talkers"][0]["frames_total"] >= out["top_talkers"][-1]["frames_total"]
    events = [e["event"] for e in out["timeline"]]
    assert events[0] == "first packet of the capture" and events[-1] == "last packet of the capture"
    assert any(e.startswith("first problem") for e in events)
    names = [p["pass"] for p in out["passes"]]
    assert names[:3] == ["pcap_info", "capture_quality", "conversations"] and "http_transactions" in names
    assert {n["pass"] for n in out["not_checked"]} >= {"call_kpis", "diameter_transactions"}
    assert all("no " in n["reason"] for n in out["not_checked"])


def test_focus_limits_the_passes(inc, caps: Path):
    out = inc.incident_summary(str(caps / "web.pcap"), focus="dns")
    names = {p["pass"] for p in out["passes"]}
    assert names == {"pcap_info", "capture_quality", "conversations", "dns_transactions", "icmp_errors"}
    assert {f["evidence"]["tool"] for f in out["findings"]} <= {"dns_transactions", "icmp_errors", "capture_quality"}
    bad = inc.incident_summary(str(caps / "web.pcap"), focus="email")
    assert bad["error"]["type"] == "invalid_argument"


def test_clean_dns_only_capture_and_signalling(inc, caps: Path):
    sig = inc.incident_summary(str(caps / "signalling.pcap"), focus="mobile")
    kinds = _kinds(sig)
    assert "diameter_unanswered" in kinds and "gtpv2-c_failed" in kinds
    failed = next(f for f in sig["findings"] if f["kind"] == "gtpv2-c_failed")
    assert failed["evidence"]["frames"] == [12]
    voice = inc.incident_summary(str(caps / "voice" / "call_mix.pcap"), focus="voip")
    calls = next(f for f in voice["findings"] if f["kind"] == "call_failures")
    assert calls["text"].startswith("4 of 10 calls failed (NER 66.7%") and calls["severity"] == "high"


def test_window_reaches_every_pass(inc, caps: Path):
    full = inc.incident_summary(str(caps / "dns_only.pcap"))
    part = inc.incident_summary(str(caps / "dns_only.pcap"), end="+0.2s")
    assert "dns_unanswered" in _kinds(full)
    assert part["capture"]["frames_in_window"] < full["capture"]["packets"]
    assert part["window"]["end_arg"] == "+0.2s" and "only the start/end window was read" in part["capture"]["cannot_show"]
    for f in part["findings"]:
        assert f["next_call"]["args"]["end"] == "+0.2s"


def test_budget_used_up_lists_what_was_not_checked(inc, caps: Path, monkeypatch):
    clock = iter(range(0, 10_000, 20))  # every look at the clock moves it 20 s on
    monkeypatch.setattr(srv, "_now", lambda: float(next(clock)))
    out = inc.incident_summary(str(caps / "web.pcap"), budget_s=50)
    ran = [p["pass"] for p in out["passes"]]
    assert ran[0] == "pcap_info" and len(ran) <= 3
    skipped = {n["pass"]: n["reason"] for n in out["not_checked"]}
    assert "conversations" in skipped and "time budget of 50.0s used up" in skipped["http_transactions"]


def test_runner_deadline_caps_each_run(inc, caps: Path):
    import time
    from tshark_mcp.runner import reset_deadline, set_deadline
    token = set_deadline(time.monotonic() - 1)
    try:
        out = inc.pcap_info(str(caps / "web.pcap"))
    finally:
        reset_deadline(token)
    assert out["error"]["type"] == "timeout"


async def _over_stdio(caps: Path) -> dict:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=sys.executable, args=["-m", "tshark_mcp.server", "--allow-dir", str(caps)],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return {"web": await session.call_tool("incident_summary", {"path": str(caps / "web.pcap"), "focus": "web"})}


def test_incident_summary_over_stdio(caps: Path):
    got = asyncio.run(_over_stdio(caps))
    out = got["web"].structured_content
    assert not got["web"].is_error and out["findings"][0]["severity"] == "high"
    assert "http_5xx" in [f["kind"] for f in out["findings"]]

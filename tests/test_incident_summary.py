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
    g.write_incident_coverage_pcaps(d / "cov")
    g.write_ims_pcaps(d / "ims")
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
    assert names == {"pcap_info", "capture_quality", "conversations", "dns_transactions", "icmp_errors", "expert_info"}
    assert {f["evidence"]["tool"] for f in out["findings"]} <= {"dns_transactions", "icmp_errors", "capture_quality",
                                                                "expert_info"}
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


def _by_kind(out) -> dict[str, dict]:
    return {f["kind"]: f for f in out["findings"]}


def test_sctp_and_sigtran_passes(inc, caps: Path):
    """D3: an INIT/ABORT storm, unanswered heartbeats, a MAP error and an unanswered Begin
    were all silent before the sctp_associations and sigtran_messages passes."""
    out = inc.incident_summary(str(caps / "cov" / "sctp_map.pcap"))
    TypeAdapter(models.IncidentSummaryResult).validate_python(out)
    f = _by_kind(out)
    assert f["sctp_init_rejected"]["text"] == ("192.0.2.60:2906 <-> 192.0.2.61:2905: 4 INITs and 3 ABORTs before "
                                               "the association came up")
    assert f["sctp_heartbeat_loss"]["text"].endswith("(3 of 3)")
    assert f["map_errors"]["text"] == "1 MAP/TCAP error(s) returned: systemFailure x1"
    assert f["tcap_unanswered"]["severity"] == "medium" and f["tcap_unanswered"]["evidence"]["frames"]
    # focus=mobile now runs them too, instead of only Diameter and GTPv2-C
    mobile = inc.incident_summary(str(caps / "cov" / "sctp_map.pcap"), focus="mobile")
    assert {"sctp_associations", "sigtran_messages"} <= {p["pass"] for p in mobile["passes"]}
    assert "map_errors" in _kinds(mobile)


def test_gtpv1_and_pfcp_passes(inc, caps: Path):
    out = inc.incident_summary(str(caps / "cov" / "n4_gn.pcap"), focus="mobile")
    f = _by_kind(out)
    assert f["gtpv1-c_failed"]["text"] == "1 GTPv1-C request(s) were rejected"
    assert f["gtpv1-c_failed"]["evidence"]["frames"] == [1]
    assert f["gtpv1-c_unanswered"]["evidence"]["frames"] == [3]
    assert f["pfcp_unanswered"]["text"] == "1 PFCP request(s) got no answer"
    assert f["pfcp_unanswered"]["evidence"]["args"]["view"] == "transactions"


def test_tunnel_and_quic_passes(inc, caps: Path):
    out = inc.incident_summary(str(caps / "cov" / "web_tunnels.pcap"))
    f = _by_kind(out)
    ike = f["tunnel_handshake_failed"]
    assert ike["severity"] == "high" and "IPsec 192.0.2.11 <-> 192.0.2.12 (no response)" in ike["text"]
    assert ike["next_call"] == {"tool": "tunnels_overview", "args": {"path": str(caps / "cov" / "web_tunnels.pcap"),
                                                                     "endpoint": "192.0.2.11"}}
    assert "GRE 192.0.2.1 <-> 192.0.2.2" in f["tunnel_one_way"]["text"]
    assert f["quic_failed"]["text"] == "1 of 1 QUIC connections did not complete (1 no response)"


def test_one_packet_tunnel_is_not_one_way_finding(inc, caps: Path):
    out = inc.incident_summary(str(caps / "cov" / "unanalysed.pcap"))
    assert "tunnel_one_way" not in _kinds(out)  # a single malformed GTP-U packet


def test_ims_registration_pass(inc, caps: Path):
    out = inc.incident_summary(str(caps / "ims" / "ims_register.pcap"), focus="mobile")
    f = _by_kind(out)
    failed = f["ims_registration_failed"]
    assert failed["severity"] == "high" and failed["text"].startswith("4 of 9 IMS user(s) failed to register; first: 403")
    assert failed["next_call"]["tool"] == "ims_registration" and failed["next_call"]["args"]["impu"]
    assert f["ims_challenge_loop"]["severity"] == "medium"


def test_sdp_one_way_media_is_not_one_way_audio(inc, caps: Path):
    """D8: a=recvonly offer, a=sendonly answer: RTP one way is what the call asked for."""
    p = str(caps / "cov" / "recvonly_call.pcap")
    rtp = inc.rtp_streams(p)
    assert rtp["summary"]["one_way"] == 1 and rtp["summary"]["expected_one_way"] == 1
    (stream,) = rtp["streams"]
    assert stream["expected_one_way"] == "a=recvonly in the SDP of frame 1"
    assert "as the call asks" in stream["issues"][0]
    out = inc.incident_summary(p)
    assert "one_way_audio" not in _kinds(out)
    # a sendrecv call that is one way is still a high finding
    voice = inc.incident_summary(str(caps / "voice" / "voice_problems.pcap"), focus="voip")
    assert _by_kind(voice)["one_way_audio"]["text"] == "1 of 3 RTP streams have no reverse stream (one-way audio)"


def test_not_analysed_and_expert_errors(inc, caps: Path):
    p = str(caps / "cov" / "unanalysed.pcap")
    out = inc.incident_summary(p)
    unread = {u["protocol"]: u for u in out["not_analysed"]}
    assert set(unread) == {"coap", "dhcp", "mqtt"}
    assert unread["coap"] == {"protocol": "coap", "frames": 2,
                              "next_call": {"tool": "filter_packets", "args": {"path": p, "display_filter": "coap",
                                                                                "limit": 20}}}
    assert out["summary"].endswith("; no checks exist for: coap, dhcp, mqtt")
    expert = _by_kind(out)["expert_errors"]
    assert expert["severity"] == "low" and expert["evidence"]["frames"] == [5]
    assert expert["evidence"]["args"]["severity"] == "error"
    # a capture fully covered by the passes has nothing unread
    assert inc.incident_summary(str(caps / "web.pcap"))["not_analysed"] == []


def test_not_analysed_unit():
    rows = [{"protocol": "eth/ip/udp/coap", "frames": 4}, {"protocol": "eth/ip/tcp/tls", "frames": 9},
            {"protocol": "eth/ip/sctp/s1ap", "frames": 3}, {"protocol": "eth/arp", "frames": 20},
            {"protocol": "eth/ip/udp/_ws.malformed", "frames": 1}]
    out = incident.not_analysed(rows, {"path": "/x.pcap"})
    assert [u["protocol"] for u in out] == ["coap", "s1ap"]
    assert out[1]["next_call"] == {"tool": "nas_procedures", "args": {"path": "/x.pcap"}}


def test_tls_rule_leaves_quic_to_the_quic_pass():
    """D9c: a QUIC handshake seen up to the ServerHello is not a failed TLS handshake."""
    result = {"summary": {"outcomes": {"established": 1, "server_hello": 1}},
              "connections": [{"transport": "tcp", "outcome": "established", "frame": 1},
                              {"transport": "quic", "outcome": "server_hello", "frame": 9}]}
    assert incident.from_tls(result, {"path": "/x"}) == []
    result["connections"].append({"transport": "tcp", "outcome": "alert", "frame": 20})
    result["summary"]["outcomes"]["alert"] = 1
    (f,) = incident.from_tls(result, {"path": "/x"})
    assert f["text"] == "1 of 2 TLS handshakes did not complete" and f["evidence"]["frames"] == [20]


def test_tls_pass_filters_quic_out(inc, caps: Path):
    out = inc.incident_summary(str(caps / "cov" / "web_tunnels.pcap"), focus="tls")
    assert "quic_connections" in {p["pass"] for p in out["passes"]}
    assert "tls_failed" not in _kinds(out)


async def _over_stdio(caps: Path) -> dict:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=sys.executable, args=["-m", "tshark_mcp.server", "--allow-dir", str(caps)],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return {"web": await session.call_tool("incident_summary", {"path": str(caps / "web.pcap"), "focus": "web"}),
                    "unread": await session.call_tool("incident_summary", {"path": str(caps / "cov" / "unanalysed.pcap")}),
                    "sctp": await session.call_tool("incident_summary", {"path": str(caps / "cov" / "sctp_map.pcap"),
                                                                         "focus": "mobile"})}


def test_incident_summary_over_stdio(caps: Path):
    got = asyncio.run(_over_stdio(caps))
    out = got["web"].structured_content
    assert not got["web"].is_error and out["findings"][0]["severity"] == "high"
    assert "http_5xx" in [f["kind"] for f in out["findings"]]
    unread = got["unread"].structured_content
    assert not got["unread"].is_error and [u["protocol"] for u in unread["not_analysed"]] == ["coap", "dhcp", "mqtt"]
    sctp = got["sctp"].structured_content
    assert {"sctp_init_rejected", "map_errors"} <= {f["kind"] for f in sctp["findings"]}


def test_every_next_call_runs(inc, caps: Path):
    """Each finding's and each not_analysed entry's next_call is a valid call of an existing tool."""
    for name in ("sctp_map", "n4_gn", "web_tunnels", "recvonly_call", "unanalysed"):
        out = inc.incident_summary(str(caps / "cov" / f"{name}.pcap"))
        for step in [f["next_call"] for f in out["findings"]] + [u["next_call"] for u in out["not_analysed"]]:
            result = inc.TOOLS[step["tool"]](**step["args"])
            assert "error" not in result, (name, step, result.get("error"))
    restart = incident.from_pfcp({"summary": {"peer_restarts": 1}}, {"path": "/x", "view": "transactions"})
    assert restart[0]["next_call"]["args"]["view"] == "sessions"


def test_next_call_names_the_toolset_of_an_unlisted_tool(inc, caps: Path):
    """With the default toolsets, a next_call to a mobile tool says --toolsets mobile lists it."""
    from tshark_mcp import toolsets
    p = str(caps / "cov" / "sctp_map.pcap")
    try:
        toolsets.set_active(toolsets.parse("default"))
        out = inc.incident_summary(p)
    finally:
        toolsets.set_active(toolsets.parse("all"))
    steps = {f["kind"]: f["next_call"] for f in out["findings"]}
    assert steps["sctp_init_rejected"]["tool"] == "sctp_associations" and steps["sctp_init_rejected"]["toolset"] == "mobile"
    assert steps["map_errors"]["toolset"] == "mobile"
    assert all("toolset" not in f["next_call"] for f in inc.incident_summary(p)["findings"])  # every toolset listed

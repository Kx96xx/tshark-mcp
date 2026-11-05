"""The server as a client sees it: start ``tshark-mcp`` over stdio, list the tools
and their schemas, then call every tool and check the structured output validates."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from . import pcapgen
from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark

CAPTURE_FREE_TOOLS = {"find_fields", "check_filter", "cause_lookup"}  # they read tshark's glossary, never a capture

EXPECTED_TOOLS = {
    "pfcp_sessions",
    "tcp_connections",
    "icmp_errors",
    "capture_metadata",
    "http_transactions",
    "pcap_info", "conversations", "filter_packets", "diameter_transactions", "diameter_sessions", "gtp_sessions",
    "gtp_user_plane", "sip_dialogs", "sctp_associations", "sigtran_messages", "trace_subscriber", "find_identifier",
    "diameter_avps", "compare_captures", "gtp_tunnel_health", "message_rates",
    "gtpv1_sessions", "dns_transactions", "tls_handshakes", "capture_quality", "rtp_streams", "tcp_health", "sip_call_detail", "packet_detail", "response_times", "expert_info", "media_path_check", "dtmf_events", "ims_registration", "sms_over_ims", "find_fields", "check_filter",
    "cause_lookup",
    "call_kpis",
    "gtp_ies",
    "roaming_attach_check",
    "capture_index",
    "incident_summary",
    "diff_captures",
    "throughput_timeline",
}


def _attr(obj: Any, *names: str) -> Any:
    """mcp 2.x uses snake_case attributes, 1.x camelCase; accept either."""
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return None


def _calls(pcap_dir: Path) -> list[tuple[str, dict[str, Any]]]:
    d = str(pcap_dir)
    return [
        ("pcap_info", {"path": f"{d}/diameter.pcap"}),
        ("pfcp_sessions", {"path": f"{d}/all.pcap"}),
        ("conversations", {"path": f"{d}/gtpv2.pcap", "layer": "udp", "filter": "gtpv2"}),
        ("filter_packets", {"path": f"{d}/diameter.pcap", "display_filter": "diameter.cmd.code == 318"}),
        ("diameter_transactions", {"path": f"{d}/diameter.pcap"}),
        ("diameter_sessions", {"path": f"{d}/diameter.pcap", "imsi": pcapgen.IMSI}),
        ("gtp_sessions", {"path": f"{d}/gtpv2.pcap", "teid": "0xc001"}),
        ("gtp_user_plane", {"path": f"{d}/gtpu.pcap"}),
        ("gtp_ies", {"path": f"{d}/gtpv2.pcap", "message": "Create Session Request"}),
        ("roaming_attach_check", {"path": f"{d}/gtpv2.pcap", "imsi": pcapgen.IMSI_OTHER}),
        ("sip_dialogs", {"path": f"{d}/sip.pcap", "method": "INVITE"}),
        ("sctp_associations", {"path": f"{d}/sctp.pcap"}),
        ("sigtran_messages", {"path": f"{d}/sigtran.pcap"}),
        ("trace_subscriber", {"path": f"{d}/all.pcap", "imsi": pcapgen.IMSI, "msisdn": pcapgen.MSISDN}),
        ("find_identifier", {"path": d, "identifier": pcapgen.IMSI, "max_files": 3}),
        ("capture_index", {"path": d, "start": "+1s", "max_files": 5}),
        ("incident_summary", {"path": f"{d}/all.pcap", "focus": "mobile"}),
        ("diff_captures", {"path_a": f"{d}/all.pcap", "path_b": f"{d}/sip.pcap", "by": "tcp"}),
        ("throughput_timeline", {"path": f"{d}/sip.pcap", "interval": 5, "per": "conversation"}),
        ("diameter_avps", {"path": f"{d}/diameter.pcap", "command_code": 316}),
        ("gtp_tunnel_health", {"path": f"{d}/gtpu.pcap"}),
        ("message_rates", {"path": f"{d}/all.pcap", "interval": 10}),
        ("gtpv1_sessions", {"path": f"{d}/gtpv2.pcap"}),
        ("capture_quality", {"path": f"{d}/all.pcap"}),
        ("capture_metadata", {"path": f"{d}/diameter.pcap"}),
        ("rtp_streams", {"path": f"{d}/voice/voice_call.pcap", "call_id": pcapgen.CALL_ID_VOICE}),
        ("tcp_health", {"path": f"{d}/sip.pcap"}),
        ("tcp_connections", {"path": f"{d}/sip.pcap", "view": "destinations"}),
        ("icmp_errors", {"path": f"{d}/all.pcap", "kind": "frag_needed"}),
        ("http_transactions", {"path": f"{d}/all.pcap", "view": "endpoints"}),
        ("sip_call_detail", {"path": f"{d}/voice/voice_call.pcap", "call_id": pcapgen.CALL_ID_VOICE}),
        ("packet_detail", {"path": f"{d}/diameter.pcap", "frame": 1, "layers": ["diameter"]}),
        ("expert_info", {"path": f"{d}/all.pcap", "severity": "note"}),
        ("media_path_check", {"path": f"{d}/voice/voice_problems.pcap", "call_id": pcapgen.CALL_ID_NAT}),
        ("dtmf_events", {"path": f"{d}/voice/voice_dtmf.pcap"}),
        ("call_kpis", {"path": f"{d}/voice/call_mix.pcap", "group_by": "destination_prefix"}),
        ("ims_registration", {"path": f"{d}/ims/ims_register.pcap"}),
        ("sms_over_ims", {"path": f"{d}/ims/ims_sms.pcap"}),
        ("find_fields", {"query": "result code", "protocol": "diameter", "limit": 5}),
        ("check_filter", {"filter": "gtp.teid == 0x100000000"}),
        ("cause_lookup", {"protocol": "diameter", "code": 5004, "application": "s6a"}),
        ("compare_captures", {"path_a": f"{d}/all.pcap", "path_b": f"{d}/diameter.pcap", "imsi": pcapgen.IMSI}),
        # Error paths must come back as structured errors, never as protocol failures.
        ("pcap_info", {"path": "/definitely/not/allowed.pcap"}),
        ("gtp_sessions", {"path": f"{d}/gtpv2.pcap", "apn": "bad;apn"}),
    ]


async def _session(pcap_dir: Path, log_path: Path):
    env = dict(os.environ)
    env["TSHARK_MCP_TSHARK"] = TSHARK
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "tshark_mcp.server", "--allow-dir", str(pcap_dir), "--log-file", str(log_path)],
        env=env,
    )
    return stdio_client(params)


async def _run(pcap_dir: Path, log_path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    async with await _session(pcap_dir, log_path) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            out["server_name"] = _attr(init, "server_info", "serverInfo").name
            listed = await session.list_tools()
            out["tools"] = {t.name: t for t in listed.tools}
            out["results"] = []
            for name, args in _calls(pcap_dir):
                out["results"].append((name, args, await session.call_tool(name, args)))
    return out


@pytest.fixture(scope="module")
def client_run(pcap_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    log_path = tmp_path_factory.mktemp("client") / "audit.jsonl"
    data = asyncio.run(_run(pcap_dir, log_path))
    data["log_path"] = log_path
    return data


def test_server_identity(client_run):
    assert client_run["server_name"] == "tshark-mcp"


def test_list_tools_names_and_schemas(client_run):
    tools = client_run["tools"]
    assert set(tools) == EXPECTED_TOOLS
    for name, tool in tools.items():
        input_schema = _attr(tool, "input_schema", "inputSchema")
        output_schema = _attr(tool, "output_schema", "outputSchema")
        assert input_schema["type"] == "object", name
        assert ("path" in input_schema["properties"] or {"path_a", "path_b"} <= set(input_schema["properties"])
                or name in CAPTURE_FREE_TOOLS), name
        assert output_schema is not None and output_schema["type"] == "object", name
        assert "error" in output_schema["properties"], name
        assert tool.title, name
        assert tool.description and len(tool.description) > 40, name
        ann = tool.annotations
        assert _attr(ann, "read_only_hint", "readOnlyHint") is True, name
        assert _attr(ann, "idempotent_hint", "idempotentHint") is True, name
        assert getattr(ann, "open_world_hint", getattr(ann, "openWorldHint", None)) is False, name
        assert getattr(ann, "destructive_hint", getattr(ann, "destructiveHint", None)) is False, name
        # Every tool takes the per-call redaction level, and only the three modes.
        redact_schema = input_schema["properties"]["redact"]
        assert "redact" not in input_schema.get("required", []), name
        assert {"off", "ids", "ids+ips"} <= set(json.dumps(redact_schema).replace('"', " ").split()), name

    def props(name: str) -> dict[str, Any]:
        return _attr(tools[name], "input_schema", "inputSchema")["properties"]

    SHAPING = ("columns", "output", "max_output_kb")  # every row tool (one with limit) takes them
    assert {"path", "identifier", "kind", "max_files", "offset", "start", "end", "redact"} == set(props("find_identifier"))
    assert {"path", "session_id", "imsi", "command_code", "filter", "limit", "offset", "start", "end", "redact", *SHAPING} == set(props("diameter_sessions"))
    assert {"path", "imsi", "apn", "teid", "filter", "limit", "offset", "start", "end", "redact", *SHAPING} == set(props("gtp_sessions"))
    assert {"path", "call_id", "number", "method", "filter", "limit", "offset", "start", "end", "redact", *SHAPING} == set(props("sip_dialogs"))
    assert {"path", "layer", "filter", "limit", "offset", "start", "end", "redact", *SHAPING} == set(props("conversations"))
    # The paging contract: every tool that takes a row limit also takes an offset and
    # reports total_matched / returned / dropped / next_offset.
    for name in tools:
        if "limit" in props(name):
            assert "offset" in props(name), name
            assert set(SHAPING) <= set(props(name)), name
            assert {"total_matched", "returned", "dropped", "offset", "next_offset"} <= set(
                _attr(tools[name], "output_schema", "outputSchema")["properties"]), name

    def out_props(name: str) -> dict[str, Any]:
        return _attr(tools[name], "output_schema", "outputSchema")["properties"]

    assert "sessions" in out_props("diameter_sessions") and "files" in out_props("find_identifier")
    assert "transactions" in out_props("gtp_sessions") and "dialogs" in out_props("sip_dialogs")
    assert "timeline" in out_props("trace_subscriber") and "conversations" in out_props("conversations")


def test_every_tool_call_returns_structured_content(client_run):
    results = client_run["results"]
    assert len(results) == len(_calls(Path("/x")))
    for name, args, result in results:
        structured = _attr(result, "structured_content", "structuredContent")
        assert isinstance(structured, dict), (name, result)
        assert result.content and result.content[0].type == "text", name
        if "error" in structured:
            # Errors are flagged isError and keep the structured error, the fix hint and the same JSON as text.
            assert _attr(result, "is_error", "isError") is True, (name, result)
            assert args in ({"path": "/definitely/not/allowed.pcap"}, {"path": args.get("path"), "apn": "bad;apn"}), (name, structured)
            assert structured["error"]["type"] in ("path_not_allowed", "invalid_argument")
            assert structured["error"]["fix"], structured
            assert json.loads(result.content[0].text) == structured
        else:
            assert _attr(result, "is_error", "isError") in (None, False), (name, result)
    errors = [_attr(r, "structured_content", "structuredContent")["error"] for _, _, r in results[-2:]]
    assert errors[0]["type"] == "path_not_allowed" and errors[0]["allowed_dirs"]
    assert errors[1]["type"] == "invalid_argument"

    # Every call but the last two is a happy path, one per tool; the last two are the error paths.
    by_name = {(n, tuple(sorted(a))): _attr(r, "structured_content", "structuredContent") for n, a, r in results[:-2]}
    info = by_name[("pcap_info", ("path",))]
    assert info["packets"] == 7 and info["protocol_hierarchy"][0]["frames"] == 7

    sessions = by_name[("diameter_sessions", ("imsi", "path"))]
    assert sessions["count"] == 2 and sessions["sessions"][0]["transactions"][0]["answer"] == "ULA"

    gtp = by_name[("gtp_sessions", ("path", "teid"))]
    assert [t["message"] for t in gtp["transactions"]] == ["Create Session Request", "Delete Session Request"]
    assert gtp["transactions"][0]["response_fteids"][0]["interface"].startswith("S5/S8")

    found = by_name[("find_identifier", ("identifier", "max_files", "path"))]
    assert found["files_scanned"] == 3 and found["kind"] == "subscriber"
    summary = by_name[("incident_summary", ("focus", "path"))]
    assert summary["findings"] and {f["evidence"]["tool"] for f in summary["findings"]} <= {
        "diameter_transactions", "gtp_sessions", "capture_quality"}
    tput = by_name[("throughput_timeline", ("interval", "path", "per"))]
    assert tput["interval_s"] == 5 and tput["summary"]["packets"] > 0 and tput["series"]
    changed = by_name[("diff_captures", ("by", "path_a", "path_b"))]
    assert changed["by"] == "tcp" and "tcp" in changed["summary"] and changed["a"]["packets"] > changed["b"]["packets"]
    index = by_name[("capture_index", ("max_files", "path", "start"))]
    assert index["files_indexed"] == 5 and index["files"][0]["first_epoch"] <= index["files"][-1]["first_epoch"]
    assert index["summary"]["window_files"] and "window_covered" in index["summary"]

    trace = by_name[("trace_subscriber", ("imsi", "msisdn", "path"))]
    assert trace["by_protocol"] == {"diameter": 2, "gtpv2": 2, "sip": 1, "map": 3}
    sip_row = next(r for r in trace["timeline"] if r["protocol"] == "sip")
    assert sip_row["call_id"] == "a1b2c3d4@ue.example"  # an extra key kept by the open row model

    avp = by_name[("diameter_avps", ("command_code", "path"))]
    assert avp["transactions"][0]["request_avps"]["ULR-Flags"].startswith("34 [")

    v1 = by_name[("gtpv1_sessions", ("path",))]
    assert v1["transactions"] == [] and v1["total_found"] == 0

    rates = by_name[("message_rates", ("interval", "path"))]
    assert rates["distinct_messages"] > 0 and rates["by_message"][0]["distinct"] >= 1

    health = by_name[("gtp_tunnel_health", ("path",))]
    assert health["summary"]["tunnels"] >= 1 and "outer_icmp" in health

    diff = by_name[("compare_captures", ("imsi", "path_a", "path_b"))]
    assert diff["a"]["steps"] > diff["b"]["steps"] and diff["first_divergence"]["op"] == "only_a"

    conns = by_name[("tcp_connections", ("path", "view"))]
    assert conns["view"] == "destinations" and "by_outcome" in conns["summary"]
    icmp = by_name[("icmp_errors", ("kind", "path"))]
    assert "by_kind" in icmp["summary"] and isinstance(icmp["errors"], list)
    meta = by_name[("capture_metadata", ("path",))]
    assert meta["metadata_available"] is False and meta["file"]["format"] == "pcap"
    cause = by_name[("cause_lookup", ("application", "code", "protocol"))]
    assert cause["name"] == "DIAMETER_ERROR_ROAMING_NOT_ALLOWED" and cause["avp"] == "Experimental-Result-Code"
    assert cause["ref"].startswith("TS 29.272") and "Error-Diagnostic" in cause["application_note"]
    http = by_name[("http_transactions", ("path", "view"))]
    assert http["view"] == "endpoints" and "status_mix" in http["summary"]
    kpis = by_name[("call_kpis", ("group_by", "path"))]
    assert {r["destination_prefix"]: r["asr_pct"] for r in kpis["groups"]} == {"4477": 40.0, "1555": 50.0}
    assert kpis["summary"]["calls"] == 10 and kpis["worst_calls"][0]["frame"] > 0
    roam = by_name[("roaming_attach_check", ("imsi", "path"))]
    (attempt,) = roam["attempts"]
    assert attempt["first_failure"]["code"] == 78 and "Create Session failed" in attempt["verdict"]
    assert any(c["check"] == "subscription" and c["result"] == "unknown" for c in attempt["checks"])

    ies = by_name[("gtp_ies", ("message", "path"))]
    rejected = next(t for t in ies["transactions"] if t.get("cause") == 78)
    assert rejected["request_ies"]["apn"] == "bogus.apn" and "'bogus.apn'" in rejected["likely_causes"][0]
    assert "request_ies" in ies["untrusted_text_fields"]

    dialogs = by_name[("sip_dialogs", ("method", "path"))]
    assert dialogs["dialogs"][0]["from"].startswith("sip:+")


def test_audit_log_has_one_line_per_call(client_run):
    import json
    lines = [json.loads(ln) for ln in Path(client_run["log_path"]).read_text().splitlines()]
    assert [ln["tool"] for ln in lines] == [name for name, _ in _calls(Path("/x"))]
    assert lines[-2]["status"] == "path_not_allowed" and lines[-1]["status"] == "invalid_argument"

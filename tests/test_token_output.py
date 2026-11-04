"""Token-aware output: columns projection, output=summary, max_output_kb and tokens_estimate."""

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

from tshark_mcp import output as shaping
from tshark_mcp import models

from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark


def _size(result: dict[str, Any]) -> int:
    return len(json.dumps(result, separators=(",", ":")).encode())


def test_every_result_carries_tokens_estimate(server, pcap_dir: Path):
    result = server.gtp_sessions(path=str(pcap_dir / "gtpv2.pcap"))
    assert "error" not in result
    estimate = result.pop("tokens_estimate")
    assert abs(estimate - _size(result) / shaping.BYTES_PER_TOKEN) < 20
    assert "tokens_estimate" in server.pcap_info(path=str(pcap_dir / "gtpv2.pcap"))
    assert "tokens_estimate" not in server.pcap_info(path=str(pcap_dir / "missing.pcap"))


def test_columns_keep_named_keys_and_frame_keys(server, pcap_dir: Path):
    full = server.gtp_sessions(path=str(pcap_dir / "gtpv2.pcap"))
    slim = server.gtp_sessions(path=str(pcap_dir / "gtpv2.pcap"), columns=["message"])
    assert slim["columns"] == ["message"]
    assert slim["total_matched"] == full["total_matched"] and slim["transactions"]
    for row in slim["transactions"]:
        assert "message" in row and "request_frame" in row
        assert set(row) <= {"message"} | {k for k in row if shaping.is_frame_key(k)}
    assert slim["tokens_estimate"] < full["tokens_estimate"]


def test_unknown_column_names_the_valid_ones(server, pcap_dir: Path):
    err = server.gtp_sessions(path=str(pcap_dir / "gtpv2.pcap"), columns=["nonsense"])["error"]
    assert err["type"] == "invalid_argument" and "valid columns" in err["message"] and "cause" in err["message"]
    assert err["fix"]
    bad = server.gtp_sessions(path=str(pcap_dir / "gtpv2.pcap"), columns=["a;b"])["error"]
    assert bad["type"] == "invalid_argument"


def test_columns_on_untyped_rows_are_checked_against_the_rows(server, pcap_dir: Path):
    path = str(pcap_dir / "gtpv2.pcap")
    ok = server.filter_packets(path=path, display_filter="gtpv2", fields=["frame.number", "gtpv2.message_type", "ip.src"],
                               columns=["gtpv2.message_type"])
    assert "error" not in ok and ok["packets"], ok
    assert all("ip.src" not in row and "gtpv2.message_type" in row for row in ok["packets"])
    err = server.filter_packets(path=path, display_filter="gtpv2", fields=["frame.number"], columns=["nothere"])
    assert err["error"]["type"] == "invalid_argument" and "valid columns" in err["error"]["message"]


def test_summary_keeps_three_rows_and_pages_from_there(server, pcap_dir: Path):
    path = str(pcap_dir / "all.pcap")
    full = server.conversations(path=path)
    assert full["returned"] > shaping.SUMMARY_ROWS
    summary = server.conversations(path=path, output="summary")
    assert summary["output"] == "summary"
    assert summary["returned"] == shaping.SUMMARY_ROWS == len(summary["conversations"])
    assert summary["next_offset"] == shaping.SUMMARY_ROWS
    assert summary["total_matched"] == full["total_matched"]
    assert summary["truncated"] and "output='rows' and offset=3" in summary["truncated_reason"]
    assert summary["conversations"] == full["conversations"][:3]
    rest = server.conversations(path=path, offset=summary["next_offset"])
    assert rest["conversations"][0] == full["conversations"][3]


ROW_CALLS = [
    ("conversations", "all.pcap", {}),
    ("gtp_sessions", "all.pcap", {}),
    ("diameter_sessions", "all.pcap", {}),
    ("diameter_transactions", "all.pcap", {}),
    ("sip_dialogs", "all.pcap", {}),
    ("trace_subscriber", "all.pcap", {"imsi": "001010123456789"}),
    ("message_rates", "all.pcap", {"protocol": "diameter"}),
    ("expert_info", "all.pcap", {}),
    ("tcp_health", "all.pcap", {}),
    ("filter_packets", "all.pcap", {"display_filter": "frame"}),
]


@pytest.mark.parametrize("tool,capture,args", ROW_CALLS, ids=[c[0] for c in ROW_CALLS])
def test_summary_fits_four_kb(server, pcap_dir: Path, tool: str, capture: str, args: dict[str, Any]):
    result = getattr(server, tool)(path=str(pcap_dir / capture), output="summary", **args)
    assert "error" not in result, result
    assert _size(result) <= shaping.SUMMARY_MAX_BYTES, (tool, _size(result))


def test_max_output_kb_only_lowers_the_cap(server, pcap_dir: Path):
    path = str(pcap_dir / "all.pcap")
    small = server.conversations(path=path, max_output_kb=1)
    assert _size(small) <= 1024 and small["truncated"] and small["next_offset"]
    big = server.conversations(path=path, max_output_kb=100000)
    assert big == {**server.conversations(path=path), "tokens_estimate": big["tokens_estimate"]}
    for bad in (0, -1, "lots", float("nan")):
        err = server.conversations(path=path, max_output_kb=bad)["error"]
        assert err["type"] == "invalid_argument" and "max_output_kb" in err["message"]


def test_bad_output_mode_is_an_error(server, pcap_dir: Path):
    err = server.conversations(path=str(pcap_dir / "all.pcap"), output="everything")["error"]
    assert err["type"] == "invalid_argument" and "output must be one of" in err["message"]


def test_row_keys_come_from_the_models():
    keys = shaping.row_keys(models.GtpSessionsResult)
    assert keys and "cause" in keys and "request_frame" in keys
    assert shaping.row_keys(models.FilterPacketsResult) is None


# ------------------------------------------------------------------ through the MCP stdio client
async def _client(pcap_dir: Path) -> dict[str, Any]:
    env = dict(os.environ)
    env["TSHARK_MCP_TSHARK"] = TSHARK
    params = StdioServerParameters(command=sys.executable, args=["-m", "tshark_mcp.server", "--allow-dir", str(pcap_dir)],
                                   env=env)
    path = str(pcap_dir / "gtpv2.pcap")
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name: t for t in (await session.list_tools()).tools}
            projected = await session.call_tool("gtp_sessions", {"path": path, "columns": ["message"], "output": "summary",
                                                                 "max_output_kb": 2})
            plain = await session.call_tool("pcap_info", {"path": path})
    return {"tools": tools, "projected": projected, "plain": plain}


def test_shaping_arguments_over_stdio(pcap_dir: Path):
    out = asyncio.run(_client(pcap_dir))
    for name, tool in out["tools"].items():
        props = (getattr(tool, "input_schema", None) or tool.inputSchema)["properties"]
        if "limit" in props:
            assert {"columns", "output", "max_output_kb"} <= set(props), name
        else:
            assert not {"columns", "output", "max_output_kb"} & set(props), name
    structured = out["projected"].structured_content
    assert "error" not in structured, structured
    assert structured["output"] == "summary" and structured["columns"] == ["message"]
    assert structured["tokens_estimate"] > 0 and _size(structured) <= 2048
    assert all(set(r) <= {"message", "request_frame", "answer_frame"} | {k for k in r if shaping.is_frame_key(k)}
               for r in structured["transactions"])
    assert out["plain"].structured_content["tokens_estimate"] > 0

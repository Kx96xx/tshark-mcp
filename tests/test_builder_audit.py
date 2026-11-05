"""mcp-builder audit fixes: compact JSON text (G2), has_more (G4), columns enum (G7), summary rows (G11),
checked through the real MCP stdio client."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark


async def _calls(pcap_dir: Path) -> dict:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=sys.executable, args=["-m", "tshark_mcp.server", "--allow-dir", str(pcap_dir)],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))
    diameter = str(pcap_dir / "diameter.pcap")
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            calls = {
                "info": ("pcap_info", {"path": diameter}),
                "page1": ("diameter_transactions", {"path": diameter, "limit": 1}),
                "all": ("diameter_transactions", {"path": diameter}),
                "ims": ("ims_registration", {"path": str(pcap_dir / "ims" / "ims_register.pcap"), "output": "summary"}),
                "legs": ("call_legs", {"path": str(pcap_dir / "voice" / "call_legs.pcap"), "output": "summary"}),
                "bad_column": ("diameter_transactions", {"path": diameter, "columns": ["nope"]}),
            }
            out = {k: await session.call_tool(name, args) for k, (name, args) in calls.items()}
            tools = {t.name: t for t in (await session.list_tools()).tools}
            out["schema"] = await session.read_resource("schema://tools/diameter_transactions")
            out["tools"] = tools
            return out


def test_builder_audit_over_stdio(pcap_dir: Path):
    got = asyncio.run(_calls(pcap_dir))
    # G2: the text is compact JSON, one line, and parses to exactly structuredContent (errors too).
    for key in ("info", "page1", "all", "ims", "legs", "bad_column"):
        result = got[key]
        text = result.content[0].text
        assert text == json.dumps(result.structured_content, separators=(",", ":"), ensure_ascii=False), key
        assert json.loads(text) == result.structured_content, key
    # G4: has_more next to next_offset.
    page1, everything = got["page1"].structured_content, got["all"].structured_content
    assert page1["has_more"] is True and page1["next_offset"] == 1
    assert everything["has_more"] is False and "next_offset" not in everything
    assert "has_more" not in got["info"].structured_content  # not a paged result
    # G11: output="summary" keeps its three rows on wide rows (it returned 1 of 3 under a 4 KB cap).
    assert len(got["ims"].structured_content["registrations"]) == 3
    assert len(got["legs"].structured_content["calls"]) == 3
    # G7: an unknown column is still the server's own error with the valid names and a fix.
    bad = got["bad_column"]
    assert bad.is_error and bad.structured_content["error"]["type"] == "invalid_argument"
    assert "valid columns:" in bad.structured_content["error"]["message"]
    # The compact list has no columns enum; the schema resource (full) has it.
    listed = got["tools"]["diameter_transactions"].input_schema["properties"]["columns"]
    assert "enum" not in json.dumps(listed) and listed["description"]
    full = json.loads(got["schema"].contents[0].text)
    arrays = [v for v in full["inputSchema"]["properties"]["columns"]["anyOf"] if v.get("type") == "array"]
    assert "result_code" in arrays[0]["items"]["enum"]
    # G1: every listed argument has a description.
    assert all(p.get("description") for t in got["tools"].values() for p in t.input_schema["properties"].values())

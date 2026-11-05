"""Toolsets: a small default tools/list, the rest opt-in with --toolsets."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from tshark_mcp import prompts, server, toolsets

from .conftest import TSHARK, requires_tshark


def _restore_all():
    toolsets.set_active(toolsets.parse("all"))


def test_parse():
    assert toolsets.parse(None) == {"default"}
    assert toolsets.parse("mobile, voice") == {"default", "mobile", "voice"}
    assert toolsets.parse("ALL") == {"default", "mobile", "voice", "network"}
    with pytest.raises(ValueError, match="unknown toolset.*email.*choose from default, mobile, voice, network, all"):
        toolsets.parse("email")


def test_every_tool_has_a_toolset_and_default_is_small():
    missing = [n for n, fn in server.TOOLS.items() if toolsets.of(n, fn) is None]
    assert not missing, f"give these tools a toolset (toolsets.SERVER_TOOLS, or TOOLSET = ... in their module): {missing}"
    assert not set(toolsets.SERVER_TOOLS) - set(server.TOOLS), "SERVER_TOOLS names a tool that does not exist"
    default = [n for n, fn in server.TOOLS.items() if toolsets.of(n, fn) == "default"]
    assert 25 <= len(default) <= 35, len(default)
    assert {"incident_summary", "pcap_info", "capture_quality", "filter_packets", "packet_detail", "cause_lookup",
            "trace_subscriber", "tcp_connections", "sip_dialogs"} <= set(default)
    assert toolsets.of("diameter_peers", server.TOOLS["diameter_peers"]) == "mobile"  # from its module


def _sizes() -> dict[str, int]:
    tools = asyncio.run(server.app.list_tools())
    return {t.name: len(json.dumps(t.model_dump(mode="json", by_alias=True, exclude_none=True), separators=(",", ":")))
            for t in tools}


def test_default_list_is_smaller_and_prompts_follow_it():
    try:
        everything = _sizes()
        toolsets.set_active(toolsets.parse("default"))
        default = _sizes()
        listed_prompts = {p.name for p in asyncio.run(server.app.list_prompts())}
        toolsets.set_active(toolsets.parse("mobile,network"))
        with_more = {p.name for p in asyncio.run(server.app.list_prompts())}
    finally:
        _restore_all()
    assert len(everything) == len(server.TOOLS) and set(default) < set(everything)
    # tools/list is at most two thirds of the full one in bytes (about 4 bytes per token).
    assert sum(default.values()) * 3 <= sum(everything.values()) * 2, (sum(default.values()), sum(everything.values()))
    # every listed prompt names only listed tools
    assert "slow_data_session" not in listed_prompts and "one_way_audio" in listed_prompts
    for name in listed_prompts:
        assert prompts.prompt_tools(name) & set(server.TOOLS) <= set(default), name
    assert "slow_data_session" in with_more


@requires_tshark
def test_default_and_all_over_stdio(tmp_path: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def go(extra: list[str]) -> tuple[set[str], set[str], bool]:
        env = {k: v for k, v in os.environ.items() if k != "TSHARK_MCP_TOOLSETS"}
        params = StdioServerParameters(command=sys.executable, env=dict(env, TSHARK_MCP_TSHARK=TSHARK),
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path), *extra])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {t.name for t in (await session.list_tools()).tools}
                names_p = {p.name for p in (await session.list_prompts()).prompts}
                # an unlisted tool still answers a call by name (incident_summary's next_call)
                result = await session.call_tool("sigtran_health", {"path": str(tmp_path / "missing.pcap")})
                return names, names_p, result.structured_content["error"]["type"] == "not_found"

    default, default_prompts, answered = asyncio.run(go([]))
    assert answered and "incident_summary" in default and "sigtran_health" not in default
    assert len(default) == sum(1 for n, fn in server.TOOLS.items() if toolsets.of(n, fn) == "default")
    assert len(default_prompts) == len(prompts.PROMPTS) - 1
    voice, _, _ = asyncio.run(go(["--toolsets", "voice"]))
    assert voice - default == {n for n, fn in server.TOOLS.items() if toolsets.of(n, fn) == "voice"}
    everything, all_prompts, _ = asyncio.run(go(["--toolsets", "all"]))
    assert everything == set(server.TOOLS) and all_prompts == set(prompts.PROMPTS)


def test_unknown_toolset_refuses_to_start(tmp_path: Path, capsys):
    assert server.main(["--allow-dir", str(tmp_path), "--toolsets", "email"]) == 2
    assert "unknown toolset(s) email" in capsys.readouterr().err

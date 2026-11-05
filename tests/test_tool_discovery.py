"""Tool registration by discovery: every module of tshark_mcp/tools/ registers its tool when the
server loads, with no shared list to edit; the registry (server.TOOLS) is the one source of the
tool set, in-process and over stdio."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tshark_mcp import server, tools

from .conftest import requires_tshark


def test_registry_matches_the_published_tool_list():
    listed = [t.name for t in asyncio.run(server.app.list_tools())]
    assert listed == server.tool_names()
    assert len(set(listed)) == len(listed)


def test_every_tool_module_registers_and_is_reachable_on_server():
    assert "diameter_peers" in tools.modules()
    by_module: dict[str, list[str]] = {}
    for name, fn in server.TOOLS.items():
        by_module.setdefault(fn.__module__, []).append(name)
        assert getattr(server, name) is fn, name
    for module in tools.modules():
        assert by_module.get(f"tshark_mcp.tools.{module}"), f"tools/{module}.py registered no tool"
    assert by_module["tshark_mcp.tools.diameter_peers"] == ["diameter_peers"]
    # Discovered tools come after the ones defined in server.py, in module name order.
    discovered = [n for n, fn in server.TOOLS.items() if fn.__module__.startswith("tshark_mcp.tools.")]
    assert server.tool_names()[-len(discovered):] == discovered


def test_a_name_registered_twice_is_refused():
    with pytest.raises(RuntimeError, match="registered twice"):
        @server._tool(title="dup", annotations=server.READ_ONLY)
        def pcap_info(path: str) -> dict:  # noqa: F811
            """A second pcap_info."""
            return {}


NEW_TOOL = '''
"""A tool module dropped into the package: nothing else is edited."""
from __future__ import annotations

from typing import Any

from ..server import READ_ONLY, _tool


@_tool(title="Discovery probe", annotations=READ_ONLY)
def discovery_probe(word: str) -> dict[str, Any]:
    """Echo a word back; exists only to show a new module is found and served without edits."""
    return {"word": word}
'''


def test_a_new_module_is_discovered_without_editing_anything(tmp_path: Path):
    """Run in a child process (the registry is global): add a directory to the package path
    holding one new module, import the server and call the tool."""
    (tmp_path / "zz_discovery_probe.py").write_text(NEW_TOOL)
    code = textwrap.dedent(f"""
        import asyncio, json
        import tshark_mcp.tools as tools
        tools.__path__.append({str(tmp_path)!r})
        from tshark_mcp import server
        names = server.tool_names()
        listed = [t.name for t in asyncio.run(server.app.list_tools())]
        print(json.dumps({{"last": names[-1], "listed": "discovery_probe" in listed,
                          "result": server.discovery_probe("hi"), "n": len(names)}}))
    """)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert data["last"] == "discovery_probe" and data["listed"] is True
    assert data["result"] == {"word": "hi"}
    assert data["n"] == len(server.TOOLS) + 1


@requires_tshark
def test_python_dash_m_serves_the_discovered_tools(tmp_path: Path):
    """``python -m tshark_mcp.server`` must not run a second copy of server.py that lacks the
    tools registered by tools/ modules: the real MCP stdio client lists and calls one."""
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def go() -> tuple[set[str], bool]:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path), "--toolsets", "all"])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {t.name for t in (await session.list_tools()).tools}
                result = await session.call_tool("diameter_peers", {"path": str(tmp_path / "missing.pcap")})
                return names, bool(result.isError if hasattr(result, "isError") else result.is_error)

    names, is_error = asyncio.run(go())
    assert names == set(server.TOOLS)
    assert is_error  # a structured not_found error from the discovered tool, not "unknown tool"

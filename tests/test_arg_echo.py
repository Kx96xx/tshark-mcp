"""Error messages quote an over-long argument by its first characters and its length, never in full."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from tshark_mcp.limits import ECHO_MAX_CHARS, MESSAGE_MAX_CHARS, ToolError, clip, echo, lint_digits

from .conftest import TSHARK, requires_tshark

LONG = "x" * 5000
ERROR_BUDGET = 2500  # bytes of JSON for any error, with its fix hint, whatever the argument


def _err(result: dict[str, Any]) -> dict[str, Any]:
    assert "error" in result, result
    return result["error"]


def test_echo_keeps_short_values_as_repr():
    assert echo("abc") == "'abc'"
    assert echo(42) == "42"
    assert echo("/a/b", quote=False) == "/a/b"


def test_echo_cuts_long_values_and_names_their_length():
    text = echo(LONG)
    assert len(text) < ECHO_MAX_CHARS + 40
    assert text.startswith("'xxx") and text.endswith("... (5000 characters)")
    assert echo(LONG, quote=False).endswith("... (5000 characters)")


def test_echo_survives_an_unprintable_value():
    class Bad:
        def __repr__(self) -> str:
            raise RuntimeError("no")

    assert echo(Bad()) == "<Bad>"


def test_clip_and_tool_error_cap_message_and_text_details():
    assert clip("short") == "short"
    long_message = "m" * 5000
    assert clip(long_message).endswith(f"(cut at {MESSAGE_MAX_CHARS} of 5000 characters)")
    err = ToolError("invalid_filter", long_message, display_filter="f" * 5000, count=3)
    assert len(err.message) < MESSAGE_MAX_CHARS + 60
    assert len(err.details["display_filter"]) < MESSAGE_MAX_CHARS + 60
    assert err.details["count"] == 3


def test_shared_imsi_validation_does_not_echo_in_full():
    try:
        lint_digits(LONG, "imsi")
    except ToolError as exc:
        assert "(5000 characters)" in exc.message and len(exc.message) < 200
    else:
        raise AssertionError("expected a ToolError")


@requires_tshark
def test_gtp_ies_message_is_not_echoed_in_full(server, pcap_dir: Path):
    err = _err(server.gtp_ies(path=str(pcap_dir / "gtpv2.pcap"), message=LONG))
    assert err["type"] == "invalid_argument"
    assert "(5000 characters)" in err["message"]
    assert len(json.dumps(err)) < ERROR_BUDGET


@requires_tshark
def test_trace_subscriber_imsi_is_not_echoed_in_full(server, pcap_dir: Path):
    err = _err(server.trace_subscriber(path=str(pcap_dir / "diameter.pcap"), imsi=LONG))
    assert err["type"] == "invalid_argument" and len(json.dumps(err)) < ERROR_BUDGET


@requires_tshark
def test_long_path_is_not_echoed_in_full(server, pcap_dir: Path):
    err = _err(server.pcap_info(path=str(pcap_dir / ("a" * 200)) + "/" + "b" * 4000 + ".pcap"))
    assert len(json.dumps(err)) < ERROR_BUDGET, err


# ------------------------------------------------------------------ through the MCP stdio client
def _string_props(schema: dict[str, Any]) -> list[str]:
    """Arguments of a tool that accept a string (alone or among other types), except redact."""
    out = []
    for name, prop in (schema.get("properties") or {}).items():
        if name == "redact":
            continue
        if '"string"' in json.dumps(prop):
            out.append(name)
    return out


async def _sweep(pcap_dir: Path) -> list[tuple[str, str, Any]]:
    env = dict(os.environ)
    env["TSHARK_MCP_TSHARK"] = TSHARK
    params = StdioServerParameters(command=sys.executable, args=["-m", "tshark_mcp.server", "--allow-dir", str(pcap_dir)],
                                   env=env)
    capture = str(pcap_dir / "all.pcap")
    out = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for tool in (await session.list_tools()).tools:
                schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema")
                required = set(schema.get("required") or [])
                for arg in _string_props(schema):
                    args: dict[str, Any] = {}
                    for name in required:
                        args[name] = capture if name.startswith("path") else ("diameter" if name == "protocol" else "1")
                    if tool.name == "cause_lookup":
                        args.setdefault("protocol", "diameter")
                        args.setdefault("code", "5001")
                    if tool.name in ("find_fields",):
                        args.setdefault("query", "imsi")
                    args[arg] = LONG
                    out.append((tool.name, arg, await session.call_tool(tool.name, args)))
    return out


@requires_tshark
def test_no_tool_echoes_a_long_argument_over_stdio(pcap_dir: Path):
    results = asyncio.run(_sweep(pcap_dir))
    assert len(results) > 60  # every tool has at least one string argument (path)
    errors = 0
    for tool, arg, result in results:
        text = result.content[0].text
        if "x" * 200 in text:
            raise AssertionError(f"{tool}({arg}=<5000 characters>) echoed the value: {text[:300]}")
        structured = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
        if structured and "error" in structured:
            errors += 1
            assert len(text.encode()) < ERROR_BUDGET * 2, (tool, arg, len(text))
    assert errors > 60

"""The tool list stays small: compact schemas by default, full schemas on request."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from tshark_mcp import schemas, server

from . import pcapgen
from .conftest import TSHARK, requires_tshark

# Budgets for the compact tools/list. They scale with the number of tools; a new tool whose
# description runs past DESCRIPTION_MAX moves its detail into a `Details:` paragraph.
# 2,750 until the row tools took columns / output / max_output_kb (about 260 bytes each on 33 tools).
# 2,900 until the start/end window arguments on every capture tool (about 180 bytes each).
# 3,000 until every argument got a schema description (mcp-builder G1, about 320 bytes per tool;
# measured 2,892 -> 3,210 on 55 tools).
AVERAGE_TOOL_BYTES_MAX = 3_250
TOOL_BYTES_MAX = 4_608
DESCRIPTION_MAX = 1_500
INSTRUCTIONS_MAX = 3_900


def _size(obj: Any) -> int:
    return len(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode())


def _listed(profile: str) -> list[Any]:
    server.set_schema_profile(profile)
    try:
        return asyncio.run(server.app.list_tools())
    finally:
        server.set_schema_profile(schemas.DEFAULT_PROFILE)


def _dump(tool: Any) -> dict[str, Any]:
    return tool.model_dump(mode="json", by_alias=True, exclude_none=True)


# ------------------------------------------------------------------ budgets
def test_compact_tool_list_fits_the_budget():
    tools = _listed("compact")
    sizes = {t.name: _size(_dump(t)) for t in tools}
    assert sum(sizes.values()) / len(sizes) <= AVERAGE_TOOL_BYTES_MAX, sorted(sizes.items(), key=lambda kv: -kv[1])[:5]
    assert max(sizes.values()) <= TOOL_BYTES_MAX, max(sizes.items(), key=lambda kv: kv[1])
    long = {t.name: len(t.description) for t in tools if len(t.description) > DESCRIPTION_MAX}
    assert not long, f"move the detail of these descriptions into a `Details:` paragraph: {long}"
    assert len(server.INSTRUCTIONS) <= INSTRUCTIONS_MAX


def test_compact_is_much_smaller_than_full():
    compact = _size([_dump(t) for t in _listed("compact")])
    full = _size([_dump(t) for t in _listed("full")])
    assert compact * 2 < full, (compact, full)


# ------------------------------------------------------------------ the compact contract
def test_compact_schema_keeps_top_level_keys_and_accepts_what_full_accepts():
    full = {t.name: t for t in _listed("full")}
    for tool in _listed("compact"):
        out, whole = tool.output_schema, full[tool.name].output_schema
        assert "$defs" not in out and "error" in out["properties"] and out["additionalProperties"] is True
        assert set(out["properties"]) == set(whole["properties"]) - schemas.COMMON_KEYS, tool.name
        assert set(tool.input_schema["properties"]) == set(full[tool.name].input_schema["properties"]), tool.name
        assert tool.title == full[tool.name].title and tool.annotations == full[tool.name].annotations
        jsonschema.Draft202012Validator.check_schema(out)


def test_row_lists_name_their_keys():
    gtp = next(t for t in _listed("compact") if t.name == "gtp_sessions")
    rows = gtp.output_schema["properties"]["transactions"]
    assert rows["type"] == "array" and rows["items"] == {"type": "object"}
    assert rows["description"].startswith("rows with keys: ") and "request_frame" in rows["description"]
    assert gtp.output_schema["properties"]["next_offset"] == {"type": "integer"}


def test_input_titles_are_dropped_but_a_property_named_title_stays():
    schema = {"title": "fArguments", "type": "object", "properties": {
        "title": {"title": "Title", "type": "string"}, "path": {"title": "Path", "type": "string"}}}
    assert schemas.strip_titles(schema) == {"type": "object", "properties": {
        "title": {"type": "string"}, "path": {"type": "string"}}}


def test_details_move_out_of_the_compact_description():
    doc = """Pair things.
    Narrow with `imsi`.
    Details: how pairing works,
    at length."""
    assert schemas.split_description(doc) == ("Pair things.\nNarrow with `imsi`.", "how pairing works,\nat length.")
    assert schemas.compact_description("x", doc).endswith("More detail: resource schema://tools/x.")
    assert "how pairing works" in schemas.full_description(doc) and "Details:" not in schemas.full_description(doc)
    assert schemas.compact_description("x", "No details here.") == "No details here."
    gtp = {t.name: t for t in _listed("compact")}["gtp_sessions"]
    assert "Proxy chains" not in gtp.description and "schema://tools/gtp_sessions" in gtp.description


def test_full_profile_is_the_sdk_schema():
    for tool in _listed("full"):
        assert "Details:" not in tool.description
        assert tool.output_schema == server.app._tool_manager.get_tool(tool.name).output_schema


def test_profile_is_checked():
    with pytest.raises(ValueError):
        server.set_schema_profile("tiny")
    assert server.build_parser().parse_args(["--schema-profile", "full"]).schema_profile == "full"


# ------------------------------------------------------------------ over stdio
async def _over_stdio(pcap_dir: Path, profile: str | None) -> dict[str, Any]:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    env = dict(os.environ)
    env["TSHARK_MCP_TSHARK"] = TSHARK
    env.pop("TSHARK_MCP_SCHEMA_PROFILE", None)
    args = ["-m", "tshark_mcp.server", "--allow-dir", str(pcap_dir)]
    if profile:
        args += ["--schema-profile", profile]
    out: dict[str, Any] = {}
    async with stdio_client(StdioServerParameters(command=sys.executable, args=args, env=env)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            out["tools"] = {t.name: t for t in (await session.list_tools()).tools}
            out["resources"] = [str(r.uri) for r in (await session.list_resources()).resources]
            schema = await session.read_resource("schema://tools/gtp_sessions")
            out["schema"] = json.loads(schema.contents[0].text)
            # The client validates structured content against the listed output schema.
            out["gtp"] = await session.call_tool("gtp_sessions", {"path": str(pcap_dir / "gtpv2.pcap"), "teid": "0xc001"})
            out["diameter"] = await session.call_tool("diameter_sessions", {"path": str(pcap_dir / "diameter.pcap"),
                                                                            "imsi": pcapgen.IMSI})
    return out


@requires_tshark
@pytest.mark.parametrize("profile", [None, "full"])
def test_tool_list_and_schema_resources_over_stdio(pcap_dir: Path, profile: str | None):
    got = asyncio.run(_over_stdio(pcap_dir, profile))
    tools = got["tools"]
    # Schema resources, plus the MCP Apps view of call_ladder.
    assert set(got["resources"]) == {f"schema://tools/{name}" for name in tools} | {"ui://tshark-mcp/ladder.html"}
    gtp_out = tools["gtp_sessions"].output_schema
    if profile == "full":
        assert "$defs" in gtp_out and "Proxy chains" in tools["gtp_sessions"].description
    else:
        assert "$defs" not in gtp_out and "Proxy chains" not in tools["gtp_sessions"].description
        assert sum(_size(t.model_dump(mode="json", by_alias=True, exclude_none=True)) for t in tools.values()) \
            <= AVERAGE_TOOL_BYTES_MAX * len(tools)
    # The resource is the full schema in either profile.
    full = got["schema"]
    assert full["name"] == "gtp_sessions" and "$defs" in full["outputSchema"] and "Proxy chains" in full["description"]
    assert "redact" in full["inputSchema"]["properties"]
    for name in ("gtp", "diameter"):
        result = got[name]
        assert not result.is_error, result
        jsonschema.validate(result.structured_content, full["outputSchema"] if name == "gtp" else
                            tools["diameter_sessions"].output_schema)
    assert [t["message"] for t in got["gtp"].structured_content["transactions"]] == [
        "Create Session Request", "Delete Session Request"]


def test_optional_arguments_become_a_type_list():
    schema = {"type": "object", "properties": {
        "imsi": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None, "title": "Imsi"},
        "teid": {"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}], "default": None},
        "view": {"default": "sessions", "enum": ["sessions", "transactions"], "type": "string"}}}
    assert schemas.compact_input_schema(schema)["properties"] == {
        "imsi": {"type": ["string", "null"]},
        "teid": {"type": ["string", "integer", "null"]},
        "view": {"default": "sessions", "enum": ["sessions", "transactions"], "type": "string"}}


# ------------------------------------------------------------------ mcp-builder audit (G1, G7)
def test_every_argument_has_a_description():
    """G1: every argument of every tool has a one-line description, in both profiles."""
    from tshark_mcp import argdocs
    for profile in ("compact", "full"):
        for tool in _listed(profile):
            for name, prop in tool.input_schema["properties"].items():
                text = prop.get("description")
                assert text, f"{tool.name}.{name} has no description: add it to src/tshark_mcp/argdocs.py"
                assert len(text) <= argdocs.MAX_CHARS and "\n" not in text, (tool.name, name, text)


def test_columns_enum_in_full_schema_only():
    """G7: the valid columns are an items enum in the full schema; the compact list leaves it out."""
    from tshark_mcp import output
    full = {t.name: t for t in _listed("full")}
    compact = {t.name: t for t in _listed("compact")}
    for name, fn in server.TOOLS.items():
        if "columns" not in full[name].input_schema["properties"]:
            continue
        known = output.row_keys(server.inspect.signature(fn).return_annotation)
        prop = full[name].input_schema["properties"]["columns"]
        arrays = [v for v in prop.get("anyOf", [prop]) if v.get("type") == "array"]
        if known:
            assert arrays[0]["items"]["enum"] == sorted(known), name
        else:  # filter_packets: untyped rows, any field name
            assert "enum" not in arrays[0]["items"], name
        assert "enum" not in json.dumps(compact[name].input_schema["properties"]["columns"]), name

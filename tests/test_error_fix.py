"""Tool errors: isError on the wire, the structured error kept, and a ``fix`` per error type."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from tshark_mcp import errors
from tshark_mcp.limits import Allowlist, Limits

from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark


def _err(result: dict) -> dict:
    assert set(result) >= {"error"}, result
    return result["error"]


def test_not_found_lists_candidates_in_the_allowed_directory(server, pcap_dir: Path):
    err = _err(server.pcap_info(path=str(pcap_dir / "diamter.pcap")))
    assert err["type"] == "not_found"
    assert str(pcap_dir / "diameter.pcap") in err["candidates"]
    assert len(err["candidates"]) <= errors.MAX_CANDIDATES
    assert all(Path(c).parent == pcap_dir for c in err["candidates"])
    assert "candidates" in err["fix"]


def test_not_a_file_points_at_find_identifier(server, pcap_dir: Path):
    err = _err(server.pcap_info(path=str(pcap_dir)))
    assert err["type"] == "not_a_file"
    assert "find_identifier" in err["fix"] and err["candidates"]


def test_path_not_allowed_keeps_allowed_dirs(server, pcap_dir: Path):
    err = _err(server.pcap_info(path="/definitely/not/allowed.pcap"))
    assert err["type"] == "path_not_allowed"
    assert err["allowed_dirs"] == [str(pcap_dir.resolve())]
    assert "allowed_dirs" in err["fix"]
    assert "candidates" not in err


def test_candidates_never_leave_the_allowlist(configure, tmp_path: Path, pcap_dir: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "inside.pcap").write_bytes((pcap_dir / "diameter.pcap").read_bytes())
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"x")
    (allowed / "escape.pcap").symlink_to(outside)
    srv = configure(allow=[str(allowed)])
    err = _err(srv.pcap_info(path=str(allowed / "missing.pcap")))
    assert err["candidates"] == [str(allowed / "inside.pcap")]
    # A missing path whose nearest existing parent is outside the allowlist lists nothing.
    assert errors.candidate_captures(Allowlist.from_strings([str(allowed)]), str(tmp_path / "nope" / "x.pcap"),
                                     {".pcap"}) == []


def test_invalid_filter_suggests_close_field_names(server, pcap_dir: Path):
    err = _err(server.filter_packets(path=str(pcap_dir / "diameter.pcap"), display_filter="diameter.Sesion-Id"))
    assert err["type"] == "invalid_filter"
    assert "check_filter" in err["fix"] and "find_fields" in err["fix"]
    assert "diameter.Session-Id" in err["suggestions"]
    assert len(err["suggestions"]) <= errors.MAX_SUGGESTIONS


def test_unknown_field_suggests_close_field_names(server, pcap_dir: Path):
    err = _err(server.filter_packets(path=str(pcap_dir / "diameter.pcap"), display_filter="diameter",
                                     fields=["frame.number", "diameter.cmd.cod"]))
    assert err["type"] == "unknown_field"
    assert "diameter.cmd.code" in err["suggestions"]


def test_timeout_names_the_narrowing_arguments(configure, pcap_dir: Path):
    srv = configure(limits=Limits(timeout_seconds=0.001))
    err = _err(srv.gtp_sessions(path=str(pcap_dir / "gtpv2.pcap")))
    assert err["type"] == "timeout"
    assert "imsi" in err["fix"] and "teid" in err["fix"] and "filter" in err["fix"]


def test_unknown_token_says_tokens_live_for_one_run(server, pcap_dir: Path):
    err = _err(server.diameter_sessions(path=str(pcap_dir / "diameter.pcap"), imsi="imsi:0123456789"))
    assert err["type"] == "unknown_token"
    assert "server run" in err["fix"]


def test_invalid_argument_has_a_fix(server, pcap_dir: Path):
    err = _err(server.gtp_sessions(path=str(pcap_dir / "gtpv2.pcap"), apn="bad;apn"))
    assert err["type"] == "invalid_argument" and "inputSchema" in err["fix"]


@pytest.mark.parametrize("kind", sorted(errors.STATIC_FIXES) + ["timeout", "output_too_large", "something_new"])
def test_every_error_type_gets_a_fix(kind: str):
    err = errors.add_fix({"type": kind, "message": "m"}, "pcap_info", {"path": "/x"}, allowlist=None,
                         catalogue=None, suffixes={".pcap"})
    assert isinstance(err["fix"], str) and len(err["fix"]) > 20


def test_a_failing_producer_still_leaves_a_fix():
    def boom() -> frozenset[str]:
        raise RuntimeError("no glossary")
    err = errors.add_fix({"type": "invalid_filter", "message": "m"}, "filter_packets", {"filter": "x.y"},
                         allowlist=None, catalogue=boom, suffixes={".pcap"})
    assert err["fix"]


def test_as_call_result_flags_errors_only():
    from tshark_mcp.server import as_call_result
    ok = as_call_result({"packets": 1, "name": "\u00e9"})
    assert ok.is_error is False and ok.structured_content == {"packets": 1, "name": "\u00e9"}
    assert ok.content[0].text == '{"packets":1,"name":"\u00e9"}'  # compact JSON, mcp-builder G2
    res = as_call_result({"error": {"type": "not_found", "message": "m", "fix": "f"}})
    assert res.is_error is True
    assert res.structured_content["error"]["type"] == "not_found"
    assert json.loads(res.content[0].text) == res.structured_content


async def _stdio_calls(pcap_dir: Path) -> list:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    env = dict(os.environ)
    env["TSHARK_MCP_TSHARK"] = TSHARK
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "tshark_mcp.server", "--allow-dir", str(pcap_dir)], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return [
                await session.call_tool("pcap_info", {"path": str(pcap_dir / "diamter.pcap")}),
                await session.call_tool("filter_packets", {"path": str(pcap_dir / "diameter.pcap"),
                                                           "display_filter": "diameter.Sesion-Id"}),
                await session.call_tool("pcap_info", {"path": str(pcap_dir / "diameter.pcap")}),
            ]


def test_errors_over_stdio_are_is_error_with_structured_content(pcap_dir: Path):
    missing, bad_filter, ok = asyncio.run(_stdio_calls(pcap_dir))
    assert missing.is_error is True
    assert missing.structured_content["error"]["type"] == "not_found"
    assert str(pcap_dir / "diameter.pcap") in missing.structured_content["error"]["candidates"]
    assert json.loads(missing.content[0].text) == missing.structured_content
    assert bad_filter.is_error is True
    assert "diameter.Session-Id" in bad_filter.structured_content["error"]["suggestions"]
    assert not ok.is_error and ok.structured_content["packets"] == 7

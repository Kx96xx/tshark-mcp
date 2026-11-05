"""CAMEL operations in sigtran_messages, and INIT rejections in sctp_associations
(public-validation D13, D14).

D13: CAP components sit in tshark's ``camel`` layer (``camel.local``, ``camel.error_code_local``,
``camel.present``), not in gsm_old, so ``by_operation`` was empty on CAMEL traffic.
D14: an association that came up after a run of INITs answered with ABORT and an INIT collision
read as ``handshake: complete`` with no issue.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from pydantic import TypeAdapter

from tshark_mcp import models

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark


def _call(configure, tmp_path: Path, tool: str, path: Path) -> dict:
    srv = configure(allow=[str(tmp_path)])
    out = getattr(srv, tool)(str(path))
    assert "error" not in out, out
    return out


def test_camel_operations_are_named(configure, tmp_path):
    out = _call(configure, tmp_path, "sigtran_messages", g.write_camel_pcap(tmp_path / "cap.pcap"))
    TypeAdapter(models.SigtranMessagesResult).validate_python(out)
    assert out["summary"]["by_operation"] == {"initialDP": 1, "requestReportBCSMEvent": 1, "continue": 1,
                                              "eventReportBCSM": 1, "releaseCall": 1}
    second = out["messages"][1]["components"]
    assert [(c["operation"], c["invoke_id"], c["application"]) for c in second] == [
        ("requestReportBCSMEvent", 1, "camel"), ("continue", 2, "camel")]
    assert out["messages"][0].get("answered_in_frame") and "unanswered" not in out["messages"][0]


def test_map_operations_are_unchanged(configure, tmp_path):
    out = _call(configure, tmp_path, "sigtran_messages", g.write_sigtran_pcap(tmp_path / "map.pcap"))
    ops = out["summary"]["by_operation"]
    assert ops.get("updateLocation") and "application" not in out["messages"][0]["components"][0]


def test_inits_answered_by_abort_and_an_init_collision(configure, tmp_path):
    out = _call(configure, tmp_path, "sctp_associations", g.write_sctp_init_collision_pcap(tmp_path / "init.pcap"))
    TypeAdapter(models.SctpAssociationsResult).validate_python(out)
    [a] = out["associations"]
    assert a["handshake"] == "complete" and a["inits_aborted"] == 3 and a["init_collision"] is True
    assert any(i.startswith("3 INITs answered with ABORT") for i in a["issues"])
    assert any(i.startswith("INIT collision") for i in a["issues"])


def test_a_clean_handshake_has_no_issues(configure, tmp_path):
    [a] = _call(configure, tmp_path, "sctp_associations", g.write_sctp_pcap(tmp_path / "ok.pcap"))["associations"]
    assert a["handshake"] == "complete" and "issues" not in a and "inits_aborted" not in a


def test_camel_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = g.write_camel_pcap(tmp_path / "cap.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("sigtran_messages", {"path": str(cap)})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    assert asyncio.run(go())["summary"]["by_operation"]["initialDP"] == 1

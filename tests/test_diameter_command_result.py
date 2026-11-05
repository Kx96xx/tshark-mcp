"""Diameter results at command level (public-validation D17).

A credit-control answer carries a Result-Code at command level and one inside each
Multiple-Services-Credit-Control (RFC 4006 8.16); Proxy-Info and other grouped AVPs can hold
more. The answer's result is the command-level one: an MSCC's DIAMETER_CREDIT_LIMIT_REACHED is
reported apart in ``mscc_result_codes``. Application 4 is Gy/Ro in every tool.
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


def _call(configure, tmp_path: Path, tool: str, path: Path, **kw) -> dict:
    srv = configure(allow=[str(tmp_path)])
    out = getattr(srv, tool)(str(path), **kw)
    assert "error" not in out, out
    return out


def test_command_level_result_and_mscc_codes(configure, tmp_path):
    out = _call(configure, tmp_path, "diameter_transactions", g.write_gy_mscc_pcap(tmp_path / "gy.pcap"))
    TypeAdapter(models.DiameterTransactionsResult).validate_python(out)
    initial, update = out["transactions"]
    assert initial["result_code"] == 2001 and initial["result"] == "DIAMETER_SUCCESS" and initial["success"] is True
    assert initial["mscc_result_codes"] == [4012, 2001]
    assert initial["mscc_results"] == ["DIAMETER_CREDIT_LIMIT_REACHED"]
    assert initial["application"] == "Credit-Control (Gy/Ro)"
    # Experimental-Result alone stands for the result; the Proxy-Info does not add one.
    assert "result_code" not in update and update["experimental_result_code"] == 5030 and update["success"] is False


def test_roaming_attach_check_names_gy_the_same_way(configure, tmp_path):
    out = _call(configure, tmp_path, "roaming_attach_check", g.write_gy_mscc_pcap(tmp_path / "gy.pcap"), imsi=g.IMSI)
    steps = [s["step"] for a in out["attempts"] for s in a["steps"]]
    assert "Gy/Ro CCR-I/CCA-I" in steps and not any(s.startswith("Gx ") for s in steps)
    step = next(s for a in out["attempts"] for s in a["steps"] if s["step"] == "Gy/Ro CCR-I/CCA-I")
    assert step["code"] == 2001 and step["success"] is True


def test_diameter_result_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = g.write_gy_mscc_pcap(tmp_path / "gy.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("diameter_transactions", {"path": str(cap)})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    first = asyncio.run(go())["transactions"][0]
    assert first["result_code"] == 2001 and first["mscc_result_codes"] == [4012, 2001]

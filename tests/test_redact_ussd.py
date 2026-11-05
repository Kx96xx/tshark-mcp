"""Redaction of numbers typed into USSD strings and SMS text (public-validation D12).

``packet_detail(..., redact="ids")`` on a MAP processUnstructuredSS-Request returned the
USSD string ``*140*<number>#`` in clear, and the packed GSM 7-bit bytes of the same text,
while the IMSI and MSISDN fields next to it were redacted.
"""

from __future__ import annotations

import asyncio
import json
import sys

from tshark_mcp.redact import Redactor

from . import pcapgen as g
from .conftest import requires_tshark


def _clean(out: object) -> str:
    text = json.dumps(out)
    assert g.USSD_NUMBER not in text and g.MSISDN not in text, text
    return text


@requires_tshark
def test_packet_detail_hides_the_number_in_a_ussd_string(configure, tmp_path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.packet_detail(str(g.write_ussd_pcap(tmp_path / "ussd.pcap")), frame=1, redact="ids")
    text = _clean(out)
    assert "*140*msisdn:" in text  # the shape of the string stays readable
    assert "bytes of packed text>" in text and "aa:18:0d" not in text


@requires_tshark
def test_filter_packets_hides_text_and_packed_bytes(configure, tmp_path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.filter_packets(str(g.write_ussd_pcap(tmp_path / "ussd.pcap")), display_filter="gsm_map",
                             fields=["gsm_map.ussd_string", "gsm_map.ss.ussd_String"], redact="ids")
    _clean(out)
    row = out["packets"][0]
    assert row["gsm_map.ussd_string"].startswith("*140*msisdn:") and row["gsm_map.ussd_string"].endswith("#")
    assert row["gsm_map.ss.ussd_String"].startswith("<redacted: ")


@requires_tshark
def test_the_prescan_seeds_the_typed_number(configure, tmp_path):
    """A tool that shows only the bare number (no USSD key around it) still hides it after the pre-scan."""
    srv = configure(allow=[str(tmp_path)])
    out = srv.filter_packets(str(g.write_ussd_pcap(tmp_path / "ussd.pcap")), display_filter="gsm_map",
                             fields=["frame.number"], redact="ids")
    assert "error" not in out
    seeded = srv.state().redactor.apply({"note": f"call {g.USSD_NUMBER} back"}, "ids")[0]
    assert g.USSD_NUMBER not in seeded["note"]


def test_unit_text_keys_and_packed_bytes():
    r = Redactor(key=b"k" * 32)
    out, counts = r.apply({"gsm_sms.sms_text": "send 15550100888 to 4321", "sms_text_bytes": "61:62",
                           "gsm_map.ss.ussd_String": "aa180da6", "gsm_map.ussd_string": "*100#"}, "ids")
    assert "15550100888" not in out["gsm_sms.sms_text"] and out["gsm_sms.sms_text"].endswith(" to 4321")
    assert out["gsm_map.ss.ussd_String"] == "<redacted: 4 bytes of packed text>"
    assert out["gsm_map.ussd_string"] == "*100#"  # a service code, not a number
    assert counts == {"msisdn": 1}


@requires_tshark
def test_ussd_redaction_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = g.write_ussd_pcap(tmp_path / "ussd.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path), "--redact", "ids"])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("packet_detail", {"path": str(cap), "frame": 1})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    _clean(asyncio.run(go()))

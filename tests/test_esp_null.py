"""esp_null: SIP inside IPsec ESP with NULL encryption on the SIP/IMS tools, and the `ipsec` block."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from tshark_mcp import ipsec, runner
from tshark_mcp.limits import Limits, ToolError

from . import pcapgen
from .conftest import requires_tshark

SIP_TOOLS = ("sip_dialogs", "call_legs", "volte_call_chain", "sip_call_detail", "ims_registration",
             "sms_over_ims", "trace_subscriber")


@pytest.fixture(scope="module")
def gm_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("gm")
    pcapgen.write_gm_esp_null_pcap(d / "gm.pcap")
    pcapgen.write_gm_esp_null_pcap(d / "gm_hidden.pcap", clear_challenge=False)
    return d


@pytest.fixture
def gm(configure, gm_dir: Path):
    return configure(allow=[str(gm_dir)])


class TestUnit:
    def test_parse_and_block(self):
        out = "1\t0x0000115c\teth:ethertype:ip:esp:udp:sip\n2\t0x0badc0de\teth:ethertype:ip:esp\n3\t0x0badc0de\teth:ethertype:ip:esp\n"
        recs = ipsec.parse(out)
        assert [r["decoded"] for r in recs] == [True, False, False] and recs[0]["spi"] == 0x115C
        b = ipsec.block(recs, False, 0)
        assert b["esp_packets"] == 3 and b["decoded_null"] == 1 and b["unreadable"] == 2
        assert b["spis"][0] == {"spi": "0x0badc0de", "packets": 2} and b["first_unreadable_frame"] == 2
        assert b["hint"].startswith("SIP may be inside 2 ESP packet(s)") and "esp_null=true" in b["hint"]
        assert ipsec.block([], False, 0) is None
        assert "no ESP" in ipsec.block([], True, 0)["hint"]
        assert "encrypted" in ipsec.block(recs, True, 1)["hint"]

    def test_preference_is_allowed_and_nothing_else(self):
        runner.assert_read_only(["-r", "x.pcap", "-o", ipsec.PREFERENCE])
        with pytest.raises(ToolError):
            runner.assert_read_only(["-r", "x.pcap", "-o", "esp.enable_encryption_decode:TRUE"])

    def test_preferences_reach_every_capture_read(self, tmp_path: Path):
        seen: list[list[str]] = []

        class Probe(runner.Runner):
            def _execute(self, program, args, **kw):  # noqa: ANN001
                seen.append(list(args))
                return runner.RunResult(tuple(args), 0, "", "", 0, 0)
        cap = tmp_path / "x.pcap"
        cap.write_bytes(runner.EMPTY_PCAP)
        r = Probe(Limits(), tshark=sys.executable)
        token = runner.set_preferences(ipsec.PREFERENCES)
        try:
            r.read_capture(cap, ["-T", "fields", "-e", "frame.number"])
        finally:
            runner.reset_preferences(token)
        r.read_capture(cap, ["-T", "fields", "-e", "frame.number"])
        assert seen[0][-6:-4] == ["-o", ipsec.PREFERENCE] or ipsec.PREFERENCE in seen[0]
        assert ipsec.PREFERENCE not in seen[1]


@requires_tshark
class TestTools:
    def test_hidden_without_flag_and_read_with_it(self, gm, gm_dir: Path):
        path = str(gm_dir / "gm.pcap")
        plain = gm.ims_registration(path)
        (row,) = plain["registrations"]
        assert row["verdict"] != "registered"
        assert plain["ipsec"]["esp_packets"] == 5 and plain["ipsec"]["unreadable"] == 5
        assert plain["ipsec"]["decoded_null"] == 0 and "more SIP may be inside" in plain["ipsec"]["hint"]
        null = gm.ims_registration(path, esp_null=True)
        (row,) = null["registrations"]
        assert row["verdict"] == "registered", row
        assert null["ipsec"]["decoded_null"] == 2 and null["ipsec"]["unreadable"] == 3
        assert {"spi": "0x0badc0de", "packets": 3} in null["ipsec"]["spis"]
        assert "stay unreadable" in null["ipsec"]["hint"]

    def test_sip_dialogs_says_sip_may_be_inside_esp(self, gm, gm_dir: Path):
        path = str(gm_dir / "gm_hidden.pcap")
        plain = gm.sip_dialogs(path)
        assert plain["total_matched"] == 0
        assert plain["ipsec"]["hint"].startswith("SIP may be inside 5 ESP packet(s)")
        null = gm.sip_dialogs(path, esp_null=True)
        assert null["total_matched"] == 1 and null["ipsec"]["decoded_null"] == 2

    def test_every_sip_tool_takes_esp_null(self, gm, gm_dir: Path):
        path = str(gm_dir / "gm.pcap")
        call_id = f"reg-{pcapgen.IMS_GM[-3:]}@ue.example"
        args = {"sip_call_detail": {"call_id": call_id}, "trace_subscriber": {"imsi": pcapgen.IMS_GM}}
        for name in SIP_TOOLS:
            out = getattr(gm, name)(path, esp_null=True, **args.get(name, {}))
            assert "error" not in out, (name, out)
            assert out["ipsec"]["decoded_null"] == 2, name

    def test_capture_without_esp_has_no_block(self, server, pcap_dir: Path):
        out = server.sip_dialogs(str(pcap_dir / "sip.pcap"))
        assert "ipsec" not in out and out["total_matched"] > 0
        assert "ipsec" not in server.pcap_info(str(pcap_dir / "sip.pcap"))

    def test_pcap_info_hints(self, gm, gm_dir: Path):
        out = gm.pcap_info(str(gm_dir / "gm.pcap"))
        assert out["ipsec"]["esp_packets"] == 5 and "esp_null=true" in out["ipsec"]["hint"]

    def test_redaction_sees_identities_inside_null_esp(self, gm, gm_dir: Path):
        out = gm.ims_registration(str(gm_dir / "gm_hidden.pcap"), esp_null=True, redact="ids")
        assert pcapgen.IMS_GM not in json.dumps(out)
        assert out["registrations"]

    def test_bad_flag_is_an_argument_error(self, gm, gm_dir: Path):
        out = gm.sip_dialogs(str(gm_dir / "gm.pcap"), esp_null="yes")
        assert out["error"]["type"] == "invalid_argument"

    def test_over_mcp_stdio(self, gm_dir: Path):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async def go() -> tuple[dict, dict]:
            params = StdioServerParameters(command=sys.executable,
                                           args=["-m", "tshark_mcp.server", "--allow-dir", str(gm_dir)])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = {t.name: t for t in (await session.list_tools()).tools}
                    schema = tools["ims_registration"].input_schema["properties"]["esp_null"]
                    res = await session.call_tool("ims_registration", {"path": str(gm_dir / "gm.pcap"),
                                                                       "esp_null": True})
                    return schema, res.structured_content
        schema, out = asyncio.run(go())
        assert "NULL" in json.dumps(schema)
        assert out["registrations"][0]["verdict"] == "registered" and out["ipsec"]["decoded_null"] == 2

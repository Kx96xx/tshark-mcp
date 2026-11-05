"""sbi_transactions: 5G SBI HTTP/2 transactions on synthetic h2c captures (tests/pcapgen.py)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from tshark_mcp import redact, sbi

from . import pcapgen
from .conftest import requires_tshark
from .test_response_times import Capture
from .test_tls import client_hello


@pytest.fixture(scope="module")
def sbi_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("sbi")
    pcapgen.write_sbi_pcap(d / "sbi.pcap")
    cap = Capture()
    c = cap.conn("192.0.2.114", sport=443).open()
    c.send("c", payload=client_hello("udm.5gc.mnc001.mcc001.3gppnetwork.org"), dt=0.001)
    c = cap.conn("203.0.113.9", sport=443).open()
    c.send("c", payload=client_hello("www.example.com", alpn=("http/1.1",)), dt=0.001)
    cap.write(d / "sbi_tls.pcap")
    return d


@pytest.fixture
def srv(configure, sbi_dir: Path):
    return configure(allow=[str(sbi_dir)])


class TestUnit:
    def test_service_template_and_roles(self):
        assert sbi.service_of("/nudm-sdm/v2/imsi-001010123456789/am-data?x=1") == ("nudm-sdm", "v2", "/{supi}/am-data")
        assert sbi.service_of("/nsmf-pdusession/v1/sm-contexts/7/modify")[2] == "/sm-contexts/{id}/modify"
        assert sbi.producer_of("nudm-sdm") == "UDM" and sbi.producer_of("nnrf-disc") == "NRF"
        assert sbi.producer_of("n5g-eir-eic") == "5G-EIR" and sbi.producer_of("other") is None
        assert sbi.consumer_of("SMF-aaaa", {}) == "SMF" and sbi.consumer_of(None, {"requester-nf-type": "AMF"}) == "AMF"
        assert sbi.consumer_of("curl/8", {}) is None

    def test_suci_keeps_only_routing_parts(self):
        parts = sbi.suci_parts(pcapgen.SBI_SUCI)
        assert parts == {"mcc": "001", "mnc": "01", "routing_indicator": "0000", "protection_scheme": "null",
                         "home_network_key_id": 0}
        assert "0123456789" not in sbi.scrub_suci(f"/nudm-ueau/v1/{pcapgen.SBI_SUCI}/security-information")
        assert sbi.identity("imsi-001010123456789") == ("supi", "001010123456789")
        assert sbi.identity("msisdn-15550100123") == ("gpsi", "15550100123")

    def test_redaction_kinds(self):
        assert redact.kind_for_key("supi") == "imsi" and redact.kind_for_key("gpsi") == "number"
        assert redact.kind_for_key("pei") == "imei"


@requires_tshark
class TestTool:
    def test_transactions_causes_and_roles(self, srv, sbi_dir: Path):
        out = srv.sbi_transactions(str(sbi_dir / "sbi.pcap"))
        rows = out["transactions"]
        by = {(r["operation"], r.get("status")): r for r in rows}
        disc = by[("GET /nf-instances", 200)]
        assert disc["producer"] == "NRF" and disc["consumer"] == "AMF" and disc["nf_profiles_returned"] == 2
        assert disc["discovery"]["target_nf_type"] == "AUSF"
        auth = by[("POST /ue-authentications", 403)]
        assert auth["cause"] == "SERVING_NETWORK_NOT_AUTHORIZED" and auth["cause_explained"]["ref"].startswith("TS 29.509")
        assert auth["suci"]["routing_indicator"] == "0000" and auth["outcome"] == "client_error"
        udm = by[("GET /{supi}/am-data", 404)]
        assert udm["cause"] == "USER_NOT_FOUND" and udm["supi"] == pcapgen.SBI_SUPI and udm["producer"] == "UDM"
        created = by[("POST /sm-contexts", 201)]
        assert created["location"].endswith("/sm-contexts/7") and created["gpsi"] == pcapgen.SBI_GPSI
        failed = by[("POST /sm-contexts", 500)]
        assert failed["cause"] == "SYSTEM_FAILURE" and failed["latency_ms"] == pytest.approx(900, abs=1)
        assert failed["dnn"] == "ims" and failed["detail"] == "no UPF"
        reset = by[("POST /sm-policies", None)]
        assert reset["reset"]["error"] == "CANCEL" and reset["consumer"] == "SMF" and reset["producer"] == "PCF"
        assert out["verdict"].startswith("4 of 7 SBI transaction(s) failed; first: POST /ue-authentications to AUSF -> 403")
        services = {s["operation"]: s for s in out["summary"]["services"]}
        assert services["POST /sm-contexts"]["calls"] == 2 and services["POST /sm-contexts"]["pct_5xx"] == 50.0
        assert out["summary"]["nrf_discovery"][0]["nf_profiles_returned"] == 2
        assert out["summary"]["tls_unreadable"] == 0
        for key in ("dnn", "title", "detail", "uri", "location"):
            if any(key in r for r in rows):
                assert key in out["untrusted_text_fields"], key

    def test_authentication_material_is_never_returned(self, srv, sbi_dir: Path):
        text = json.dumps(srv.sbi_transactions(str(sbi_dir / "sbi.pcap")))
        assert pcapgen.SBI_SECRET_RAND not in text and pcapgen.SBI_SECRET_KAUSF not in text
        assert "-0-0-0123456789" not in text and "suci-" not in text  # SUCI scheme output (null scheme MSIN)
        assert '"withheld_keys": ["5gAuthData", "kausf"]' in text

    def test_filters(self, srv, sbi_dir: Path):
        path = str(sbi_dir / "sbi.pcap")
        assert {r["service"] for r in srv.sbi_transactions(path, service="nsmf")["transactions"]} == {"nsmf-pdusession"}
        assert [r["status"] for r in srv.sbi_transactions(path, status="4xx")["transactions"]] == [403, 404]
        assert len(srv.sbi_transactions(path, status="error")["transactions"]) == 4
        assert all(r["supi"] == pcapgen.SBI_SUPI for r in srv.sbi_transactions(path, supi=pcapgen.SBI_SUPI)["transactions"])
        assert srv.sbi_transactions(path, status="9xx")["error"]["type"] == "invalid_argument"
        assert srv.sbi_transactions(path, service="n;drop")["error"]["type"] == "invalid_argument"

    def test_ports_decode_and_hpack_state_missing(self, srv, sbi_dir: Path):
        out = srv.sbi_transactions(str(sbi_dir / "sbi.pcap"), ports=[80])
        missing = [r for r in out["transactions"] if r.get("hpack_state_missing")]
        assert missing and missing[0]["stream_id"] == 41
        assert out["summary"]["hpack_state_missing"] == 2 and "before the capture started" in out["verdict"]

    def test_redaction_joins_supi_with_imsi_tokens(self, srv, sbi_dir: Path):
        out = srv.sbi_transactions(str(sbi_dir / "sbi.pcap"), redact="ids")
        text = json.dumps(out)
        assert pcapgen.SBI_SUPI not in text and pcapgen.SBI_GPSI not in text
        supis = {r["supi"] for r in out["transactions"] if "supi" in r}
        assert len(supis) == 1 and next(iter(supis)).startswith("imsi:")

    def test_tls_sbi_is_counted_and_the_verdict_says_so(self, srv, sbi_dir: Path):
        out = srv.sbi_transactions(str(sbi_dir / "sbi_tls.pcap"))
        assert out["transactions"] == [] and out["summary"]["tls_unreadable"] == 1
        assert "encrypted" in out["verdict"]

    def test_over_mcp_stdio(self, sbi_dir: Path):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async def go():
            params = StdioServerParameters(command=sys.executable,
                                           args=["-m", "tshark_mcp.server", "--toolsets", "all", "--allow-dir", str(sbi_dir)])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    names = {t.name for t in (await session.list_tools()).tools}
                    res = await session.call_tool("sbi_transactions", {"path": str(sbi_dir / "sbi.pcap"),
                                                                       "status": "5xx"})
                    return names, res.structured_content
        names, out = asyncio.run(go())
        assert "sbi_transactions" in names
        assert [r["cause"] for r in out["transactions"]] == ["SYSTEM_FAILURE"]

"""iot_sessions: MQTT 3.1.1/5.0, CoAP retransmission exhaustion, LwM2M expiry, MQTT inside GTP-U."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from tshark_mcp import iot

from . import pcapgen
from .conftest import requires_tshark


@pytest.fixture(scope="module")
def iot_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("iot")
    pcapgen.write_iot_pcap(d / "iot.pcap")
    return d


@pytest.fixture
def srv(configure, iot_dir: Path):
    return configure(allow=[str(iot_dir)])


def test_coap_code_format():
    assert iot.coap_code("65") == "2.01" and iot.coap_code("2") == "0.02" and iot.coap_code("132") == "4.04"


@requires_tshark
class TestTool:
    def _mqtt(self, out: dict) -> dict[str, list[dict]]:
        by: dict[str, list[dict]] = {}
        for r in out["sessions"]:
            if r["protocol"] == "mqtt":
                by.setdefault(r["client_id"], []).append(r)
        return by

    def test_mqtt_refusals_keepalive_and_loop(self, srv, iot_dir: Path):
        out = srv.iot_sessions(str(iot_dir / "iot.pcap"), protocol="mqtt")
        by = self._mqtt(out)
        (a,) = by["dev-a"]
        assert a["connack"]["code"] == 5 and a["connack"]["name"] == "not authorized" and a["user_name_sent"]
        assert a["verdict"].startswith("refused: CONNACK not authorized")
        (b,) = by["dev-b"]
        assert b["keepalive_s"] == 60 and b["keepalive_violated"] and b["pings"]["median_interval_s"] == 120.0
        assert b["puback_ms"]["median"] == 40.0 and b["connack"]["session_present"] and b["topics"] == {"fleet/{client_id}/telemetry": 1}
        assert b["ended"] == {"how": "FIN", "by": "client", "frame": b["ended"]["frame"]} and b["disconnect"]["by"] == "client"
        c = by["dev-c"]
        assert len(c) == 6 and c[0]["connack"]["code"] == 0x87 and c[0]["protocol_version"] == "5.0"
        assert all(r["reconnect_loop"] for r in c) and c[1]["reconnect_interval_s"]["median"] == 30.0
        assert c[1]["ended"]["how"] == "RST" and c[1]["ended"]["by"] == "broker"
        assert out["summary"]["mqtt"]["refused"] == 2 and out["summary"]["mqtt"]["reconnect_loops"] == 1

    def test_mqtt_inside_gtpu_names_the_teid(self, srv, iot_dir: Path):
        (f,) = self._mqtt(srv.iot_sessions(str(iot_dir / "iot.pcap"), client="dev-f"))["dev-f"]
        assert f["gtpu_teid"] == "0x00a0b0c0" and f["client"].startswith(pcapgen.IOT_DEV_F) and f["verdict"] == "healthy"

    def test_coap_exhausted_and_lwm2m_expired(self, srv, iot_dir: Path):
        out = srv.iot_sessions(str(iot_dir / "iot.pcap"))
        coap = {r["client"]: r for r in out["sessions"] if r["protocol"] == "coap"}
        d = coap[f"{pcapgen.IOT_DEV_D}:5683"]
        (ex,) = d["exhausted"]
        assert ex["sends"] == 5 and ex["request"] == "POST /sensors/temp" and d["retransmissions"] == 4
        (lw,) = [r for r in out["sessions"] if r["protocol"] == "lwm2m"]
        assert lw["endpoint"] == "urn:dev:e-0001" and lw["registrations"][0]["lifetime_s"] == 300
        assert lw["registrations"][0]["result"] == "2.01 Created" and lw["registrations"][0]["location"] == "/rd/5a3f"
        assert lw["expired"] and lw["updates"] == 0 and lw["verdict"].startswith("expired")

    def test_no_payload_byte_in_the_output(self, srv, iot_dir: Path):
        text = json.dumps(srv.iot_sessions(str(iot_dir / "iot.pcap")))
        assert pcapgen.IOT_PAYLOAD.decode() not in text and "dev-password" not in text and "dev-user" not in text

    def test_redaction_hides_client_ids_and_endpoints(self, srv, iot_dir: Path):
        out = srv.iot_sessions(str(iot_dir / "iot.pcap"), redact="ids")
        text = json.dumps(out)
        assert '"dev-b"' not in text and "urn:dev:e-0001" not in text and "fleet/dev-b/" not in text
        assert all(r["client_id"].startswith("user:") for r in out["sessions"] if r.get("client_id"))

    def test_arguments(self, srv, iot_dir: Path):
        path = str(iot_dir / "iot.pcap")
        assert {r["protocol"] for r in srv.iot_sessions(path, protocol="lwm2m")["sessions"]} == {"lwm2m"}
        assert srv.iot_sessions(path, protocol="zigbee")["error"]["type"] == "invalid_argument"

    def test_over_mcp_stdio(self, iot_dir: Path):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async def go():
            params = StdioServerParameters(command=sys.executable,
                                           args=["-m", "tshark_mcp.server", "--allow-dir", str(iot_dir)])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    res = await session.call_tool("iot_sessions", {"path": str(iot_dir / "iot.pcap"), "protocol": "coap"})
                    return res.structured_content
        out = asyncio.run(go())
        assert any(r.get("exhausted") for r in out["sessions"])

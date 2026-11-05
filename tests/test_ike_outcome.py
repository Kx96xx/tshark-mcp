"""tunnels_overview: IKE outcome after a DH-group retry, Teredo, and the empty-result note
(public-validation D10, D22).

D10: INVALID_KE_PAYLOAD is the responder naming the DH group it wants (RFC 7296 1.3); the
initiator retries and the tunnel comes up. The outcome used to be "failed" on the first error
notify even with IKE_AUTH answered and ESP both ways.
D22: Teredo tunnels were not a kind, and a capture with no tunnel tshark decodes came back with
nothing to say why.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from pydantic import TypeAdapter
from scapy.all import UDP, Ether, IP, Raw  # type: ignore

from tshark_mcp import models

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

GW = "198.51.100.200"


def _run(configure, tmp_path: Path, path: Path, **kw) -> dict:
    srv = configure(allow=[str(tmp_path)])
    out = srv.tunnels_overview(str(path), **kw)
    assert "error" not in out, out
    TypeAdapter(models.TunnelsOverviewResult).validate_python(out)
    return out


def _by_peer(out: dict) -> dict[str, dict]:
    return {t["endpoint_a"] if t["endpoint_b"] == GW else t["endpoint_b"]: t for t in out["tunnels"]}


def test_dh_group_retry_then_auth_is_established(configure, tmp_path):
    rows = _by_peer(_run(configure, tmp_path, g.write_ike_outcomes_pcap(tmp_path / "ike.pcap")))
    ok = rows["192.0.2.201"]
    assert ok["handshake"]["outcome"] == "established" and ok["esp_pairs"] == "both directions"
    assert "retried with it" in ok["handshake"]["retried"][0]
    assert not ok.get("issues")


def test_real_ike_failures_stay_failures(configure, tmp_path):
    rows = _by_peer(_run(configure, tmp_path, g.write_ike_outcomes_pcap(tmp_path / "ike.pcap")))
    bad = rows["192.0.2.202"]
    assert bad["handshake"]["outcome"] == "failed"
    assert any("NO_PROPOSAL_CHOSEN" in i for i in bad["issues"])
    gave_up = rows["192.0.2.203"]
    assert gave_up["handshake"]["outcome"] == "incomplete"
    assert "did not try again" in gave_up["handshake"]["retried"][0]
    assert any("INVALID_KE_PAYLOAD" in i for i in gave_up["issues"])


def test_teredo_is_a_tunnel_kind(configure, tmp_path):
    out = _run(configure, tmp_path, g.write_teredo_pcap(tmp_path / "teredo.pcap"))
    [row] = out["tunnels"]
    assert row["kind"] == "Teredo" and 3544 in row["udp_ports"] and row["one_way"] is False
    assert row["inner_protocols"] == {"icmpv6": 2}
    assert _run(configure, tmp_path, tmp_path / "teredo.pcap", kind="teredo")["tunnels"]


def test_no_tunnel_comes_with_a_note(configure, tmp_path):
    pkt = Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src="192.0.2.220", dst="192.0.2.221") / UDP(sport=58226, dport=8880) \
        / Raw(bytes(58))
    path = g._frames_to_pcap(tmp_path / "marker.pcap", [(1_700_003_200.0, bytes(pkt))])
    out = _run(configure, tmp_path, path)
    assert out["tunnels"] == [] and "plain UDP or TCP" in out["summary"]["note"]


def test_ike_outcome_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = g.write_ike_outcomes_pcap(tmp_path / "ike.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("tunnels_overview", {"path": str(cap)})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    rows = _by_peer(asyncio.run(go()))
    assert rows["192.0.2.201"]["handshake"]["outcome"] == "established"

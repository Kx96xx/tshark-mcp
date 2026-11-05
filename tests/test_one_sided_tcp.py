"""Connections captured in one direction only (public-validation D2).

A one-way tap or asymmetric routing leaves only one direction of a TCP connection in the
file. The packets that are there still prove the other side answered: a client does not
send data without a SYN-ACK, and a server does not send data before the client's ACK. Such
a connection is ``one_sided``, never ``filtered``, ``handshake_incomplete`` or a failed TLS
handshake, and incident_summary gives it one low finding instead of high-severity failures.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from pydantic import TypeAdapter

from tshark_mcp import models

from .conftest import requires_tshark
from .test_tls import CCS, Capture, alert, app_data, certificate_msg, client_hello, handshake, make_cert, record, server_hello

pytestmark = requires_tshark


def client_only(path: Path) -> Path:
    """The client's direction of a TLS 1.3 connection: SYN, ACK, ClientHello, Finished, data, FIN."""
    cap = Capture()
    c = cap.conn()
    c.send("c", flags="S")
    c.send("c", flags="A", dt=0.012)
    c.send("c", client_hello("one-way.example.com"))
    c.send("c", CCS + app_data(53), dt=0.030)
    c.send("c", app_data(400))
    c.send("c", flags="FA", dt=0.020)
    return cap.write(path)


def server_only(path: Path) -> Path:
    """The server's direction of a TLS 1.2 connection: SYN-ACK, ServerHello + certificate, CCS, data."""
    cap = Capture()
    c = cap.conn()
    c.seq["c"] += 1  # the client's SYN is not in the file but was acknowledged
    c.send("s", flags="SA")
    cert = make_cert("srv.example.com", ["srv.example.com"], "250101000000Z", "350101000000Z")
    c.send("s", server_hello(0x0303, 0xC02F) + record(22, certificate_msg(cert) + handshake(14, b"")), dt=0.020)
    c.send("s", CCS + record(22, bytes(40)), dt=0.020)
    c.send("s", app_data(1200), dt=0.030)
    return cap.write(path)


def real_failures(path: Path) -> Path:
    """Controls: a SYN never answered (retried), and a SYN-ACK the client never acknowledged."""
    cap = Capture()
    c = cap.conn()
    for dt in (0.0, 1.0, 2.0, 4.0):
        c.seq["c"] = 1000
        c.send("c", flags="S", dt=dt)
    c = cap.conn()
    c.send("c", flags="S")
    c.send("s", flags="SA")
    c.seq["s"] = 9000
    c.send("s", flags="SA", dt=1.0)
    # Keep the capture running well past the last SYN so neither counts as near the capture end.
    c = cap.conn().open()
    c.send("c", alert(1, 0), dt=5.0)
    return cap.write(path)


def _tool(configure, tmp_path: Path, name: str, path: Path, **kw):
    srv = configure(allow=[str(tmp_path)])
    out = getattr(srv, name)(str(path), **kw)
    assert "error" not in out, out
    return out


def test_client_only_connection_is_one_sided(configure, tmp_path):
    cap = client_only(tmp_path / "client_only.pcap")
    out = _tool(configure, tmp_path, "tcp_connections", cap)
    TypeAdapter(models.TcpConnectionsResult).validate_python(out)
    [row] = out["connections"]
    assert row["outcome"] == "one_sided" and row["missing_direction"] == "server_to_client"
    assert "near_capture_end" not in row
    dests = _tool(configure, tmp_path, "tcp_connections", cap, view="destinations")["destinations"]
    assert dests[0]["one_sided"] == 1 and dests[0]["attempts"] == 0 and "success_rate" not in dests[0]
    assert any("one direction only" in i for i in dests[0]["issues"])


def test_server_only_connection_is_one_sided(configure, tmp_path):
    cap = server_only(tmp_path / "server_only.pcap")
    [row] = _tool(configure, tmp_path, "tcp_connections", cap)["connections"]
    assert row["outcome"] == "one_sided" and row["missing_direction"] == "client_to_server"
    assert row["client"].endswith(":50001") and row["server"].endswith(":443")


def test_real_failures_keep_their_outcomes(configure, tmp_path):
    out = _tool(configure, tmp_path, "tcp_connections", real_failures(tmp_path / "fail.pcap"))
    outcomes = sorted(r["outcome"] for r in out["connections"])
    assert outcomes == ["connected", "filtered", "handshake_incomplete"]


def test_tcp_health_names_the_missing_direction(configure, tmp_path):
    out = _tool(configure, tmp_path, "tcp_health", client_only(tmp_path / "client_only.pcap"))
    issues = out["streams"][0]["issues"]
    assert any("only the client's direction" in i for i in issues)
    assert not any("no SYN-ACK" in i for i in issues)
    out = _tool(configure, tmp_path, "tcp_health", real_failures(tmp_path / "fail.pcap"))
    assert any("no SYN-ACK" in i for s in out["streams"] for i in s.get("issues", []))


def test_tls_one_sided_is_not_a_failure(configure, tmp_path):
    out = _tool(configure, tmp_path, "tls_handshakes", client_only(tmp_path / "client_only.pcap"))
    [row] = out["connections"]
    assert row["outcome"] == "one_sided" and "client's direction" in row["note"]
    assert not any("did not complete" in i for i in out["issues"])
    out = _tool(configure, tmp_path, "tls_handshakes", server_only(tmp_path / "server_only.pcap"))
    [row] = out["connections"]
    assert row["client_hello_missing"] is True and row["client"].endswith(":50001")
    assert out["summary"]["client_hello_missing"] == 1


def test_incident_summary_reports_low_one_sided_finding(configure, tmp_path):
    for name, build in (("client_only.pcap", client_only), ("server_only.pcap", server_only)):
        out = _tool(configure, tmp_path, "incident_summary", build(tmp_path / name))
        kinds = {f["kind"]: f for f in out["findings"]}
        assert not {"connect_failures", "tls_failed", "tcp_unanswered_syn"} & set(kinds), (name, kinds)
        assert kinds["tcp_one_sided"]["severity"] == "low"
        assert kinds["tcp_one_sided"]["next_call"] == {"tool": "capture_quality", "args": {"path": str(tmp_path / name)}}


def test_one_sided_over_the_real_mcp_stdio_client(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    cap = client_only(tmp_path / "client_only.pcap")

    async def go() -> dict:
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("tcp_connections", {"path": str(cap)})
                structured = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
                return structured or json.loads(res.content[0].text)

    out = asyncio.run(go())
    assert out["connections"][0]["outcome"] == "one_sided"
    assert out["summary"]["by_outcome"] == {"one_sided": 1}

"""security_triage: scans, beacons, DNS tunnel hints, JA4 groups, ARP conflicts, cleartext credentials."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from tshark_mcp import triage

from . import pcapgen
from .conftest import requires_tshark, tshark_version


@pytest.fixture(scope="module")
def tri_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("triage")
    pcapgen.write_triage_pcap(d / "triage.pcap")
    return d


@pytest.fixture
def srv(configure, tri_dir: Path):
    return configure(allow=[str(tri_dir)])


class TestUnit:
    def test_regular_series_scores_high_and_short_one_is_insufficient(self):
        series = {("c", "s", "tcp/443"): [(1000.0 + i * 60 + (0.5 if i % 2 else -0.5), 500, i) for i in range(20)],
                  ("c", "t", "tcp/80"): [(1000.0 + i * 7, 100, i) for i in range(5)]}
        rows = {r["server"]: r for r in triage.beacons(series, 1200.0)}
        assert rows["s"]["score"] > 0.9 and rows["s"]["interval_s"]["median"] == pytest.approx(60, abs=1.1)
        assert rows["t"]["insufficient_samples"] and "score" not in rows["t"]

    def test_zone_and_entropy(self):
        assert triage.zone_of("abc.tunnel.example.") == "tunnel.example"
        assert triage.zone_of("www.example.co.uk") == "example.co.uk"
        assert triage._entropy("aaaa") == 0 and triage._entropy("abcd") == 2


@requires_tshark
class TestTool:
    def _findings(self, out: dict) -> dict[str, list[dict]]:
        by: dict[str, list[dict]] = {}
        for f in out["findings"]:
            by.setdefault(f["kind"], []).append(f)
        return by

    def test_every_scenario_is_found(self, srv, tri_dir: Path):
        out = srv.security_triage(str(tri_dir / "triage.pcap"))
        by = self._findings(out)
        (scan,) = by["port_scan"]
        assert scan["subject"] == {"source": pcapgen.TRIAGE_SCANNER, "target": pcapgen.TRIAGE_TARGET}
        assert scan["evidence"]["ports"] == 50 and scan["evidence"]["open_ports"] == [22, 50]
        (beacon,) = by["beacon"]
        assert beacon["subject"]["server"] == pcapgen.TRIAGE_BEACON and beacon["evidence"]["count"] == 20
        assert beacon["evidence"]["score"] >= 0.85 and "update.beacon.example" in beacon["subject"]["service"]
        (tunnel,) = by["dns_tunnel_hint"]
        assert tunnel["subject"]["zone"] == "tunnel.example" and tunnel["evidence"]["txt"] == 40
        (arp,) = by["arp_conflict"]
        assert arp["subject"]["ip"] == "192.0.2.1" and len(arp["evidence"]["macs"]) == 2
        creds = {f["subject"]["protocol"] for f in by["cleartext_credentials"]}
        assert creds == {"FTP", "HTTP Basic"}
        assert out["findings"][0]["severity"] == "high" and out["scope"].startswith("Defensive triage")

    def test_agent_like_beacon_reports_statistics_even_with_a_low_score(self, srv, tri_dir: Path):
        out = srv.security_triage(str(tri_dir / "triage.pcap"), kinds=["beacons"])
        agent = next(c for c in out["beacon_candidates"] if c["server"] == pcapgen.TRIAGE_AGENT)
        assert agent["count"] == 15 and agent["score"] < 0.85
        assert {"median", "mad", "bowley_skew"} <= set(agent["interval_s"]) and "size_bytes" in agent

    def test_credentials_are_never_returned(self, srv, tri_dir: Path):
        text = json.dumps(srv.security_triage(str(tri_dir / "triage.pcap")))
        assert pcapgen.TRIAGE_FTP_PASS not in text and pcapgen.TRIAGE_BASIC not in text and "alice" not in text

    def test_three_tls_client_groups(self, srv, tri_dir: Path):
        out = srv.security_triage(str(tri_dir / "triage.pcap"), kinds=["tls_fingerprints"])
        clients = out["tls_clients"]
        assert len(clients) == 3
        if tshark_version() >= (4, 4):
            assert all(c.get("ja4") for c in clients)
        else:
            assert all(c.get("ja4") or c.get("ja3") for c in clients)
        rare = [f for f in out["findings"] if f["kind"] == "rare_tls_client"]
        assert [f["subject"]["client"] for f in rare] == ["10.1.0.12"]
        assert all("ja4_r" not in c for c in clients)
        if tshark_version() >= (4, 4):
            raw = srv.security_triage(str(tri_dir / "triage.pcap"), kinds=["tls_fingerprints"], raw=True)
            assert all(c.get("ja4_r") for c in raw["tls_clients"])

    def test_kinds_select_and_validate(self, srv, tri_dir: Path):
        out = srv.security_triage(str(tri_dir / "triage.pcap"), kinds=["arp"])
        assert {f["kind"] for f in out["findings"]} == {"arp_conflict"} and out["kinds"] == ["arp"]
        assert srv.security_triage(str(tri_dir / "triage.pcap"), kinds=["nmap"])["error"]["type"] == "invalid_argument"

    def test_clean_capture_has_no_finding(self, configure, pcap_dir: Path):
        out = configure().security_triage(str(pcap_dir / "diameter.pcap"))
        assert out["findings"] == [] and out["verdict"] == "no finding from the selected checks"

    def test_over_mcp_stdio(self, tri_dir: Path):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async def go():
            params = StdioServerParameters(command=sys.executable,
                                           args=["-m", "tshark_mcp.server", "--allow-dir", str(tri_dir)])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    res = await session.call_tool("security_triage", {"path": str(tri_dir / "triage.pcap"),
                                                                      "kinds": ["scans", "cleartext_credentials"]})
                    return res.structured_content
        out = asyncio.run(go())
        assert {f["kind"] for f in out["findings"]} == {"port_scan", "cleartext_credentials"}

"""diff_captures: before/after captures built from one generator with one parameter changed per section."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import rdpcap, wrpcap  # type: ignore

from tshark_mcp import capdiff, models
from tshark_mcp import server as srv
from tshark_mcp.limits import Limits

from . import test_dns as tdns
from . import test_tls as ttls
from .conftest import TSHARK, requires_tshark
from .test_http_transactions import API, req, resp
from .test_response_times import Capture as HttpCapture
from .test_tcp_connections import CLI, DB, Wire

pytestmark = requires_tshark


def _merge(path: Path, parts: list[Path]) -> Path:
    packets = []
    for p in parts:
        packets.extend(rdpcap(str(p)))
    packets.sort(key=lambda p: float(p.time))
    wrpcap(str(path), packets)
    return path


def _dns(path: Path, answer: bool, extra: str) -> Path:
    b = tdns.Builder()
    for i in range(5):
        b.at(1.0).query(tdns.RES_A, 0x2000 + i, "db.example.com", sport=41000 + i)
        if answer:
            b.at(0.012).answer(tdns.RES_A, 0x2000 + i, "db.example.com", sport=41000 + i)
    b.at(1.0).query(tdns.RES_A, 0x2100, extra, sport=42000)
    b.at(0.012).answer(tdns.RES_A, 0x2100, extra, sport=42000)
    b.at(5.0).query(tdns.RES_A, 0x2200, "tail.example.com", sport=42001)
    b.at(0.012).answer(tdns.RES_A, 0x2200, "tail.example.com", sport=42001)
    return b.write(path)


def _tls(path: Path, version: int) -> Path:
    cap = ttls.Capture()
    for _ in range(3):
        c = cap.conn().open()
        c.send("c", ttls.client_hello("api.example.com"))
        suite = 0x1301 if version == 0x0304 else 0xC02F
        c.send("s", ttls.server_hello(version=version, suite=suite) + ttls.CCS + ttls.app_data(1200), dt=0.030)
        c.send("c", ttls.CCS + ttls.app_data(53))
        c.send("c", ttls.app_data(300))
        c.send("s", ttls.app_data(900), dt=0.040)
    return cap.write(path)


def _http(path: Path, code: int) -> Path:
    cap = HttpCapture()
    c = cap.conn(API, sport=80).open()
    for _ in range(4):
        c.send("c", payload=req("GET", "/api/items"), dt=0.010)
        c.send("s", payload=resp(code, "OK" if code == 200 else "Internal Server Error", b"x" * 40), dt=0.030)
    c.send("c", flags="A", dt=0.5)
    return cap.write(path)


def _conns(path: Path, answered: bool) -> Path:
    w = Wire()
    for i in range(3):
        at = 1_700_020_000.0 + 1.0 + 2 * i
        if answered:
            w.full(CLI, DB, 43000 + i, 5432, at)
        else:
            for dt in (0.0, 1.0):
                w.add(w.pkt(CLI, DB, 43000 + i, 5432, "S", 7000 + i), at + dt)
    w.add(w.pkt(CLI, DB, 43999, 5432, "A", 1, 1), 1_700_020_030.0)  # keeps the SYNs away from the capture end
    return w.write(path.parent)  # writes conns.pcap


@pytest.fixture(scope="module")
def pair(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    d = tmp_path_factory.mktemp("diff")
    out = []
    for side, good in (("before", True), ("after", False)):
        parts = d / side
        parts.mkdir()
        files = [
            _dns(parts / "dns.pcap", answer=good, extra="old.example.com" if good else "new.example.com"),
            _tls(parts / "tls.pcap", 0x0304 if good else 0x0303),
            _http(parts / "http.pcap", 200 if good else 500),
            _conns(parts / "conns.pcap", answered=good),
        ]
        out.append(_merge(d / f"{side}.pcap", files))
    return out[0], out[1]


@pytest.fixture
def diff(pair):
    srv.configure([str(pair[0].parent)], limits=Limits(), tshark=TSHARK)
    yield srv
    srv._STATE = None


def _row(out, section: str, key: str) -> dict:
    return next(r for r in out["differences"] if r["section"] == section and r["key"] == key)


def test_each_section_labels_the_change(diff, pair):
    out = diff.diff_captures(str(pair[0]), str(pair[1]))
    assert "error" not in out, out
    TypeAdapter(models.DiffCapturesResult).validate_python(out)
    dest = _row(out, "destinations", f"{DB}:5432")
    assert dest["change"] == "worse" and dest["a"]["success_rate"] == 1.0 and dest["b"]["success_rate"] == 0.0
    assert "went from 100.0% connected to 0.0% (filtered)" in dest["sentence"]
    name = _row(out, "dns", "name db.example.com")
    assert name["change"] == "worse" and name["delta"]["answered_share"] == -1.0
    assert _row(out, "dns", f"resolver {tdns.RES_A}")["change"] == "worse"
    assert _row(out, "dns", "name old.example.com")["change"] == "vanished"
    assert _row(out, "dns", "name new.example.com")["change"] == "appeared"
    tls = _row(out, "tls", "api.example.com")
    assert tls["change"] == "worse" and "negotiates TLS 1.2 instead of TLS 1.3" in tls["sentence"]
    http = _row(out, "http", "GET api.example.com/api/items")
    assert http["change"] == "worse" and http["a"]["share_5xx"] == 0.0 and http["b"]["share_5xx"] == 1.0
    assert "5xx share went from 0.0% to 100.0%" in http["sentence"]
    # Worse rows first, ranked by size; unchanged keys are left out by default.
    changes = [r["change"] for r in out["differences"]]
    assert changes == sorted(changes, key=capdiff.CHANGES.index) and "same" not in changes
    assert len(out["first_differences"]) == 5 and out["first_differences"][0] == out["differences"][0]["sentence"]
    assert out["summary"]["http"] == {"worse": 1} and out["a"]["packets"] > 0 and out["b"]["duration_s"] > 0


def test_same_rows_and_one_section(diff, pair):
    same = diff.diff_captures(str(pair[0]), str(pair[0]), by="dns", include_same=True)
    assert {r["change"] for r in same["differences"]} == {"same"} and same["first_differences"] == []
    assert {r["section"] for r in same["differences"]} == {"dns"}
    nothing = diff.diff_captures(str(pair[0]), str(pair[0]))
    assert nothing["differences"] == [] and nothing["total_matched"] == 0


def test_rates_are_per_minute(diff, pair):
    out = diff.diff_captures(str(pair[0]), str(pair[1]), by="dns")
    row = _row(out, "dns", "name db.example.com")
    minutes_a = out["a"]["duration_s"] / 60
    assert row["rate_per_min"]["a"] == round(5 / minutes_a, 3)


def test_paging_and_bad_arguments(diff, pair):
    page = diff.diff_captures(str(pair[0]), str(pair[1]), limit=2)
    assert page["returned"] == 2 and page["next_offset"] == 2
    rest = diff.diff_captures(str(pair[0]), str(pair[1]), limit=2, offset=2)
    assert rest["differences"][0] != page["differences"][0]
    assert diff.diff_captures(str(pair[0]), str(pair[1]), by="udp")["error"]["type"] == "invalid_argument"
    assert diff.diff_captures(str(pair[0]), str(pair[1]), filter="tcp.port ==")["error"]["type"] == "invalid_filter"


def test_window_applies_to_both_captures(diff, pair):
    full = diff.diff_captures(str(pair[0]), str(pair[1]), by="dns")
    out = diff.diff_captures(str(pair[0]), str(pair[1]), by="dns", end="+0.5s")
    assert out["a"]["frames_in_window"] < out["a"]["packets"]
    # Only the first query is in the window: the other names are not compared.
    assert {r["key"] for r in out["differences"]} < {r["key"] for r in full["differences"]}
    assert out["window"]["captures"][0]["capture"] == str(pair[0])


async def _over_stdio(pair) -> dict:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "tshark_mcp.server", "--allow-dir", str(pair[0].parent)],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool("diff_captures", {"path_a": str(pair[0]), "path_b": str(pair[1]),
                                                             "by": "http"})


def test_diff_captures_over_stdio(pair):
    got = asyncio.run(_over_stdio(pair))
    assert not got.is_error and got.structured_content["differences"][0]["change"] == "worse"

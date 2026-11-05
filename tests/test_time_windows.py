"""Time windows (start/end on every capture tool) and capture_index (ring-buffer directories)."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest
from scapy.all import IP, UDP, Ether, Raw  # type: ignore

from tshark_mcp import server as srv
from tshark_mcp import window
from tshark_mcp.limits import Limits, ToolError

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark

T0 = 1_700_000_000.0
A, B = "192.0.2.11", "198.51.100.12"


def _udp(i: int) -> bytes:
    return bytes(Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=A, dst=B) / UDP(sport=40000, dport=9000) / Raw(b"%04d" % i))


def _ring(directory: Path, name: str, first: float, count: int, step: float = 1.0) -> Path:
    return g._frames_to_pcap(directory / name, [(first + i * step, _udp(i)) for i in range(count)])


@pytest.fixture
def ring(tmp_path: Path) -> Path:
    """Three ring files: ring_1 T0..T0+9, ring_2 T0+10..T0+19 (no hole), a 20 s hole, ring_3
    T0+40..T0+49; plus ring_0, named first but recorded last (the ring wrapped) and overlapping
    ring_3 by 5 s."""
    d = tmp_path / "ring"
    d.mkdir()
    _ring(d, "ring_1.pcap", T0, 10)
    _ring(d, "ring_2.pcap", T0 + 10, 10)
    _ring(d, "ring_3.pcap", T0 + 40, 10)
    _ring(d, "ring_0.pcap", T0 + 45, 10)
    return d


@pytest.fixture
def win(ring: Path):
    srv.configure([str(ring)], limits=Limits(), tshark=TSHARK)
    yield srv
    srv._STATE = None


def _raw_count(path: Path, flt: str) -> int:
    out = subprocess.run([TSHARK, "-n", "-r", str(path), "-Y", flt, "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True, check=True).stdout
    return len(out.split())


# ------------------------------------------------------------------ parsing
def test_bounds_accept_iso_epoch_and_relative():
    assert window.parse_bound("2023-11-14T22:13:20Z", "start").seconds == T0
    assert window.parse_bound("2023-11-14T22:13:20", "start").seconds == T0  # no zone is UTC
    assert window.parse_bound("2023-11-14T23:13:20+01:00", "start").seconds == T0
    assert window.parse_bound(T0, "start").seconds == T0
    assert window.parse_bound(str(T0), "start").seconds == T0
    assert window.parse_bound("+120s", "start") == window.Bound("from_start", 120.0, "+120s")
    assert window.parse_bound("-2m", "end") == window.Bound("from_end", 120.0, "-2m")
    assert window.parse_bound("+500ms", "start").seconds == 0.5
    assert window.parse_bound("+3", "start").seconds == 3.0
    assert window.parse_bound(None, "start") is None and window.parse_bound(" ", "end") is None


@pytest.mark.parametrize("bad", ["yesterday", "120", 120, True, "+5x", "2023-13-01T00:00:00Z"])
def test_bad_bounds_are_refused_with_the_accepted_forms(bad):
    with pytest.raises(ToolError) as err:
        window.parse_bound(bad, "start")
    assert err.value.type == "invalid_argument" and "start=" in err.value.message


def test_start_after_end_is_refused():
    with pytest.raises(ToolError, match="after end"):
        window.parse(T0 + 10, T0)


# ------------------------------------------------------------------ the filter on every tool
def test_window_matches_raw_tshark_frame_counts(win, ring: Path):
    path = ring / "ring_1.pcap"
    lo, hi = T0 + 2.5, T0 + 6
    got = win.filter_packets(str(path), "udp", ["frame.number"], limit=100, start=lo, end=hi)
    expected = _raw_count(path, f"frame.time_epoch >= {lo} && frame.time_epoch <= {hi}")
    assert got["total_matched"] == expected == 4
    assert [int(r["frame.number"]) for r in got["packets"]] == [4, 5, 6, 7]
    w = got["window"]
    assert w["start_epoch"] == lo and w["end_epoch"] == hi and w["overlaps_capture"] is True
    assert w["filter"] == f"frame.time_epoch >= {lo:.1f} && frame.time_epoch <= {int(hi)}"
    assert w["capture_first"] == "2023-11-14T22:13:20.000Z" and w["capture_last"] == "2023-11-14T22:13:29.000Z"
    assert got["display_filter"] == "udp"  # the user's filter is reported as given


def test_relative_bounds_resolve_against_each_capture(win, ring: Path):
    got = win.filter_packets(str(ring / "ring_1.pcap"), "udp", ["frame.number"], start="+7s")
    assert got["total_matched"] == 3 and got["window"]["start_arg"] == "+7s"
    got = win.filter_packets(str(ring / "ring_1.pcap"), "udp", ["frame.number"], end="-8s")
    assert [r["frame.number"] for r in got["packets"]] == ["1", "2"]
    got = win.filter_packets(str(ring / "ring_1.pcap"), "udp", ["frame.number"], start="-3s", end="-1s")
    assert [r["frame.number"] for r in got["packets"]] == ["7", "8", "9"]


def test_statistics_tools_are_windowed_too(win, ring: Path):
    path = str(ring / "ring_1.pcap")
    conv = win.conversations(path, layer="udp", start="+5s")
    assert conv["total_frames"] == 5
    info = win.pcap_info(path, start="+5s", end="+6s")
    eth = next(r for r in info["protocol_hierarchy"] if r["protocol"] == "eth")
    assert eth["frames"] == 2 == info["frames_in_window"] and info["packets"] == 10  # the file totals stay the file's
    assert info["window_hint"]["start"] == "2023-11-14T22:13:20.000Z"
    expert = win.expert_info(path, severity="chat", start="+100s")
    assert expert["total_matched"] == 0


def test_window_outside_the_capture_warns(win, ring: Path):
    got = win.filter_packets(str(ring / "ring_1.pcap"), "udp", start=T0 + 1000)
    assert got["total_matched"] == 0 and got["window"]["overlaps_capture"] is False
    assert any("lies outside ring_1.pcap" in w for w in got["warnings"])


def test_bad_window_is_a_structured_error(win, ring: Path):
    got = win.filter_packets(str(ring / "ring_1.pcap"), "udp", start="noon")
    assert got["error"]["type"] == "invalid_argument" and got["error"]["fix"]
    got = win.filter_packets(str(ring / "ring_1.pcap"), "udp", start="+9s", end="-5s")
    assert got["error"]["type"] == "invalid_argument" and "empty" in got["error"]["message"]


def test_window_starting_past_the_frame_cap_still_reports_the_cap(ring: Path):
    srv.configure([str(ring)], limits=Limits(max_scan_packets=4), tshark=TSHARK)
    try:
        got = srv.filter_packets(str(ring / "ring_1.pcap"), "udp", start="+6s")
        assert got["total_matched"] == 0 and got["total_is_lower_bound"] is True
        assert "frame cap" in got["truncated_reason"]
    finally:
        srv._STATE = None


def test_statistics_run_without_the_window_is_refused(win, ring: Path):
    tokens = window.bind(window.parse("+1s", None))
    try:
        with pytest.raises(ToolError, match="-z statistic"):
            win.state().runner.read_capture(ring / "ring_1.pcap", ["-q", "-z", "io,phs"])
    finally:
        window.unbind(tokens)


def test_find_identifier_skips_files_outside_the_window(win, ring: Path):
    got = win.find_identifier(str(ring), A, start=T0 + 41, end=T0 + 42)
    assert got["files_outside_window"] == 3  # ring_0 starts at +45
    assert [Path(r["path"]).name for r in got["files"]] == ["ring_3.pcap"] and got["total_hits"] == 2


def test_multi_file_window_lists_each_capture(win, ring: Path):
    got = win.compare_captures(str(ring / "ring_1.pcap"), str(ring / "ring_2.pcap"), start="+1s")
    assert "error" not in got, got
    names = [Path(c["capture"]).name for c in got["window"].get("captures", [])]
    assert names == ["ring_1.pcap", "ring_2.pcap"]
    assert got["window"]["captures"][1]["start_epoch"] == T0 + 11


def test_every_capture_tool_but_three_takes_the_window(win):
    import inspect
    with_window, without = set(), set()
    for name, tool in asyncio.run(_tools()).items():
        props = tool.input_schema["properties"]
        (with_window if {"start", "end"} <= set(props) else without).add(name)
    assert without == {"find_fields", "check_filter", "cause_lookup", "packet_detail", "capture_metadata"}
    assert "capture_index" in with_window  # its own start/end, picking files
    assert "start" in inspect.signature(srv.dns_transactions).parameters


async def _tools():
    return {t.name: t for t in await srv.app.list_tools()}


# ------------------------------------------------------------------ capture_index
def test_capture_index_orders_files_and_finds_holes_and_overlaps(win, ring: Path):
    got = win.capture_index(str(ring))
    assert [r["name"] for r in got["files"]] == ["ring_1.pcap", "ring_2.pcap", "ring_3.pcap", "ring_0.pcap"]
    first = got["files"][0]
    assert first["packets"] == 10 and first["duration_s"] == 9.0 and first["interfaces"] == 1
    assert first["first"] == "2023-11-14T22:13:20.000Z" and first["link_type"]
    by = {r["name"]: r for r in got["files"]}
    assert by["ring_2.pcap"]["gap_before_s"] == 1.0  # one packet interval: not a hole at min_gap_s=1
    assert by["ring_3.pcap"]["gap_before_s"] == 21.0
    assert by["ring_0.pcap"]["overlap_before_s"] == 4.0
    s = got["summary"]
    assert s["packets"] == 40 and s["span_s"] == 54.0 and s["overlaps"] == 1
    assert [(h["after"], h["before"], h["seconds"]) for h in s["holes"]] == [("ring_2.pcap", "ring_3.pcap", 21.0)]
    assert len(win.capture_index(str(ring), min_gap_s=0.5)["summary"]["holes"]) == 2
    assert s["ordering"].startswith("name order differs")
    assert any("21.0s without a file between ring_2.pcap" in i for i in got["issues"])


def test_capture_index_min_gap_and_window(win, ring: Path):
    got = win.capture_index(str(ring), min_gap_s=5, start=T0 + 15, end=T0 + 42)
    s = got["summary"]
    assert [h["before"] for h in s["holes"]] == ["ring_3.pcap"] and s["holes"][0]["in_window"] is True
    assert s["window_files"] == ["ring_2.pcap", "ring_3.pcap"] and s["window_covered"] is False
    assert any("only partly covered" in i for i in got["issues"])
    covered = win.capture_index(str(ring), min_gap_s=5, start="+2s", end="+12s")["summary"]
    assert covered["window_files"] == ["ring_1.pcap", "ring_2.pcap"] and covered["window_covered"] is True
    late = win.capture_index(str(ring), end="-50s")["summary"]
    assert late["window_files"] == ["ring_1.pcap"]


def test_capture_index_pages_over_files(win, ring: Path):
    got = win.capture_index(str(ring), max_files=2)
    assert got["files_indexed"] == 2 and got["next_offset"] == 2 and got["files_not_indexed"] == 2
    assert [r["name"] for r in got["files"]] == ["ring_1.pcap", "ring_0.pcap"]  # the first two by name, in time order
    rest = win.capture_index(str(ring), max_files=2, offset=2)
    assert "next_offset" not in rest and [r["name"] for r in rest["files"]] == ["ring_2.pcap", "ring_3.pcap"]


def test_capture_index_refuses_paths_outside_the_allowlist(win, tmp_path: Path):
    got = win.capture_index(str(tmp_path))
    assert got["error"]["type"] == "path_not_allowed"


# ------------------------------------------------------------------ through the MCP stdio client
async def _over_stdio(ring: Path) -> dict:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    env = dict(os.environ, TSHARK_MCP_TSHARK=TSHARK)
    params = StdioServerParameters(command=sys.executable, args=["-m", "tshark_mcp.server", "--allow-dir", str(ring)],
                                   env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return {
                "index": await session.call_tool("capture_index", {"path": str(ring), "start": "+15s", "end": "+42s"}),
                "packets": await session.call_tool("filter_packets", {"path": str(ring / "ring_3.pcap"),
                                                                      "display_filter": "udp", "start": "-2s"}),
                "bad": await session.call_tool("conversations", {"path": str(ring / "ring_3.pcap"), "end": "later"}),
            }


def test_window_and_capture_index_over_stdio(ring: Path):
    got = asyncio.run(_over_stdio(ring))
    index = got["index"].structured_content
    assert not got["index"].is_error and index["summary"]["window_files"] == ["ring_2.pcap", "ring_3.pcap"]
    packets = got["packets"].structured_content
    assert packets["total_matched"] == 3 and packets["window"]["start_arg"] == "-2s"
    assert got["bad"].is_error and got["bad"].structured_content["error"]["type"] == "invalid_argument"

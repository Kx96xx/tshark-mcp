"""export_subset: the one write tool, off unless --export-dir, never overwrites, never writes elsewhere."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from tshark_mcp import export as exporting
from tshark_mcp import models
from tshark_mcp import server as srv
from tshark_mcp.limits import Limits, ToolError
from tshark_mcp.runner import Runner, _check_write_argv, assert_read_only

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark

FILTER = "diameter"


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path, Path]:
    caps = tmp_path / "caps"
    out = tmp_path / "exports"
    caps.mkdir()
    out.mkdir()
    capture = g.write_diameter_pcap(caps / "diameter.pcap")
    return caps, out, capture


@pytest.fixture
def on(dirs, tmp_path: Path):
    caps, out, capture = dirs
    srv.configure([str(caps)], limits=Limits(), tshark=TSHARK, export_dir=str(out), log_path=tmp_path / "audit.jsonl")
    yield srv
    srv._STATE = None


def _tshark(*args: str) -> list[str]:
    return subprocess.run([TSHARK, "-n", *args], capture_output=True, text=True, check=True,
                          env=dict(os.environ, WIRESHARK_CONFIG_DIR=os.devnull)).stdout.split()


def test_off_by_default(dirs):
    caps, out, capture = dirs
    srv.configure([str(caps)], limits=Limits(), tshark=TSHARK)
    try:
        err = srv.export_subset(str(capture), FILTER, "x")["error"]
    finally:
        srv._STATE = None
    assert err["type"] == "export_disabled" and "--export-dir" in err["fix"]
    assert list(out.iterdir()) == []


def test_writes_exactly_the_matching_packets(on, dirs, tmp_path: Path):
    caps, out, capture = dirs
    res = on.export_subset(str(capture), FILTER, "case-1 sip", max_packets=1000)
    assert "error" not in res, res
    TypeAdapter(models.ExportSubsetResult).validate_python(res)
    w = res["written"]
    assert w["name"] == "case-1_sip.pcapng" and Path(w["path"]) == out / "case-1_sip.pcapng" and not res["capped"]
    expected = _tshark("-r", str(capture), "-Y", FILTER, "-T", "fields", "-e", "frame.number")
    assert w["packets"] == len(expected) > 2
    assert len(_tshark("-r", w["path"], "-T", "fields", "-e", "frame.number")) == len(expected)
    assert w["sha256"] == hashlib.sha256(Path(w["path"]).read_bytes()).hexdigest() and w["bytes"] == Path(w["path"]).stat().st_size
    assert w["first_frame"] == int(expected[0]) and w["last_frame"] == int(expected[-1])
    assert "addresses, identifiers and payloads" in res["reminder"]
    assert sorted(p.name for p in out.iterdir()) == ["case-1_sip.pcapng"]  # no temporary file left
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    write = next(r for r in records if r["status"] == "write")
    assert write["args"]["sha256"] == w["sha256"] and write["args"]["written"] == w["path"]


def test_never_overwrites_and_never_follows_a_planted_symlink(on, dirs, tmp_path: Path):
    caps, out, capture = dirs
    assert "error" not in on.export_subset(str(capture), FILTER, "one.pcapng")
    before = (out / "one.pcapng").read_bytes()
    err = on.export_subset(str(capture), "frame.number == 1", "one.pcapng")["error"]
    assert err["type"] == "file_exists" and (out / "one.pcapng").read_bytes() == before
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    (out / "trap.pcapng").symlink_to(victim)
    assert on.export_subset(str(capture), FILTER, "trap")["error"]["type"] == "file_exists"
    assert victim.read_text() == "keep me"


@pytest.mark.parametrize("name", ["../escape", "sub/dir.pcapng", ".hidden", "", "a" * 120])
def test_bad_names_are_refused(on, dirs, name: str):
    caps, out, capture = dirs
    assert on.export_subset(str(capture), FILTER, name)["error"]["type"] == "invalid_argument"
    assert list(out.iterdir()) == []


def test_caps_headers_only_and_window(on, dirs):
    caps, out, capture = dirs
    two = on.export_subset(str(capture), FILTER, "two", max_packets=2)
    assert two["written"]["packets"] == 2 and two["capped"] and "max_packets=2" in two["capped_reason"]
    cut = on.export_subset(str(capture), FILTER, "cut", headers_only=True)
    lens = [int(x) for x in _tshark("-r", cut["written"]["path"], "-T", "fields", "-e", "frame.cap_len")]
    assert max(lens) <= 96 and cut["written"]["snaplen"] == 96 and "cut to the first 96 bytes" in cut["reminder"]
    late = on.export_subset(str(capture), FILTER, "late", start="+0.5s")
    full = on.export_subset(str(capture), FILTER, "full")
    assert 0 < late["written"]["packets"] < full["written"]["packets"] and late["window"]
    assert on.export_subset(str(capture), "", "empty")["error"]["type"] == "invalid_argument"
    assert on.export_subset(str(capture), "frame.number == 99999", "none")["error"]["type"] == "not_found"
    assert on.export_subset(str(capture), FILTER, "s", snaplen=10)["error"]["type"] == "invalid_argument"
    assert on.export_subset("/etc/passwd", FILTER, "p")["error"]["type"] == "path_not_allowed"


def test_size_cap(dirs):
    caps, out, capture = dirs
    srv.configure([str(caps)], limits=Limits(), tshark=TSHARK, export_dir=str(out), export_max_mb=0.0015)
    try:
        res = srv.export_subset(str(capture), FILTER, "small")
    finally:
        srv._STATE = None
    assert res["capped"] and "--export-max-mb" in res["capped_reason"]
    assert res["written"]["bytes"] <= int(0.0015 * 1024 * 1024)


def test_export_dir_rules(tmp_path: Path):
    caps = tmp_path / "caps"
    (caps / "inner").mkdir(parents=True)
    with pytest.raises(ValueError, match="overlaps the allowed directory"):
        exporting.configure(str(caps / "inner"), None, (caps.resolve(),))
    with pytest.raises(ValueError, match="overlaps the allowed directory"):
        exporting.configure(str(tmp_path), None, (caps.resolve(),))  # contains the allow dir
    assert exporting.configure(str(caps / "inner"), None, (caps.resolve(),), inside_allow_dir=True)
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        exporting.configure(str(tmp_path / "link"), None, ())
    with pytest.raises(ValueError, match="does not exist"):
        exporting.configure(str(tmp_path / "missing"), None, ())
    with pytest.raises(ValueError, match="export-max-mb"):
        exporting.configure(str(real), 0, ())
    assert exporting.configure(None, None, ()) is None


def test_write_flags_stay_refused_everywhere_else(dirs, tmp_path: Path):
    caps, out, capture = dirs
    for argv in (["-n", "-r", str(capture), "-w", str(out / "x.pcapng")], ["-n", "-r", str(capture), "-F", "pcapng"]):
        with pytest.raises(ToolError):
            assert_read_only(argv)
    with pytest.raises(ToolError):
        _check_write_argv(["-n", "-r", str(capture), "-c", "5", "-Y", "x", "-F", "pcapng", "-w", "o", "-X", "lua_script:a"])
    runner = Runner(Limits(), tshark=TSHARK)
    with pytest.raises(ToolError, match="outside the export directory"):
        runner.write_subset(capture, tmp_path / (exporting.TMP_PREFIX + "x.pcapng"), out.resolve(), FILTER, 10)
    with pytest.raises(ToolError, match="outside the export directory"):
        runner.write_subset(capture, out.resolve() / "final.pcapng", out.resolve(), FILTER, 10)
    assert list(out.iterdir()) == []


async def _over_stdio(caps: Path, out: Path, capture: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "tshark_mcp.server", "--allow-dir", str(caps), "--export-dir", str(out)],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name: t for t in (await session.list_tools()).tools}
            got = await session.call_tool("export_subset", {"path": str(capture), "display_filter": FILTER,
                                                            "name": "vendor.pcapng", "headers_only": True})
            return tools["export_subset"], got


def test_export_subset_over_stdio(dirs):
    caps, out, capture = dirs
    tool, got = asyncio.run(_over_stdio(caps, out, capture))
    ann = tool.annotations
    assert getattr(ann, "readOnlyHint", getattr(ann, "read_only_hint", None)) is False
    assert getattr(ann, "destructiveHint", getattr(ann, "destructive_hint", None)) is False
    out_json = got.structured_content
    assert not got.is_error and out_json["written"]["name"] == "vendor.pcapng" and (out / "vendor.pcapng").exists()

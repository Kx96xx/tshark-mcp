"""open_capture handles and the memory result cache (Wave 4 item: capture handles)."""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

from tshark_mcp import handles, runner as runner_mod
from tshark_mcp.runner import ResultCache, RunResult

from .conftest import TSHARK, requires_tshark


def _result(n: int) -> RunResult:
    return RunResult(argv=("tshark",), returncode=0, stdout="x" * n, stderr="", duration_ms=1, stdout_bytes=n)


# --------------------------------------------------------------------------- the cache alone
def test_cache_lru_is_bounded_in_bytes(tmp_path: Path):
    f = tmp_path / "a.pcap"
    f.write_bytes(b"1")
    cache = ResultCache(100)
    k1, k2, k3 = (ResultCache.key(f, "tshark", [str(i)]) for i in range(3))
    cache.put(k1, _result(40))
    cache.put(k2, _result(40))
    assert cache.get(k1) is not None  # k1 is now the most recent
    cache.put(k3, _result(40))         # 120 bytes: the least recent (k2) goes
    assert cache.get(k2) is None and cache.get(k1) is not None and cache.get(k3) is not None
    cache.put(ResultCache.key(f, "tshark", ["big"]), _result(500))  # larger than the cache: not kept
    assert cache.describe()["entries"] == 2


def test_cache_key_follows_the_file_identity(tmp_path: Path):
    f = tmp_path / "a.pcap"
    f.write_bytes(b"1")
    before = ResultCache.key(f, "tshark", ["-r"])
    os.utime(f, ns=(time.time_ns() + 10_000_000, time.time_ns() + 10_000_000))
    assert ResultCache.key(f, "tshark", ["-r"]) != before
    f.write_bytes(b"12")
    assert ResultCache.key(f, "tshark", ["-r"]) != before
    assert ResultCache.key(tmp_path / "gone.pcap", "tshark", []) is None


# --------------------------------------------------------------------------- in process
@pytest.fixture
def counted(configure, monkeypatch):
    """The server with a counter of the tshark/capinfos processes it starts."""
    srv = configure()
    spawned = []
    real = runner_mod.Runner._run

    def run(self, program, args, **kw):
        spawned.append(list(args))
        return real(self, program, args, **kw)

    monkeypatch.setattr(runner_mod.Runner, "_run", run)
    return srv, spawned


@requires_tshark
def test_repeated_call_runs_no_tshark(counted, pcap_dir: Path):
    srv, spawned = counted
    p = str(pcap_dir / "diameter.pcap")
    first = srv.diameter_transactions(p)
    n = len(spawned)
    second = srv.diameter_transactions(p)
    assert len(spawned) == n, "the second identical call started a process"
    assert second["cache"]["hits"] >= 1 and "cache" not in first
    strip = lambda r: {k: v for k, v in r.items() if k not in ("cache", "tokens_estimate")}  # noqa: E731
    assert strip(first) == strip(second)


@requires_tshark
def test_redaction_is_applied_after_the_cache(counted, pcap_dir: Path):
    srv, spawned = counted
    p = str(pcap_dir / "diameter.pcap")
    clear = srv.diameter_transactions(p)
    n = len(spawned)
    redacted = srv.diameter_transactions(p, redact="ids")
    assert "001010123456789" in str(clear) and "001010123456789" not in str(redacted)
    assert redacted["cache"]["hits"] >= 1
    # the pre-scan of redaction may read the file once; the tool's own runs come from the cache
    assert len(spawned) - n <= 2


@requires_tshark
def test_cache_off(configure, pcap_dir: Path, monkeypatch):
    srv = configure()
    srv.state().runner.cache = None
    p = str(pcap_dir / "diameter.pcap")
    srv.diameter_transactions(p)
    assert "cache" not in srv.diameter_transactions(p)


@requires_tshark
def test_handle_pins_file_filter_and_window(configure, pcap_dir: Path, tmp_path: Path):
    srv = configure(allow=[str(pcap_dir), str(tmp_path)])
    p = str(pcap_dir / "diameter.pcap")
    plain = srv.diameter_transactions(p)
    opened = srv.open_capture(p)
    assert opened["handle"].startswith("cap:") and len(opened["handle"]) == 20
    assert opened["path"] == p and opened["packets"] > 0
    via = srv.diameter_transactions(opened["handle"])
    assert via["transactions"] == plain["transactions"]
    # a pinned filter is ANDed into every call on the handle
    ulr = srv.open_capture(p, filter="diameter.cmd.code == 316")
    assert ulr["filter"] == "diameter.cmd.code == 316" and ulr["handle"] != opened["handle"]
    rows = srv.diameter_transactions(ulr["handle"])["transactions"]
    assert rows and all(r["command_code"] == 316 for r in rows) and len(rows) < len(plain["transactions"])
    # a pinned window applies unless the call names its own
    early = srv.open_capture(p, end="+0.001s")
    assert early["end"] == "+0.001s"
    windowed = srv.diameter_transactions(early["handle"])
    assert windowed["window"]["end_arg"] == "+0.001s" and len(windowed["transactions"]) < len(plain["transactions"])
    own = srv.diameter_transactions(early["handle"], end="+3600s")
    assert own["window"]["end_arg"] == "+3600s"


@requires_tshark
def test_stale_unknown_and_nested_handles(configure, pcap_dir: Path, tmp_path: Path):
    srv = configure(allow=[str(pcap_dir), str(tmp_path)])
    copy = tmp_path / "copy.pcap"
    shutil.copy(pcap_dir / "diameter.pcap", copy)
    h = srv.open_capture(str(copy))["handle"]
    assert "error" not in srv.pcap_info(h)
    with open(copy, "ab") as fh:
        fh.write(b"\0" * 16)
    stale = srv.pcap_info(h)
    assert stale["error"]["type"] == "stale_handle" and stale["error"]["fix"]
    unknown = srv.pcap_info("cap:0123456789abcdef")
    assert unknown["error"]["type"] == "unknown_handle"
    again = srv.open_capture(srv.open_capture(str(pcap_dir / "diameter.pcap"))["handle"])
    assert again["error"]["type"] == "invalid_argument"


@requires_tshark
def test_handle_cannot_reach_outside_the_allow_dirs(configure, pcap_dir: Path, tmp_path: Path):
    """A handle made while a directory was allowed is refused after the allowlist no longer has it."""
    outside = tmp_path / "x"
    outside.mkdir()
    shutil.copy(pcap_dir / "diameter.pcap", outside / "d.pcap")
    srv = configure(allow=[str(outside)])
    h = srv.open_capture(str(outside / "d.pcap"))["handle"]
    configure(allow=[str(pcap_dir)])  # same process: handles survive, the allowlist changed
    assert srv.pcap_info(h)["error"]["type"] == "path_not_allowed"


def test_handles_are_bounded():
    handles.clear()
    assert handles.MAX_HANDLES == 64


@requires_tshark
def test_incident_summary_on_a_handle_reuses_runs(counted, pcap_dir: Path):
    srv, spawned = counted
    h = srv.open_capture(str(pcap_dir / "all.pcap"), filter="diameter")["handle"]
    first = srv.incident_summary(h, focus="mobile")
    assert "error" not in first
    n = len(spawned)
    second = srv.incident_summary(h, focus="mobile")
    assert len(spawned) == n and second["cache"]["hits"] > 0
    assert second["findings"] == first["findings"]


# --------------------------------------------------------------------------- over stdio
@requires_tshark
def test_handles_and_cache_over_stdio(pcap_dir: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def go(extra: list[str]) -> dict:
        params = StdioServerParameters(command=sys.executable, env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK),
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(pcap_dir), *extra])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                opened = (await session.call_tool("open_capture", {"path": str(pcap_dir / "gtpv2.pcap"),
                                                                   "filter": "gtpv2.message_type == 32 || gtpv2.message_type == 33"})).structured_content
                one = (await session.call_tool("gtp_sessions", {"path": opened["handle"]})).structured_content
                two = (await session.call_tool("gtp_sessions", {"path": opened["handle"]})).structured_content
                return {"opened": opened, "one": one, "two": two}

    got = asyncio.run(go([]))
    assert got["opened"]["handle"].startswith("cap:")
    msgs = {t["message"] for t in got["one"]["transactions"]}
    assert msgs == {"Create Session Request"}
    assert got["two"]["cache"]["hits"] >= 1
    off = asyncio.run(go(["--cache-mb", "0"]))
    assert "cache" not in off["two"]

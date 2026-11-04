"""Cancellation kills tshark; long calls report progress when the client asks for it."""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
import time
from pathlib import Path

import anyio

from tshark_mcp import progress
from tshark_mcp.limits import Limits
from tshark_mcp.runner import Runner

from . import pcapgen
from .conftest import TSHARK, requires_tshark


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers kill(0); the runner reaps its children, so treat one as gone.
    try:
        waited, _ = os.waitpid(pid, os.WNOHANG)
        return waited == 0
    except ChildProcessError:
        return True


def _sleeper(tmp_path: Path, pid_file: Path) -> str:
    """A fake tshark: answers the glossary and filter dry runs, sleeps on a real read."""
    script = tmp_path / "fake-tshark"
    script.write_text(f"#!{sys.executable}\n" + textwrap.dedent(f"""
        import os, sys, time
        argv = sys.argv[1:]
        if "-G" in argv or "-" in argv or "--version" in argv or "-v" in argv:
            sys.exit(0)
        with open({str(pid_file)!r}, "a") as fh:
            fh.write(f"{{os.getpid()}}\\n")
        time.sleep(30)
    """))
    script.chmod(0o755)
    return str(script)


def _pids(pid_file: Path) -> list[int]:
    return [int(x) for x in pid_file.read_text().split()] if pid_file.exists() else []


def test_cancelled_worker_kills_tshark(tmp_path: Path):
    pid_file = tmp_path / "pids"
    runner = Runner(Limits(timeout_seconds=30), tshark=_sleeper(tmp_path, pid_file))
    outcome: dict[str, object] = {}

    def work() -> None:
        try:
            runner.read_capture(tmp_path / "x.pcap", [])
        except progress.Cancelled:
            outcome["cancelled"] = True

    async def main() -> None:
        # Long enough for a new script to start (macOS scans a fresh executable on first run).
        with anyio.move_on_after(3.0):
            await anyio.to_thread.run_sync(work)

    started = time.monotonic()
    anyio.run(main)
    assert outcome == {"cancelled": True}
    assert time.monotonic() - started < 4.5, "the worker must notice the cancellation quickly"
    pids = _pids(pid_file)
    assert len(pids) == 1 and not _alive(pids[0])


def test_cancel_check_is_a_no_op_outside_a_worker_thread():
    assert progress.cancelled() is False
    progress.raise_if_cancelled()
    assert progress.report(1, 2, "x") is False


def test_reports_are_rate_limited_and_increasing():
    sent: list[tuple[float, float | None, str | None]] = []

    class Ctx:
        async def report_progress(self, value, total=None, message=None):
            sent.append((value, total, message))

    def work() -> None:
        token = progress.bind(Ctx())
        try:
            assert progress.report(1, 3, "first")
            assert not progress.report(2, 3, "too soon")
            assert not progress.report(1, 3, "not increasing", final=True)
            assert progress.report(3, 3, "done", final=True)
        finally:
            progress.unbind(token)

    async def main() -> None:
        await anyio.to_thread.run_sync(work)

    anyio.run(main)
    assert sent == [(1.0, 3.0, "first"), (3.0, 3.0, "done")]


# ------------------------------------------------------------------ over stdio
def _params(allow: Path, tshark: str):
    from mcp.client.stdio import StdioServerParameters
    env = dict(os.environ)
    env["TSHARK_MCP_TSHARK"] = tshark
    return StdioServerParameters(command=sys.executable, args=["-m", "tshark_mcp.server", "--allow-dir", str(allow)],
                                 env=env)


@requires_tshark
def test_cancelling_a_call_over_stdio_kills_tshark(tmp_path: Path, pcap_dir: Path):
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    pid_file = tmp_path / "pids"
    fake = _sleeper(tmp_path, pid_file)
    # capinfos is looked up beside tshark; give the fake directory the real one so pcap_info reaches tshark.
    real_capinfos = shutil.which("capinfos") or str(Path(TSHARK).with_name("capinfos"))
    if os.access(real_capinfos, os.X_OK):
        (tmp_path / "capinfos").symlink_to(real_capinfos)
    capture = pcap_dir / "diameter.pcap"

    async def main() -> object:
        async with stdio_client(_params(pcap_dir, fake)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                with anyio.move_on_after(4.0):
                    await session.call_tool("conversations", {"path": str(capture)})
                # The session is still usable after the cancelled call.
                for _ in range(40):
                    if _pids(pid_file) and not any(_alive(p) for p in _pids(pid_file)):
                        break
                    await anyio.sleep(0.1)
                return await session.call_tool("find_fields", {"query": "teid", "limit": 1})

    after = anyio.run(main)
    pids = _pids(pid_file)
    assert pids, "the fake tshark never started"
    assert not any(_alive(p) for p in pids), "tshark kept running after the request was cancelled"
    assert after is not None


@requires_tshark
def test_find_identifier_reports_progress_per_file_over_stdio(tmp_path: Path, pcap_dir: Path):
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    for name in ("diameter.pcap", "gtpv2.pcap", "sip.pcap", "sctp.pcap"):
        shutil.copy(pcap_dir / name, tmp_path / name)
    seen: list[tuple[float, float | None, str | None]] = []

    async def on_progress(value: float, total: float | None, message: str | None) -> None:
        seen.append((value, total, message))

    async def main() -> object:
        async with stdio_client(_params(tmp_path, TSHARK)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.call_tool("find_identifier", {"path": str(tmp_path), "identifier": pcapgen.IMSI},
                                               progress_callback=on_progress)

    result = anyio.run(main)
    assert not result.is_error, result
    assert seen, "no progress notification arrived"
    values = [v for v, _, _ in seen]
    assert values == sorted(values) and len(set(values)) == len(values)
    last = seen[-1]
    assert last[0] == last[1] == 4 and "4/4 files" in last[2]

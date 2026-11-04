"""Security hardening of the tshark child: clean profile, resource limits, a cap on
concurrent runs, a capture that cannot be swapped mid-run, decode-as validation and
symlinks that escape the allowed directories."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from tshark_mcp.limits import Limits, ToolError
from tshark_mcp.runner import Runner, assert_read_only, check_decode_as, check_result

from . import pcapgen
from .conftest import TSHARK, requires_tshark


def _fake_tshark(tmp_path: Path, body: str, name: str = "fake-tshark") -> str:
    script = tmp_path / name
    script.write_text(f"#!{sys.executable}\nimport sys, time, os\n" + textwrap.dedent(body))
    script.chmod(0o755)
    return str(script)


def _lua_enabled() -> bool:
    import subprocess
    out = subprocess.run([TSHARK, "-v"], capture_output=True, text=True).stdout
    return "with Lua" in out or "+Lua" in out or ", Lua" in out


# ------------------------------------------------------------------ clean profile
@requires_tshark
class TestCleanProfile:
    def _plant(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A personal Lua plugin in every place tshark looks for one, each printing a marker."""
        home = tmp_path / "home"
        cfg = tmp_path / "cfg"
        for plugins in (home / ".local/lib/wireshark/plugins", home / ".config/wireshark/plugins", cfg / "plugins"):
            plugins.mkdir(parents=True)
            (plugins / "marker.lua").write_text('print("PLANTED_MARKER")\n')
        (cfg / "init.lua").write_text('print("PLANTED_MARKER")\n')
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("WIRESHARK_CONFIG_DIR", str(cfg))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    def test_personal_lua_never_loads(self, tmp_path: Path, pcap_dir: Path, monkeypatch: pytest.MonkeyPatch):
        if not _lua_enabled():
            pytest.skip("tshark built without Lua")
        self._plant(tmp_path, monkeypatch)
        capture = pcap_dir / "diameter.pcap"
        clean = Runner(Limits(), tshark=TSHARK).read_capture(capture, ["-T", "fields", "-e", "frame.number"])
        assert clean.returncode == 0 and clean.stdout.split() == ["1", "2", "3", "4", "5", "6", "7"]
        assert "PLANTED_MARKER" not in clean.stdout + clean.stderr
        # The planted scripts do load when the operator opts in, so the check above means something.
        opted = Runner(Limits(), tshark=TSHARK, user_profile=True).read_capture(capture, ["-T", "fields", "-e", "frame.number"])
        assert "PLANTED_MARKER" in opted.stdout + opted.stderr

    def test_child_env_drops_inherited_variables(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SSLKEYLOGFILE", "/tmp/keys")
        monkeypatch.setenv("WIRESHARK_PLUGIN_DIR", "/tmp/plugins")
        monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
        fake = _fake_tshark(tmp_path, """
            import json
            print(json.dumps(dict(os.environ)))
        """)
        env = json.loads(Runner(Limits(), tshark=fake).read_capture(tmp_path / "x.pcap", []).stdout)
        assert not {"SSLKEYLOGFILE", "WIRESHARK_PLUGIN_DIR", "LD_PRELOAD"} & set(env)
        empty = Path(env["WIRESHARK_CONFIG_DIR"])
        assert env["HOME"] == env["XDG_CONFIG_HOME"] == env["WIRESHARK_EXTCAP_DIR"] == str(empty)
        assert empty.is_dir() and list(empty.iterdir()) == []
        assert not os.access(empty, os.W_OK)


# ------------------------------------------------------------------ resource limits
def test_child_runs_at_lower_priority(tmp_path: Path):
    fake = _fake_tshark(tmp_path, """
        print(os.getpriority(os.PRIO_PROCESS, 0))
    """)
    nice = int(Runner(Limits(), tshark=fake).read_capture(tmp_path / "x.pcap", []).stdout)
    assert nice >= min(19, os.getpriority(os.PRIO_PROCESS, 0) + 10)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS is applied on Linux only")
def test_memory_limit_turns_into_out_of_memory_error(tmp_path: Path):
    fake = _fake_tshark(tmp_path, """
        time.sleep(0.3)  # the limit is applied right after the start
        hog = []
        while True:
            hog.append(bytearray(64 * 1024 * 1024))
    """)
    runner = Runner(Limits(max_tshark_memory_bytes=256 * 1024 * 1024, timeout_seconds=20), tshark=fake)
    result = runner.read_capture(tmp_path / "x.pcap", [])
    with pytest.raises(ToolError) as exc:
        check_result(result)
    assert exc.value.type == "tshark_failed" and exc.value.details["out_of_memory"] is True


def test_out_of_memory_marker_is_reported(tmp_path: Path):
    fake = _fake_tshark(tmp_path, """
        sys.stderr.write("GLib-ERROR: failed to allocate 4294967296 bytes\\n")
        sys.exit(134)
    """)
    result = Runner(Limits(), tshark=fake).read_capture(tmp_path / "x.pcap", [])
    with pytest.raises(ToolError) as exc:
        check_result(result)
    assert exc.value.details.get("out_of_memory") is True and "memory" in exc.value.message


# ------------------------------------------------------------------ concurrency
def test_third_parallel_run_is_busy(tmp_path: Path):
    fake = _fake_tshark(tmp_path, """
        time.sleep(1.5)
    """)
    runner = Runner(Limits(max_concurrent_runs=2, busy_wait_seconds=0.3, timeout_seconds=10), tshark=fake)
    outcomes: list[str] = []
    lock = threading.Lock()

    def call() -> None:
        try:
            runner.read_capture(tmp_path / "x.pcap", [])
            what = "ok"
        except ToolError as exc:
            what = exc.type
        with lock:
            outcomes.append(what)

    threads = [threading.Thread(target=call) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert sorted(outcomes) == ["busy", "ok", "ok"]
    # Slots are released: the next run goes through.
    runner.read_capture(tmp_path / "x.pcap", [])


def test_a_slot_is_released_after_a_failure(tmp_path: Path):
    fake = _fake_tshark(tmp_path, """
        time.sleep(5)
    """)
    runner = Runner(Limits(max_concurrent_runs=1, busy_wait_seconds=0.1, timeout_seconds=0.2), tshark=fake)
    for _ in range(3):
        with pytest.raises(ToolError) as exc:
            runner.read_capture(tmp_path / "x.pcap", [])
        assert exc.value.type == "timeout"


# ------------------------------------------------------------------ swapped capture
def test_capture_swapped_during_the_run_is_refused(tmp_path: Path):
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"original")
    other = tmp_path / "other.pcap"
    other.write_bytes(b"replacement")
    fake = _fake_tshark(tmp_path, f"""
        os.replace({str(other)!r}, {str(capture)!r})
        print("read")
    """)
    with pytest.raises(ToolError) as exc:
        Runner(Limits(), tshark=fake).read_capture(capture, [])
    assert exc.value.type == "capture_changed"


def test_unchanged_capture_is_read(tmp_path: Path):
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"original")
    fake = _fake_tshark(tmp_path, """
        print("read")
    """)
    assert Runner(Limits(), tshark=fake).read_capture(capture, []).stdout == "read\n"


# ------------------------------------------------------------------ decode-as
@pytest.mark.parametrize("rule", ["udp.port==2152,gtp", "tcp.port==3868,diameter", "sctp.port==2905,m3ua",
                                  "sctp.ppi==46,diameter", "udp.port==5060-5070,sip"])
def test_decode_as_rules_allowed(rule: str):
    check_decode_as(rule)
    assert_read_only(["-n", "-r", "x.pcap", "-d", rule])


@pytest.mark.parametrize("rule", ["", "udp.port==2152", "frame.number==1,lua_evil", "udp.port==70000,gtp",
                                  "udp.port==9-3,gtp", "udp.port==2152,gtp;rm", "udp.port==2152,GTP X",
                                  "ip.proto==17,udp", "udp.port==2152,gtp,extra", "-w"])
def test_decode_as_rules_refused(rule: str):
    with pytest.raises(ToolError) as exc:
        assert_read_only(["-n", "-r", "x.pcap", "-d", rule])
    assert exc.value.type == "forbidden_flag"


def test_decode_as_without_value_refused():
    with pytest.raises(ToolError):
        assert_read_only(["-n", "-r", "x.pcap", "-d"])


# ------------------------------------------------------------------ symlink escapes
@pytest.fixture
def escape_tree(tmp_path: Path, pcap_dir: Path) -> tuple[Path, Path]:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    shutil.copy(pcap_dir / "diameter.pcap", outside / "secret.pcap")
    shutil.copy(pcap_dir / "gtpv2.pcap", allowed / "inside.pcap")
    (allowed / "linked.pcap").symlink_to(outside / "secret.pcap")
    (allowed / "subdir").symlink_to(outside, target_is_directory=True)
    return allowed, outside


@requires_tshark
def test_find_identifier_skips_a_file_symlink_out_of_the_allowlist(configure, escape_tree):
    allowed, _ = escape_tree
    srv = configure(allow=[str(allowed)])
    result = srv.find_identifier(path=str(allowed), identifier=pcapgen.IMSI)
    assert all("secret" not in row["path"] for row in result["files"])
    refused = {e["path"]: e["error"] for e in result["errors"]}
    assert refused == {str(allowed / "linked.pcap"): "path_not_allowed"}


@requires_tshark
def test_find_identifier_refuses_a_directory_symlink_out_of_the_allowlist(configure, escape_tree):
    allowed, _ = escape_tree
    srv = configure(allow=[str(allowed)])
    result = srv.find_identifier(path=str(allowed / "subdir"), identifier=pcapgen.IMSI)
    assert result["error"]["type"] == "path_not_allowed"
    assert srv.pcap_info(path=str(allowed / "subdir" / "secret.pcap"))["error"]["type"] == "path_not_allowed"


# ------------------------------------------------------------------ over stdio
async def _stdio_folders(pcap_dir: Path, home: Path) -> object:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    env = dict(os.environ)
    env["TSHARK_MCP_TSHARK"] = TSHARK
    env["HOME"] = str(home)
    env.pop("WIRESHARK_CONFIG_DIR", None)
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "tshark_mcp.server", "--allow-dir", str(pcap_dir),
                                         "--max-concurrent-runs", "1"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool("filter_packets", {"path": str(pcap_dir / "diameter.pcap"),
                                                              "display_filter": "frame.number == 1"})


@requires_tshark
def test_planted_plugin_does_not_run_through_the_server(pcap_dir: Path, tmp_path: Path):
    if not _lua_enabled():
        pytest.skip("tshark built without Lua")
    home = tmp_path / "home"
    plugins = home / ".local/lib/wireshark/plugins"
    plugins.mkdir(parents=True)
    marker = tmp_path / "plugin-ran"
    # A Lua script that leaves a file behind if it is ever loaded.
    (plugins / "evil.lua").write_text(f"local f = io.open({json.dumps(str(marker))}, 'w'); f:write('x'); f:close()\n")
    import subprocess
    subprocess.run([TSHARK, "-n", "-r", str(pcap_dir / "diameter.pcap"), "-c", "1"], capture_output=True,
                   env={**os.environ, "HOME": str(home)}, check=True)
    assert marker.exists(), "the planted script must load in a plain tshark run for this test to mean anything"
    marker.unlink()
    result = asyncio.run(_stdio_folders(pcap_dir, home))
    structured = result.structured_content
    assert "error" not in structured, structured
    assert structured["returned"] == 1
    assert not marker.exists()


def test_new_error_types_have_a_fix():
    from tshark_mcp import errors
    for kind in ("busy", "capture_changed"):
        assert errors.add_fix({"type": kind, "message": "m"}, "pcap_info", {"path": "/x"}, allowlist=None,
                              catalogue=None, suffixes={".pcap"})["fix"]
    oom = errors.add_fix({"type": "tshark_failed", "message": "m", "out_of_memory": True}, "gtp_sessions",
                         {"path": "/x", "imsi": None, "teid": None}, allowlist=None, catalogue=None, suffixes={".pcap"})
    assert "memory" in oom["fix"] and "imsi" in oom["fix"]

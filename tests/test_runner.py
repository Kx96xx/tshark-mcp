"""Runner tests. The timeout and output-cap behaviour is exercised with a fake
"tshark" (a tiny Python script) so the tests are fast and deterministic; the
filter dry run uses the real binary when it is installed."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from tshark_mcp.limits import Limits, ToolError
from tshark_mcp.runner import EMPTY_PCAP, FORBIDDEN_FLAGS, Runner, assert_read_only, check_result

from .conftest import TSHARK, requires_tshark


def _fake_tshark(tmp_path: Path, body: str) -> str:
    script = tmp_path / "fake-tshark"
    script.write_text(f"#!{sys.executable}\nimport sys, time, os\n" + textwrap.dedent(body))
    script.chmod(0o755)
    return str(script)


class TestReadOnlyGuard:
    @pytest.mark.parametrize("flag", sorted(FORBIDDEN_FLAGS))
    def test_every_forbidden_flag_is_refused(self, flag):
        with pytest.raises(ToolError) as exc:
            assert_read_only(["-r", "x.pcap", flag, "value"])
        assert exc.value.type == "forbidden_flag"

    def test_long_option_with_equals_is_refused(self):
        with pytest.raises(ToolError):
            assert_read_only(["-r", "x.pcap", "--interface=en0"])

    def test_combined_short_options_are_refused(self):
        with pytest.raises(ToolError):
            assert_read_only(["-r", "x.pcap", "-qw"])

    def test_missing_dash_r_is_refused(self):
        with pytest.raises(ToolError) as exc:
            assert_read_only(["-T", "json"])
        assert "-r" in exc.value.message

    def test_glossary_dump_needs_no_file(self):
        assert_read_only(["-G", "fields"])

    def test_normal_read_argv_passes(self):
        assert_read_only(["-n", "-r", "x.pcap", "-c", "5", "-Y", "diameter", "-T", "json", "-2"])

    def test_capture_never_appears_in_source(self):
        src_dir = Path(__file__).resolve().parents[1] / "src" / "tshark_mcp"
        for py in src_dir.glob("*.py"):
            text = py.read_text()
            assert '"-i"' not in text.replace('"-i", "--interface"', "")
            assert "tcp" + "dump" not in text.lower()


class TestFakeSubprocess:
    def test_a_crashing_tshark_is_explained(self, tmp_path: Path):
        """tshark dies of SIGSEGV on some fuzzed captures; the error used to be 'tshark exited
        with -11', which reads like a server fault and gives no way out. The fake dies of
        SIGTERM: any signal death gives a negative return code and takes the same path, and a
        real SIGSEGV would make the macOS crash reporter pop up a dialog on every test run."""
        fake = _fake_tshark(tmp_path, """
            import signal
            os.kill(os.getpid(), signal.SIGTERM)
        """)
        runner = Runner(Limits(), tshark=fake)
        with pytest.raises(ToolError) as exc:
            check_result(runner._execute(fake, ["-r", str(tmp_path / "x.pcap")]))
        assert exc.value.type == "tshark_failed"
        assert "tshark crashed (SIGTERM)" in str(exc.value) and "newer tshark" in str(exc.value)
        assert exc.value.details["returncode"] == -15

    def test_timeout_kills_child(self, tmp_path: Path):
        fake = _fake_tshark(tmp_path, """
            sys.stdout.write("partial")
            sys.stdout.flush()
            time.sleep(30)
        """)
        runner = Runner(Limits(timeout_seconds=0.3), tshark=fake)
        with pytest.raises(ToolError) as exc:
            runner.read_capture(tmp_path / "any.pcap", ["-T", "json"])
        assert exc.value.type == "timeout"

    def test_output_cap_kills_child(self, tmp_path: Path):
        fake = _fake_tshark(tmp_path, """
            while True:
                sys.stdout.write("x" * 65536)
                sys.stdout.flush()
        """)
        runner = Runner(Limits(max_stdout_bytes=200_000, timeout_seconds=5), tshark=fake)
        with pytest.raises(ToolError) as exc:
            runner.read_capture(tmp_path / "any.pcap", ["-T", "json"])
        assert exc.value.type == "output_too_large"

    def test_successful_run_returns_streams_and_timing(self, tmp_path: Path):
        fake = _fake_tshark(tmp_path, """
            sys.stdout.write("hello\\n")
            sys.stderr.write("warn\\n")
            sys.exit(0)
        """)
        runner = Runner(Limits(), tshark=fake)
        result = runner.read_capture(tmp_path / "any.pcap", ["-T", "fields"], max_packets=7, display_filter="sip")
        assert result.returncode == 0
        assert result.stdout == "hello\n" and result.stderr == "warn\n"
        assert result.stdout_bytes == 6
        assert result.duration_ms >= 0
        assert result.argv[1:4] == ("-n", "-r", str(tmp_path / "any.pcap"))
        assert "-c" in result.argv and "7" in result.argv and "-Y" in result.argv and "sip" in result.argv

    def test_nonzero_exit_becomes_tool_error(self, tmp_path: Path):
        fake = _fake_tshark(tmp_path, """
            sys.stderr.write("tshark: boom\\n")
            sys.exit(2)
        """)
        runner = Runner(Limits(), tshark=fake)
        result = runner.read_capture(tmp_path / "any.pcap", ["-T", "fields"])
        with pytest.raises(ToolError) as exc:
            check_result(result)
        assert exc.value.type == "tshark_failed" and "boom" in exc.value.message

    def test_stdin_is_delivered_for_dry_run(self, tmp_path: Path):
        fake = _fake_tshark(tmp_path, """
            data = sys.stdin.buffer.read()
            sys.exit(0 if len(data) == 24 else 7)
        """)
        runner = Runner(Limits(), tshark=fake)
        runner.validate_display_filter("ip")  # does not raise: the fake saw 24 bytes of pcap header

    def test_forbidden_flag_never_spawns(self, tmp_path: Path):
        marker = tmp_path / "ran"
        fake = _fake_tshark(tmp_path, f"""
            open({str(marker)!r}, "w").write("ran")
        """)
        runner = Runner(Limits(), tshark=fake)
        with pytest.raises(ToolError):
            runner.read_capture(tmp_path / "any.pcap", ["-w", "/tmp/out.pcap"])
        assert not marker.exists()

    def test_missing_binary(self, tmp_path: Path):
        with pytest.raises(ToolError) as exc:
            Runner(Limits(), tshark=str(tmp_path / "does-not-exist"))
        assert exc.value.type == "tshark_missing"


@requires_tshark
class TestRealTshark:
    def test_empty_pcap_constant_is_valid(self, tmp_path: Path):
        f = tmp_path / "empty.pcap"
        f.write_bytes(EMPTY_PCAP)
        runner = Runner(Limits(), tshark=TSHARK)
        result = runner.read_capture(f, ["-T", "fields", "-e", "frame.number"])
        assert result.returncode == 0 and result.stdout == ""

    def test_dry_run_rejects_bad_field(self):
        runner = Runner(Limits(), tshark=TSHARK)
        with pytest.raises(ToolError) as exc:
            runner.validate_display_filter("nosuch.field == 1")
        assert exc.value.type == "invalid_filter"
        assert "nosuch.field" in exc.value.message

    def test_dry_run_accepts_good_filter(self):
        Runner(Limits(), tshark=TSHARK).validate_display_filter("diameter.cmd.code == 316 && ip.src == 192.0.2.1")

    def test_name_resolution_is_disabled(self, tmp_path: Path):
        f = tmp_path / "empty.pcap"
        f.write_bytes(EMPTY_PCAP)
        result = Runner(Limits(), tshark=TSHARK).read_capture(f, ["-T", "fields", "-e", "frame.number"])
        assert result.argv[1] == "-n"

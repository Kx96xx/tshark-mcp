"""Subprocess wrapper around tshark.

The runner is the only place that starts a process. It enforces:

* argv-list execution (never a shell string);
* read-only mode: ``-r`` is mandatory and every capture, write and export flag
  is refused before the process starts;
* a wall-clock timeout and a cap on the bytes read from stdout, both of which
  kill the child when exceeded;
* ``-n`` on every run so tshark never performs name resolution (no DNS).
"""

from __future__ import annotations

import os
import selectors
from contextvars import ContextVar, Token
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .limits import Limits, ToolError

# Messages tshark prints when a capture ends early or has a damaged record. The
# packets before the bad record are still dissected and printed, so a run that
# stopped for one of these reasons is returned with a warning instead of failing.
PARTIAL_READ_MARKERS: tuple[str, ...] = (
    "appears to have been cut short",
    "appears to be damaged or corrupt",
    "has a packet with a network type that",
    "less data than indicated",
)

_WARNINGS: ContextVar[list[str] | None] = ContextVar("tshark_mcp_warnings", default=None)


def begin_warnings() -> Token:
    """Start collecting per-call warnings (one list per tool call, context-local)."""
    return _WARNINGS.set([])


def note_warning(message: str) -> None:
    sink = _WARNINGS.get()
    if sink is not None and message not in sink:
        sink.append(message)


def collect_warnings(token: Token) -> list[str]:
    warnings = list(_WARNINGS.get() or [])
    _WARNINGS.reset(token)
    return warnings

# Flags that would make tshark capture, write, export or load code. Any of
# these anywhere in argv aborts the call before a process is created.
FORBIDDEN_FLAGS: frozenset[str] = frozenset({
    "-i", "--interface",
    "-w",
    "-D", "--list-interfaces",
    "-L", "--list-data-link-types",
    "-a", "--autostop",
    "-b", "--ring-buffer",
    "-f", "--capture-filter",
    "-p", "--no-promiscuous-mode",
    "-I", "--monitor-mode",
    "-B", "--buffer-size",
    "-y", "--linktype",
    "-F",
    "-k",
    "-S",
    "-P", "--print",
    "-X",
    "-o",
    "-C", "--config-profile",
    "-g",
    "--capture-comment",
    "--export-objects", "--export-pdus", "--export-tls-session-keys",
    "--temp-dir",
    "--update-interval",
})

# The only preferences a tool may set with -o: switch on checksum validation, which
# tshark leaves off by default. Anything else after -o (a keylog file, an extcap or
# Lua path, a temp directory) is refused like any other forbidden flag.
ALLOWED_PREFERENCES: frozenset[str] = frozenset({
    "ip.check_checksum:TRUE", "tcp.check_checksum:TRUE", "udp.check_checksum:TRUE",
})

# A tiny but complete pcap file (global header only) fed on stdin to compile a
# display filter without touching the user's capture.
EMPTY_PCAP = bytes.fromhex("d4c3b2a1" "0200" "0400" "00000000" "00000000" "ffff0000" "01000000")


@dataclass(frozen=True)
class RunResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    stdout_bytes: int


def find_tshark(explicit: str | None = None) -> str:
    """Locate the tshark binary from an explicit path, ``TSHARK_MCP_TSHARK`` or PATH."""
    candidate = explicit or os.environ.get("TSHARK_MCP_TSHARK") or shutil.which("tshark")
    if candidate is None:
        for fallback in ("/opt/homebrew/bin/tshark", "/usr/local/bin/tshark", "/usr/bin/tshark"):
            if os.access(fallback, os.X_OK):
                candidate = fallback
                break
    if candidate is None or not os.access(candidate, os.X_OK):
        raise ToolError("tshark_missing", "tshark was not found; install Wireshark/tshark or set TSHARK_MCP_TSHARK")
    return candidate


def assert_read_only(args: Sequence[str]) -> None:
    """Raise if ``args`` (everything after the program name) could capture or write."""
    for index, arg in enumerate(args):
        head = arg.split("=", 1)[0] if arg.startswith("--") else arg
        if arg == "-o" and index + 1 < len(args) and args[index + 1] in ALLOWED_PREFERENCES:
            continue
        if head in FORBIDDEN_FLAGS:
            raise ToolError("forbidden_flag", f"refusing to run tshark with {arg!r}")
        # Combined short options such as "-qw" are refused outright.
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 2 and not arg[1:].isdigit():
            if arg not in ("-2",):
                raise ToolError("forbidden_flag", f"refusing combined short option {arg!r}")
    if "-G" in args:
        return  # glossary dump, no input file
    if "-r" not in args:
        raise ToolError("forbidden_flag", "tshark must be run with -r (read an existing file)")


class Runner:
    """Runs tshark in read-only mode under the configured limits."""

    def __init__(self, limits: Limits, tshark: str | None = None, capinfos: str | None = None) -> None:
        self.limits = limits
        self.tshark = find_tshark(tshark)
        self.capinfos = capinfos or self._sibling("capinfos")

    def _sibling(self, name: str) -> str | None:
        beside = Path(self.tshark).with_name(name)
        if beside.exists() and os.access(beside, os.X_OK):
            return str(beside)
        return shutil.which(name)

    # ---------------------------------------------------------------- public API
    def read_capture(self, capture: Path, args: Sequence[str], *, max_packets: int | None = None,
                     display_filter: str | None = None, timeout: float | None = None) -> RunResult:
        """Run ``tshark -n -r <capture> [-c N] [-Y filter] <args>``.

        ``timeout`` can only shorten the configured per-run limit (a caller with a
        shared budget passes what is left of it)."""
        argv: list[str] = ["-n", "-r", str(capture)]
        if max_packets is not None:
            # One more than the frame-read cap so a caller can place a sentinel frame just past it.
            argv += ["-c", str(max(1, min(int(max_packets), self.limits.max_scan_packets + 1)))]
        if display_filter:
            argv += ["-Y", display_filter]
        argv += list(args)
        return self._execute(self.tshark, argv, timeout=timeout)

    def list_fields(self) -> RunResult:
        return self._execute(self.tshark, ["-G", "fields"])

    def validate_display_filter(self, display_filter: str) -> None:
        """Compile the filter against an empty capture; raise ToolError if tshark rejects it."""
        result = self._execute(self.tshark, ["-n", "-r", "-", "-Y", display_filter], stdin=EMPTY_PCAP)
        if result.returncode != 0:
            message = result.stderr.strip() or "tshark rejected the display filter"
            raise ToolError("invalid_filter", message, display_filter=display_filter)

    def capinfos_summary(self, capture: Path) -> RunResult | None:
        """Machine-readable capinfos summary, or None when capinfos is unavailable."""
        if not self.capinfos:
            return None
        return self._execute(self.capinfos, ["-M", "-S", "-c", "-u", "-a", "-e", "-s", "-E", "-t", str(capture)],
                             read_only_check=False)

    # ---------------------------------------------------------------- internals
    def _execute(self, program: str, args: Sequence[str], *, stdin: bytes | None = None,
                 read_only_check: bool = True, timeout: float | None = None) -> RunResult:
        if read_only_check:
            assert_read_only(args)
        argv = [program, *args]
        started = time.monotonic()
        limit = self.limits.timeout_seconds if timeout is None else max(0.0, min(timeout, self.limits.timeout_seconds))
        deadline = started + limit
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
            )
        except OSError as exc:
            raise ToolError("exec_failed", f"could not start {program}: {exc}") from None

        stderr_chunks: list[bytes] = []
        stderr_thread = threading.Thread(target=_drain, args=(proc.stderr, stderr_chunks), daemon=True)
        stderr_thread.start()
        if stdin is not None and proc.stdin is not None:
            try:
                proc.stdin.write(stdin)
            except BrokenPipeError:
                pass
            finally:
                proc.stdin.close()

        stdout_chunks: list[bytes] = []
        total = 0
        failure: ToolError | None = None
        assert proc.stdout is not None
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = ToolError("timeout", f"tshark exceeded {round(limit, 3)}s and was killed",
                                        timeout_seconds=round(limit, 3))
                    break
                if not sel.select(timeout=min(remaining, 0.5)):
                    continue
                chunk = os.read(proc.stdout.fileno(), 1 << 16)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.limits.max_stdout_bytes:
                    failure = ToolError("output_too_large",
                                        f"tshark produced more than {self.limits.max_stdout_bytes} bytes; narrow the filter",
                                        max_stdout_bytes=self.limits.max_stdout_bytes)
                    break
                stdout_chunks.append(chunk)

        if failure is not None:
            _kill(proc)
            raise failure
        try:
            returncode = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _kill(proc)
            raise ToolError("timeout", f"tshark exceeded {round(limit, 3)}s and was killed",
                            timeout_seconds=round(limit, 3)) from None
        stderr_thread.join(timeout=1.0)
        duration_ms = int((time.monotonic() - started) * 1000)
        return RunResult(
            argv=tuple(argv),
            returncode=returncode,
            stdout=b"".join(stdout_chunks).decode("utf-8", "replace"),
            stderr=b"".join(stderr_chunks).decode("utf-8", "replace"),
            duration_ms=duration_ms,
            stdout_bytes=total,
        )


def _drain(stream, sink: list[bytes]) -> None:
    try:
        for chunk in iter(lambda: stream.read(1 << 14), b""):
            sink.append(chunk)
    except (OSError, ValueError):
        pass


def _kill(proc: subprocess.Popen) -> None:
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def check_result(result: RunResult, *, allow_nonzero: bool = False) -> RunResult:
    """Turn a failing tshark exit into a ToolError with the stderr text.

    A capture that was cut short (a ring-buffer file still being written, an
    interrupted copy) makes tshark exit non-zero after printing everything it
    could read, which may be nothing when the filter matched no packet. That
    output is kept and the condition is reported as a warning.
    """
    if result.returncode != 0 and not allow_nonzero:
        stderr = result.stderr.strip()
        if any(marker in stderr for marker in PARTIAL_READ_MARKERS):
            first_line = stderr.splitlines()[0]
            note_warning(f"tshark stopped before the end of the file; results cover the readable part only: {first_line}")
            return result
        raise ToolError("tshark_failed", stderr or f"tshark exited with {result.returncode}",
                        returncode=result.returncode)
    return result

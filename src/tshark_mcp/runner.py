"""Subprocess wrapper around tshark.

The runner is the only place that starts a process. It enforces:

* argv-list execution (never a shell string);
* read-only mode: ``-r`` is mandatory and every capture, write and export flag
  is refused before the process starts;
* a wall-clock timeout and a cap on the bytes read from stdout, both of which
  kill the child when exceeded;
* ``-n`` on every run so tshark never performs name resolution (no DNS);
* a clean environment: tshark gets an empty, read-only personal configuration
  directory, so no personal ``init.lua``, Lua or binary plugin, extcap, preference or
  profile from the account running the server is loaded;
* a lower CPU priority (nice 10) and, on Linux, an address-space limit for the child;
* at most ``max_concurrent_runs`` children at once (a later call waits up to
  ``busy_wait_seconds``, then fails with ``busy``);
* a cancelled MCP request kills the child within a quarter of a second;
* the capture keeps the same device and inode from before the start to the end of the
  run, so a file swapped in after the allowlist check is never read.
"""

from __future__ import annotations

import atexit
import os
import re
import selectors
import sys
import tempfile
from contextvars import ContextVar, Token
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from . import progress, window
from .limits import Limits, ToolError, echo

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


_DEADLINE: ContextVar[float | None] = ContextVar("tshark_mcp_deadline", default=None)


def set_deadline(at: float | None) -> Token:
    """Cap every run of this call (context) at ``at`` (a ``time.monotonic()`` value): a tool that
    runs several other tools under one budget sets it once, and each run gets what is left."""
    return _DEADLINE.set(at)


def reset_deadline(token: Token) -> None:
    _DEADLINE.reset(token)


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
    # nas_procedures: read NAS sent with null ciphering (EEA0) only when asked, the same on every tshark.
    "nas-eps.null_decipher:TRUE", "nas-eps.null_decipher:FALSE",
    # http_transactions: read a response's status line from its first segment when tshark cannot
    # reassemble the whole response in one pass. Changes dissection only, never what is read or written.
    "tcp.desegment_tcp_streams:FALSE",
})


# Statistics (-z) tshark may compute. Each only reads the dissected packets and
# prints a table; anything else after -z is refused.
ALLOWED_STATS: frozenset[str] = frozenset({"io", "conv", "endpoints", "expert", "rtp", "sip", "diameter", "dns", "http"})

# Decode-as (-d) is allowed only as "<layer>==<port or range>,<protocol>" on these
# selectors: it changes which built-in dissector reads a port, nothing else.
DECODE_AS_SELECTORS: frozenset[str] = frozenset({"tcp.port", "udp.port", "sctp.port", "sctp.ppi"})
_DECODE_AS = re.compile(r"^(?P<sel>[a-z]+\.[a-z]+)==(?P<lo>\d{1,5})(?:-(?P<hi>\d{1,5}))?,(?P<proto>[a-z][a-z0-9_.\-]{0,63})$")


def check_decode_as(value: str) -> None:
    """Raise unless ``value`` is a decode-as rule on an allowed selector."""
    m = _DECODE_AS.match(value or "")
    if not m or m.group("sel") not in DECODE_AS_SELECTORS:
        raise ToolError("forbidden_flag", f"refusing decode-as rule {echo(value)}; allowed: "
                        f"<{'|'.join(sorted(DECODE_AS_SELECTORS))}>==<number>[-<number>],<protocol>")
    lo, hi = int(m.group("lo")), int(m.group("hi") or m.group("lo"))
    top = 0xFFFFFFFF if m.group("sel") == "sctp.ppi" else 65535
    if lo > hi or hi > top:
        raise ToolError("forbidden_flag", f"refusing decode-as rule {echo(value)}: bad number or range")


# Variables kept from the server's environment for the child; everything else (including
# WIRESHARK_*, SSLKEYLOGFILE, LD_PRELOAD, DYLD_*) is dropped.
KEPT_ENV: tuple[str, ...] = ("PATH", "LANG", "LANGUAGE", "TZ", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR")
NICE_INCREMENT = 10
CANCEL_POLL_SECONDS = 0.25
# Lines tshark, GLib or a Python fake print when an allocation fails.
OUT_OF_MEMORY_MARKERS: tuple[str, ...] = ("out of memory", "failed to allocate", "cannot allocate memory",
                                          "bad_alloc", "memoryerror")

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
        # A desktop host (Claude Desktop) starts the server without the shell's PATH.
        for fallback in ("/opt/homebrew/bin/tshark", "/usr/local/bin/tshark", "/usr/bin/tshark",
                         "/Applications/Wireshark.app/Contents/MacOS/tshark"):
            if os.access(fallback, os.X_OK):
                candidate = fallback
                break
    if candidate is None or not os.access(candidate, os.X_OK):
        raise ToolError("tshark_missing", "tshark was not found; install Wireshark/tshark or set TSHARK_MCP_TSHARK")
    return candidate


def assert_read_only(args: Sequence[str]) -> None:
    """Raise if ``args`` (everything after the program name) could capture or write."""
    for index, arg in enumerate(args):
        if arg == "-d":
            check_decode_as(args[index + 1] if index + 1 < len(args) else "")
        if arg == "-z":
            stat = args[index + 1] if index + 1 < len(args) else ""
            if stat.split(",", 1)[0] not in ALLOWED_STATS:
                raise ToolError("forbidden_flag", f"refusing statistic -z {echo(stat.split(',', 1)[0])}")
        head = arg.split("=", 1)[0] if arg.startswith("--") else arg
        if arg == "-o" and index + 1 < len(args) and args[index + 1] in ALLOWED_PREFERENCES:
            continue
        if head in FORBIDDEN_FLAGS:
            raise ToolError("forbidden_flag", f"refusing to run tshark with {echo(arg)}")
        # Combined short options such as "-qw" are refused outright.
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 2 and not arg[1:].isdigit():
            if arg not in ("-2",):
                raise ToolError("forbidden_flag", f"refusing combined short option {echo(arg)}")
    if "-G" in args:
        return  # glossary dump, no input file
    if "-r" not in args:
        raise ToolError("forbidden_flag", "tshark must be run with -r (read an existing file)")


def _check_write_argv(argv: Sequence[str]) -> None:
    """The exact shape write_subset builds; anything else (an extra flag, a second -w) is refused."""
    shape = ["-n", "-r", None, "-c", None, "-Y", None, "-F", "pcapng", "-w", None]
    if len(argv) != len(shape) or any(want is not None and got != want for got, want in zip(argv, shape)):
        raise ToolError("forbidden_flag", "refusing a write run that is not the export shape")
    if not argv[4].isdigit():
        raise ToolError("forbidden_flag", "refusing a write run with a bad frame count")


class Runner:
    """Runs tshark in read-only mode under the configured limits."""

    def __init__(self, limits: Limits, tshark: str | None = None, capinfos: str | None = None,
                 user_profile: bool = False) -> None:
        self.limits = limits
        self.tshark = find_tshark(tshark)
        self.capinfos = capinfos or self._sibling("capinfos")
        self.dftest = self._sibling("dftest")
        self.user_profile = user_profile
        self._slots = threading.BoundedSemaphore(limits.max_concurrent_runs)
        self._env: dict[str, str] | None = None

    def child_env(self) -> dict[str, str] | None:
        """The environment every child gets: None (inherit) with ``user_profile``, otherwise
        the kept variables plus an empty read-only directory as HOME, XDG config and data
        homes, Wireshark's personal configuration and extcap directories."""
        if self.user_profile:
            return None
        if self._env is None:
            empty = tempfile.mkdtemp(prefix="tshark-mcp-profile-")
            os.chmod(empty, 0o500)
            atexit.register(_remove_dir, empty)
            env = {k: v for k, v in os.environ.items() if k in KEPT_ENV or k.startswith("LC_")}
            for var in ("HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                        "WIRESHARK_CONFIG_DIR", "WIRESHARK_EXTCAP_DIR"):
                env[var] = empty
            self._env = env
        return self._env

    def _sibling(self, name: str) -> str | None:
        beside = Path(self.tshark).with_name(name)
        if beside.exists() and os.access(beside, os.X_OK):
            return str(beside)
        return shutil.which(name)

    # ---------------------------------------------------------------- public API
    def read_capture(self, capture: Path, args: Sequence[str], *, max_packets: int | None = None,
                     display_filter: str | None = None, timeout: float | None = None,
                     sentinel: int | None = None, stats_windowed: bool = False) -> RunResult:
        """Run ``tshark -n -r <capture> [-c N] [-Y filter] <args>``.

        ``timeout`` can only shorten the configured per-run limit (a caller with a
        shared budget passes what is left of it). The call's time window (``start`` /
        ``end``, see :mod:`window`) goes ahead of ``display_filter``; frame ``sentinel``
        (the one just past the read cap) is kept whatever the filter and the window say.
        ``-Y`` does not reach ``-z`` statistics, so a statistics run under a window must
        have put the window into its own statistic filter (``stats_windowed``)."""
        argv: list[str] = ["-n", "-r", str(capture)]
        identity = _identity(capture)
        if max_packets is not None:
            # One more than the frame-read cap so a caller can place a sentinel frame just past it.
            argv += ["-c", str(max(1, min(int(max_packets), self.limits.max_scan_packets + 1)))]
        clause = window.clause(capture, self.capinfos_summary)
        if clause and "-z" in args and not stats_windowed:
            raise ToolError("internal_error", "a -z statistic under a time window must carry the window in its filter")
        display_filter = window.combine(clause, display_filter)
        if sentinel is not None and display_filter:
            display_filter = f"({display_filter}) || frame.number == {int(sentinel)}"
        if display_filter:
            argv += ["-Y", display_filter]
        argv += list(args)
        return self._execute(self.tshark, argv, timeout=timeout,
                             capture=(capture, identity) if identity is not None else None)

    def write_subset(self, capture: Path, out: Path, export_dir: Path, display_filter: str, frames_read: int,
                     timeout: float | None = None) -> RunResult:
        """The only run that writes: ``tshark -n -r <capture> -c N -Y <filter> -F pcapng -w <out>``.

        Built here, never from agent text: ``out`` must be a temporary file the server created
        directly inside ``export_dir`` (see :mod:`export`). The call's time window goes ahead of
        the filter as in :meth:`read_capture`. ``-w`` and ``-F`` stay forbidden everywhere else."""
        from .export import TMP_PREFIX
        if out.parent != export_dir or not out.name.startswith(TMP_PREFIX) or out.is_symlink():
            raise ToolError("forbidden_flag", "refusing to write outside the export directory's temporary files")
        if not display_filter:
            raise ToolError("forbidden_flag", "an export needs a display filter")
        identity = _identity(capture)
        flt = window.combine(window.clause(capture, self.capinfos_summary), display_filter)
        n = max(1, min(int(frames_read), self.limits.max_scan_packets))
        argv = ["-n", "-r", str(capture), "-c", str(n), "-Y", flt, "-F", "pcapng", "-w", str(out)]
        _check_write_argv(argv)
        return self._execute(self.tshark, argv, timeout=timeout, read_only_check=False,
                             capture=(capture, identity) if identity is not None else None)

    def cut_payloads(self, src: Path, out: Path, export_dir: Path, snaplen: int) -> RunResult:
        """``editcap -s <snaplen> <src> <out>`` on two of the export's own temporary files."""
        from .export import TMP_PREFIX
        editcap = self._sibling("editcap")
        if not editcap:
            raise ToolError("tshark_missing", "editcap (installed with tshark) was not found; cannot cut payloads")
        for f in (src, out):
            if f.parent != export_dir or not f.name.startswith(TMP_PREFIX) or f.is_symlink():
                raise ToolError("forbidden_flag", "refusing to run editcap outside the export directory")
        return self._execute(editcap, ["-s", str(int(snaplen)), str(src), str(out)], read_only_check=False)

    def list_fields(self) -> RunResult:
        return self._execute(self.tshark, ["-G", "fields"])

    def list_values(self, keep: Callable[[bytes], bool]) -> RunResult:
        """``tshark -G values`` (the value strings of every field, about 100 MB with
        tshark 4.6), keeping only the lines ``keep`` accepts. The filter runs while
        tshark writes, so the stdout cap applies to the kept lines, not the whole dump."""
        return self._execute(self.tshark, ["-G", "values"], keep_line=keep)

    def compile_filter(self, display_filter: str) -> RunResult:
        """Compile the filter by running tshark on an empty capture fed on stdin; no file is read."""
        return self._execute(self.tshark, ["-n", "-r", "-", "-Y", display_filter], stdin=EMPTY_PCAP)

    def dftest_filter(self, display_filter: str) -> RunResult | None:
        """``dftest -- <filter>``: compiles the filter and prints tshark's filter warnings
        (deprecated names and the like), which tshark itself does not show. None when
        dftest is not installed beside tshark."""
        if not self.dftest:
            return None
        return self._execute(self.dftest, ["--", display_filter], read_only_check=False)

    def validate_display_filter(self, display_filter: str) -> None:
        """Compile the filter against an empty capture; raise ToolError if tshark rejects it."""
        result = self.compile_filter(display_filter)
        if result.returncode != 0:
            message = result.stderr.strip() or "tshark rejected the display filter"
            raise ToolError("invalid_filter", message, display_filter=display_filter)

    def capinfos_summary(self, capture: Path) -> RunResult | None:
        """Machine-readable capinfos summary, or None when capinfos is unavailable."""
        if not self.capinfos:
            return None
        identity = _identity(capture)
        return self._execute(self.capinfos, ["-M", "-S", "-c", "-u", "-a", "-e", "-s", "-E", "-t", str(capture)],
                             read_only_check=False, capture=(capture, identity) if identity is not None else None)

    def capinfos_index(self, capture: Path, timeout: float | None = None) -> RunResult | None:
        """capinfos with the interface count (``-I``), for capture_index; None without capinfos."""
        if not self.capinfos:
            return None
        identity = _identity(capture)
        return self._execute(self.capinfos, ["-M", "-S", "-c", "-a", "-e", "-s", "-E", "-t", "-I", str(capture)],
                             read_only_check=False, timeout=timeout,
                             capture=(capture, identity) if identity is not None else None)

    # ---------------------------------------------------------------- internals
    def _execute(self, program: str, args: Sequence[str], *, stdin: bytes | None = None,
                 read_only_check: bool = True, timeout: float | None = None,
                 capture: tuple[Path, tuple[int, int]] | None = None,
                 keep_line: Callable[[bytes], bool] | None = None) -> RunResult:
        if read_only_check:
            assert_read_only(args)
        started = time.monotonic()
        limit = self.limits.timeout_seconds if timeout is None else max(0.0, min(timeout, self.limits.timeout_seconds))
        budget_end = _DEADLINE.get()
        if budget_end is not None:
            left = budget_end - time.monotonic()
            if left <= 0:
                raise ToolError("timeout", "the call's time budget was used up before the next tshark run")
            limit = min(limit, left)
        wait = max(0.0, min(self.limits.busy_wait_seconds, limit))
        if not self._acquire(wait):
            raise ToolError("busy", f"{self.limits.max_concurrent_runs} tshark runs are already in progress and none "
                                    f"finished within {round(wait, 3)}s", max_concurrent_runs=self.limits.max_concurrent_runs)
        try:
            progress.raise_if_cancelled()
            result = self._run(program, args, stdin=stdin, limit=limit, started=started, capture=capture,
                               keep_line=keep_line)
        finally:
            self._slots.release()
        progress.run_finished(result.duration_ms)
        return result

    def _acquire(self, wait: float) -> bool:
        """Wait up to ``wait`` seconds for a run slot, giving up early on cancellation."""
        end = time.monotonic() + wait
        while True:
            if self._slots.acquire(timeout=max(0.0, min(CANCEL_POLL_SECONDS, end - time.monotonic()))):
                return True
            progress.raise_if_cancelled()
            if time.monotonic() >= end:
                return False

    def _run(self, program: str, args: Sequence[str], *, stdin: bytes | None, limit: float, started: float,
             capture: tuple[Path, tuple[int, int]] | None,
             keep_line: Callable[[bytes], bool] | None = None) -> RunResult:
        argv = [program, *args]
        # The wait for a slot does not eat into the run's own time limit.
        deadline = time.monotonic() + limit
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                env=self.child_env(),
            )
        except OSError as exc:
            raise ToolError("exec_failed", f"could not start {program}: {exc}") from None
        self._constrain(proc.pid)
        if capture is not None and _identity(capture[0]) != capture[1]:
            _kill(proc)
            raise _changed(capture[0])

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
        partial = b""  # an unfinished line, when lines are filtered
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
                if progress.cancelled():
                    _kill(proc)
                    raise progress.Cancelled()
                if not sel.select(timeout=min(remaining, CANCEL_POLL_SECONDS)):
                    continue
                chunk = os.read(proc.stdout.fileno(), 1 << 16)
                if not chunk:
                    if keep_line is not None and partial and keep_line(partial):
                        stdout_chunks.append(partial)
                        total += len(partial)
                    break
                if keep_line is not None:
                    lines = (partial + chunk).split(b"\n")
                    partial = lines.pop()
                    chunk = b"".join(line + b"\n" for line in lines if keep_line(line))
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
        if capture is not None and _identity(capture[0]) != capture[1]:
            raise _changed(capture[0])
        duration_ms = int((time.monotonic() - started) * 1000)
        return RunResult(
            argv=tuple(argv),
            returncode=returncode,
            stdout=b"".join(stdout_chunks).decode("utf-8", "replace"),
            stderr=b"".join(stderr_chunks).decode("utf-8", "replace"),
            duration_ms=duration_ms,
            stdout_bytes=total,
        )


    def _constrain(self, pid: int) -> None:
        """Lower the child's priority and, where the platform allows it, cap its address
        space. Applied right after the start, before tshark has finished loading its
        dissectors and opened the capture; a failure leaves the run unconstrained but bounded
        by the time and output caps."""
        try:
            os.setpriority(os.PRIO_PROCESS, pid, min(19, os.getpriority(os.PRIO_PROCESS, os.getpid()) + NICE_INCREMENT))
        except (AttributeError, OSError):
            pass
        if sys.platform.startswith("linux"):
            try:
                import resource
                cap = self.limits.max_tshark_memory_bytes
                resource.prlimit(pid, resource.RLIMIT_AS, (cap, cap))
            except (ImportError, AttributeError, OSError, ValueError):
                pass


def _identity(path: Path) -> tuple[int, int] | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (info.st_dev, info.st_ino)


def _changed(path: Path) -> ToolError:
    return ToolError("capture_changed", f"{path.name} was replaced while tshark was reading it; nothing from that "
                                        "run is returned")


def _remove_dir(path: str) -> None:
    try:
        os.chmod(path, 0o700)
        os.rmdir(path)
    except OSError:
        pass


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
        lowered = stderr.lower()
        if any(marker in lowered for marker in OUT_OF_MEMORY_MARKERS):
            raise ToolError("tshark_failed", f"tshark ran out of memory (the server caps the memory of each run): "
                            f"{stderr.splitlines()[-1] if stderr else result.returncode}",
                            returncode=result.returncode, out_of_memory=True)
        if any(marker in stderr for marker in PARTIAL_READ_MARKERS):
            first_line = stderr.splitlines()[0]
            note_warning(f"tshark stopped before the end of the file; results cover the readable part only: {first_line}")
            return result
        if result.returncode < 0:
            raise ToolError("tshark_failed", crash_message(result.returncode, stderr), returncode=result.returncode)
        raise ToolError("tshark_failed", stderr or f"tshark exited with {result.returncode}",
                        returncode=result.returncode)
    return result


def crash_message(returncode: int, stderr: str = "") -> str:
    """What to tell the caller when tshark died of a signal: the crash is in tshark's own
    dissectors (this server only reads its output), so the way out is a newer tshark or a
    filter that keeps the offending packets from being dissected."""
    import signal as _signal

    try:
        name = _signal.Signals(-returncode).name
    except ValueError:
        name = f"signal {-returncode}"
    text = (f"tshark crashed ({name}) while reading this capture: a bug in tshark's own dissectors, not in "
            f"this server; the capture may be malformed or fuzzed. Try a newer tshark, or a narrower display "
            f"filter so the packets that trigger it are not dissected")
    return f"{text}. tshark said: {stderr}" if stderr else text

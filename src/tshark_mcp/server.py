"""tshark-mcp: read-only packet capture analysis for LLM agents.

The MCP app and the tools live here. Every tool goes through
:func:`_guarded`, which resolves the capture path against the allowlist,
converts failures into structured errors, trims oversized results and writes a
JSON-lines audit record.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import __version__, avps, compare, diameter, gtp, gtpv1, models, pairing, rates, search, sigtran, sip, tunnels
from .fields import field_catalogue, iso, parse_packets, split_fields_line, to_int, validate_fields
from .limits import (
    Allowlist, Limits, ToolError, clamp_limit, lint_apn, lint_digits, lint_display_filter, lint_field_name,
    lint_quoted_value, lint_sip_method, lint_teid,
)
from .runner import Runner, begin_warnings, check_result, collect_warnings

from mcp.types import ToolAnnotations

try:  # mcp >= 2.0 renamed FastMCP to MCPServer; the decorator API is the same.
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # pragma: no cover - mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

# Every tool reads an existing file and nothing else: the same call on the same
# file gives the same answer, and no tool reaches outside the allowed directories.
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

INSTRUCTIONS = """\
Read-only analysis of existing packet captures with tshark. Captures must live
inside the allowed directories (see the error message if a path is refused).
Every call is bounded: file size, packets dissected, output bytes and run time.
When you do not know which file holds the subscriber, call find_identifier on
the directory first. Start on a file with pcap_info, then use the protocol
tools. For "why did subscriber X fail" questions call trace_subscriber first,
then drill into diameter_sessions, diameter_transactions, gtp_sessions,
gtpv1_sessions, sigtran_messages or sip_dialogs with a structured filter (imsi, session_id,
call_id, ...) or a display filter. diameter_avps shows the AVPs behind a
Diameter transaction (subscription data, flags, cancellation type).
With a working and a failing capture of the same procedure, compare_captures
reports where they first diverge. Results are JSON; "truncated": true means a
cap was reached and you should narrow the filter.
"""

app = _Server("tshark-mcp", instructions=INSTRUCTIONS, version=__version__)


# ------------------------------------------------------------------ server state
@dataclass
class ServerState:
    allowlist: Allowlist
    limits: Limits
    runner: Runner
    log_path: Path | None


_STATE: ServerState | None = None
_now = time.monotonic  # separable so tests can exhaust the multi-file time budget without slowing tshark


def configure(allow_dirs: list[str] | tuple[str, ...], limits: Limits | None = None, tshark: str | None = None,
              log_path: str | os.PathLike[str] | None = None) -> ServerState:
    """Initialise the global server state (used by ``main`` and by the tests)."""
    global _STATE
    limits = limits or Limits.from_env()
    _STATE = ServerState(
        allowlist=Allowlist.from_strings(list(allow_dirs)),
        limits=limits,
        runner=Runner(limits, tshark=tshark),
        log_path=Path(log_path) if log_path else None,
    )
    return _STATE


def state() -> ServerState:
    if _STATE is None:
        raise ToolError("not_configured", "server not configured; start it with --allow-dir")
    return _STATE


# ------------------------------------------------------------------ guard rail
def _guarded(tool: str, args: dict[str, Any], fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    started = time.monotonic()
    status = "ok"
    token = begin_warnings()
    try:
        result = fn()
    except ToolError as exc:
        status = exc.type
        result = exc.to_dict()
    except Exception as exc:  # noqa: BLE001 - never leak a traceback to the client
        status = "internal_error"
        result = ToolError("internal_error", f"{type(exc).__name__}: {exc}").to_dict()
    warnings = collect_warnings(token)
    if warnings and "error" not in result:
        result["warnings"] = warnings
    try:
        limits = state().limits
        result = _fit(result, limits.max_output_bytes)
    except ToolError:
        pass
    duration_ms = int((time.monotonic() - started) * 1000)
    payload_bytes = len(json.dumps(result, separators=(",", ":")).encode())
    _audit(tool, args, duration_ms, status, payload_bytes)
    return result


def _fit(result: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Drop rows from the largest list until the JSON fits within ``max_bytes``."""
    def size(obj: Any) -> int:
        return len(json.dumps(obj, separators=(",", ":"), default=str).encode())

    if size(result) <= max_bytes:
        return result
    out = dict(result)
    for _ in range(64):
        lists = [(k, v) for k, v in out.items() if isinstance(v, list) and len(v) > 1]
        if not lists:
            break
        key, value = max(lists, key=lambda kv: size(kv[1]))
        out[key] = value[: max(1, len(value) // 2)]
        out["truncated"] = True
        out["truncated_reason"] = f"output exceeded {max_bytes} bytes; rows were dropped, narrow the filter or lower limit"
        if size(out) <= max_bytes:
            return out
    out["truncated"] = True
    out["truncated_reason"] = f"output exceeded {max_bytes} bytes even after dropping rows"
    return out


def _audit(tool: str, args: dict[str, Any], duration_ms: int, status: str, payload_bytes: int) -> None:
    st = _STATE
    if st is None or st.log_path is None:
        return
    record = {
        "ts": iso(time.time()), "tool": tool, "args": {k: v for k, v in args.items() if v is not None},
        "duration_ms": duration_ms, "status": status, "bytes": payload_bytes,
    }
    try:
        with st.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except OSError as exc:  # pragma: no cover - logging must never break a tool
        print(f"tshark-mcp: cannot write audit log: {exc}", file=sys.stderr)


# ------------------------------------------------------------------ shared helpers
def _resolve(path: str) -> Path:
    st = state()
    return st.allowlist.resolve(path, st.limits)


def _filter(user_filter: str | None, base: str | None = None) -> str | None:
    """Lint, dry-run compile and combine a model-supplied display filter with a base filter."""
    if user_filter is None or str(user_filter).strip() == "":
        return base
    text = lint_display_filter(str(user_filter))
    state().runner.validate_display_filter(text)
    return f"({base}) && ({text})" if base else text


@dataclass
class Scan:
    """What one bounded pass over a capture saw.

    tshark's ``-c N`` stops after N frames *read*, not N frames matched, so a
    display filter on a long capture would silently see only the start of the
    file. Every pass therefore reads up to ``max_scan_packets`` frames (plus one
    sentinel frame that reveals whether the file goes on) and keeps the first
    ``match_cap`` matching packets; both caps are reported separately.
    """

    matched: int = 0
    match_cap: int = 0
    read_cap: int = 0
    hit_match_cap: bool = False
    hit_read_cap: bool = False

    @property
    def truncated(self) -> bool:
        return self.hit_match_cap or self.hit_read_cap

    def reason(self) -> str | None:
        parts = []
        if self.hit_match_cap:
            parts.append(f"packet cap reached: only the first {self.match_cap} matching packets were dissected; narrow the filter")
        if self.hit_read_cap:
            parts.append(f"frame cap reached: only the first {self.read_cap} frames of the capture were read; "
                         "slice the capture or raise max_scan_packets")
        return "; ".join(parts) or None


def _fields_core(capture: Path, display_filter: str | None, fields: list[str], max_matched: int,
                 aggregator: str, timeout: float | None = None) -> tuple[list[tuple[int | None, str]], Scan]:
    """Run ``-T fields`` under the frame-read cap; return (frame, line) pairs for the kept matches."""
    st = state()
    read_cap = st.limits.max_scan_packets
    sentinel = read_cap + 1
    flt = f"({display_filter}) || frame.number == {sentinel}" if display_filter else None
    # tshark prints a field asked for twice only once, so reuse the caller's own frame.number column.
    appended = "frame.number" not in fields
    columns = [*fields, "frame.number"] if appended else list(fields)
    frame_index = columns.index("frame.number")
    args = ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", f"aggregator={aggregator}"]
    for f in columns:
        args += ["-e", f]
    result = check_result(st.runner.read_capture(capture, args, max_packets=sentinel, display_filter=flt, timeout=timeout))
    scan = Scan(match_cap=max_matched, read_cap=read_cap)
    kept: list[tuple[int | None, str]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        frame_col = parts[frame_index] if frame_index < len(parts) else ""
        body = "\t".join(parts[:-1]) if appended else line
        frame = to_int(frame_col.split(aggregator)[0].strip())
        if frame is not None and frame > read_cap:
            scan.hit_read_cap = True
            continue
        if scan.matched >= max_matched:
            scan.hit_match_cap = True
            continue
        scan.matched += 1
        kept.append((frame, body))
    return kept, scan


def _fields_run(capture: Path, display_filter: str | None, fields: list[str], max_matched: int,
                aggregator: str = ",", timeout: float | None = None) -> tuple[str, Scan]:
    """``-T fields`` output (one line per kept packet, ``fields`` columns) and the scan summary."""
    kept, scan = _fields_core(capture, display_filter, fields, max_matched, aggregator, timeout)
    stdout = "".join(body + "\n" for _, body in kept)
    return stdout, scan


def _json_run(capture: Path, display_filter: str | None, layers: str, max_matched: int,
              deadline: float | None = None) -> tuple[list[dict], Scan]:
    """Fully dissect the first ``max_matched`` packets matching ``display_filter``.

    A cheap first pass lists the matching frame numbers under the read cap; the
    JSON pass then dissects exactly those frames, so a broad filter on a large
    capture costs one bounded JSON run rather than an oversized one. With a
    ``deadline`` (a ``_now()`` value) both runs share what is left of that budget.
    """
    kept, scan = _fields_core(capture, display_filter, [], max_matched, ",", timeout=_left(deadline))
    frames = [f for f, _ in kept if f is not None]
    if not frames:
        return [], scan
    last = max(frames)
    flt = f"({display_filter}) && frame.number <= {last}" if display_filter else f"frame.number <= {last}"
    result = check_result(state().runner.read_capture(
        capture, ["-T", "json", "--no-duplicate-keys", "-J", layers], max_packets=last, display_filter=flt,
        timeout=_left(deadline),
    ))
    return parse_packets(result.stdout), scan


def _left(deadline: float | None) -> float | None:
    """Seconds left before ``deadline``; a spent budget raises the same timeout a run would."""
    if deadline is None:
        return None
    remaining = deadline - _now()
    if remaining <= 0:
        raise ToolError("timeout", "the call's time budget was used up before the next tshark run")
    return remaining


def _envelope(rows_key: str, rows: list[dict[str, Any]], limit: int, scan: Scan | None = None,
              **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {rows_key: rows[:limit], "count": len(rows[:limit]), "total_found": len(rows)}
    if scan is not None:
        out["packets_scanned"] = scan.matched
    out.update(extra)
    reasons = []
    if scan is not None and scan.truncated:
        reasons.append(scan.reason())
    if len(rows) > limit:
        reasons.append("more rows than limit; narrow the filter or page with a tighter filter")
    if reasons:
        out["truncated"] = True
        out["truncated_reason"] = "; ".join(r for r in reasons if r)
    return out


def _merge_scans(first: Scan | None, second: Scan) -> Scan:
    """Combine the selection pass and the fetch pass of a two-pass tool into one summary."""
    if first is None:
        return second
    return Scan(matched=second.matched, match_cap=second.match_cap, read_cap=second.read_cap,
                hit_match_cap=first.hit_match_cap or second.hit_match_cap,
                hit_read_cap=first.hit_read_cap or second.hit_read_cap)


# ------------------------------------------------------------------ tools
@app.tool(title="Capture summary", annotations=READ_ONLY)
def pcap_info(path: str) -> models.PcapInfoResult:
    """Summarise a capture file: packet count, duration, first/last timestamp, size,
    link type and the top protocol-hierarchy entries. Call this first to learn what a
    capture contains before choosing a protocol tool. `path` must be inside an allowed
    directory."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        info: dict[str, Any] = {"path": str(capture), "file_size_bytes": capture.stat().st_size}
        summary = st.runner.capinfos_summary(capture)
        if summary is not None and summary.returncode == 0:
            info.update(_parse_capinfos(summary.stdout))
        else:
            info["capinfos"] = "unavailable; packet totals come from the protocol hierarchy"
        phs = check_result(st.runner.read_capture(capture, ["-q", "-z", "io,phs"]))
        hierarchy = _parse_phs(phs.stdout)
        if "packets" not in info and hierarchy:
            info["packets"] = hierarchy[0]["frames"]
        info["protocol_hierarchy"] = sorted(hierarchy, key=lambda r: -r["frames"])[:15]
        info["limits"] = st.limits.describe()
        return info
    return _guarded("pcap_info", {"path": path}, run)


CONVERSATION_LAYERS = ("ip", "ipv6", "tcp", "udp", "sctp", "eth")


@app.tool(title="Conversations (top talkers)", annotations=READ_ONLY)
def conversations(path: str, layer: str = "ip", filter: str | None = None, limit: int = 200) -> models.ConversationsResult:
    """List conversations (top talkers) at one layer: `layer` is one of ip, ipv6, tcp,
    udp, sctp or eth. Each row has both endpoints, frames and bytes in each direction,
    totals, relative start time and duration. `filter` is an optional display filter
    that restricts which packets are counted, e.g. `gtp` or `sctp.port == 3868`.
    Sorted by total frames, capped at `limit`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        if layer not in CONVERSATION_LAYERS:
            raise ToolError("invalid_argument", f"layer must be one of {', '.join(CONVERSATION_LAYERS)}")
        cap = clamp_limit(limit, state().limits.max_packets, 200)
        flt = _filter(filter)
        stat = f"conv,{layer}" + (f",{flt}" if flt else "")
        result = check_result(state().runner.read_capture(capture, ["-q", "-z", stat]))
        rows = _parse_conversations(result.stdout)
        rows.sort(key=lambda r: -r["frames_total"])
        return _envelope("conversations", rows, cap, None, layer=layer, display_filter=flt,
                         total_frames=sum(r["frames_total"] for r in rows),
                         total_bytes=sum(r["bytes_total"] for r in rows))
    return _guarded("conversations", {"path": path, "layer": layer, "filter": filter, "limit": limit}, run)


@app.tool(title="Filter packets", annotations=READ_ONLY)
def filter_packets(path: str, display_filter: str, fields: list[str] | None = None, limit: int = 200) -> models.FilterPacketsResult:
    """Return packets matching a Wireshark display filter as rows of fields. Default
    fields: frame.number, frame.time_epoch, ip.src, ip.dst, _ws.col.protocol, _ws.col.info.
    Pass `fields` (tshark field names such as "diameter.cmd.code") to choose your own;
    unknown names are rejected. Multiple occurrences of a field are joined with commas.
    Use this for anything the dedicated protocol tools do not cover."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        flt = _filter(display_filter)
        names = [lint_field_name(f) for f in (fields or _default_fields(st.runner))]
        if not names:
            raise ToolError("invalid_argument", "fields must not be empty")
        validate_fields(st.runner, names)
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        stdout, scan = _fields_run(capture, flt, names, cap)
        rows = []
        for line in stdout.splitlines():
            cols = split_fields_line(line)
            if len(cols) != len(names):
                continue
            rows.append({k: v for k, v in zip(names, cols) if v != ""})
        return _envelope("packets", rows, cap, scan, fields=names, display_filter=flt)
    return _guarded("filter_packets", {"path": path, "display_filter": display_filter, "fields": fields, "limit": limit}, run)


DEFAULT_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "_ws.col.protocol", "_ws.col.info"]


def _default_fields(runner: Runner) -> list[str]:
    """tshark 4.2 renamed the column fields to lower case; older builds only know the capitalised names."""
    catalogue = field_catalogue(runner)
    out = []
    for name in DEFAULT_FIELDS:
        if name not in catalogue and name.startswith("_ws.col."):
            legacy = "_ws.col." + name.rsplit(".", 1)[1].capitalize()
            name = legacy if legacy in catalogue else name
        out.append(name)
    return out


def _protocol_column(runner: Runner) -> str | None:
    """The protocol column field under whichever name this tshark knows, or None."""
    catalogue = field_catalogue(runner)
    for name in ("_ws.col.protocol", "_ws.col.Protocol"):
        if name in catalogue:
            return name
    return None


@app.tool(title="Diameter transactions", annotations=READ_ONLY)
def diameter_transactions(path: str, filter: str | None = None, limit: int = 200) -> models.DiameterTransactionsResult:
    """Pair Diameter requests with their answers (Hop-by-Hop + End-to-End id, checked
    against Session-Id). Each transaction gives command code and name (ULR/ULA, AIR/AIA,
    CCR/CCA, ...), application, origin/destination host and realm, User-Name (IMSI),
    Result-Code or Experimental-Result-Code with its name, round-trip ms and
    `unanswered: true` for requests with no answer. `filter` is an optional display
    filter ANDed with `diameter`, e.g. `diameter.cmd.code == 316`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        flt = _filter(filter, base="diameter")
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        packets, scan = _json_run(capture, flt, diameter.JSON_LAYERS, st.limits.max_packets)
        txs = diameter.pair(diameter.extract_messages(packets))
        rows = [diameter.transaction_row(t) for t in txs]
        summary = _summarise(rows, "request", "unanswered", lambda r: r.get("success") is False)
        return _envelope("transactions", rows, cap, scan, summary=summary)
    return _guarded("diameter_transactions", {"path": path, "filter": filter, "limit": limit}, run)


@app.tool(title="Diameter sessions", annotations=READ_ONLY)
def diameter_sessions(path: str, session_id: str | None = None, imsi: str | None = None,
                      command_code: int | None = None, filter: str | None = None, limit: int = 200) -> models.DiameterSessionsResult:
    """Group Diameter traffic by Session-Id. Each session gives the application, origin
    and destination hosts and realms, User-Name (IMSI), first/last timestamp and duration,
    the request and answer command codes seen, every Result-Code or Experimental-Result-Code,
    counts of unanswered and failed transactions, the worst round-trip, and the list of
    transactions (request paired with its answer by Hop-by-Hop id, with RTT). Narrow with
    `session_id` (exact), `imsi` (User-Name digits) or `command_code` (e.g. 316 for ULR):
    matching messages select the sessions, then every message of those sessions is
    fetched so answers are not lost. `filter` is an extra display filter ANDed with
    `diameter`. Messages without a Session-Id (DWR, CER) are counted, not listed."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        sid = lint_quoted_value(session_id, "session_id") if session_id else None
        imsi_d = lint_digits(imsi, "imsi") if imsi else None
        code = None
        if command_code is not None:
            code = to_int(str(command_code))
            if code is None or code < 0 or code > 0xFFFFFF:
                raise ToolError("invalid_argument", f"command_code must be a 24-bit integer, got {command_code!r}")
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        base = _filter(filter, base="diameter")
        select = diameter.session_filter(sid, imsi_d, code)
        messages, scan = _diameter_fetch(capture, base, select)
        if messages is None:
            return _envelope("sessions", [], cap, scan, summary={"sessions": 0, "unanswered": 0, "failed": 0,
                                                                  "without_session_id": 0}, selection=select)
        txs = diameter.pair(messages)
        rows, without = diameter.session_rows(txs)
        if sid:
            rows = [r for r in rows if r["session_id"] == sid]
        if imsi_d:
            mine = diameter.subscriber_sessions(messages, imsi_d, None, exact_imsi=True)
            rows = [r for r in rows if r["session_id"] in mine]
        if code is not None:
            rows = [r for r in rows if code in r["request_codes"]]
        summary = {
            "sessions": len(rows),
            "unanswered": sum(r["unanswered"] for r in rows),
            "failed": sum(r["failed"] for r in rows),
            "without_session_id": without,
            "by_application": _count(rows, "application"),
        }
        return _envelope("sessions", rows, cap, scan, summary=summary, selection=select)
    return _guarded("diameter_sessions", {"path": path, "session_id": session_id, "imsi": imsi,
                                          "command_code": command_code, "filter": filter, "limit": limit}, run)


def _diameter_fetch(capture: Path, base: str, select: str | None, keep_raw: bool = False,
                    fallback_to_selection: bool = False) -> tuple[list | None, Scan]:
    """Messages of every Diameter session that ``select`` touches (all messages under
    ``base`` without a selection). Answers rarely repeat the selecting AVPs, so a first
    pass collects the Session-Ids and a second fetches those sessions whole. Returns
    ``None`` for the messages when the selection matched no session."""
    st = state()
    pre: Scan | None = None
    flt = base
    if select:
        stdout, pre = _fields_run(capture, f"({base}) && ({select})", ["diameter.Session-Id"], st.limits.max_scan_packets)
        # A packet can bundle several messages; keep every Session-Id it carries and
        # drop the sessions that turn out not to match once each message is dissected.
        sessions = {v.strip() for ln in stdout.splitlines() for v in ln.split(",") if v.strip()}
        corr = diameter.correlation_filter(sessions)
        if corr is not None:
            flt = f"({base}) && ({corr})"
        elif fallback_to_selection and stdout.strip():
            flt = f"({base}) && ({select})"  # messages without a Session-Id (CER, DWR)
        else:
            return None, pre
    packets, scan = _json_run(capture, flt, diameter.JSON_LAYERS, st.limits.max_packets)
    return diameter.extract_messages(packets, keep_raw=keep_raw), _merge_scans(pre, scan)


AVP_DETAIL = ("key", "full")


@app.tool(title="Diameter AVP detail", annotations=READ_ONLY)
def diameter_avps(path: str, session_id: str | None = None, imsi: str | None = None, command_code: int | None = None,
                  frame: int | None = None, filter: str | None = None, detail: str = "key", max_avps: int = 200,
                  limit: int = 20) -> models.DiameterAvpsResult:
    """The AVPs of Diameter requests and answers, paired as in diameter_transactions.
    Select with `session_id`, `imsi` (User-Name digits), `command_code` (316 ULR, 317 CLR,
    318 AIR, 319 IDR, 321 PUR, 272 CCR, ...) and/or `frame` (a request or answer frame
    number); the whole session is fetched so answers are kept. `detail="key"` (default)
    gives the AVPs read first: Result-Code and Experimental-Result, ULR/ULA/CLR/PUR/PUA/
    IDR/NOR flags with bit names, Cancellation-Type, RAT-Type, Visited-PLMN-Id, AIR
    vectors, Gx CC-Request-Type, Event-Trigger, rule reports and QoS, and a digest of
    Subscription-Data (MSISDN, status, ODB, access restrictions, AMBR, one line per APN
    with PDN type, QCI, ARP, AMBR and PGW). `detail="full"` gives every AVP as a nested
    tree, at most `max_avps` leaf AVPs per message (server cap 2000); `avps_dropped`
    counts the rest. Enumerated values are named, e.g. "SUBSCRIPTION_WITHDRAWAL (2)".
    `limit` caps transactions (default 20). `filter` is ANDed with `diameter`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        if detail not in AVP_DETAIL:
            raise ToolError("invalid_argument", f"detail must be one of {', '.join(AVP_DETAIL)}")
        sid = lint_quoted_value(session_id, "session_id") if session_id else None
        imsi_d = lint_digits(imsi, "imsi") if imsi else None
        code = None
        if command_code is not None:
            code = to_int(str(command_code))
            if code is None or code < 0 or code > 0xFFFFFF:
                raise ToolError("invalid_argument", f"command_code must be a 24-bit integer, got {command_code!r}")
        frame_n = None
        if frame is not None:
            frame_n = to_int(str(frame))
            if frame_n is None or frame_n < 1:
                raise ToolError("invalid_argument", f"frame must be a positive frame number, got {frame!r}")
        leaves = clamp_limit(max_avps, avps.HARD_MAX_AVPS, 200)
        cap = clamp_limit(limit, st.limits.max_packets, 20)
        base = _filter(filter, base="diameter")
        parts = [p for p in (diameter.session_filter(sid, imsi_d, code),
                             f"frame.number == {frame_n}" if frame_n is not None else None) if p]
        select = " && ".join(parts) if parts else None
        messages, scan = _diameter_fetch(capture, base, select, keep_raw=True, fallback_to_selection=True)
        if messages is None:
            return _envelope("transactions", [], cap, scan, detail=detail, selection=select)
        txs = diameter.pair(messages)
        mine = diameter.subscriber_sessions(messages, imsi_d, None, exact_imsi=True) if imsi_d else None
        rows = []
        for tx in txs:
            anchor = tx.request or tx.answer
            assert anchor is not None
            f = anchor.fields
            if sid and f.get("session_id") != sid:
                continue
            if mine is not None and f.get("session_id") not in mine:
                continue
            if code is not None and f.get("command_code") != code:
                continue
            if frame_n is not None and frame_n not in {m.frame for m in (tx.request, tx.answer) if m is not None}:
                continue
            row = diameter.transaction_row(tx)
            out = {k: row[k] for k in ("time", "request", "answer", "command", "application", "session_id", "user_name",
                                       "origin_host", "destination_host", "answer_origin_host", "request_frame",
                                       "answer_frame", "rtt_ms", "result", "success", "unanswered", "unmatched_answer")
                   if k in row}
            for side, msg in (("request", tx.request), ("answer", tx.answer)):
                if msg is None:
                    continue
                tree, dropped = avps.avp_tree(msg.fields.get("raw") or {}, leaves)
                out[f"{side}_avps"] = tree if detail == "full" else avps.key_view(tree)
                if dropped and detail == "full":
                    out[f"{side}_avps_dropped"] = dropped
            rows.append(out)
        out = _envelope("transactions", rows, cap, scan, detail=detail, selection=select)
        if detail == "full" and any(k.endswith("_avps_dropped") for r in rows for k in r):
            note = f"some messages have more than {leaves} AVPs; raise max_avps (server cap {avps.HARD_MAX_AVPS})"
            out["truncated"] = True
            out["truncated_reason"] = f'{out["truncated_reason"]}; {note}' if out.get("truncated_reason") else note
        return out
    return _guarded("diameter_avps", {"path": path, "session_id": session_id, "imsi": imsi, "command_code": command_code,
                                      "frame": frame, "filter": filter, "detail": detail, "max_avps": max_avps,
                                      "limit": limit}, run)


@app.tool(title="GTPv2-C sessions", annotations=READ_ONLY)
def gtp_sessions(path: str, imsi: str | None = None, apn: str | None = None, teid: str | int | None = None,
                 filter: str | None = None, limit: int = 200) -> models.GtpSessionsResult:
    """Pair GTPv2-C requests with responses by sequence number and peer pair. A response
    sent by the request's target towards another address (a NAT or proxy boundary) is
    paired too and its path is given as `response_path`. Reports
    message names (Create Session, Modify Bearer, Delete Session, Echo, ...), IMSI, MSISDN,
    APN, F-TEIDs with interface names, cause code and name, allocated UE address (PAA),
    round-trip ms and `unanswered: true`. Narrow with `imsi` (digits), `apn` (case-insensitive; a network
    identifier such as `internet` also matches `internet.mnc001.mcc001.gprs`) or `teid` (decimal or 0x hex; matches the header TEID or any F-TEID):
    the matching requests select sequence numbers, then both halves of each transaction
    are fetched so responses are kept. `filter` is a raw display filter ANDed with `gtpv2`,
    e.g. `gtpv2.message_type == 32`; it applies literally to each packet.
    Proxy chains: legs of one procedure (same IMSI, message and APN within 1 s) where
    some leg has no response get `chain` (leg k of n, answered legs and their frames);
    a leg without a response while another leg was answered gets
    `leg_without_response` and a `note` (not `unanswered`), saying whether the
    response was not relayed back or the relaying node answered on its own. A request
    captured twice within 50 ms gets `duplicate_of_frame`. `summary` counts
    `legs_without_response` and `duplicates`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        imsi_d = lint_digits(imsi, "imsi") if imsi else None
        apn_s = lint_apn(apn) if apn else None
        teid_i = lint_teid(teid) if teid is not None and str(teid).strip() != "" else None
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        base = _filter(filter, base="gtpv2")
        select = gtp.selection_filter(imsi_d, apn_s, teid_i)
        pre: Scan | None = None
        flt = base
        if select:
            stdout, pre = _fields_run(capture, f"({base}) && ({select})", ["gtpv2.seq"], st.limits.max_scan_packets)
            seqs = {s for ln in stdout.splitlines() for s in (to_int(v) for v in ln.strip().split(",")) if s is not None}
            corr = gtp.correlation_filter(seqs, set())
            if corr is None:
                return _envelope("transactions", [], cap, pre,
                                 summary={"by_message": {}, "unanswered": 0, "failed": 0}, selection=select)
            flt = f"({base}) && ({corr})"
        packets, scan = _json_run(capture, flt, gtp.JSON_LAYERS, st.limits.max_packets)
        scan = _merge_scans(pre, scan)
        txs = gtp.pair(gtp.extract_messages(packets))
        rows = [gtp.transaction_row(t) for t in txs]
        pairing.annotate_legs(txs, rows, _gtp_identity)
        if select:
            rows = [r for r in rows if gtp.row_matches(r, imsi_d, apn_s, teid_i)]
        summary = _summarise(rows, "message", "unanswered", lambda r: r.get("accepted") is False)
        summary.update(_leg_summary(rows))
        return _envelope("transactions", rows, cap, scan, summary=summary, selection=select)
    return _guarded("gtp_sessions", {"path": path, "imsi": imsi, "apn": apn, "teid": teid, "filter": filter,
                                     "limit": limit}, run)


@app.tool(title="GTPv1-C PDP contexts", annotations=READ_ONLY)
def gtpv1_sessions(path: str, imsi: str | None = None, apn: str | None = None, teid: str | int | None = None,
                   filter: str | None = None, limit: int = 200) -> models.Gtpv1SessionsResult:
    """Pair GTPv1-C (Gn/Gp, TS 29.060) requests with responses by sequence number and
    peer pair, across a proxy or NAT too (`response_path`): Create, Update and Delete PDP
    Context, Echo, SGSN Context, Forward Relocation, PDU Notification, ... Each row gives
    the message, IMSI, MSISDN, APN, NSAPI, RAT type, IMEISV, the TEID-C and TEID-U and GSN
    address on each side, the end-user address allocated, cause code and name, round-trip
    ms and `unanswered: true`. Narrow with `imsi`, `apn` (case-insensitive) or `teid` (the
    header TEID or a TEID-C/TEID-U, decimal or 0x hex): matching requests select sequence
    numbers and both halves of each transaction are fetched. `filter` is ANDed with
    GTPv1-C (`gtp && gtp.message != 0xff`).
    Proxy chains: legs of one procedure (same IMSI, message and APN within 1 s) where
    some leg has no response get `chain` (leg k of n, answered legs and their frames);
    a leg without a response while another leg was answered gets
    `leg_without_response` and a `note` (not `unanswered`), saying whether the
    response was not relayed back or the relaying node answered on its own. A request
    captured twice within 50 ms gets `duplicate_of_frame`. `summary` counts
    `legs_without_response` and `duplicates`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        imsi_d = lint_digits(imsi, "imsi") if imsi else None
        apn_s = lint_apn(apn) if apn else None
        teid_i = lint_teid(teid) if teid is not None and str(teid).strip() != "" else None
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        base = _filter(filter, base=gtpv1.BASE_FILTER)
        select = gtpv1.selection_filter(imsi_d, apn_s, teid_i)
        pre: Scan | None = None
        flt = base
        if select:
            stdout, pre = _fields_run(capture, f"({base}) && ({select})", ["gtp.seq_number"], st.limits.max_scan_packets)
            seqs = {s for ln in stdout.splitlines() for s in (to_int(v) for v in ln.strip().split(",")) if s is not None}
            corr = gtpv1.correlation_filter(seqs, set())
            if corr is None:
                return _envelope("transactions", [], cap, pre,
                                 summary={"by_message": {}, "unanswered": 0, "failed": 0}, selection=select)
            flt = f"({base}) && ({corr})"
        packets, scan = _json_run(capture, flt, gtpv1.JSON_LAYERS, st.limits.max_packets)
        scan = _merge_scans(pre, scan)
        txs = gtpv1.pair(gtpv1.extract_messages(packets))
        rows = [gtpv1.transaction_row(t) for t in txs]
        pairing.annotate_legs(txs, rows, _gtp_identity)
        if select:
            rows = [r for r in rows if gtpv1.row_matches(r, imsi_d, apn_s, teid_i)]
        summary = _summarise(rows, "message", "unanswered", lambda r: r.get("accepted") is False)
        summary.update(_leg_summary(rows))
        return _envelope("transactions", rows, cap, scan, summary=summary, selection=select)
    return _guarded("gtpv1_sessions", {"path": path, "imsi": imsi, "apn": apn, "teid": teid, "filter": filter,
                                       "limit": limit}, run)


@app.tool(title="GTP-U tunnels", annotations=READ_ONLY)
def gtp_user_plane(path: str, teid: str | int | None = None, limit: int = 200) -> models.GtpUserPlaneResult:
    """Summarise GTP-U (G-PDU) traffic per tunnel endpoint id: packets, bytes, first and
    last time, outer endpoints and the inner IP sources/destinations. A TEID is one
    direction of a bearer; look up the matching F-TEIDs with gtp_sessions. `teid` may be
    decimal or 0x-prefixed hex to restrict the view to one tunnel."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        teid_int = None
        if teid is not None and str(teid).strip() != "":
            teid_int = to_int(str(teid).strip())
            if teid_int is None or teid_int < 0 or teid_int > 0xFFFFFFFF:
                raise ToolError("invalid_argument", f"teid must be a 32-bit integer (decimal or 0x hex), got {teid!r}")
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        stdout, scan = _fields_run(capture, gtp.user_plane_filter(teid_int), gtp.USER_PLANE_FIELDS,
                                   st.limits.max_scan_packets)
        rows = gtp.summarise_user_plane(stdout)
        return _envelope("tunnels", rows, cap, scan,
                         total_packets=sum(r["packets"] for r in rows),
                         total_payload_bytes=sum(r["payload_bytes"] for r in rows))
    return _guarded("gtp_user_plane", {"path": path, "teid": teid, "limit": limit}, run)


@app.tool(title="GTP-U tunnel health", annotations=READ_ONLY)
def gtp_tunnel_health(path: str, teid: str | int | None = None, mtu: int = 1500, limit: int = 200) -> models.GtpTunnelHealthResult:
    """User-plane health per GTP-U tunnel (TEID), read from the packets inside it: inner
    TCP segments, flows, SYN/SYN-ACK and the MSS values they carry, retransmissions
    (with the share of data segments), fast retransmissions, duplicate ACKs, lost
    segments, zero windows and resets; inner ICMP by type, including fragmentation
    needed / packet too big with the next-hop MTU; the largest outer and inner IP
    packets, the tunnel overhead and DF-flagged packets above `mtu` (the path MTU to
    check against, default 1500); and whether the reverse direction carries traffic.
    `issues` spells out what looks wrong, e.g. an MSS whose segments cannot fit the
    path once tunnelled, a retransmission share of 5% or more, or a one-way tunnel.
    `outer_icmp` lists ICMP errors sent about the tunnel packets themselves (a
    transport MTU or reachability problem). `teid` (decimal or 0x hex) narrows to one
    tunnel; tunnels with issues come first."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        teid_int = lint_teid(teid) if teid is not None and str(teid).strip() != "" else None
        path_mtu = to_int(str(mtu))
        if path_mtu is None or not 576 <= path_mtu <= 65535:
            raise ToolError("invalid_argument", f"mtu must be between 576 and 65535, got {mtu!r}")
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        stdout, scan = _fields_run(capture, tunnels.display_filter(teid_int), tunnels.FIELDS, st.limits.max_scan_packets,
                                   aggregator=tunnels.AGGREGATOR)
        gpdus, outer = tunnels.parse(stdout)
        rows, outer_errors = tunnels.summarise(gpdus, outer, path_mtu)
        tcp_rows = [r["tcp"] for r in rows if r.get("tcp")]
        summary = {
            "tunnels": len(rows),
            "tunnels_with_issues": sum(1 for r in rows if r.get("issues")),
            "g_pdus": len(gpdus),
            "inner_tcp_segments": sum(t.get("segments", 0) for t in tcp_rows),
            "inner_tcp_retransmissions": sum(t.get("retransmissions", 0) for t in tcp_rows),
            "outer_icmp_errors": len(outer),
        }
        return _envelope("tunnels", rows, cap, scan, path_mtu=path_mtu, summary=summary, outer_icmp=outer_errors)
    return _guarded("gtp_tunnel_health", {"path": path, "teid": teid, "mtu": mtu, "limit": limit}, run)


@app.tool(title="Message rates and storms", annotations=READ_ONLY)
def message_rates(path: str, protocol: str = "auto", interval: float = 1.0, imsi: str | None = None,
                  filter: str | None = None, burst_min: int = 5, storm_min: int = 5, limit: int = 50) -> models.MessageRatesResult:
    """Message rates over time and storm detection for Diameter, GTPv2-C, SIP and MAP
    (`protocol` auto, diameter, gtpv2, sip or map). Every message is counted by name
    (ULR, ULA, PUR, Create Session Request, REGISTER, 4xx REGISTER, updateLocation, ...)
    per `interval` seconds. `by_message` gives each type's total, peak per interval and
    when, and mean rate; `bursts` are runs of intervals where a type ran at three times
    its usual rate or more and at least `burst_min` per interval; `subscriber_loops`
    lists subscribers that sent the same request `storm_min` times or more, with the
    gap between repeats and whether they are regular (a purge or attach loop);
    `timeline` gives the busiest message types per interval (merged into wider bins
    past 500 rows); `storms` says it in one line each. `imsi` keeps only messages that
    name the subscriber (mostly requests). `filter` is ANDed with the protocol filter."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        if protocol not in rates.PROTOCOLS:
            raise ToolError("invalid_argument", f"protocol must be one of {', '.join(rates.PROTOCOLS)}")
        try:
            step = float(interval)
        except (TypeError, ValueError):
            raise ToolError("invalid_argument", f"interval must be a number of seconds, got {interval!r}") from None
        if not 0.001 <= step <= 86400:
            raise ToolError("invalid_argument", "interval must be between 0.001 and 86400 seconds")
        imsi_d = lint_digits(imsi, "imsi") if imsi else None
        b_min = clamp_limit(burst_min, 1_000_000, 5)
        s_min = clamp_limit(storm_min, 1_000_000, 5)
        cap = clamp_limit(limit, st.limits.max_packets, 50)
        flt = _filter(filter, base=rates.display_filter(protocol))
        stdout, scan = _fields_run(capture, flt, rates.FIELDS, st.limits.max_scan_packets, aggregator=rates.AGGREGATOR)
        evts = rates.events(stdout, protocol)
        if imsi_d:
            evts = [e for e in evts if e.get("subscriber") and imsi_d in e["subscriber"]]
        out = rates.summarise(evts, step, b_min, s_min, cap)
        out.update({"protocol": protocol, "interval_s": step, "display_filter": flt, "packets_scanned": scan.matched})
        if scan.truncated:
            out["truncated"] = True
            out["truncated_reason"] = scan.reason()
        return out
    return _guarded("message_rates", {"path": path, "protocol": protocol, "interval": interval, "imsi": imsi,
                                      "filter": filter, "burst_min": burst_min, "storm_min": storm_min, "limit": limit}, run)


@app.tool(title="SIP dialogs", annotations=READ_ONLY)
def sip_dialogs(path: str, call_id: str | None = None, number: str | None = None, method: str | None = None,
                filter: str | None = None, limit: int = 200) -> models.SipDialogsResult:
    """Group SIP messages by Call-ID. Each dialog lists the method/response sequence with
    timestamps, From, To, Request-URI, P-Asserted-Identity, the method chain, the final
    status of the initial request, time to that final response and the dialog duration;
    `outcome_status` is the final status after any 401/407 challenge was retried (a
    REGISTER answered 401 then 200 succeeded), `attempts` counts transactions of the
    initial method and `resent_messages` counts retransmissions;
    `no_final_response: true` marks requests that never completed. Narrow with `call_id`
    (exact), `number` (digits found in From, To, Request-URI or P-Asserted-Identity) or
    `method` (INVITE, REGISTER, MESSAGE, ...): matching messages select the dialogs, then
    every message of those dialogs is fetched so responses are kept. `filter` is a raw
    display filter ANDed with `sip`; it applies literally to each packet."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        cid = lint_quoted_value(call_id, "call_id") if call_id else None
        num = lint_digits(number, "number") if number else None
        meth = lint_sip_method(method) if method else None
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        base = _filter(filter, base="sip")
        select = sip.selection_filter(cid, num, meth)
        pre: Scan | None = None
        flt = base
        if select:
            stdout, pre = _fields_run(capture, f"({base}) && ({select})", ["sip.Call-ID"], st.limits.max_scan_packets)
            # A TCP segment can carry several SIP messages: keep every Call-ID it has and,
            # once each message is parsed, drop the dialogs that do not match themselves.
            alone, shared = sip.selected_call_ids(stdout)
            corr = sip.correlation_filter(alone | shared)
            if corr is None:
                return _envelope("dialogs", [], cap, pre, summary={"by_message": {}, "unanswered": 0, "failed": 0},
                                 selection=select)
            flt = f"({base}) && ({corr})"
        stdout, scan = _fields_run(capture, flt, sip.FIELDS, st.limits.max_scan_packets, aggregator=sip.AGGREGATOR)
        rows = sip.group_dialogs(stdout)
        if select and shared:
            keep = sip.matching_call_ids(stdout, cid, num, meth)
            rows = [r for r in rows if r["call_id"] not in shared or r["call_id"] in keep]
        summary = _summarise(rows, "initial_method", "no_final_response", sip.dialog_failed)
        return _envelope("dialogs", rows, cap, _merge_scans(pre, scan), summary=summary, selection=select)
    return _guarded("sip_dialogs", {"path": path, "call_id": call_id, "number": number, "method": method,
                                    "filter": filter, "limit": limit}, run)


@app.tool(title="Find identifier across captures", annotations=READ_ONLY)
def find_identifier(path: str, identifier: str, kind: str = "auto", max_files: int = 20) -> models.FindIdentifierResult:
    """Find which capture files mention an identifier. `path` is one capture or a
    directory inside the allowed roots (its .pcap/.pcapng/.cap files are scanned, not
    subdirectories). `identifier` is an IMSI, MSISDN, IPv4/IPv6 address, SIP Call-ID or
    Diameter Session-Id; `kind` is auto, imsi, msisdn, ip, call_id or session_id (auto
    searches digits as both IMSI and MSISDN). Returns one row per file with hits: hit
    count, first and last timestamp and a per-protocol breakdown, sorted by hits. At most
    `max_files` files are opened (capped by the server), each under the usual packet,
    size and time limits, and the whole call shares one time budget; files that could
    not be read are listed under `errors`. Use it to pick the file before pcap_info."""
    def run() -> dict[str, Any]:
        st = state()
        if not isinstance(identifier, str) or not identifier.strip():
            raise ToolError("invalid_argument", "identifier must be a non-empty string")
        resolved_kind, flt = search.build_filter(identifier, kind)
        flt = lint_display_filter(flt)
        st.runner.validate_display_filter(flt)
        file_cap = clamp_limit(max_files, st.limits.max_files, min(20, st.limits.max_files))

        target = st.allowlist.resolve_inside(path)
        if target.is_dir():
            candidates = search.list_captures(target)
        else:
            candidates = [target]
        fields = ["frame.time_epoch", "frame.number"]
        protocol_field = _protocol_column(st.runner)
        protocol_col = protocol_field is not None
        if protocol_field is not None:
            fields.append(protocol_field)

        deadline = _now() + st.limits.timeout_seconds
        rows: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        partial: list[str] = []
        scanned = 0
        truncated_reason = None
        for candidate in candidates:
            if scanned >= file_cap:
                truncated_reason = f"more than {file_cap} files; raise max_files (server cap {st.limits.max_files}) or narrow the directory"
                break
            if _now() >= deadline:
                truncated_reason = f"time budget of {st.limits.timeout_seconds}s used up after {scanned} files"
                break
            scanned += 1
            try:
                capture = st.allowlist.resolve(str(candidate), st.limits)
                # Each run gets only what is left of the shared budget.
                stdout, scan = _fields_run(capture, flt, fields, st.limits.max_scan_packets,
                                           timeout=deadline - _now())
            except ToolError as exc:
                errors.append({"path": str(candidate), "error": exc.type, "message": exc.message})
                if exc.type == "timeout":
                    truncated_reason = f"time budget of {st.limits.timeout_seconds}s used up while reading this file"
                    break
                continue
            summary = search.summarise_hits(stdout, protocol_col)
            if summary["hits"] == 0:
                if scan.hit_read_cap:
                    # No hit in the part that was read says nothing about the rest of the file.
                    partial.append(str(capture))
                continue
            row: dict[str, Any] = {
                "path": str(capture), "hits": summary["hits"], "first": iso(summary["first"]),
                "last": iso(summary["last"]), "protocols": summary["protocols"],
            }
            if scan.truncated:
                row["truncated"] = True
                row["truncated_reason"] = f"{scan.reason()}; the count is a lower bound"
            rows.append(row)
        rows.sort(key=lambda r: (-r["hits"], r["path"]))
        out = _envelope("files", rows, file_cap, None, identifier=identifier.strip(), kind=resolved_kind,
                        display_filter=flt, files_scanned=scanned, files_found=len(candidates),
                        files_with_hits=len(rows), total_hits=sum(r["hits"] for r in rows), errors=errors)
        if partial:
            out["partially_scanned"] = partial
            note = (f"{len(partial)} file(s) without hits were only read up to the frame cap of "
                    f"{st.limits.max_scan_packets}; see partially_scanned")
            truncated_reason = f"{truncated_reason}; {note}" if truncated_reason else note
        if truncated_reason:
            out["truncated"] = True
            out["truncated_reason"] = truncated_reason
        return out
    return _guarded("find_identifier", {"path": path, "identifier": identifier, "kind": kind, "max_files": max_files}, run)


@app.tool(title="SCTP associations", annotations=READ_ONLY)
def sctp_associations(path: str, limit: int = 200) -> models.SctpAssociationsResult:
    """Summarise SCTP associations by endpoint pair: handshake state (INIT/INIT-ACK
    frames and initiate tags), DATA chunk count, heartbeats sent versus acknowledged,
    retransmissions, and whether ABORT or SHUTDOWN was seen. Useful for Diameter and
    SIGTRAN transport health before looking at the application layer."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        stdout, scan = _fields_run(capture, sigtran.SCTP_FILTER, sigtran.SCTP_FIELDS, st.limits.max_scan_packets)
        rows = sigtran.summarise_sctp(stdout)
        return _envelope("associations", rows, cap, scan)
    return _guarded("sctp_associations", {"path": path, "limit": limit}, run)


@app.tool(title="SIGTRAN / MAP messages", annotations=READ_ONLY)
def sigtran_messages(path: str, filter: str | None = None, limit: int = 200) -> models.SigtranMessagesResult:
    """List M3UA/SCCP/TCAP/MAP messages: SCCP type (UDT, XUDT with segmentation info),
    calling and called global titles and SSNs, point codes, TCAP primitive and
    transaction ids, components (invoke, returnResultLast, returnError) with MAP opcode and
    operation name (updateLocation, sendAuthenticationInfo, mo-forwardSM, ...), IMSI and
    MSISDN. Begins are linked to their End/Continue when the transaction id matches.
    `filter` is ANDed with `sccp || m3ua`, e.g. `gsm_old.localValue == 2`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        flt = _filter(filter, base=sigtran.MESSAGE_FILTER)
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        packets, scan = _json_run(capture, flt, sigtran.JSON_LAYERS, st.limits.max_packets)
        rows = sigtran.extract_rows(packets)
        ops: dict[str, int] = {}
        for r in rows:
            for c in r.get("components", []):
                # A returnError now carries the operation it answers; count it by its error.
                name = c.get("error") or c.get("operation") or c.get("type")
                ops[name] = ops.get(name, 0) + 1
        summary = {"by_operation": ops, "unanswered_begins": sum(1 for r in rows if r.get("unanswered")),
                   "segmented": sum(1 for r in rows if r.get("segmentation"))}
        return _envelope("messages", rows, cap, scan, summary=summary)
    return _guarded("sigtran_messages", {"path": path, "filter": filter, "limit": limit}, run)


@app.tool(title="Subscriber trace", annotations=READ_ONLY)
def trace_subscriber(path: str, imsi: str | None = None, msisdn: str | None = None, limit: int = 300) -> models.TraceSubscriberResult:
    """Build one time-ordered timeline for a subscriber across Diameter (User-Name),
    GTPv2-C and GTPv1-C (IMSI/MSISDN IEs, then following the control-plane TEIDs), MAP (IMSI/MSISDN)
    and SIP (From/To/P-Asserted-Identity containing the MSISDN). Each row carries the
    protocol, message name, result (Result-Code, GTP cause, SIP final status), peers and
    the request/answer pairing including `unanswered: true`. Give `imsi`, `msisdn` or
    both as digit strings. The whole call shares one time budget (the per-run timeout);
    when it runs out the timeline found so far is returned with `truncated` and the pass
    that stopped marked `timed_out`. GTP rows carry the proxy-chain fields of
    gtp_sessions (`chain`, `leg_without_response`, `duplicate_of_frame`, `note`).
    Start here for "why did subscriber X fail" questions."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        if not imsi and not msisdn:
            raise ToolError("invalid_argument", "give imsi, msisdn or both")
        imsi_d = lint_digits(imsi, "imsi") if imsi else None
        msisdn_d = lint_digits(msisdn, "msisdn") if msisdn else None
        cap = clamp_limit(limit, st.limits.max_packets, 300)
        deadline = _now() + st.limits.timeout_seconds
        timeline, notes, stopped = _trace_timeline(capture, imsi_d, msisdn_d, deadline)
        by_protocol: dict[str, int] = {}
        for r in timeline:
            by_protocol[r["protocol"]] = by_protocol.get(r["protocol"], 0) + 1
        failures = [r for r in timeline if r.get("unanswered") or r.get("failed")]
        out = _envelope("timeline", timeline, cap, None, identity={"imsi": imsi_d, "msisdn": msisdn_d},
                        by_protocol=by_protocol, failures=len(failures), passes=notes)
        reasons = _trace_reasons(notes, stopped, st.limits.timeout_seconds)
        if reasons:
            out["truncated"] = True
            out["truncated_reason"] = "; ".join(reasons)
        return out
    return _guarded("trace_subscriber", {"path": path, "imsi": imsi, "msisdn": msisdn, "limit": limit}, run)


def _trace_reasons(notes: dict[str, Any], stopped: str | None, budget: float) -> list[str]:
    reasons = []
    if stopped is not None:
        reasons.append(f"time budget of {budget}s used up during the {stopped} pass; "
                       "later passes did not run and the timeline is incomplete")
    if any(n.get("truncated") for n in notes.values()):
        reasons.append("a pass hit the packet or frame cap (see passes); the timeline may be incomplete")
    return reasons


def _trace_timeline(capture: Path, imsi_d: str | None, msisdn_d: str | None, deadline: float,
                    with_avps: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    """The subscriber timeline behind trace_subscriber: (rows in time order, per-pass
    notes, the pass the time budget ran out in or None). Every tshark run gets only
    what is left before ``deadline``; a spent budget ends the trace with what the
    earlier passes found. ``with_avps`` adds the key AVPs to each Diameter row."""
    st = state()
    timeline: list[dict[str, Any]] = []
    notes: dict[str, Any] = {}
    stage = "diameter"
    stopped: str | None = None
    try:
        # Diameter: sessions naming the subscriber, then every message of those sessions.
        sessions: set[str] = set()
        flt = diameter.identity_filter(imsi_d, msisdn_d)
        if flt:
            stdout, scan = _fields_run(capture, flt, ["diameter.Session-Id"], st.limits.max_scan_packets, timeout=_left(deadline))
            sessions = {v.strip() for ln in stdout.splitlines() for v in ln.split(",") if v.strip()}
            notes["diameter"] = {"sessions": 0, "truncated": scan.truncated}
        corr = diameter.correlation_filter(sessions)
        if corr:
            packets, scan = _json_run(capture, corr, diameter.JSON_LAYERS, st.limits.max_packets, deadline=deadline)
            messages = diameter.extract_messages(packets, keep_raw=with_avps)
            mine = diameter.subscriber_sessions(messages, imsi_d, msisdn_d)
            notes["diameter"]["sessions"] = len(mine)
            for tx in diameter.pair(messages):
                row = diameter.transaction_row(tx)
                if row.get("session_id") not in mine:
                    continue
                timeline.append(_diameter_step(tx, row, with_avps))
            notes["diameter"]["truncated"] = notes["diameter"]["truncated"] or scan.truncated

        stage = "gtpv2"
        # GTPv2-C, then GTPv1-C (Gn/Gp): requests naming the subscriber, then the same
        # sequence numbers and the control-plane TEIDs.
        _trace_gtp(gtp, "gtpv2", capture, imsi_d, msisdn_d, deadline, notes, timeline)
        stage = "gtpv1"
        _trace_gtp(gtpv1, "gtpv1", capture, imsi_d, msisdn_d, deadline, notes, timeline)

        stage = "map"
        # MAP: components naming the subscriber, then the whole TCAP transactions.
        flt = sigtran.identity_filter(imsi_d, msisdn_d)
        if flt:
            stdout, scan = _fields_run(capture, flt, ["tcap.tid"], st.limits.max_scan_packets, timeout=_left(deadline))
            tids = {_colonise(t) for ln in stdout.splitlines() for t in ln.strip().split(",") if t.strip()}
            notes["map"] = {"transactions": len(tids), "truncated": scan.truncated}
            corr = sigtran.correlation_filter(tids)
            if corr:
                packets, scan = _json_run(capture, corr, sigtran.JSON_LAYERS, st.limits.max_packets, deadline=deadline)
                for row in sigtran.extract_rows(packets):
                    timeline.append(_map_step(row))
                notes["map"]["truncated"] = notes["map"]["truncated"] or scan.truncated

        stage = "sip"
        # SIP: dialogs whose identities contain the MSISDN (or IMSI), then the full dialogs.
        flt = sip.identity_filter(imsi_d, msisdn_d)
        if flt:
            stdout, scan = _fields_run(capture, flt, ["sip.Call-ID"], st.limits.max_scan_packets, timeout=_left(deadline))
            alone, shared = sip.selected_call_ids(stdout)
            notes["sip"] = {"dialogs": len(alone | shared), "truncated": scan.truncated}
            corr = sip.correlation_filter(alone | shared)
            if corr:
                stdout, scan = _fields_run(capture, corr, sip.FIELDS, st.limits.max_scan_packets, aggregator=sip.AGGREGATOR,
                                           timeout=_left(deadline))
                dialogs = sip.group_dialogs(stdout)
                if shared:
                    keep = sip.matching_call_ids(stdout, number=msisdn_d, imsi=imsi_d)
                    dialogs = [d for d in dialogs if d["call_id"] not in shared or d["call_id"] in keep]
                    notes["sip"]["dialogs"] = len(dialogs)
                for row in dialogs:
                    timeline.append(_sip_step(row))
                notes["sip"]["truncated"] = notes["sip"]["truncated"] or scan.truncated
    except ToolError as exc:
        if exc.type != "timeout":
            raise
        stopped = stage
        notes.setdefault(stopped, {})["timed_out"] = True

    timeline.sort(key=lambda r: (r.get("time") or "", r.get("request_frame") or r.get("frame") or 0))
    return timeline, notes, stopped


def _capture_steps(capture: Path, deadline: float) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    """Every Diameter, GTPv2-C, MAP and SIP transaction of a capture as timeline rows
    (each protocol under the usual packet caps), for comparing two captures without a
    subscriber. Returns (rows in time order, per-protocol notes, the pass the time
    budget ran out in or None)."""
    st = state()
    steps: list[dict[str, Any]] = []
    notes: dict[str, Any] = {}
    stage = "diameter"
    try:
        packets, scan = _json_run(capture, "diameter", diameter.JSON_LAYERS, st.limits.max_packets, deadline=deadline)
        txs = diameter.pair(diameter.extract_messages(packets, keep_raw=True))
        steps += [_diameter_step(tx, diameter.transaction_row(tx), True) for tx in txs]
        notes["diameter"] = {"transactions": len(txs), "truncated": scan.truncated}
        stage = "gtpv2"
        packets, scan = _json_run(capture, "gtpv2", gtp.JSON_LAYERS, st.limits.max_packets, deadline=deadline)
        txs = gtp.pair(gtp.extract_messages(packets))
        steps += [_gtp_step(gtp.transaction_row(tx)) for tx in txs]
        notes["gtpv2"] = {"transactions": len(txs), "truncated": scan.truncated}
        stage = "gtpv1"
        packets, scan = _json_run(capture, gtpv1.BASE_FILTER, gtpv1.JSON_LAYERS, st.limits.max_packets, deadline=deadline)
        txs = gtpv1.pair(gtpv1.extract_messages(packets))
        if txs:
            steps += [_gtpv1_step(gtpv1.transaction_row(tx)) for tx in txs]
            notes["gtpv1"] = {"transactions": len(txs), "truncated": scan.truncated}
        stage = "map"
        packets, scan = _json_run(capture, sigtran.MESSAGE_FILTER, sigtran.JSON_LAYERS, st.limits.max_packets, deadline=deadline)
        rows = [r for r in sigtran.extract_rows(packets) if r.get("components") or r.get("tcap")]
        steps += [_map_step(r) for r in rows]
        notes["map"] = {"messages": len(rows), "truncated": scan.truncated}
        stage = "sip"
        stdout, scan = _fields_run(capture, "sip", sip.FIELDS, st.limits.max_scan_packets, aggregator=sip.AGGREGATOR,
                                   timeout=_left(deadline))
        dialogs = sip.group_dialogs(stdout)
        steps += [_sip_step(d) for d in dialogs]
        notes["sip"] = {"dialogs": len(dialogs), "truncated": scan.truncated}
    except ToolError as exc:
        if exc.type != "timeout":
            raise
        notes.setdefault(stage, {})["timed_out"] = True
        steps.sort(key=lambda r: (r.get("time") or "", r.get("request_frame") or r.get("frame") or 0))
        return steps, notes, stage
    steps.sort(key=lambda r: (r.get("time") or "", r.get("request_frame") or r.get("frame") or 0))
    return steps, notes, None


@app.tool(title="Compare two captures", annotations=READ_ONLY)
def compare_captures(path_a: str, path_b: str, imsi: str | None = None, msisdn: str | None = None,
                     imsi_b: str | None = None, msisdn_b: str | None = None, collapse_repeats: bool = True,
                     limit: int = 100) -> models.CompareCapturesResult:
    """Compare a working and a failing capture of the same procedure. Builds the message
    ladder of each (the trace_subscriber timeline for `imsi`/`msisdn`; give `imsi_b`/
    `msisdn_b` when capture B is a different subscriber; without any identity, every
    Diameter, GTPv2-C, MAP and SIP transaction of the file), drops keepalives (CER, DWR,
    Echo), merges consecutive identical retries into one step with `repeat`, aligns the
    two ladders by protocol and message, and reports `first_divergence` (the first step
    that is missing, replaced or different), every aligned step with its `op` (same,
    changed, replaced, only_a, only_b) and, for changed steps, the `differences`: result,
    pairing, the key Diameter AVPs (flags, Cancellation-Type, subscription APNs, ...) and
    the GTP IEs (APN, RAT, cause, F-TEID interfaces, PAA allocated); identities are
    ignored. `timing` lists the largest round-trip and offset gaps. Both captures share
    one time budget. `limit` caps the ladder rows returned (default 100)."""
    def run() -> dict[str, Any]:
        st = state()
        capture_a, capture_b = _resolve(path_a), _resolve(path_b)
        ids = {}
        for name, value in (("imsi", imsi), ("msisdn", msisdn), ("imsi_b", imsi_b), ("msisdn_b", msisdn_b)):
            ids[name] = lint_digits(value, name) if value else None
        if (ids["imsi_b"] or ids["msisdn_b"]) and not (ids["imsi"] or ids["msisdn"]):
            raise ToolError("invalid_argument", "imsi_b/msisdn_b need imsi or msisdn for capture A")
        cap = clamp_limit(limit, st.limits.max_packets, 100)
        deadline = _now() + st.limits.timeout_seconds
        sides = {}
        stopped = None
        for side, capture, ident in (("a", capture_a, (ids["imsi"], ids["msisdn"])),
                                     ("b", capture_b, (ids["imsi_b"] or (None if ids["msisdn_b"] else ids["imsi"]),
                                                       ids["msisdn_b"] or (None if ids["imsi_b"] else ids["msisdn"])))):
            if stopped is not None:
                sides[side] = ([], {"skipped": True}, ident)
                continue
            if ident[0] or ident[1]:
                steps, notes, stop = _trace_timeline(capture, ident[0], ident[1], deadline, with_avps=True)
            else:
                steps, notes, stop = _capture_steps(capture, deadline)
            if stop is not None:
                stopped = f"{side}:{stop}"
            sides[side] = (steps, notes, ident)
        a = compare.prepare(sides["a"][0], collapse_repeats)
        b = compare.prepare(sides["b"][0], collapse_repeats)
        ladder = compare.align(a, b)
        out = _envelope("ladder", ladder, cap, None)
        out.update({
            "a": dict(compare.side_summary(a), path=str(capture_a), identity=_identity(sides["a"][2]), passes=sides["a"][1]),
            "b": dict(compare.side_summary(b), path=str(capture_b), identity=_identity(sides["b"][2]), passes=sides["b"][1]),
            "summary": compare.summarise(ladder),
            "first_divergence": compare.first_divergence(ladder),
            "identical": all(e["op"] == "same" for e in ladder),
            "timing": compare.timing(ladder),
        })
        empty = [side.upper() for side, steps in (("a", a), ("b", b)) if not steps]
        if empty:
            what = "the subscriber" if any(sides[s][2][0] or sides[s][2][1] for s in ("a", "b")) else "any transaction"
            out["notes"] = [f"capture {' and '.join(empty)} has no Diameter, GTPv2-C, MAP or SIP signalling for {what}; "
                            "a user-plane capture is better read with gtp_user_plane"]
        reasons = [out["truncated_reason"]] if out.get("truncated_reason") else []
        if stopped is not None:
            reasons.append(f"time budget of {st.limits.timeout_seconds}s used up during the {stopped} pass; "
                           "the ladders are incomplete")
        if any(n.get("truncated") for side in ("a", "b") for n in sides[side][1].values() if isinstance(n, dict)):
            reasons.append("a pass hit the packet or frame cap (see a.passes and b.passes); the ladders may be incomplete")
        if reasons:
            out["truncated"] = True
            out["truncated_reason"] = "; ".join(reasons)
        return out
    return _guarded("compare_captures", {"path_a": path_a, "path_b": path_b, "imsi": imsi, "msisdn": msisdn,
                                         "imsi_b": imsi_b, "msisdn_b": msisdn_b, "collapse_repeats": collapse_repeats,
                                         "limit": limit}, run)


def _identity(ident: tuple[str | None, str | None]) -> dict[str, str] | None:
    out = {k: v for k, v in (("imsi", ident[0]), ("msisdn", ident[1])) if v}
    return out or None


def _trace_gtp(module: Any, key: str, capture: Path, imsi_d: str | None, msisdn_d: str | None, deadline: float,
               notes: dict[str, Any], timeline: list[dict[str, Any]]) -> None:
    """One GTP version's passes of the subscriber trace (``module`` is gtp or gtpv1)."""
    st = state()
    flt = module.identity_filter(imsi_d, msisdn_d)
    if not flt:
        return
    packets, scan = _json_run(capture, flt, module.JSON_LAYERS, st.limits.max_packets, deadline=deadline)
    seed = module.extract_messages(packets)
    if not seed and key == "gtpv1":
        return  # most captures carry no GTPv1-C; keep the passes summary short
    seqs, teids = module.sequence_numbers(seed), module.control_teids(seed)
    notes[key] = {"seed_messages": len(seed), "sequence_numbers": len(seqs), "control_teids": len(teids),
                  "truncated": scan.truncated}
    corr = module.correlation_filter(seqs, teids)
    # Pass two fetches the paired responses; they reveal the peer's control-plane
    # TEIDs, which later messages (Modify/Delete Session, Update/Delete PDP Context)
    # carry in their header, so pass three follows those. Both passes are bounded.
    collected: dict[tuple, Any] = {}
    try:
        for _pass in range(2):
            if not corr:
                break
            packets, scan = _json_run(capture, corr, module.JSON_LAYERS, st.limits.max_packets, deadline=deadline)
            fetched = module.extract_messages(packets)
            for m in fetched:
                collected.setdefault((m.frame, m.src, m.dst, m.fields.get("seq"), m.fields.get("message_type")), m)
            learnt: set[int] = set()
            for tx in module.pair(fetched):
                if _gtp_row_belongs(module.transaction_row(tx), imsi_d, msisdn_d, teids, seqs):
                    learnt |= module.control_teids([m for m in (tx.request, tx.answer) if m is not None])
            notes[key]["truncated"] = notes[key]["truncated"] or scan.truncated
            new_teids = learnt - teids
            teids |= new_teids
            notes[key]["control_teids"] = len(teids)
            corr = module.correlation_filter(set(), new_teids)
    finally:
        # Pair once over every pass: a request fetched by a TEID learnt in pass three
        # still meets the response that pass two fetched by sequence number.
        txs = module.pair(list(collected.values()))
        rows = [module.transaction_row(tx) for tx in txs]
        pairing.annotate_legs(txs, rows, _gtp_identity)
        for row in rows:
            if _gtp_row_belongs(row, imsi_d, msisdn_d, teids, seqs):
                timeline.append(_gtp_step(row) if key == "gtpv2" else _gtpv1_step(row))


def _diameter_step(tx: Any, row: dict[str, Any], with_avps: bool = False) -> dict[str, Any]:
    extra: dict[str, Any] = {"application": row.get("application"), "origin_host": row.get("origin_host"),
                             "destination_host": row.get("destination_host")}
    if with_avps:
        for side, msg in (("request_avps", tx.request), ("answer_avps", tx.answer)):
            if msg is not None and msg.fields.get("raw"):
                extra[side] = avps.key_view(avps.avp_tree(msg.fields["raw"], avps.HARD_MAX_AVPS)[0])
    return _timeline_row("diameter", row, message=f'{row.get("request")}/{row.get("answer") or "-"}',
                         detail=row.get("command"), result=row.get("result"), identity=row.get("user_name"), extra=extra)


def _gtp_step(row: dict[str, Any]) -> dict[str, Any]:
    return _timeline_row("gtpv2", row, message=row.get("message"), detail=row.get("response"),
                         result=row.get("cause_name"), identity=row.get("imsi") or row.get("msisdn"),
                         extra={"apn": row.get("apn"), "paa": row.get("paa"), "teid": row.get("teid"),
                                "rat_type": row.get("rat_type"), "request_fteids": row.get("request_fteids"),
                                "response_fteids": row.get("response_fteids")})


def _gtpv1_step(row: dict[str, Any]) -> dict[str, Any]:
    return _timeline_row("gtpv1", row, message=row.get("message"), detail=row.get("response"),
                         result=row.get("cause_name"), identity=row.get("imsi") or row.get("msisdn"),
                         extra={"apn": row.get("apn"), "paa": row.get("end_user_address"), "teid": row.get("teid"),
                                "rat_type": row.get("rat_type"), "nsapi": row.get("nsapi"),
                                "request_gsn": row.get("request_gsn"), "response_gsn": row.get("response_gsn"),
                                "response_path": row.get("response_path")})


def _map_step(row: dict[str, Any]) -> dict[str, Any]:
    comps = row.get("components", [])
    names = [c.get("operation") or c.get("error") or c.get("type") for c in comps]
    result = next((c.get("error") for c in comps if c.get("error")), None)
    if result is None and any(c.get("type", "").startswith("returnResult") for c in comps):
        result = "returnResult"
    return _timeline_row("map", row, message=f'{row.get("tcap", row.get("sccp"))} {" ".join(n for n in names if n)}'.strip(),
                         detail=f'{row.get("calling_gt")} > {row.get("called_gt")}', result=result,
                         identity=row.get("imsi") or row.get("msisdn"),
                         extra={"frame": row.get("frame"), "sccp": row.get("sccp"),
                                "segmentation": row.get("segmentation"),
                                "answered_in_frame": row.get("answered_in_frame"),
                                "in_response_to_frame": row.get("in_response_to_frame")})


def _sip_step(row: dict[str, Any]) -> dict[str, Any]:
    final = row.get("outcome_status") or row.get("final_status")
    return _timeline_row("sip", row, message=f'{row.get("initial_method")} -> {final if final else "no final response"}',
                         detail=row.get("request_uri"), result=str(final) if final else None,
                         identity=row.get("p_asserted_identity") or row.get("from"),
                         extra={"call_id": row.get("call_id"), "from": row.get("from"), "to": row.get("to"),
                                "time_to_final_ms": row.get("time_to_final_ms"), "methods": row.get("methods")})


def _timeline_row(protocol: str, row: dict[str, Any], *, message: str | None, detail: str | None, result: str | None,
                  identity: str | None, extra: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "time": row.get("time"), "protocol": protocol, "message": message, "detail": detail, "result": result,
        "identity": identity, "src": row.get("src"), "dst": row.get("dst"),
        "request_frame": row.get("request_frame"), "answer_frame": row.get("answer_frame"), "rtt_ms": row.get("rtt_ms"),
    }
    if row.get("unanswered") or row.get("no_final_response"):
        out["unanswered"] = True
    for key in ("leg_without_response", "duplicate_of_frame", "chain"):
        if row.get(key):
            out[key] = row[key]
    if row.get("leg_without_response") or row.get("duplicate_of_frame"):
        out["note"] = row.get("note")
    failed = (row.get("success") is False or row.get("accepted") is False
              or (protocol == "sip" and sip.dialog_failed(row))
              or (protocol == "map" and any(c.get("type") == "returnError" for c in row.get("components", []))))
    if failed:
        out["failed"] = True
    out.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def _gtp_identity(msg: Any) -> tuple | None:
    """Legs of one GTP procedure relayed through proxies: same IMSI, message and APN."""
    f = msg.fields
    if not f.get("imsi"):
        return None
    return (f["imsi"], f.get("message_type"), (f.get("apn") or "").lower())


def _leg_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    out = {"legs_without_response": sum(1 for r in rows if r.get("leg_without_response")),
           "duplicates": sum(1 for r in rows if r.get("duplicate_of_frame"))}
    return {k: v for k, v in out.items() if v}


def _gtp_row_belongs(row: dict[str, Any], imsi: str | None, msisdn: str | None, teids: set[int], seqs: set[int]) -> bool:
    if imsi and row.get("imsi") == imsi:
        return True
    if msisdn and row.get("msisdn") == msisdn:
        return True
    if row.get("imsi") or row.get("msisdn"):
        return False  # a different subscriber that happens to share a sequence number
    teid = to_int(row.get("teid"))
    if teid and teid in teids:
        return True
    return row.get("seq") in seqs


def _colonise(hex_tid: str) -> str:
    h = hex_tid.strip().replace(":", "")
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def _count(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        name = str(r.get(key))
        out[name] = out.get(name, 0) + 1
    return out


def _summarise(rows: list[dict[str, Any]], name_key: str, unanswered_key: str,
               failed: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
    by_name: dict[str, int] = {}
    for r in rows:
        n = str(r.get(name_key))
        by_name[n] = by_name.get(n, 0) + 1
    return {
        "by_message": by_name,
        "unanswered": sum(1 for r in rows if r.get(unanswered_key)),
        "failed": sum(1 for r in rows if failed(r)),
    }


# ------------------------------------------------------------------ parsers for -z output
def _parse_capinfos(stdout: str) -> dict[str, Any]:
    mapping = {
        "File type": "file_type", "File encapsulation": "link_type", "Number of packets": "packets",
        "Capture duration": "duration_s", "Earliest packet time": "first_packet", "Latest packet time": "last_packet",
        # capinfos before Wireshark 4.4 used these labels.
        "First packet time": "first_packet", "Last packet time": "last_packet",
    }
    out: dict[str, Any] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        target = mapping.get(key)
        if target is None:
            continue
        if target == "packets":
            out[target] = to_int(value.split()[0]) if value else None
        elif target == "duration_s":
            try:
                out[target] = float(value.split()[0])
            except (ValueError, IndexError):
                out[target] = value
        elif target in ("first_packet", "last_packet"):
            try:
                ts = float(value)
                out[target] = iso(ts)
                out[target + "_epoch"] = ts
            except ValueError:
                out[target] = value
        else:
            out[target] = value
    return out


_PHS_LINE = re.compile(r"^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)")


def _parse_phs(stdout: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    stack: list[tuple[int, str]] = []
    for line in stdout.splitlines():
        m = _PHS_LINE.match(line)
        if not m:
            continue
        indent, proto, frames, byts = len(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, proto))
        # tshark 4.4+ prints a "frame" root that older builds omit; drop it so paths match.
        path = "/".join(p for _, p in stack if p != "frame")
        if not path:
            continue
        rows.append({"protocol": path, "frames": frames, "bytes": byts})
    return rows


_UNITS = {"bytes": 1, "kB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3, "TB": 1000 ** 4}


def _parse_conversations(stdout: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if "<->" not in line:
            continue
        tokens = line.split()
        try:
            arrow = tokens.index("<->")
        except ValueError:
            continue
        a, b = " ".join(tokens[:arrow]), tokens[arrow + 1]
        numbers: list[float] = []
        for tok in tokens[arrow + 2:]:
            if tok in _UNITS and numbers:
                numbers[-1] *= _UNITS[tok]
                continue
            try:
                numbers.append(float(tok))
            except ValueError:
                continue
        if len(numbers) < 8:
            continue
        rows.append({
            "a": a, "b": b,
            "frames_b_to_a": int(numbers[0]), "bytes_b_to_a": int(numbers[1]),
            "frames_a_to_b": int(numbers[2]), "bytes_a_to_b": int(numbers[3]),
            "frames_total": int(numbers[4]), "bytes_total": int(numbers[5]),
            "start_rel_s": numbers[6], "duration_s": numbers[7],
        })
    return rows


# ------------------------------------------------------------------ entry point
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tshark-mcp", description="Read-only MCP server for packet capture analysis with tshark.")
    p.add_argument("--allow-dir", action="append", default=[], metavar="DIR",
                   help="directory whose captures may be read (repeatable; or TSHARK_MCP_ALLOW_DIRS)")
    p.add_argument("--log-file", default=os.environ.get("TSHARK_MCP_LOG"), metavar="PATH",
                   help="append one JSON line per tool call here (or TSHARK_MCP_LOG)")
    p.add_argument("--tshark", default=None, help="path to the tshark binary (or TSHARK_MCP_TSHARK)")
    p.add_argument("--max-file-mb", type=float, default=None, help="refuse captures larger than this (default 500)")
    p.add_argument("--max-packets", type=int, default=None, help="matching packets dissected in full per call (default 500)")
    p.add_argument("--max-scan-packets", type=int, default=None,
                   help="frames read from a capture per tshark run, and matching packets kept by the aggregating tools (default 200000)")
    p.add_argument("--max-output-kb", type=float, default=None, help="JSON bytes returned per call (default 200)")
    p.add_argument("--timeout", type=float, default=None, help="seconds per tshark run (default 60)")
    p.add_argument("--max-files", type=int, default=None, help="capture files one find_identifier call may open (default 50)")
    p.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    p.add_argument("--version", action="version", version=f"tshark-mcp {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        limits = Limits.from_env()
        overrides: dict[str, Any] = {}
        if args.max_file_mb is not None:
            overrides["max_file_bytes"] = int(args.max_file_mb * 1024 * 1024)
        if args.max_packets is not None:
            overrides["max_packets"] = args.max_packets
        if args.max_scan_packets is not None:
            overrides["max_scan_packets"] = args.max_scan_packets
        if args.max_output_kb is not None:
            overrides["max_output_bytes"] = int(args.max_output_kb * 1024)
        if args.timeout is not None:
            overrides["timeout_seconds"] = args.timeout
        if args.max_files is not None:
            overrides["max_files"] = args.max_files
        if overrides:
            from dataclasses import replace
            limits = replace(limits, **overrides)
        allow_dirs = list(args.allow_dir) or ([os.environ["TSHARK_MCP_ALLOW_DIRS"]] if os.environ.get("TSHARK_MCP_ALLOW_DIRS") else [])
        if not allow_dirs:
            print("tshark-mcp: no --allow-dir given and TSHARK_MCP_ALLOW_DIRS is unset; refusing to start", file=sys.stderr)
            return 2
        st = configure(allow_dirs, limits=limits, tshark=args.tshark, log_path=args.log_file)
    except (ValueError, ToolError) as exc:
        print(f"tshark-mcp: {exc}", file=sys.stderr)
        return 2
    print(f"tshark-mcp {__version__}: tshark={st.runner.tshark} allow={st.allowlist.describe()} limits={st.limits.describe()}",
          file=sys.stderr)
    app.run(transport=args.transport)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

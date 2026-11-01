"""tshark-mcp: read-only packet capture analysis for LLM agents.

The MCP app and the ten tools live here. Every tool goes through
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

from . import __version__, diameter, gtp, sigtran, sip
from .fields import field_catalogue, iso, parse_packets, split_fields_line, to_int, validate_fields
from .limits import Allowlist, Limits, ToolError, clamp_limit, lint_digits, lint_display_filter, lint_field_name
from .runner import Runner, check_result

try:  # mcp >= 2.0 renamed FastMCP to MCPServer; the decorator API is the same.
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # pragma: no cover - mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

INSTRUCTIONS = """\
Read-only analysis of existing packet captures with tshark. Captures must live
inside the allowed directories (see the error message if a path is refused).
Every call is bounded: file size, packets dissected, output bytes and run time.
Start with pcap_info, then use the protocol tools. For "why did subscriber X
fail" questions call trace_subscriber first, then drill into
diameter_transactions, gtp_sessions, sigtran_messages or sip_dialogs with a
display filter. Results are JSON; "truncated": true means a cap was reached and
you should narrow the filter.
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
    try:
        result = fn()
    except ToolError as exc:
        status = exc.type
        result = exc.to_dict()
    except Exception as exc:  # noqa: BLE001 - never leak a traceback to the client
        status = "internal_error"
        result = ToolError("internal_error", f"{type(exc).__name__}: {exc}").to_dict()
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


def _json_run(capture: Path, display_filter: str | None, layers: str, max_packets: int) -> tuple[list[dict], bool]:
    """Run tshark in JSON mode; return (packets, hit_packet_cap)."""
    result = check_result(state().runner.read_capture(
        capture, ["-T", "json", "--no-duplicate-keys", "-J", layers], max_packets=max_packets,
        display_filter=display_filter,
    ))
    packets = parse_packets(result.stdout)
    return packets, len(packets) >= max_packets


def _fields_run(capture: Path, display_filter: str | None, fields: list[str], max_packets: int,
                aggregator: str = ",") -> tuple[str, int, bool]:
    args = ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", f"-E", f"aggregator={aggregator}"]
    for f in fields:
        args += ["-e", f]
    result = check_result(state().runner.read_capture(capture, args, max_packets=max_packets, display_filter=display_filter))
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    return result.stdout, len(lines), len(lines) >= max_packets


def _envelope(rows_key: str, rows: list[dict[str, Any]], limit: int, scanned: int | None, hit_cap: bool,
              **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {rows_key: rows[:limit], "count": len(rows[:limit]), "total_found": len(rows)}
    if scanned is not None:
        out["packets_scanned"] = scanned
    out.update(extra)
    if hit_cap or len(rows) > limit:
        out["truncated"] = True
        out["truncated_reason"] = ("packet cap reached" if hit_cap else "more rows than limit") + "; narrow the filter"
    return out


# ------------------------------------------------------------------ tools
@app.tool()
def pcap_info(path: str) -> dict[str, Any]:
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


@app.tool()
def conversations(path: str, layer: str = "ip", limit: int = 200) -> dict[str, Any]:
    """List conversations (endpoint pairs) at one layer: `layer` is one of ip, ipv6, tcp,
    udp, sctp or eth. Each row has both endpoints, frames and bytes in each direction,
    start time and duration. Sorted by total frames, capped at `limit`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        if layer not in ("ip", "ipv6", "tcp", "udp", "sctp", "eth"):
            raise ToolError("invalid_argument", "layer must be one of ip, ipv6, tcp, udp, sctp, eth")
        cap = clamp_limit(limit, state().limits.max_packets, 200)
        result = check_result(state().runner.read_capture(capture, ["-q", "-z", f"conv,{layer}"]))
        rows = _parse_conversations(result.stdout)
        rows.sort(key=lambda r: -r["frames_total"])
        return _envelope("conversations", rows, cap, None, False, layer=layer)
    return _guarded("conversations", {"path": path, "layer": layer, "limit": limit}, run)


@app.tool()
def filter_packets(path: str, display_filter: str, fields: list[str] | None = None, limit: int = 200) -> dict[str, Any]:
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
        stdout, scanned, hit = _fields_run(capture, flt, names, cap)
        rows = []
        for line in stdout.splitlines():
            cols = split_fields_line(line)
            if len(cols) != len(names):
                continue
            rows.append({k: v for k, v in zip(names, cols) if v != ""})
        return _envelope("packets", rows, cap, scanned, hit, fields=names, display_filter=flt)
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


@app.tool()
def diameter_transactions(path: str, filter: str | None = None, limit: int = 200) -> dict[str, Any]:
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
        packets, hit = _json_run(capture, flt, diameter.JSON_LAYERS, st.limits.max_packets)
        txs = diameter.pair(diameter.extract_messages(packets))
        rows = [diameter.transaction_row(t) for t in txs]
        summary = _summarise(rows, "request", "unanswered", lambda r: r.get("success") is False)
        return _envelope("transactions", rows, cap, len(packets), hit, summary=summary)
    return _guarded("diameter_transactions", {"path": path, "filter": filter, "limit": limit}, run)


@app.tool()
def gtp_sessions(path: str, filter: str | None = None, limit: int = 200) -> dict[str, Any]:
    """Pair GTPv2-C requests with responses by sequence number and peer pair. Reports
    message names (Create Session, Modify Bearer, Delete Session, Echo, ...), IMSI, MSISDN,
    APN, F-TEIDs with interface names, cause code and name, allocated UE address (PAA),
    round-trip ms and `unanswered: true`. `filter` is ANDed with `gtpv2`, e.g.
    `e212.imsi == "001010123456789"` or `gtpv2.message_type == 32`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        flt = _filter(filter, base="gtpv2")
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        packets, hit = _json_run(capture, flt, gtp.JSON_LAYERS, st.limits.max_packets)
        txs = gtp.pair(gtp.extract_messages(packets))
        rows = [gtp.transaction_row(t) for t in txs]
        summary = _summarise(rows, "message", "unanswered", lambda r: r.get("accepted") is False)
        return _envelope("transactions", rows, cap, len(packets), hit, summary=summary)
    return _guarded("gtp_sessions", {"path": path, "filter": filter, "limit": limit}, run)


@app.tool()
def gtp_user_plane(path: str, teid: str | int | None = None, limit: int = 200) -> dict[str, Any]:
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
        stdout, scanned, hit = _fields_run(capture, gtp.user_plane_filter(teid_int), gtp.USER_PLANE_FIELDS,
                                           st.limits.max_scan_packets)
        rows = gtp.summarise_user_plane(stdout)
        return _envelope("tunnels", rows, cap, scanned, hit,
                         total_packets=sum(r["packets"] for r in rows),
                         total_payload_bytes=sum(r["payload_bytes"] for r in rows))
    return _guarded("gtp_user_plane", {"path": path, "teid": teid, "limit": limit}, run)


@app.tool()
def sip_dialogs(path: str, filter: str | None = None, limit: int = 200) -> dict[str, Any]:
    """Group SIP messages by Call-ID. Each dialog lists the method/response sequence with
    timestamps, From, To, Request-URI, P-Asserted-Identity, the final status of the
    initial request and time to that final response; `no_final_response: true` marks
    requests that never completed. `filter` is ANDed with `sip`, e.g.
    `sip.Method == "INVITE" || sip.Status-Code >= 400`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        flt = _filter(filter, base="sip")
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        stdout, scanned, hit = _fields_run(capture, flt, sip.FIELDS, st.limits.max_packets, aggregator=sip.AGGREGATOR)
        rows = sip.group_dialogs(stdout)
        summary = _summarise(rows, "initial_method", "no_final_response",
                             lambda r: (r.get("final_status") or 0) >= 400)
        return _envelope("dialogs", rows, cap, scanned, hit, summary=summary)
    return _guarded("sip_dialogs", {"path": path, "filter": filter, "limit": limit}, run)


@app.tool()
def sctp_associations(path: str, limit: int = 200) -> dict[str, Any]:
    """Summarise SCTP associations by endpoint pair: handshake state (INIT/INIT-ACK
    frames and initiate tags), DATA chunk count, heartbeats sent versus acknowledged,
    retransmissions, and whether ABORT or SHUTDOWN was seen. Useful for Diameter and
    SIGTRAN transport health before looking at the application layer."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        cap = clamp_limit(limit, st.limits.max_packets, 200)
        stdout, scanned, hit = _fields_run(capture, sigtran.SCTP_FILTER, sigtran.SCTP_FIELDS, st.limits.max_scan_packets)
        rows = sigtran.summarise_sctp(stdout)
        return _envelope("associations", rows, cap, scanned, hit)
    return _guarded("sctp_associations", {"path": path, "limit": limit}, run)


@app.tool()
def sigtran_messages(path: str, filter: str | None = None, limit: int = 200) -> dict[str, Any]:
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
        packets, hit = _json_run(capture, flt, sigtran.JSON_LAYERS, st.limits.max_packets)
        rows = sigtran.extract_rows(packets)
        ops: dict[str, int] = {}
        for r in rows:
            for c in r.get("components", []):
                name = c.get("operation") or c.get("error") or c.get("type")
                ops[name] = ops.get(name, 0) + 1
        summary = {"by_operation": ops, "unanswered_begins": sum(1 for r in rows if r.get("unanswered")),
                   "segmented": sum(1 for r in rows if r.get("segmentation"))}
        return _envelope("messages", rows, cap, len(packets), hit, summary=summary)
    return _guarded("sigtran_messages", {"path": path, "filter": filter, "limit": limit}, run)


@app.tool()
def trace_subscriber(path: str, imsi: str | None = None, msisdn: str | None = None, limit: int = 300) -> dict[str, Any]:
    """Build one time-ordered timeline for a subscriber across Diameter (User-Name),
    GTPv2-C (IMSI/MSISDN IEs, then following the control-plane TEIDs), MAP (IMSI/MSISDN)
    and SIP (From/To/P-Asserted-Identity containing the MSISDN). Each row carries the
    protocol, message name, result (Result-Code, GTP cause, SIP final status), peers and
    the request/answer pairing including `unanswered: true`. Give `imsi`, `msisdn` or
    both as digit strings. Start here for "why did subscriber X fail" questions."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        if not imsi and not msisdn:
            raise ToolError("invalid_argument", "give imsi, msisdn or both")
        imsi_d = lint_digits(imsi, "imsi") if imsi else None
        msisdn_d = lint_digits(msisdn, "msisdn") if msisdn else None
        cap = clamp_limit(limit, st.limits.max_packets, 300)
        timeline: list[dict[str, Any]] = []
        notes: dict[str, Any] = {}

        # Diameter: sessions naming the subscriber, then every message of those sessions.
        sessions: set[str] = set()
        flt = diameter.identity_filter(imsi_d, msisdn_d)
        if flt:
            stdout, _, hit = _fields_run(capture, flt, ["diameter.Session-Id"], st.limits.max_packets)
            sessions = {ln.strip().split(",")[0] for ln in stdout.splitlines() if ln.strip()}
            notes["diameter"] = {"sessions": len(sessions), "truncated": hit}
        corr = diameter.correlation_filter(sessions)
        if corr:
            packets, hit = _json_run(capture, corr, diameter.JSON_LAYERS, st.limits.max_packets)
            for tx in diameter.pair(diameter.extract_messages(packets)):
                row = diameter.transaction_row(tx)
                timeline.append(_timeline_row("diameter", row, message=f'{row.get("request")}/{row.get("answer") or "-"}',
                                              detail=row.get("command"), result=row.get("result"),
                                              identity=row.get("user_name"), extra={"application": row.get("application"),
                                              "origin_host": row.get("origin_host"), "destination_host": row.get("destination_host")}))
            notes["diameter"]["truncated"] = notes["diameter"]["truncated"] or hit

        # GTPv2-C: requests naming the subscriber, then the same sequence numbers and TEIDs.
        flt = gtp.identity_filter(imsi_d, msisdn_d)
        if flt:
            packets, hit = _json_run(capture, flt, gtp.JSON_LAYERS, st.limits.max_packets)
            seed = gtp.extract_messages(packets)
            seqs, teids = gtp.sequence_numbers(seed), gtp.control_teids(seed)
            notes["gtpv2"] = {"seed_messages": len(seed), "sequence_numbers": len(seqs), "control_teids": len(teids), "truncated": hit}
            corr = gtp.correlation_filter(seqs, teids)
            seen_frames: set[int] = set()
            # Pass two fetches the paired responses; they reveal the peer's control-plane
            # TEIDs, which later messages (Modify/Delete Session) carry in their header, so
            # pass three follows those. Both passes are bounded like any other call.
            for _pass in range(2):
                if not corr:
                    break
                packets, hit = _json_run(capture, corr, gtp.JSON_LAYERS, st.limits.max_packets)
                learnt: set[int] = set()
                for tx in gtp.pair(gtp.extract_messages(packets)):
                    row = gtp.transaction_row(tx)
                    if not _gtp_row_belongs(row, imsi_d, msisdn_d, teids, seqs):
                        continue
                    anchor = row.get("request_frame") or row.get("answer_frame")
                    if anchor in seen_frames:
                        continue
                    seen_frames.add(anchor)
                    learnt |= gtp.control_teids([m for m in (tx.request, tx.answer) if m is not None])
                    timeline.append(_timeline_row("gtpv2", row, message=row.get("message"), detail=row.get("response"),
                                                  result=row.get("cause_name"), identity=row.get("imsi") or row.get("msisdn"),
                                                  extra={"apn": row.get("apn"), "paa": row.get("paa"), "teid": row.get("teid"),
                                                         "request_fteids": row.get("request_fteids"),
                                                         "response_fteids": row.get("response_fteids")}))
                notes["gtpv2"]["truncated"] = notes["gtpv2"]["truncated"] or hit
                new_teids = learnt - teids
                teids |= new_teids
                notes["gtpv2"]["control_teids"] = len(teids)
                corr = gtp.correlation_filter(set(), new_teids)

        # MAP: components naming the subscriber, then the whole TCAP transactions.
        flt = sigtran.identity_filter(imsi_d, msisdn_d)
        if flt:
            stdout, _, hit = _fields_run(capture, flt, ["tcap.tid"], st.limits.max_packets)
            tids = {_colonise(t) for ln in stdout.splitlines() for t in ln.strip().split(",") if t.strip()}
            notes["map"] = {"transactions": len(tids), "truncated": hit}
            corr = sigtran.correlation_filter(tids)
            if corr:
                packets, hit = _json_run(capture, corr, sigtran.JSON_LAYERS, st.limits.max_packets)
                for row in sigtran.extract_rows(packets):
                    comps = row.get("components", [])
                    names = [c.get("operation") or c.get("error") or c.get("type") for c in comps]
                    result = next((c.get("error") for c in comps if c.get("error")), None)
                    if result is None and any(c.get("type", "").startswith("returnResult") for c in comps):
                        result = "returnResult"
                    timeline.append(_timeline_row("map", row, message=f'{row.get("tcap", row.get("sccp"))} {" ".join(n for n in names if n)}'.strip(),
                                                  detail=f'{row.get("calling_gt")} > {row.get("called_gt")}', result=result,
                                                  identity=row.get("imsi") or row.get("msisdn"),
                                                  extra={"frame": row.get("frame"), "sccp": row.get("sccp"),
                                                         "segmentation": row.get("segmentation"),
                                                         "answered_in_frame": row.get("answered_in_frame"),
                                                         "in_response_to_frame": row.get("in_response_to_frame")}))
                notes["map"]["truncated"] = notes["map"]["truncated"] or hit

        # SIP: dialogs whose identities contain the MSISDN (or IMSI), then the full dialogs.
        flt = sip.identity_filter(imsi_d, msisdn_d)
        if flt:
            stdout, _, hit = _fields_run(capture, flt, ["sip.Call-ID"], st.limits.max_packets)
            call_ids = {ln.strip().split(",")[0] for ln in stdout.splitlines() if ln.strip()}
            notes["sip"] = {"dialogs": len(call_ids), "truncated": hit}
            corr = sip.correlation_filter(call_ids)
            if corr:
                stdout, _, hit = _fields_run(capture, corr, sip.FIELDS, st.limits.max_packets, aggregator=sip.AGGREGATOR)
                for row in sip.group_dialogs(stdout):
                    final = row.get("final_status")
                    timeline.append(_timeline_row("sip", row, message=f'{row.get("initial_method")} -> {final if final else "no final response"}',
                                                  detail=row.get("request_uri"), result=str(final) if final else None,
                                                  identity=row.get("p_asserted_identity") or row.get("from"),
                                                  extra={"call_id": row.get("call_id"), "from": row.get("from"), "to": row.get("to"),
                                                         "time_to_final_ms": row.get("time_to_final_ms"), "methods": row.get("methods")}))
                notes["sip"]["truncated"] = notes["sip"]["truncated"] or hit

        timeline.sort(key=lambda r: (r.get("time") or "", r.get("request_frame") or r.get("frame") or 0))
        by_protocol: dict[str, int] = {}
        for r in timeline:
            by_protocol[r["protocol"]] = by_protocol.get(r["protocol"], 0) + 1
        failures = [r for r in timeline if r.get("unanswered") or r.get("failed")]
        out = _envelope("timeline", timeline, cap, None, any(n.get("truncated") for n in notes.values()),
                        identity={"imsi": imsi_d, "msisdn": msisdn_d}, by_protocol=by_protocol,
                        failures=len(failures), passes=notes)
        return out
    return _guarded("trace_subscriber", {"path": path, "imsi": imsi, "msisdn": msisdn, "limit": limit}, run)


def _timeline_row(protocol: str, row: dict[str, Any], *, message: str | None, detail: str | None, result: str | None,
                  identity: str | None, extra: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "time": row.get("time"), "protocol": protocol, "message": message, "detail": detail, "result": result,
        "identity": identity, "src": row.get("src"), "dst": row.get("dst"),
        "request_frame": row.get("request_frame"), "answer_frame": row.get("answer_frame"), "rtt_ms": row.get("rtt_ms"),
    }
    if row.get("unanswered") or row.get("no_final_response"):
        out["unanswered"] = True
    failed = (row.get("success") is False or row.get("accepted") is False
              or (protocol == "sip" and (row.get("final_status") or 0) >= 400)
              or (protocol == "map" and any(c.get("type") == "returnError" for c in row.get("components", []))))
    if failed:
        out["failed"] = True
    out.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


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
    p.add_argument("--max-packets", type=int, default=None, help="packets dissected per call (default 500)")
    p.add_argument("--max-output-kb", type=float, default=None, help="JSON bytes returned per call (default 200)")
    p.add_argument("--timeout", type=float, default=None, help="seconds per tshark run (default 60)")
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
        if args.max_output_kb is not None:
            overrides["max_output_bytes"] = int(args.max_output_kb * 1024)
        if args.timeout is not None:
            overrides["timeout_seconds"] = args.timeout
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

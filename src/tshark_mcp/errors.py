"""What to do next after a tool error.

Every structured error the server returns carries a ``fix``: one sentence that tells the
agent which argument to change or which tool to call instead. A few error types add a
machine-readable list next to it: ``candidates`` (capture files in the directory the
missing path pointed into, at most :data:`MAX_CANDIDATES`) and ``suggestions`` (field
names close to an unknown one, at most :data:`MAX_SUGGESTIONS`). Nothing here reads a
capture or lists anything outside the allowed directories.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any, Callable

from .limits import Allowlist, outside_quotes

MAX_CANDIDATES = 10
MAX_SUGGESTIONS = 5

# Arguments that narrow a call, in the order a hint names them.
NARROWING_ARGS: tuple[str, ...] = (
    "imsi", "msisdn", "teid", "seid", "ue_ip", "call_id", "session_id", "apn", "number", "impu", "ssrc",
    "server_name", "name", "command_code", "stream", "method", "filter", "display_filter", "identifier",
)

_TOKEN = re.compile(r"(?<![\w.\-])[A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]+)*")
_KEYWORDS = frozenset({"and", "or", "not", "xor", "in", "contains", "matches", "eq", "ne", "gt", "lt", "ge", "le",
                       "any", "all", "true", "false"})

STATIC_FIXES: dict[str, str] = {
    "invalid_path": "pass an absolute path to a capture file inside one of the allowed directories",
    "no_allowed_dirs": "the operator must restart the server with --allow-dir <directory> (or TSHARK_MCP_ALLOW_DIRS)",
    "not_configured": "the operator must restart the server with --allow-dir <directory>",
    "not_a_directory": "find_identifier takes a directory (or one capture file); pass the directory that holds the captures",
    "file_too_large": ("the capture is over the server's size cap; ask a human to slice it (editcap -A/-B by time or "
                       "-r by frame range) into the allowed directory, or to raise --max-file-mb"),
    "invalid_argument": "correct the argument named in message; the tool's inputSchema gives each argument's shape",
    "invalid_field": "field names are dotted tshark abbreviations such as diameter.Session-Id; use find_fields(query) to look one up",
    "unknown_token": ("redaction tokens are valid only while the server run that issued them is running; call the tool "
                      "that produced the token again for a fresh one, or pass the real value"),
    "tshark_failed": ("tshark could not read the capture; call pcap_info and capture_quality on it, and if one dissector "
                      "fails narrow the filter to the protocol you need"),
    "tshark_missing": "the operator must install tshark 4.0 or newer or point TSHARK_MCP_TSHARK at it",
    "exec_failed": "the operator must check that tshark is installed and executable (TSHARK_MCP_TSHARK)",
    "forbidden_flag": "this server only reads existing captures; no tool argument can capture, write or export",
    "parse_error": "tshark output could not be parsed; retry with a narrower filter and report the arguments as a bug",
    "busy": ("the server is already running its maximum number of tshark processes; wait for your other calls "
             "to finish and call again, one at a time"),
    "cancelled": "the client cancelled the call and tshark was killed; call again if the answer is still needed",
    "capture_changed": "the capture file was replaced while it was read; call again once the file stops changing",
    "internal_error": "retry once with narrower arguments; if it fails again report the tool name and arguments as a bug",
}


def _narrowing(args: dict[str, Any]) -> list[str]:
    return [name for name in NARROWING_ARGS if name in args]


def _narrow_fix(what: str, args: dict[str, Any]) -> str:
    names = _narrowing(args)
    how = f"pass {', '.join(names)}" if names else "use a tool that takes a selector (imsi, teid, call_id) or a filter"
    return (f"{what}: narrow the call ({how}), lower limit, or ask a human to slice the capture; "
            "raising the server caps is the operator's decision, not a retry")


def candidate_captures(allowlist: Allowlist, path: Any, suffixes: frozenset[str] | set[str]) -> list[str]:
    """Up to :data:`MAX_CANDIDATES` capture files in the closest existing directory above
    ``path`` that lies inside the allowlist; empty when there is none."""
    if not isinstance(path, str) or not path or "\x00" in path or not allowlist.roots:
        return []
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = allowlist.roots[0] / candidate
    try:
        directory = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return []
    while not directory.is_dir():
        if directory.parent == directory:
            return []
        directory = directory.parent
    if not any(directory == root or root in directory.parents for root in allowlist.roots):
        return []
    found: list[str] = []
    try:
        for entry in sorted(directory.iterdir(), key=lambda p: p.name):
            if len(found) >= MAX_CANDIDATES:
                break
            if entry.name.startswith(".") or entry.suffix.lower() not in suffixes:
                continue
            try:
                real = entry.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if real.is_file() and any(real == root or root in real.parents for root in allowlist.roots):
                found.append(str(entry))
    except OSError:
        return found
    return found


def unknown_names(display_filter: Any, catalogue: frozenset[str]) -> list[str]:
    """Dotted names in ``display_filter`` (outside quoted strings) that tshark does not know."""
    if not isinstance(display_filter, str):
        return []
    out = []
    for token in dict.fromkeys(_TOKEN.findall(outside_quotes(display_filter))):
        if token.lower() in _KEYWORDS or token in catalogue:
            continue
        if "." in token or token.isalpha():
            out.append(token)
    return out


def close_fields(names: list[str], catalogue: frozenset[str]) -> list[str]:
    """Field names close to each of ``names``, best first, at most :data:`MAX_SUGGESTIONS`.

    Candidates come from the same protocol (the first dotted label) when tshark knows it,
    otherwise from the protocol names, so the comparison never walks the whole catalogue."""
    protocols = sorted(name for name in catalogue if "." not in name)
    picks: list[str] = []
    for name in names[:3]:
        head = name.split(".", 1)[0]
        if head not in catalogue:
            head = next(iter(difflib.get_close_matches(head, protocols, n=1, cutoff=0.6)), None)
            if head is None:
                continue
        pool = [f for f in catalogue if f == head or f.startswith(head + ".")]
        target = name if "." in name else head
        for match in difflib.get_close_matches(target, pool, n=MAX_SUGGESTIONS, cutoff=0.5):
            if match not in picks:
                picks.append(match)
    return picks[:MAX_SUGGESTIONS]


def add_fix(error: dict[str, Any], tool: str, args: dict[str, Any], *, allowlist: Allowlist | None,
            catalogue: Callable[[], frozenset[str]] | None, suffixes: frozenset[str] | set[str]) -> dict[str, Any]:
    """Add ``fix`` (and ``candidates`` or ``suggestions`` where they help) to ``error``,
    the inner dict of ``{"error": {...}}``. A producer that fails leaves the static hint."""
    kind = error.get("type", "")
    if "fix" in error:
        return error
    try:
        if kind == "path_not_allowed":
            error["fix"] = "pass an absolute path inside one of allowed_dirs; paths are resolved with symlinks followed"
        elif kind in ("not_found", "not_a_file"):
            path = args.get("path") or args.get("path_a") or args.get("path_b")
            found = candidate_captures(allowlist, path, suffixes) if allowlist else []
            if kind == "not_a_file" and tool != "find_identifier":
                lead = "this tool reads one capture file; pass a file, or use find_identifier on a directory"
            else:
                lead = "no such file"
            if found:
                error["candidates"] = found
                error["fix"] = f"{lead}; candidates lists capture files in that allowed directory"
            else:
                error["fix"] = f"{lead}; check the name, or call find_identifier on an allowed directory to list captures"
        elif kind in ("invalid_filter", "unknown_field"):
            error["fix"] = ("call check_filter(filter) to see where tshark stops, and find_fields(query) for field "
                            "names; structured selectors (imsi, teid, call_id) avoid hand-written filters")
            if catalogue is not None:
                unknown = list(error.get("unknown_fields") or []) or unknown_names(
                    error.get("display_filter") or args.get("filter") or args.get("display_filter"), catalogue())
                close = close_fields(unknown, catalogue())
                if close:
                    error["suggestions"] = close
        elif kind == "tshark_failed" and error.get("out_of_memory"):
            error["fix"] = _narrow_fix("tshark ran out of memory", args)
        elif kind == "timeout":
            error["fix"] = _narrow_fix("tshark ran out of time", args)
        elif kind == "output_too_large":
            error["fix"] = _narrow_fix("tshark printed more than the server keeps", args)
        else:
            error["fix"] = STATIC_FIXES.get(kind, "read message, change the argument it names and call again")
    except Exception:  # noqa: BLE001 - a hint must never turn an error into a crash
        error.setdefault("fix", STATIC_FIXES.get(kind, "read message, change the argument it names and call again"))
    return error

"""Per-call output shaping: column projection, summary-first results, a lower output cap
and the token estimate every result carries.

A row tool (one that takes ``limit``) also takes:

* ``columns``: the row keys to keep. Unknown names are an ``invalid_argument`` error that
  lists the valid ones; frame keys (``frame``, ``*_frame``, ``frames``) are always kept so
  every row can still be opened with ``packet_detail``.
* ``output``: ``"rows"`` (default) or ``"summary"``: everything but the row list, plus the
  first :data:`SUMMARY_ROWS` rows, fitted into :data:`SUMMARY_MAX_BYTES`. The paging fields
  say where the rest starts.
* ``max_output_kb``: lowers the server's output cap for this call; it can never raise it.

Every successful result carries ``tokens_estimate``: its JSON size divided by
:data:`BYTES_PER_TOKEN`, so the agent and the audit log see what a call cost.
"""

from __future__ import annotations

import math
import re
import typing
from dataclasses import dataclass
from typing import Any

OUTPUTS = ("rows", "summary")
SUMMARY_ROWS = 3
SUMMARY_MAX_BYTES = 8192
BYTES_PER_TOKEN = 3.6
MIN_OUTPUT_KB = 1.0
MAX_COLUMNS = 64
TOKENS_KEY = "tokens_estimate"
_COLUMN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,127}$")  # row keys, or tshark field names for filter_packets
_TOKENS_ROOM = 32  # bytes kept free under the cap for the tokens_estimate key itself


@dataclass(frozen=True)
class OutputOptions:
    columns: tuple[str, ...] | None = None
    output: str = "rows"
    max_output_bytes: int | None = None


def is_frame_key(key: str) -> bool:
    return key == "frame" or key == "frames" or key.endswith("_frame") or key.endswith("_frames")


def _is_typed_dict(value: Any) -> bool:
    return isinstance(value, type) and hasattr(value, "__annotations__") and hasattr(value, "__total__")


def row_keys(result_type: Any) -> frozenset[str] | None:
    """Keys of the row TypedDicts of a result TypedDict (every top-level list of TypedDicts
    except ``trimmed``); None when the rows are untyped (filter_packets)."""
    if not _is_typed_dict(result_type):
        return None
    try:
        hints = typing.get_type_hints(result_type)
    except Exception:  # noqa: BLE001 - an unresolvable annotation just means no static check
        return None
    keys: set[str] = set()
    for name, hint in hints.items():
        if name == "trimmed" or typing.get_origin(hint) is not list:
            continue
        args = typing.get_args(hint)
        if args and _is_typed_dict(args[0]):
            try:
                keys.update(typing.get_type_hints(args[0]))
            except Exception:  # noqa: BLE001
                return None
    return frozenset(keys) or None


def parse(columns: Any, output: Any, max_output_kb: Any, known: frozenset[str] | None) -> OutputOptions:
    """Validate the three arguments; raises ValueError with a message naming the bad one."""
    from .limits import echo  # local: limits imports nothing from here, but keep the module light

    cols: tuple[str, ...] | None = None
    if columns is not None:
        if isinstance(columns, str):
            columns = [c for c in columns.replace(",", " ").split() if c]
        if not isinstance(columns, (list, tuple)) or not columns or len(columns) > MAX_COLUMNS:
            raise ValueError(f"columns must be a list of 1 to {MAX_COLUMNS} row keys")
        if not all(isinstance(c, str) and _COLUMN.match(c) for c in columns):
            raise ValueError(f"columns must be row key names such as frame or result, got {echo(list(columns))}")
        if known is not None:
            unknown = [c for c in columns if c not in known]
            if unknown:
                raise ValueError(f"unknown column(s) {echo(unknown)}; valid columns: {', '.join(sorted(known))}")
        cols = tuple(dict.fromkeys(columns))
    if output is None:
        output = "rows"
    if output not in OUTPUTS:
        raise ValueError(f"output must be one of {', '.join(OUTPUTS)}, got {echo(output)}")
    cap: int | None = None
    if max_output_kb is not None:
        try:
            kb = float(max_output_kb)
        except (TypeError, ValueError):
            raise ValueError(f"max_output_kb must be a number of kilobytes, got {echo(max_output_kb)}") from None
        if not math.isfinite(kb) or kb < MIN_OUTPUT_KB or isinstance(max_output_kb, bool):
            raise ValueError(f"max_output_kb must be at least {MIN_OUTPUT_KB:g}, got {echo(max_output_kb)}")
        cap = int(kb * 1024)
    return OutputOptions(cols, output, cap)


def project(rows: list[Any], columns: tuple[str, ...]) -> tuple[list[Any], list[str]]:
    """``rows`` with only ``columns`` and the frame keys, in the row's own key order; also the
    columns no row had (untyped rows are checked here instead of before the run)."""
    wanted = set(columns)
    seen: set[str] = set()
    out = []
    for row in rows:
        if not isinstance(row, dict):
            out.append(row)
            continue
        seen.update(row)
        out.append({k: v for k, v in row.items() if k in wanted or is_frame_key(k)})
    missing = [c for c in columns if c not in seen] if rows else []
    return out, missing


def summarise(out: dict[str, Any], rows_key: str, note: Any) -> None:
    """Keep the first :data:`SUMMARY_ROWS` rows and rewrite the paging fields to match."""
    rows = out.get(rows_key)
    if not isinstance(rows, list):
        return
    out["output"] = "summary"
    if len(rows) <= SUMMARY_ROWS:
        return
    start = int(out.get("offset") or 0)
    out[rows_key] = rows[:SUMMARY_ROWS]
    out["count"] = out["returned"] = SUMMARY_ROWS
    out["next_offset"] = start + SUMMARY_ROWS
    total = out.get("total_matched")
    if isinstance(total, int):
        out["dropped"] = max(0, total - start - SUMMARY_ROWS)
    note(out, f"output=summary shows the first {SUMMARY_ROWS} of {len(rows)} rows of this page; call again with "
              f"output='rows' and offset={start + SUMMARY_ROWS} (same arguments) for the rest")


def cap_bytes(server_cap: int, options: OutputOptions) -> int:
    """The output cap for this call: the server's, lowered by max_output_kb and by output=summary."""
    cap = server_cap
    if options.max_output_bytes is not None:
        cap = min(cap, options.max_output_bytes)
    if options.output == "summary":
        cap = min(cap, SUMMARY_MAX_BYTES)
    return max(cap - _TOKENS_ROOM, 256)


def tokens_estimate(size_bytes: int) -> int:
    return math.ceil(size_bytes / BYTES_PER_TOKEN)

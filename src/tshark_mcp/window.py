"""Time windows: the ``start`` and ``end`` arguments every capture tool takes.

A bound is ISO 8601 text (``2026-11-04T14:03:00Z``; no zone means UTC), epoch seconds
(a number or a numeric string), or a time relative to the capture: ``"+120s"`` from its
first packet, ``"-30s"`` before its last packet (units ms, s, m, h; none means seconds).
The tool decorator parses the arguments once per call and binds them here; the runner
asks :func:`clause` for each capture it reads and puts
``frame.time_epoch >= A && frame.time_epoch <= B`` ahead of the tool's own filter.
Relative bounds are resolved per capture from capinfos (first and last packet time),
cached by file identity, so a directory scan resolves ``"-60s"`` against each file.
"""

from __future__ import annotations

import os
import re
import threading
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .limits import ToolError, echo

_RELATIVE = re.compile(r"^([+-])\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?$")
_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, None: 1.0}
# Epoch seconds between 1980 and 2200: anything else as a bare number is a mistake
# (a relative offset without its sign, milliseconds instead of seconds).
EPOCH_MIN, EPOCH_MAX = 315_532_800.0, 7_258_118_400.0


@dataclass(frozen=True)
class Bound:
    kind: str  # "abs", "from_start" or "from_end"
    seconds: float
    text: str


@dataclass(frozen=True)
class Spec:
    start: Bound | None
    end: Bound | None

    @property
    def relative(self) -> bool:
        return any(b is not None and b.kind != "abs" for b in (self.start, self.end))


@dataclass(frozen=True)
class Span:
    first: float | None
    last: float | None


_SPEC: ContextVar[Spec | None] = ContextVar("tshark_mcp_window", default=None)
_SEEN: ContextVar[list[dict[str, Any]] | None] = ContextVar("tshark_mcp_window_seen", default=None)
_CACHE: dict[tuple[str, int, int, int, int], Span] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 512


def parse_bound(value: Any, name: str) -> Bound | None:
    """One ``start`` or ``end`` argument; raises ``invalid_argument`` with the accepted forms."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool):
        raise _bad(name, value)
    if isinstance(value, (int, float)):
        return _epoch(float(value), name, value)
    text = str(value).strip()
    m = _RELATIVE.match(text)
    if m:
        seconds = float(m.group(2)) * _UNITS[m.group(3)]
        return Bound("from_start" if m.group(1) == "+" else "from_end", seconds, text)
    try:
        return _epoch(float(text), name, value)
    except ValueError:
        pass
    iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError:
        raise _bad(name, value) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return Bound("abs", parsed.timestamp(), text)


def _epoch(seconds: float, name: str, raw: Any) -> Bound:
    if not (EPOCH_MIN <= seconds <= EPOCH_MAX):
        raise ToolError("invalid_argument", f"{name}={echo(raw)} is not a plausible epoch time in seconds; for a time "
                        f"relative to the capture write \"+{echo(raw, quote=False)}s\" (from its start) or \"-{echo(raw, quote=False)}s\" (before its end)")
    return Bound("abs", seconds, str(raw))


def _bad(name: str, value: Any) -> ToolError:
    return ToolError("invalid_argument", f"{name}={echo(value)} is not a time: use ISO 8601 (2026-11-04T14:03:00Z, no "
                     f"zone means UTC), epoch seconds, \"+120s\" from the capture start or \"-30s\" before its end")


def parse(start: Any, end: Any) -> Spec | None:
    """The window of a call, or None when neither bound is given."""
    lo, hi = parse_bound(start, "start"), parse_bound(end, "end")
    if lo is None and hi is None:
        return None
    if lo is not None and hi is not None and lo.kind == hi.kind == "abs" and lo.seconds > hi.seconds:
        raise ToolError("invalid_argument", f"start ({echo(lo.text, quote=False)}) is after end ({echo(hi.text, quote=False)})")
    return Spec(lo, hi)


def bind(spec: Spec | None) -> tuple[Token, Token]:
    return _SPEC.set(spec), _SEEN.set([] if spec is not None else None)


def unbind(tokens: tuple[Token, Token]) -> None:
    _SPEC.reset(tokens[0])
    _SEEN.reset(tokens[1])


def active() -> Spec | None:
    return _SPEC.get()


def span(capture: Path, capinfos: Callable[[Path], Any]) -> Span:
    """First and last packet time of ``capture`` (capinfos), cached by file identity."""
    try:
        info = os.stat(capture)
        key = (str(capture), info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)
    except OSError:
        key = None
    if key is not None:
        with _CACHE_LOCK:
            hit = _CACHE.get(key)
        if hit is not None:
            return hit
    result = capinfos(capture)
    found = parse_capinfos_times(result.stdout) if result is not None else {}
    out = Span(found.get("first"), found.get("last"))
    if key is not None and result is not None and (out.first is not None or result.returncode == 0):
        with _CACHE_LOCK:
            if len(_CACHE) >= _CACHE_MAX:
                _CACHE.clear()
            _CACHE[key] = out
    return out


def parse_capinfos_times(stdout: str) -> dict[str, float]:
    labels = {"Earliest packet time": "first", "First packet time": "first",
              "Latest packet time": "last", "Last packet time": "last"}
    out: dict[str, float] = {}
    for line in stdout.splitlines():
        key, _, value = line.partition(":")
        target = labels.get(key.strip())
        if target is None:
            continue
        try:
            out[target] = float(value.strip())
        except ValueError:
            continue
    return out


def resolve(spec: Spec, capture: Path, capinfos: Callable[[Path], Any]) -> tuple[float | None, float | None, Span]:
    """(start epoch, end epoch, capture span) of ``spec`` on ``capture``."""
    cap = span(capture, capinfos)

    def one(bound: Bound | None) -> float | None:
        if bound is None:
            return None
        if bound.kind == "abs":
            return bound.seconds
        anchor = cap.first if bound.kind == "from_start" else cap.last
        if anchor is None:
            raise ToolError("invalid_argument", f"{bound.text!r} is relative to the capture, but the first and last "
                            f"packet times of {capture.name} are unknown (capinfos missing or the file is empty); "
                            "pass ISO 8601 or epoch seconds")
        return anchor + bound.seconds if bound.kind == "from_start" else anchor - bound.seconds
    lo, hi = one(spec.start), one(spec.end)
    if lo is not None and hi is not None and lo > hi:
        raise ToolError("invalid_argument", f"the window is empty on {capture.name}: start ({spec.start.text}) "  # type: ignore[union-attr]
                        f"resolves after end ({spec.end.text})")  # type: ignore[union-attr]
    return lo, hi, cap


def _num(seconds: float) -> str:
    return f"{seconds:.9f}".rstrip("0").rstrip(".")


def filter_text(lo: float | None, hi: float | None) -> str:
    parts = []
    if lo is not None:
        parts.append(f"frame.time_epoch >= {_num(lo)}")
    if hi is not None:
        parts.append(f"frame.time_epoch <= {_num(hi)}")
    return " && ".join(parts)


def clause(capture: Path, capinfos: Callable[[Path], Any]) -> str | None:
    """The display-filter clause of the active window on ``capture``, or None; records
    what it resolved to for :func:`report`."""
    spec = _SPEC.get()
    if spec is None:
        return None
    lo, hi, cap = resolve(spec, capture, capinfos)
    text = filter_text(lo, hi)
    seen = _SEEN.get()
    if seen is not None and not any(r["capture"] == str(capture) for r in seen):
        seen.append({"capture": str(capture), "start_epoch": lo, "end_epoch": hi, "filter": text,
                     "capture_first": cap.first, "capture_last": cap.last})
    return text


def combine(window_clause: str | None, display_filter: str | None) -> str | None:
    """The window ahead of a display filter."""
    if not window_clause:
        return display_filter
    return f"({window_clause}) && ({display_filter})" if display_filter else window_clause


def overlap(lo: float | None, hi: float | None, first: float | None, last: float | None) -> bool | None:
    """Whether [lo, hi] and the capture [first, last] share a moment (None when unknown)."""
    if first is None or last is None:
        return None
    return (lo is None or lo <= last) and (hi is None or hi >= first)


def report(iso: Callable[[float | None], str | None]) -> tuple[dict[str, Any] | None, list[str]]:
    """The ``window`` block of a result and warnings for windows that miss a capture."""
    spec = _SPEC.get()
    if spec is None:
        return None, []
    seen = _SEEN.get() or []
    out: dict[str, Any] = {"start_arg": spec.start.text if spec.start else None,
                           "end_arg": spec.end.text if spec.end else None}
    warnings = []
    rows = []
    for rec in seen:
        hit = overlap(rec["start_epoch"], rec["end_epoch"], rec["capture_first"], rec["capture_last"])
        row = {"capture": rec["capture"], "start": iso(rec["start_epoch"]), "end": iso(rec["end_epoch"]),
               "start_epoch": rec["start_epoch"], "end_epoch": rec["end_epoch"], "filter": rec["filter"],
               "capture_first": iso(rec["capture_first"]), "capture_last": iso(rec["capture_last"]),
               "overlaps_capture": hit}
        rows.append({k: v for k, v in row.items() if v is not None})
        if hit is False:
            warnings.append(f"the time window lies outside {Path(rec['capture']).name} (packets "
                            f"{iso(rec['capture_first'])} to {iso(rec['capture_last'])}): nothing in it was read")
    if rows:
        first = rows[0]
        out.update({k: v for k, v in first.items() if k != "capture"})
        if len(rows) > 1:
            out["captures"] = rows
    return {k: v for k, v in out.items() if v is not None}, warnings

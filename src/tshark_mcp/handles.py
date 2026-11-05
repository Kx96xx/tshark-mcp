"""Capture handles: ``open_capture`` pins one capture (and optionally a filter and a time window)
under an opaque id that every capture tool takes in place of ``path``.

A handle is ``cap:`` plus 16 hex characters, an HMAC of the file's identity, the filter and the
window under a key drawn at start, so it cannot be guessed and a handle from another server run
is unknown here. It pins the file: real path, device, inode, size and mtime. A tool call on a
file that changed since ``open_capture`` fails with ``stale_handle``. The filter is ANDed into
every run of a call on the handle (with the time window, see :mod:`window`). The window is
used when the call gives no ``start``/``end`` of its own. Handles live in memory only, at most
:data:`MAX_HANDLES` (the oldest is dropped), and are dropped when the server stops.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from .limits import ToolError, echo

PREFIX = "cap:"
MAX_HANDLES = 64
_PATTERN = re.compile(r"^cap:[0-9a-f]{16}$")
_KEY = secrets.token_bytes(32)
_LOCK = threading.Lock()
_HANDLES: "OrderedDict[str, Handle]" = OrderedDict()


@dataclass(frozen=True)
class Handle:
    handle: str
    path: Path
    identity: tuple[int, int, int, int]  # device, inode, size, mtime_ns
    filter: str | None
    start: str | None
    end: str | None


def identity(path: Path) -> tuple[int, int, int, int]:
    info = os.stat(path)
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def looks_like(value: object) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def open_handle(path: Path, display_filter: str | None, start: str | None, end: str | None) -> Handle:
    ident = identity(path)
    material = repr((str(path), ident, display_filter, start, end)).encode()
    name = PREFIX + hmac.new(_KEY, material, hashlib.sha256).hexdigest()[:16]
    h = Handle(name, path, ident, display_filter, start, end)
    with _LOCK:
        _HANDLES.pop(name, None)
        _HANDLES[name] = h
        while len(_HANDLES) > MAX_HANDLES:
            _HANDLES.popitem(last=False)
    return h


def lookup(value: str) -> Handle:
    """The handle named ``value``; ``unknown_handle`` or ``stale_handle`` when it cannot be used."""
    text = str(value).strip()
    with _LOCK:
        h = _HANDLES.get(text) if _PATTERN.match(text) else None
        if h is not None:
            _HANDLES.move_to_end(text)
    if h is None:
        raise ToolError("unknown_handle", f"{echo(text)} is not a capture handle of this server run (handles last "
                                          "until the server stops; the oldest go after " f"{MAX_HANDLES})")
    try:
        now = identity(h.path)
    except OSError:
        now = None
    if now != h.identity:
        raise ToolError("stale_handle", f"the capture behind {h.handle} ({h.path.name}) changed or is gone since "
                                        "open_capture; nothing was read")
    return h


def clear() -> None:
    with _LOCK:
        _HANDLES.clear()

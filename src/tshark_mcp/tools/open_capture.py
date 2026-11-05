"""open_capture: a handle that pins a capture, a filter and a time window (logic in :mod:`tshark_mcp.handles`)."""

from __future__ import annotations

import os
from typing import Any


from .. import handles, models, window
from ..fields import iso
from ..limits import ToolError
from ..server import READ_ONLY, _filter, _guarded, _parse_capinfos, _resolve, _tool, state

TOOLSET = "default"  # which --toolsets lists this tool (see tshark_mcp/toolsets.py, once present)


class OpenCaptureResult(models.ToolResult, total=False):
    """``handle`` (pass it as ``path``, ``path_a`` or ``path_b`` to any capture tool), the file it pins
    (``path``, ``size_bytes``, ``mtime``, ``packets``, ``first_packet``, ``last_packet``) and what every later
    call on it reads (``filter``, ``start``, ``end``)."""
    handle: str
    path: str
    size_bytes: int
    mtime: str
    packets: int
    first_packet: str
    last_packet: str
    filter: str
    start: str
    end: str
    usage: str
    cache: dict[str, Any]


@_tool(title="Open a capture: a handle for the next calls", annotations=READ_ONLY)
def open_capture(path: str, filter: str | None = None) -> OpenCaptureResult:
    """Pin one capture for an investigation of several calls: returns a `handle` ("cap:..."),
    accepted by every capture tool in place of `path` (also `path_a`/`path_b`). A `filter` and a
    `start`/`end` window given here apply to every later call on the handle (a call's own
    `start`/`end` replaces the window; its own `filter` is ANDed). Later calls on the same file
    reuse tshark's output from a memory cache when they repeat a run (`cache` in a result counts
    the reused runs). A handle stops working when the file changes (`stale_handle`) or the server
    restarts (`unknown_handle`): call open_capture again.
    Details: The handle is an HMAC of the file identity (real path, device, inode, size, mtime),
    the filter and the window under a per-run key: unguessable, and refused by any other server
    run. At most 64 handles are kept (the oldest is dropped). Nothing is written to disk."""
    def run() -> dict[str, Any]:
        if handles.looks_like(path):
            raise ToolError("invalid_argument", "path is already a handle; pass the capture file to open_capture")
        capture = _resolve(path)
        st = state()
        flt = _filter(filter) if filter is not None and str(filter).strip() else None
        spec = window.active()
        start = spec.start.text if spec is not None and spec.start is not None else None
        end = spec.end.text if spec is not None and spec.end is not None else None
        h = handles.open_handle(capture, flt, start, end)
        info = os.stat(capture)
        out: dict[str, Any] = {"handle": h.handle, "path": str(capture), "size_bytes": info.st_size,
                               "mtime": iso(info.st_mtime)}
        summary = st.runner.capinfos_summary(capture)
        if summary is not None and summary.returncode == 0:
            parsed = _parse_capinfos(summary.stdout)
            out.update({k: parsed[k] for k in ("packets", "first_packet", "last_packet") if parsed.get(k) is not None})
        out.update({k: v for k, v in (("filter", flt), ("start", start), ("end", end)) if v is not None})
        out["usage"] = (f"pass path=\"{h.handle}\" to any capture tool" + (": every call reads only "
                        + " and ".join(x for x in (f"filter {flt}" if flt else "", "the window" if start or end else "")
                                       if x) if flt or start or end else ""))
        return out
    return _guarded("open_capture", {"path": path, "filter": filter}, run)

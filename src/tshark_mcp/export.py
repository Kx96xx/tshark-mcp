"""export_subset: the one tool that writes, and only when the operator turns it on.

The server is read-only unless it was started with ``--export-dir DIR``. Then
``export_subset`` may write a filtered subset of an allowed capture as a NEW pcapng file in
that one directory. The checks here:

- the export directory exists, is a real directory (not a symlink) and is neither inside an
  ``--allow-dir`` nor contains one, unless the operator passes ``--export-inside-allow-dir``
  (otherwise an agent could grow the corpus it reads);
- the file name is reduced to ``[A-Za-z0-9._-]``, may not start with a dot, gets ``.pcapng``;
- tshark writes to a fresh temporary file the server created with O_EXCL in that directory,
  which is then hard-linked to the final name: an existing file is never replaced, and a
  symlink planted under the final name is refused rather than followed;
- the result may not exceed ``--export-max-mb``; the packet count is capped too.

``-w`` and ``-F`` stay forbidden for every other run: the runner builds this one argv itself
(:meth:`Runner.write_subset`) and checks its exact shape before starting tshark.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .limits import ToolError, _is_within

DEFAULT_MAX_MB = 50.0
MAX_PACKETS = 100_000
NAME_MAX = 100
TMP_PREFIX = ".tshark-mcp-export-"
# Bytes a pcapng file spends besides the packet bytes: section and interface blocks, then
# 32 bytes of Enhanced Packet Block header plus padding per packet.
FILE_OVERHEAD = 1024
PER_PACKET_OVERHEAD = 36
HEADER_SNAPLEN = 96
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass(frozen=True)
class ExportConfig:
    directory: Path
    max_bytes: int

    def describe(self) -> str:
        return f"{self.directory} (max {round(self.max_bytes / 1024 / 1024, 1)} MB)"


def configure(directory: str | None, max_mb: float | None, allow_roots: tuple[Path, ...],
              inside_allow_dir: bool = False) -> ExportConfig | None:
    """The export configuration, or None (the default: export_subset refuses every call)."""
    if not directory:
        return None
    raw = Path(directory).expanduser()
    if raw.is_symlink():
        raise ValueError(f"--export-dir must not be a symlink: {directory}")
    resolved = raw.resolve()
    if not resolved.is_dir():
        raise ValueError(f"--export-dir does not exist or is not a directory: {directory}")
    if not inside_allow_dir:
        for root in allow_roots:
            if _is_within(resolved, root) or _is_within(root, resolved):
                raise ValueError(f"--export-dir {resolved} overlaps the allowed directory {root}: exported files "
                                 "would become readable captures; use a separate directory or pass "
                                 "--export-inside-allow-dir")
    mb = DEFAULT_MAX_MB if max_mb is None else float(max_mb)
    if not 0 < mb <= 4096:
        raise ValueError("--export-max-mb must be above 0 and at most 4096")
    return ExportConfig(resolved, int(mb * 1024 * 1024))


def safe_name(name: object) -> str:
    """A file name of ``[A-Za-z0-9._-]`` ending in ``.pcapng``; anything else is refused."""
    text = str(name or "").strip()
    if not text:
        raise ToolError("invalid_argument", "name must be a file name such as case-1234-sip.pcapng")
    if "/" in text or "\\" in text or ".." in text or "\x00" in text:
        raise ToolError("invalid_argument", "name must be a bare file name: no directories, no '..'")
    cleaned = _UNSAFE.sub("_", text)
    if cleaned.startswith("."):
        raise ToolError("invalid_argument", "name must not start with a dot")
    if not cleaned.lower().endswith(".pcapng"):
        cleaned += ".pcapng"
    if len(cleaned) > NAME_MAX:
        raise ToolError("invalid_argument", f"name must be at most {NAME_MAX} characters")
    return cleaned


def target(cfg: ExportConfig, name: str) -> Path:
    out = cfg.directory / name
    if os.path.lexists(out):
        raise ToolError("file_exists", f"{name} already exists in the export directory; export_subset never "
                        "overwrites: choose another name", fix="pass a new name; existing exports are never replaced")
    return out


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def budget(cap_lens: list[int], max_bytes: int) -> int:
    """How many of the packets (in order) fit in ``max_bytes`` once written."""
    total = FILE_OVERHEAD
    for i, n in enumerate(cap_lens):
        total += n + PER_PACKET_OVERHEAD
        if total > max_bytes:
            return i
    return len(cap_lens)


def publish(tmp: Path, final: Path) -> None:
    """Give ``tmp`` its final name without ever replacing a file (link fails if the name exists)."""
    try:
        os.link(tmp, final)
    except FileExistsError:
        raise ToolError("file_exists", f"{final.name} appeared in the export directory while writing; nothing was "
                        "replaced") from None
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass

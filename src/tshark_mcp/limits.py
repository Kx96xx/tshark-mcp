"""Safety limits and input validation.

Everything that bounds what the server will do lives here: the path allowlist,
the hard caps on file size, packets, output bytes and run time, and the display
filter lint. The caps can be raised or lowered through the CLI or environment
but they can never be switched off.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping


class ToolError(Exception):
    """A structured, model-readable failure.

    Tools never raise to the MCP client; the server converts a ToolError into
    ``{"error": {"type": ..., "message": ..., ...}}`` so the agent can recover.
    """

    def __init__(self, type_: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.type = type_
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type, "message": self.message}
        out.update(self.details)
        return {"error": out}


@dataclass(frozen=True)
class Limits:
    """Hard caps applied to every call. All values must be positive."""

    max_file_bytes: int = 500 * 1024 * 1024
    """Captures larger than this are refused before tshark is started."""

    max_packets: int = 500
    """Matching packets a per-packet tool dissects in full per call (Diameter, GTPv2-C, SIGTRAN rows)."""

    max_scan_packets: int = 200_000
    """Frames read from a capture per tshark run (``-c``), and the matching packets an
    aggregating tool (GTP-U, SCTP, SIP, find_identifier) keeps. A long capture is reported
    as truncated when it has more frames than this."""

    max_output_bytes: int = 30 * 1024
    """Upper bound on the JSON returned to the model (about 8k tokens); rows past it are
    left for the next page (``next_offset``) and inner lists are trimmed to fit."""

    max_stdout_bytes: int = 64 * 1024 * 1024
    """Upper bound on raw tshark stdout kept in memory; tshark is killed beyond it."""

    timeout_seconds: float = 60.0
    """Wall-clock limit per tshark invocation; tshark is killed when exceeded."""

    max_files: int = 50
    """Upper bound on capture files one multi-file call (find_identifier) will open."""

    max_concurrent_runs: int = 2
    """tshark (and capinfos, dftest) processes the server runs at once, across all calls."""

    busy_wait_seconds: float = 30.0
    """How long a run waits for a free slot before the call fails with ``busy``."""

    max_tshark_memory_bytes: int = 2 * 1024 * 1024 * 1024
    """Address-space limit (RLIMIT_AS) of each tshark run, applied on Linux."""

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"limit {name} must be a positive number, got {value!r}")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Limits":
        """Build limits from ``TSHARK_MCP_*`` variables, falling back to defaults."""
        env = os.environ if env is None else env
        base = cls()
        overrides: dict[str, Any] = {}

        def take(var: str, attr: str, scale: float, cast: type) -> None:
            raw = env.get(var)
            if raw is None or raw == "":
                return
            try:
                overrides[attr] = cast(float(raw) * scale)
            except ValueError as exc:
                raise ValueError(f"{var} must be numeric, got {raw!r}") from exc

        take("TSHARK_MCP_MAX_FILE_MB", "max_file_bytes", 1024 * 1024, int)
        take("TSHARK_MCP_MAX_PACKETS", "max_packets", 1, int)
        take("TSHARK_MCP_MAX_SCAN_PACKETS", "max_scan_packets", 1, int)
        take("TSHARK_MCP_MAX_OUTPUT_KB", "max_output_bytes", 1024, int)
        take("TSHARK_MCP_MAX_STDOUT_MB", "max_stdout_bytes", 1024 * 1024, int)
        take("TSHARK_MCP_TIMEOUT", "timeout_seconds", 1, float)
        take("TSHARK_MCP_MAX_FILES", "max_files", 1, int)
        take("TSHARK_MCP_MAX_CONCURRENT_RUNS", "max_concurrent_runs", 1, int)
        take("TSHARK_MCP_BUSY_WAIT", "busy_wait_seconds", 1, float)
        take("TSHARK_MCP_MAX_TSHARK_MEMORY_MB", "max_tshark_memory_bytes", 1024 * 1024, int)
        return replace(base, **overrides)

    def describe(self) -> dict[str, Any]:
        return {
            "max_file_mb": round(self.max_file_bytes / (1024 * 1024), 2),
            "max_packets": self.max_packets,
            "max_scan_packets": self.max_scan_packets,
            "max_output_kb": round(self.max_output_bytes / 1024, 1),
            "timeout_seconds": self.timeout_seconds,
            "max_files": self.max_files,
            "max_concurrent_runs": self.max_concurrent_runs,
            "busy_wait_seconds": self.busy_wait_seconds,
            "max_tshark_memory_mb": round(self.max_tshark_memory_bytes / (1024 * 1024), 2),
        }


@dataclass(frozen=True)
class Allowlist:
    """Directories the server may read captures from. Empty means nothing is readable."""

    roots: tuple[Path, ...] = field(default_factory=tuple)

    @classmethod
    def from_strings(cls, items: list[str] | tuple[str, ...]) -> "Allowlist":
        roots = []
        for item in items:
            for part in str(item).split(os.pathsep):
                part = part.strip()
                if not part:
                    continue
                root = Path(part).expanduser().resolve()
                if not root.is_dir():
                    raise ValueError(f"allowed directory does not exist or is not a directory: {part}")
                roots.append(root)
        return cls(tuple(roots))

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Allowlist":
        env = os.environ if env is None else env
        raw = env.get("TSHARK_MCP_ALLOW_DIRS", "")
        return cls.from_strings([raw]) if raw else cls()

    def resolve_inside(self, path: str) -> Path:
        """Resolve ``path`` (following symlinks) and check it lies inside an allowed root."""
        if not self.roots:
            raise ToolError("no_allowed_dirs", "the server was started without any --allow-dir; nothing is readable")
        if not isinstance(path, str) or not path:
            raise ToolError("invalid_path", "path must be a non-empty string")
        if "\x00" in path:
            raise ToolError("invalid_path", "path contains a NUL byte")
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            # Relative paths are resolved against the first allowed root, never the CWD.
            candidate = self.roots[0] / candidate
        try:
            # Non-strict so a path outside the roots is refused as "not allowed" whether or
            # not it exists: the server never reveals what lies outside the allowlist.
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise ToolError("invalid_path", f"cannot resolve {path}: {exc}") from None
        if not any(_is_within(resolved, root) for root in self.roots):
            raise ToolError(
                "path_not_allowed",
                f"{path} resolves to {resolved}, which is outside the allowed directories",
                allowed_dirs=[str(r) for r in self.roots],
            )
        try:
            present = resolved.exists()
        except OSError as exc:  # a name too long for the filesystem, a loop of symlinks, ...
            raise ToolError("invalid_path", f"cannot access {path}: {exc.strerror or exc}") from None
        if not present:
            raise ToolError("not_found", f"no such file: {path}")
        return resolved

    def resolve_dir(self, path: str) -> Path:
        """Resolve ``path`` and check it is a directory inside one of the allowed roots."""
        resolved = self.resolve_inside(path)
        try:
            is_dir = resolved.is_dir()
        except OSError as exc:
            raise ToolError("invalid_path", f"cannot access {path}: {exc.strerror or exc}") from None
        if not is_dir:
            raise ToolError("not_a_directory", f"{path} is not a directory")
        return resolved

    def resolve(self, path: str, limits: Limits) -> Path:
        """Resolve ``path`` (following symlinks) and check it is a readable capture
        inside one of the allowed roots and under the size cap."""
        resolved = self.resolve_inside(path)
        try:
            is_file = resolved.is_file()
            size = resolved.stat().st_size if is_file else 0
        except OSError as exc:
            raise ToolError("invalid_path", f"cannot access {path}: {exc.strerror or exc}") from None
        if not is_file:
            raise ToolError("not_a_file", f"{path} is not a regular file")
        if size > limits.max_file_bytes:
            raise ToolError(
                "file_too_large",
                f"{path} is {size} bytes; the limit is {limits.max_file_bytes} bytes",
                size_bytes=size,
                max_file_bytes=limits.max_file_bytes,
            )
        return resolved

    def describe(self) -> list[str]:
        return [str(r) for r in self.roots]


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


# Display filter lint. tshark is always started with an argv list, so none of
# these characters could reach a shell; the check exists so a bad filter fails
# with a clear message instead of a confusing dissector error, and so the
# server never forwards control characters to a child process. Quoted string
# literals are exempt from the metacharacter rule because legitimate values
# contain them (a Diameter Session-Id is "host;high;low" by specification).
_FILTER_MAX_LEN = 4000
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_METACHARS_OUTSIDE_QUOTES = re.compile(r"[;`$]")
_LONE_PIPE_OR_AMP = re.compile(r"(?<!\|)\|(?!\|)|(?<!&)&(?!&)")
_QUOTED_STRING = re.compile(r'"(?:\\.|[^"\\])*"')


def _outside_quotes(text: str) -> str:
    return _QUOTED_STRING.sub('""', text)


outside_quotes = _outside_quotes
"""``text`` with every quoted string literal emptied, so tokens inside quotes are not read as fields."""


def lint_display_filter(text: str) -> str:
    """Reject obviously unsafe or malformed display filters before the dry run."""
    if not isinstance(text, str):
        raise ToolError("invalid_filter", "display filter must be a string")
    stripped = text.strip()
    if not stripped:
        raise ToolError("invalid_filter", "display filter is empty")
    if len(stripped) > _FILTER_MAX_LEN:
        raise ToolError("invalid_filter", f"display filter longer than {_FILTER_MAX_LEN} characters")
    if _CONTROL_CHARS.search(stripped):
        raise ToolError("invalid_filter", "display filter contains a control character")
    bare = _outside_quotes(stripped)
    if _METACHARS_OUTSIDE_QUOTES.search(bare):
        raise ToolError("invalid_filter", "display filter contains ';', '`' or '$' outside a quoted string")
    if _LONE_PIPE_OR_AMP.search(bare):
        raise ToolError("invalid_filter", "use '||' and '&&' (or 'or' / 'and'); single '|' or '&' is not allowed")
    return stripped


_FIELD_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")


def lint_field_name(name: str) -> str:
    if not isinstance(name, str) or not _FIELD_NAME.match(name):
        raise ToolError("invalid_field", f"not a plausible tshark field name: {name!r}")
    return name


_DIGITS = re.compile(r"^\d{5,16}$")


def lint_digits(value: str, what: str) -> str:
    """IMSI / MSISDN arguments must be plain digits so they can be embedded in filters."""
    if not isinstance(value, str):
        raise ToolError("invalid_argument", f"{what} must be a string of digits")
    cleaned = value.strip().lstrip("+").replace(" ", "")
    if not _DIGITS.match(cleaned):
        raise ToolError("invalid_argument", f"{what} must be 5 to 16 digits, got {value!r}")
    return cleaned


_QUOTED_VALUE_MAX_LEN = 512


def lint_quoted_value(value: str, what: str) -> str:
    """A model-supplied string that will be embedded as a quoted display-filter literal.

    Diameter Session-Ids and SIP Call-IDs legitimately contain ``;``, ``@`` and
    ``|``, which are fine inside quotes. Quotes, backslashes and control
    characters are refused so the value can never close the literal.
    """
    if not isinstance(value, str):
        raise ToolError("invalid_argument", f"{what} must be a string")
    text = value.strip()
    if not text:
        raise ToolError("invalid_argument", f"{what} is empty")
    if len(text) > _QUOTED_VALUE_MAX_LEN:
        raise ToolError("invalid_argument", f"{what} longer than {_QUOTED_VALUE_MAX_LEN} characters")
    if '"' in text or "\\" in text or _CONTROL_CHARS.search(text) or "\t" in text:
        raise ToolError("invalid_argument", f"{what} must not contain quotes, backslashes or control characters")
    return text


_APN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,99}$")


def lint_apn(value: str) -> str:
    """An APN network identifier: labels of letters, digits and hyphens joined by dots."""
    if not isinstance(value, str) or not _APN.match(value.strip()):
        raise ToolError("invalid_argument", f"apn must be a dotted name of letters, digits and hyphens, got {value!r}")
    return value.strip()


_HOSTNAME = re.compile(r"^(?=.{1,253}\.?$)[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,62})(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,62}))*\.?$")


def lint_hostname(value: Any, what: str = "name") -> str:
    """A DNS name or TLS server name: dot-separated labels of letters, digits, hyphens and underscores."""
    if not isinstance(value, str) or not _HOSTNAME.match(value.strip()):
        raise ToolError("invalid_argument", f"{what} must be a DNS name such as example.com, got {value!r}")
    return value.strip().rstrip(".").lower()


_SIP_METHOD = re.compile(r"^[A-Za-z]{2,16}$")


def lint_sip_method(value: str) -> str:
    if not isinstance(value, str) or not _SIP_METHOD.match(value.strip()):
        raise ToolError("invalid_argument", f"method must be a SIP method token such as INVITE or REGISTER, got {value!r}")
    return value.strip().upper()


def lint_teid(value: Any) -> int:
    """A 32-bit tunnel endpoint id given as an int, decimal string or 0x-prefixed hex string."""
    try:
        teid = int(value) if isinstance(value, int) else int(str(value).strip(), 0)
    except (TypeError, ValueError):
        raise ToolError("invalid_argument", f"teid must be a 32-bit integer (decimal or 0x hex), got {value!r}") from None
    if teid < 0 or teid > 0xFFFFFFFF:
        raise ToolError("invalid_argument", f"teid must be a 32-bit integer (decimal or 0x hex), got {value!r}")
    return teid


def clamp_limit(limit: Any, cap: int, default: int) -> int:
    """Clamp a model-supplied row limit into ``1..cap``."""
    try:
        value = int(limit) if limit is not None else default
    except (TypeError, ValueError):
        raise ToolError("invalid_argument", f"limit must be an integer, got {limit!r}") from None
    return max(1, min(value, cap))

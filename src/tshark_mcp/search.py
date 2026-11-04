"""Identifier search across one capture or a directory of captures.

``find_identifier`` answers "which of these files mention subscriber X" before
any protocol tool is opened on the right file. The module only builds display
filters and lists candidate files; the server runs tshark on each file under
the usual caps plus a per-call file-count cap and a shared time budget.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from .fields import to_int
from .limits import ToolError, echo, lint_digits, lint_quoted_value

KINDS = ("auto", "imsi", "msisdn", "ip", "call_id", "session_id")

CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")

_DIGITS = re.compile(r"^\+?[\d ]{5,16}$")


def classify(identifier: str) -> str:
    """Guess the identifier kind for ``kind="auto"``."""
    text = identifier.strip()
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if _DIGITS.match(text):
        return "subscriber"  # IMSI or MSISDN: search both
    if ";" in text:
        return "session_id"
    if "@" in text:
        return "call_id"
    raise ToolError("invalid_argument",
                    f"cannot tell what kind of identifier {echo(identifier)} is; pass kind=imsi, msisdn, ip, call_id or session_id")


def _tbcd(digits: str) -> str:
    if len(digits) % 2:
        digits += "f"
    return ":".join(digits[i + 1] + digits[i] for i in range(0, len(digits), 2))


def build_filter(identifier: str, kind: str) -> tuple[str, str]:
    """Return ``(resolved_kind, display_filter)`` for the identifier.

    Every value is linted before it is embedded, so the result is safe to pass
    through the ordinary filter lint and dry-run compile.
    """
    if kind not in KINDS:
        raise ToolError("invalid_argument", f"kind must be one of {', '.join(KINDS)}")
    resolved = classify(identifier) if kind == "auto" else kind
    if resolved == "ip":
        try:
            addr = ipaddress.ip_address(identifier.strip())
        except ValueError:
            raise ToolError("invalid_argument", f"not an IP address: {echo(identifier)}") from None
        field = "ip.addr" if addr.version == 4 else "ipv6.addr"
        return "ip", f"{field} == {addr.compressed}"
    if resolved in ("imsi", "msisdn", "subscriber"):
        digits = lint_digits(identifier, "identifier")
        parts: list[str] = []
        if resolved in ("imsi", "subscriber"):
            parts += [
                f'e212.imsi == "{digits}"',
                f'diameter.User-Name == "{digits}"',
                f'sip.From contains "{digits}"',
                f'sip.auth contains "{digits}"',
            ]
        if resolved in ("msisdn", "subscriber"):
            parts += [
                f'e164.msisdn == "{digits}"',
                f'diameter.User-Name contains "{digits}"',
                f'diameter.Public-Identity contains "{digits}"',
                f"diameter.MSISDN == {_tbcd(digits)}",
                f'gsm_sms.tp-da == "{digits}"',
                f'gsm_sms.tp-oa == "{digits}"',
                f'sip.from.user contains "{digits}"',
                f'sip.to.user contains "{digits}"',
                f'sip.r-uri.user contains "{digits}"',
                f'sip.P-Asserted-Identity contains "{digits}"',
            ]
        return resolved, " || ".join(dict.fromkeys(parts))
    if resolved == "call_id":
        value = lint_quoted_value(identifier, "identifier")
        return "call_id", f'sip.Call-ID == "{value}"'
    if resolved == "session_id":
        value = lint_quoted_value(identifier, "identifier")
        return "session_id", f'diameter.Session-Id == "{value}"'
    raise ToolError("invalid_argument", f"unsupported identifier kind {echo(resolved)}")  # pragma: no cover


def list_captures(directory: Path) -> list[Path]:
    """Regular capture files directly inside ``directory``, sorted by name.

    Symlinks are listed too; the server resolves each one through the allowlist
    before opening it, so a link escaping the allowed roots is refused per file.
    """
    out = []
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        if entry.name.startswith("."):
            continue
        if entry.suffix.lower() not in CAPTURE_SUFFIXES:
            continue
        if entry.is_file():
            out.append(entry)
    return out


def summarise_hits(stdout: str, protocol_col: bool) -> dict[str, Any]:
    """Aggregate ``-T fields`` lines (time, frame[, protocol]) into one file row."""
    hits = 0
    first = last = None
    first_frame = last_frame = None
    protocols: dict[str, int] = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        try:
            ts = float(cols[0])
        except (ValueError, IndexError):
            continue
        hits += 1
        frame = to_int(cols[1].split(",")[0]) if len(cols) > 1 else None
        if first is None or ts < first:
            first, first_frame = ts, frame
        if last is None or ts >= last:
            last, last_frame = ts, frame
        if protocol_col and len(cols) > 2 and cols[2]:
            proto = cols[2].split(",")[0]
            protocols[proto] = protocols.get(proto, 0) + 1
    return {"hits": hits, "first": first, "last": last, "first_frame": first_frame, "last_frame": last_frame,
            "protocols": protocols}

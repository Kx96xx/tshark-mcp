"""tshark's expert information: the warnings, errors and malformed-packet flags its
dissectors raise while decoding.

Two read-only passes feed one table. ``-q -z expert,<severity>[,<filter>]`` gives
tshark's own grouping with counts and the protocol that raised each item; a
``-T fields`` pass over ``_ws.expert`` gives the frames behind each item, so every row
can be opened with ``packet_detail``. Rows are matched on severity, group and summary
text, which is the same string in both outputs.
"""

from __future__ import annotations

import re
from typing import Any

from .fields import split_fields_line, to_int

SEVERITIES = ("chat", "note", "warn", "error")
"""Lowest to highest. ``severity="warn"`` returns warnings and errors."""

# epan/proto.h: PI_SEVERITY_MASK values as tshark prints _ws.expert.severity.
SEVERITY_CODES = {0x00100000: "comment", 0x00200000: "chat", 0x00400000: "note", 0x00600000: "warn", 0x00800000: "error"}
SECTION_SEVERITY = {"Errors": "error", "Warns": "warn", "Notes": "note", "Chats": "chat", "Comments": "comment"}

# epan/proto.h: PI_GROUP_MASK values, named as -z expert names them.
GROUP_CODES = {
    0x01000000: "Checksum", 0x02000000: "Sequence", 0x03000000: "Response", 0x04000000: "Request",
    0x05000000: "Undecoded", 0x06000000: "Reassemble", 0x07000000: "Malformed", 0x08000000: "Debug",
    0x09000000: "Protocol", 0x0a000000: "Security", 0x0b000000: "Comment", 0x0c000000: "Decryption",
    0x0d000000: "Assumption", 0x0e000000: "Deprecated", 0x0f000000: "Receive", 0x10000000: "Interface",
    0x11000000: "Bug",
}

FIELDS = ["frame.number", "_ws.expert.severity", "_ws.expert.group", "_ws.expert.message"]
AGGREGATOR = "\x1f"  # unit separator: expert messages contain commas and bars (\x1c-\x1e would split lines)
SAMPLE_FRAMES = 5

_SECTION = re.compile(r"^(Errors|Warns|Notes|Chats|Comments)\s+\((\d+)\)\s*$")
_ROW = re.compile(r"^\s*(\d+)\s+(\S+)\s+(.+?)\s{2,}(\S.*)$")


def stat_arg(severity: str, display_filter: str | None) -> str:
    """The ``-z`` argument: ``expert,<severity>[,<filter>]``."""
    return f"expert,{severity}" + (f",{display_filter}" if display_filter else "")


def parse_stat(stdout: str) -> list[dict[str, Any]]:
    """Rows of ``-z expert``: severity, group, protocol, summary, count.

    The table is fixed-width with right-aligned frequency, group and protocol
    columns; a protocol name may contain spaces ("GSM SMS"), so the summary is
    whatever follows the last run of two or more spaces after the group."""
    rows: list[dict[str, Any]] = []
    severity = None
    for line in stdout.splitlines():
        m = _SECTION.match(line)
        if m:
            severity = SECTION_SEVERITY[m.group(1)]
            continue
        if severity is None or not line.strip() or line.lstrip().startswith(("Frequency", "=")):
            continue
        m = _ROW.match(line)
        if not m:
            continue
        count, group, rest = int(m.group(1)), m.group(2), m.group(3) + "  " + m.group(4)
        protocol, _, summary = rest.partition("  ")
        rows.append({"severity": severity, "group": group, "protocol": protocol.strip(),
                     "summary": summary.strip(), "count": count})
    return rows


def parse_frames(stdout: str) -> dict[tuple[str, str, str], list[int]]:
    """``(severity, group, message) -> frames`` from the ``-T fields`` pass, in frame order."""
    found: dict[tuple[str, str, str], list[int]] = {}
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        frame = to_int(cols[0].split(AGGREGATOR)[0])
        sevs, groups, msgs = (c.split(AGGREGATOR) for c in cols[1:4])
        for sev, grp, msg in zip(sevs, groups, msgs):
            key = (SEVERITY_CODES.get(to_int(sev) or 0, sev), GROUP_CODES.get(to_int(grp) or 0, grp), msg)
            frames = found.setdefault(key, [])
            if frame is not None and (not frames or frames[-1] != frame):
                frames.append(frame)
    return found


def merge(rows: list[dict[str, Any]], frames: dict[tuple[str, str, str], list[int]]) -> list[dict[str, Any]]:
    """Attach the first frame, sample frames and frame count to each ``-z expert`` row,
    then order by severity (worst first) and count."""
    for row in rows:
        hit = frames.get((row["severity"], row["group"], row["summary"]))
        if hit:
            row["first_frame"] = hit[0]
            row["frames"] = hit[:SAMPLE_FRAMES]
            row["frame_count"] = len(hit)
    rank = {s: i for i, s in enumerate(("comment", *SEVERITIES))}
    rows.sort(key=lambda r: (-rank.get(r["severity"], 0), -r["count"], r["protocol"], r["summary"]))
    return rows


def summarise(rows: list[dict[str, Any]], frames: dict[tuple[str, str, str], list[int]]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_protocol: dict[str, int] = {}
    for r in rows:
        by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + r["count"]
        by_protocol[r["protocol"]] = by_protocol.get(r["protocol"], 0) + r["count"]
    # Malformed at warn or error: a dissector exception or a field past the end of the
    # packet. Malformed notes (an odd padding) do not make a frame malformed.
    malformed = sorted({f for (sev, group, _), fs in frames.items()
                        if group == "Malformed" and sev in ("warn", "error") for f in fs})
    out: dict[str, Any] = {"by_severity": by_severity, "by_protocol": by_protocol, "malformed_frames": len(malformed)}
    if malformed:
        out["malformed_first_frames"] = malformed[:SAMPLE_FRAMES]
    return out

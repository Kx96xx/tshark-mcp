"""Field catalogue and helpers for walking tshark JSON output.

tshark's ``-T json`` output nests protocol fields inside dissection subtrees
whose key names vary by protocol. The helpers here search by exact field name
at any depth, so the protocol modules can say "give me ``diameter.Session-Id``
inside this message" without caring where the dissector put it.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from .limits import ToolError
from .runner import Runner, check_result

Json = dict[str, Any]


# ----------------------------------------------------------------- field catalogue
_GLOSSARY_CACHE: dict[str, str] = {}
_CATALOGUE_CACHE: dict[str, frozenset[str]] = {}


def glossary(runner: Runner) -> str:
    """The raw ``tshark -G fields`` text (about 20 MB), read once per binary.

    Kept as one string rather than parsed rows: a search scans it with a regular
    expression and parses only the lines that match."""
    cached = _GLOSSARY_CACHE.get(runner.tshark)
    if cached is None:
        cached = _GLOSSARY_CACHE[runner.tshark] = check_result(runner.list_fields()).stdout
    return cached


def field_catalogue(runner: Runner) -> frozenset[str]:
    """All field abbreviations tshark knows (``tshark -G fields``), cached per binary."""
    cached = _CATALOGUE_CACHE.get(runner.tshark)
    if cached is not None:
        return cached
    names: set[str] = set()
    for line in glossary(runner).splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] in ("F", "P"):
            names.add(parts[2])
    catalogue = frozenset(names)
    _CATALOGUE_CACHE[runner.tshark] = catalogue
    return catalogue


def glossary_row(line: str) -> dict[str, str] | None:
    """One ``-G fields`` line as {field, name, type, protocol, display, description}.
    Field lines are: F, name, abbreviation, type, parent protocol, display base, bitmask,
    description."""
    parts = line.split("\t")
    if parts[0] == "F" and len(parts) >= 5:
        return compact({"field": parts[2], "name": parts[1], "type": parts[3], "protocol": parts[4],
                        "display": parts[5] if len(parts) > 5 else "",
                        "description": parts[7] if len(parts) > 7 else ""})
    if parts[0] == "P" and len(parts) >= 3:
        return {"field": parts[2], "name": parts[1], "type": "protocol", "protocol": parts[2]}
    return None


def _matching_lines(text: str, word: str) -> Iterator[str]:
    """Each glossary line that contains ``word`` (case-insensitive), once."""
    last = -1
    for m in re.finditer(re.escape(word), text, re.IGNORECASE):
        start = text.rfind("\n", 0, m.start()) + 1
        if start == last:
            continue
        last = start
        end = text.find("\n", m.end())
        yield text[start:end if end != -1 else len(text)]


def search_fields(runner: Runner, words: list[str], protocol: str | None = None) -> list[dict[str, str]]:
    """Fields and protocols whose name, abbreviation or description contain every word,
    best match first: the abbreviation itself, then abbreviations starting with or
    containing the query, then names, then descriptions."""
    text = glossary(runner)
    query = " ".join(words).lower()
    proto = protocol.lower() if protocol else None
    scored: list[tuple[int, str, dict[str, str]]] = []
    for line in _matching_lines(text, max(words, key=len)):
        row = glossary_row(line)
        if row is None:
            continue
        if proto and row.get("protocol", "").lower() != proto:
            continue
        abbrev = row["field"].lower()
        name = row.get("name", "").lower()
        haystack = f'{abbrev} {name} {row.get("description", "").lower()}'
        if not all(w.lower() in haystack for w in words):
            continue
        if abbrev == query:
            score = 0
        elif abbrev.startswith(query) or abbrev.endswith("." + query):
            score = 1
        elif all(w.lower() in abbrev for w in words):
            score = 2
        elif all(w.lower() in name for w in words):
            score = 3
        else:
            score = 4
        scored.append((score, abbrev, row))
    scored.sort(key=lambda s: (s[0], len(s[1]), s[1]))
    return [row for _, _, row in scored]


def lookup_field(runner: Runner, name: str) -> dict[str, str] | None:
    """The glossary row of one exact field or protocol abbreviation."""
    m = re.search(r"^[FP]\t[^\t]*\t" + re.escape(name) + r"(\t[^\n]*)?$", glossary(runner), re.MULTILINE)
    return glossary_row(m.group(0)) if m else None


def validate_fields(runner: Runner, names: Iterable[str]) -> list[str]:
    catalogue = field_catalogue(runner)
    unknown = [n for n in names if n not in catalogue]
    if unknown:
        raise ToolError("unknown_field", f"unknown tshark field(s): {', '.join(unknown)}", unknown_fields=unknown)
    return list(names)


# ----------------------------------------------------------------- JSON walking
def parse_packets(stdout: str) -> list[Json]:
    text = stdout.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ToolError("parse_error", f"could not parse tshark JSON output: {exc}") from None
    return [p for p in data if isinstance(p, dict)]


def layers(packet: Json) -> Json:
    return packet.get("_source", {}).get("layers", {})


def protocol_messages(packet: Json, layer: str) -> list[Json]:
    """Return every ``layer`` object in the packet (a list when several PDUs are bundled)."""
    value = layers(packet).get(layer)
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def iter_values(obj: Any, key: str) -> Iterator[str]:
    """Yield every scalar value stored under ``key`` at any depth, in document order."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                if isinstance(v, list):
                    for item in v:
                        if not isinstance(item, (dict, list)):
                            yield str(item)
                elif not isinstance(v, (dict, list)):
                    yield str(v)
            if isinstance(v, (dict, list)):
                yield from iter_values(v, key)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_values(item, key)


def first(obj: Any, key: str, default: str | None = None) -> str | None:
    for value in iter_values(obj, key):
        return value
    return default


def all_values(obj: Any, key: str) -> list[str]:
    return list(iter_values(obj, key))


def dicts_with(obj: Any, key: str) -> Iterator[Json]:
    """Yield every dict (at any depth) that directly contains ``key``."""
    if isinstance(obj, dict):
        if key in obj:
            yield obj
        for v in obj.values():
            if isinstance(v, (dict, list)):
                yield from dicts_with(v, key)
    elif isinstance(obj, list):
        for item in obj:
            yield from dicts_with(item, key)


def has_key(obj: Any, key: str) -> bool:
    return first(obj, key) is not None or any(True for _ in dicts_with(obj, key))


def to_int(value: str | None, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(float(value))
        except ValueError:
            return default


def to_float(value: str | None, default: float | None = None) -> float | None:
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


# ----------------------------------------------------------------- frame helpers
def parse_time(value: str | None) -> float | None:
    """Accept epoch seconds (``-T fields``) or ISO-8601 text (``-T json`` in tshark 4.x)."""
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Python handles at most microseconds; trim nanoseconds.
    if "." in text:
        head, tail = text.split(".", 1)
        frac = ""
        rest = ""
        for ch in tail:
            if ch.isdigit() and len(frac) < 6:
                frac += ch
            elif ch.isdigit():
                continue
            else:
                rest = tail[tail.index(ch):]
                break
        text = f"{head}.{frac.ljust(6, '0')}{rest}"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def frame_number(packet: Json) -> int:
    return to_int(first(layers(packet).get("frame", {}), "frame.number"), 0) or 0


def frame_interface(packet: Json) -> int | None:
    """The capture interface (pcapng interface id) the packet was seen on, or None."""
    return to_int(first(layers(packet).get("frame", {}), "frame.interface_id"))


def frame_time(packet: Json) -> float:
    return parse_time(first(layers(packet).get("frame", {}), "frame.time_epoch")) or 0.0


def endpoints(packet: Json) -> tuple[str, str]:
    """Outer (src, dst) addresses from IPv4 or IPv6; empty strings when absent."""
    lyr = layers(packet)
    for name, src_key, dst_key in (("ip", "ip.src", "ip.dst"), ("ipv6", "ipv6.src", "ipv6.dst")):
        value = lyr.get(name)
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, dict):
            src, dst = value.get(src_key), value.get(dst_key)
            if isinstance(src, str) and isinstance(dst, str):
                return src, dst
    return "", ""


def compact(row: dict[str, Any]) -> dict[str, Any]:
    """Drop None, empty-string and empty-list values so rows stay small."""
    return {k: v for k, v in row.items() if v is not None and v != "" and v != [] and v != {}}


def split_fields_line(line: str) -> list[str]:
    return line.rstrip("\n").split("\t")

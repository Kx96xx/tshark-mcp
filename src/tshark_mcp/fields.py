"""Field catalogue and helpers for walking tshark JSON output.

tshark's ``-T json`` output nests protocol fields inside dissection subtrees
whose key names vary by protocol. The helpers here search by exact field name
at any depth, so the protocol modules can say "give me ``diameter.Session-Id``
inside this message" without caring where the dissector put it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from .limits import ToolError
from .runner import Runner, check_result

Json = dict[str, Any]


# ----------------------------------------------------------------- field catalogue
_CATALOGUE_CACHE: dict[str, frozenset[str]] = {}


def field_catalogue(runner: Runner) -> frozenset[str]:
    """All field abbreviations tshark knows (``tshark -G fields``), cached per binary."""
    cached = _CATALOGUE_CACHE.get(runner.tshark)
    if cached is not None:
        return cached
    result = check_result(runner.list_fields())
    names: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] in ("F", "P"):
            names.add(parts[2])
    catalogue = frozenset(names)
    _CATALOGUE_CACHE[runner.tshark] = catalogue
    return catalogue


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

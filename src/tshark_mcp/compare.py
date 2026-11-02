"""Align the message ladders of two captures of the same procedure.

A ladder is the time-ordered list of signalling steps (one paired transaction
per step) that trace_subscriber builds for a subscriber, or every transaction
of a capture when no subscriber is given. Steps are compared by signature
(protocol and message), aligned with a longest-matching-block diff, and the
aligned pairs are compared field by field: result, pairing, the key Diameter
AVPs and the GTP IEs. The first entry that is not identical is the divergence.
"""

from __future__ import annotations

import difflib
import re
from typing import Any

from .fields import parse_time

# Peer-level keepalives say nothing about the procedure.
NOISE = frozenset({"diameter:CER", "diameter:DWR", "diameter:DPR", "gtpv2:Echo Request", "gtpv2:Echo Response",
                   "gtpv1:Echo Request", "gtpv1:Echo Response"})

# Identities differ between two subscribers and between two runs; they are not a divergence.
IDENTITY_KEYS = frozenset({"User-Name", "MSISDN", "A-MSISDN", "IMEI", "IMEISV", "Software-Version", "Session-Id"})


def signature(step: dict[str, Any]) -> str:
    protocol = step.get("protocol", "?")
    message = str(step.get("message") or "")
    if protocol == "diameter":
        message = message.split("/", 1)[0]
    elif protocol == "sip":
        message = message.split(" -> ", 1)[0]
    return f"{protocol}:{message}"


def details(step: dict[str, Any]) -> dict[str, Any]:
    """The comparable content of a step, flattened to dotted paths."""
    out: dict[str, Any] = {
        "result": step.get("result"),
        "answered": not step.get("unanswered"),
        "failed": bool(step.get("failed")),
    }
    protocol = step.get("protocol")
    if protocol == "diameter":
        out["application"] = step.get("application")
        for side in ("request_avps", "answer_avps"):
            _flatten(step.get(side) or {}, side, out)
    elif protocol in ("gtpv2", "gtpv1"):
        out["response"] = step.get("detail")
        out["apn"] = step.get("apn")
        out["rat_type"] = step.get("rat_type")
        out["paa_allocated"] = bool(step.get("paa"))
        out["request_fteids"] = sorted(f.get("interface", "") for f in step.get("request_fteids") or [])
        out["response_fteids"] = sorted(f.get("interface", "") for f in step.get("response_fteids") or [])
    elif protocol == "sip":
        out["methods"] = step.get("methods")
    elif protocol == "map":
        out["sccp"] = step.get("sccp")
    return {k: v for k, v in out.items() if v not in (None, [], {})}


_HEX_BLOB = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){3,}$")
MAX_DIFFERENCES = 40


def _flatten(obj: Any, prefix: str, out: dict[str, Any]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in IDENTITY_KEYS:
                continue
            _flatten(v, f"{prefix}.{k}", out)
    elif isinstance(obj, list) and obj and all(isinstance(v, dict) for v in obj):
        for i, v in enumerate(obj):
            # APN configurations are keyed by name so a reordered profile is not a change.
            label = v.get("apn") or v.get("Service-Selection") or i
            _flatten(v, f"{prefix}[{label}]", out)
    elif isinstance(obj, str) and _HEX_BLOB.match(obj):
        out[prefix] = "present"  # vectors, resync tokens: whether they are there matters, not the bytes
    else:
        out[prefix] = obj


def collapse(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge consecutive steps with the same signature and content into one with a
    ``repeat`` count, so a storm of identical retries reads as one line."""
    out: list[dict[str, Any]] = []
    for step in steps:
        if out and out[-1]["_sig"] == step["_sig"] and out[-1]["_details"] == step["_details"]:
            out[-1]["repeat"] = out[-1].get("repeat", 1) + 1
            out[-1]["_last_time"] = step.get("time")
            continue
        out.append(dict(step))
    return out


def prepare(steps: list[dict[str, Any]], collapse_repeats: bool) -> list[dict[str, Any]]:
    ready = []
    start = None
    for step in steps:
        sig = signature(step)
        if sig in NOISE:
            continue
        t = parse_time(step.get("time"))
        if start is None and t is not None:
            start = t
        s = dict(step, _sig=sig, _details=details(step))
        s["_offset_s"] = round(t - start, 6) if (t is not None and start is not None) else None
        ready.append(s)
    return collapse(ready) if collapse_repeats else ready


def brief(step: dict[str, Any], index: int) -> dict[str, Any]:
    out = {
        "index": index, "time": step.get("time"), "offset_s": step.get("_offset_s"), "protocol": step.get("protocol"),
        "message": step.get("message"), "result": step.get("result"), "rtt_ms": step.get("rtt_ms"),
        "request_frame": step.get("request_frame") or step.get("frame"), "answer_frame": step.get("answer_frame"),
        "unanswered": step.get("unanswered"), "failed": step.get("failed"), "repeat": step.get("repeat"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", False)}


def differences(da: dict[str, Any], db: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Fields whose values differ. When only one side was answered, the answer's own
    fields are implied by ``answered`` and left out."""
    one_sided = da.get("answered") != db.get("answered")
    out: dict[str, dict[str, Any]] = {}
    keys = [k for k in sorted(set(da) | set(db)) if da.get(k) != db.get(k)]
    if one_sided:
        keys = [k for k in keys if not k.startswith("answer_avps") and k not in ("result", "response")]
    for key in keys[:MAX_DIFFERENCES]:
        out[key] = {"a": da.get(key), "b": db.get(key)}
    if len(keys) > MAX_DIFFERENCES:
        out["more"] = {"a": None, "b": None, "count": len(keys) - MAX_DIFFERENCES}
    return out


def align(a: list[dict[str, Any]], b: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One ladder entry per aligned step: ``same`` (equal signature and content),
    ``changed`` (equal signature, different content), ``replaced`` (different
    messages at the same place), ``only_a`` or ``only_b``."""
    sigs_a = [s["_sig"] for s in a]
    sigs_b = [s["_sig"] for s in b]
    ladder: list[dict[str, Any]] = []
    matcher = difflib.SequenceMatcher(None, sigs_a, sigs_b, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for i, j in zip(range(i1, i2), range(j1, j2)):
                diff = differences(a[i]["_details"], b[j]["_details"])
                if a[i].get("repeat", 1) != b[j].get("repeat", 1):
                    diff["repeat"] = {"a": a[i].get("repeat", 1), "b": b[j].get("repeat", 1)}
                entry = {"op": "changed" if diff else "same", "a": brief(a[i], i), "b": brief(b[j], j)}
                if diff:
                    entry["differences"] = diff
                ladder.append(entry)
            continue
        if tag == "replace":
            n = min(i2 - i1, j2 - j1)
            for k in range(n):
                ladder.append({"op": "replaced", "a": brief(a[i1 + k], i1 + k), "b": brief(b[j1 + k], j1 + k)})
            i1, j1 = i1 + n, j1 + n
        for i in range(i1, i2):
            ladder.append({"op": "only_a", "a": brief(a[i], i)})
        for j in range(j1, j2):
            ladder.append({"op": "only_b", "b": brief(b[j], j)})
    return ladder


def timing(ladder: list[dict[str, Any]]) -> dict[str, Any]:
    """Round-trip and offset gaps between aligned steps, largest first."""
    rtt, offset = [], []
    for e in ladder:
        a, b = e.get("a"), e.get("b")
        if not a or not b or e["op"] == "replaced":
            continue
        if a.get("rtt_ms") is not None and b.get("rtt_ms") is not None:
            rtt.append({"message": a.get("message"), "a_ms": a["rtt_ms"], "b_ms": b["rtt_ms"],
                        "delta_ms": round(b["rtt_ms"] - a["rtt_ms"], 3)})
        if a.get("offset_s") is not None and b.get("offset_s") is not None:
            offset.append({"message": a.get("message"), "a_s": a["offset_s"], "b_s": b["offset_s"],
                           "delta_s": round(b["offset_s"] - a["offset_s"], 6)})
    rtt.sort(key=lambda r: -abs(r["delta_ms"]))
    offset.sort(key=lambda r: -abs(r["delta_s"]))
    return {"largest_rtt_differences": rtt[:5], "largest_offset_differences": offset[:5]}


def first_divergence(ladder: list[dict[str, Any]]) -> dict[str, Any] | None:
    for position, entry in enumerate(ladder):
        if entry["op"] != "same":
            before = [e["a"]["message"] for e in ladder[max(0, position - 3):position] if e.get("a")]
            out = dict(entry, ladder_position=position)
            if before:
                out["after"] = before
            return out
    return None


def summarise(ladder: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"same": 0, "changed": 0, "replaced": 0, "only_a": 0, "only_b": 0}
    for e in ladder:
        counts[e["op"]] += 1
    return counts


def side_summary(steps: list[dict[str, Any]]) -> dict[str, Any]:
    by_protocol: dict[str, int] = {}
    for s in steps:
        by_protocol[s.get("protocol", "?")] = by_protocol.get(s.get("protocol", "?"), 0) + s.get("repeat", 1)
    offsets = [s["_offset_s"] for s in steps if s.get("_offset_s") is not None]
    return {
        "steps": len(steps),
        "messages": sum(s.get("repeat", 1) for s in steps),
        "duration_s": max(offsets) if offsets else None,
        "by_protocol": by_protocol,
        "unanswered": sum(1 for s in steps if s.get("unanswered")),
        "failed": sum(1 for s in steps if s.get("failed")),
    }

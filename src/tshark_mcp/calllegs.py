"""Stitch the legs of one call across B2BUAs, SBCs and the P-/S-CSCF/TAS chain.

A B2BUA gives every leg its own Call-ID, so ``sip_dialogs`` shows one row per leg
and nothing says which rows are the same call. This module reads one
``-T fields`` pass over the SIP messages (the same parser as ``sip_dialogs``),
builds one leg per INVITE Call-ID and links legs by, strongest first:

* ``icid``: the same ``icid-value`` in P-Charging-Vector (TS 24.229 7.2A.5);
* ``session_id``: a shared UUID in the RFC 7989 Session-ID (local or remote);
* ``x_call_id``: an ``X-...Call-ID`` / ``X-CID`` style header naming the other
  leg's Call-ID, or the same value on both legs;
* ``replaces`` / ``target_dialog``: RFC 3891 Replaces and RFC 4538 Target-Dialog
  naming the other leg's Call-ID;
* ``same_media_endpoint``: both INVITEs offer the same SDP address and port
  within ``window_s`` (a B2BUA that does not anchor media passes them through);
* ``number_and_time``: the same called number (last nine digits), the second
  INVITE leaving the address the first was sent to, within ``window_s``. The
  weakest link, and always labelled so.

The legs of a stitched call form a tree: each leg's ``parent`` is the earlier leg
it is linked to (preferring the one whose destination is this leg's source), so
a forked call keeps both branches. Per parent and child leg the module gives the
delay the element in between added, how it mapped the child's final status onto
the parent's (a B2BUA that turned 480 into 503) and which headers changed.
Content-free: SIP header values and SDP addresses only, never bodies or media.
"""

from __future__ import annotations

import re
from typing import Any

from . import sdp as sdp_mod
from . import sip
from .callkpi import normalise_number
from .fields import compact, iso, parse_time, to_int

FIELDS = [*sip.MEDIA_FIELDS, "sip.msg_hdr", "sip.r-uri.user", "sip.to.user"]

CONFIDENCE = {"icid": "high", "session_id": "high", "x_call_id": "high", "replaces": "high",
              "target_dialog": "high", "same_media_endpoint": "medium", "number_and_time": "low"}
_RANK = {"high": 3, "medium": 2, "low": 1}
_ORDER = list(CONFIDENCE)

METHOD = {
    "leg": "one Call-ID whose first request is an INVITE; a proxy that keeps the Call-ID shows as more than "
           "one entry in the leg's hops, not as another leg",
    "icid": "same icid-value in P-Charging-Vector (TS 24.229 7.2A.5): high confidence",
    "session_id": "a UUID shared in the RFC 7989 Session-ID header, local or remote part: high",
    "x_call_id": "an X- header whose name holds Call-ID or CID carrying the other leg's Call-ID, or the same "
                 "value on both legs: high",
    "replaces": "RFC 3891 Replaces names the other leg's Call-ID: high",
    "target_dialog": "RFC 4538 Target-Dialog names the other leg's Call-ID: high",
    "same_media_endpoint": "both INVITEs offer the same SDP connection address and media port within window_s: medium",
    "number_and_time": "same called number (last nine digits), the later INVITE sent from the address the earlier "
                       "one went to, within window_s: low; check it before quoting",
    "added_delay_ms": "invite: this leg's INVITE minus its parent's; final_response: the parent's final response "
                      "minus this leg's, the time the element in between took to pass each on",
    "status_mapping": "per parent and child leg with a final response: what the child received and what the "
                      "element in between sent upstream; rewritten when the status or the Q.850 cause differs",
    "where_it_failed": "the deepest failed leg (most hops from the caller); responder is the address that sent "
                       "that leg's final response",
}

_X_ID = re.compile(r"^x-[a-z0-9-]*(call-?id|cid)[a-z0-9-]*$", re.I)
_ICID = re.compile(r"icid-value\s*=\s*\"?([^\";\s]+)", re.I)
_UUID = re.compile(r"[0-9a-f]{32}", re.I)
_NULL_UUID = "0" * 32
_COMPACT = {"v": "via", "i": "call-id", "f": "from", "t": "to", "m": "contact"}
MAX_LADDER = 200


def parse_headers(raw: str | None) -> dict[str, list[str]]:
    """``sip.msg_hdr`` text (``Name: value`` lines, tshark writes the CRLFs as ``\\r\\n``)
    as lower-case header name -> values in order."""
    out: dict[str, list[str]] = {}
    if not raw:
        return out
    text = raw.replace("\\r\\n", "\n").replace("\r\n", "\n")
    for line in text.split("\n"):
        name, sep, value = line.partition(":")
        if not sep or not name.strip() or " " in name.strip():
            continue
        key = name.strip().lower()
        key = _COMPACT.get(key, key)
        out.setdefault(key, []).append(value.strip())
    return out


def _call_id_part(value: str) -> str | None:
    cid = value.split(";", 1)[0].strip()
    return cid or None


def _via_count(values: list[str]) -> int:
    return sum(v.upper().count("SIP/2.0/") or 1 for v in values)


def _rr_count(values: list[str]) -> int:
    return sum(v.count("<") or 1 for v in values)


def link_keys(headers: dict[str, list[str]]) -> dict[str, Any]:
    """The values a leg can be linked by, from its first INVITE's headers."""
    keys: dict[str, Any] = {"icid": None, "session_ids": set(), "x_ids": set(), "replaces": None, "target_dialog": None}
    for value in headers.get("p-charging-vector", []):
        m = _ICID.search(value)
        if m:
            keys["icid"] = m.group(1)
            break
    for value in headers.get("session-id", []):
        keys["session_ids"].update(u.lower() for u in _UUID.findall(value) if u != _NULL_UUID)
    for name, values in headers.items():
        if _X_ID.match(name):
            keys["x_ids"].update(v.strip().strip("<>\"") for v in values if v.strip())
    for name, key in (("replaces", "replaces"), ("target-dialog", "target_dialog")):
        if headers.get(name):
            keys[key] = _call_id_part(headers[name][0])
    return keys


def build_legs(stdout: str) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """(one record per INVITE Call-ID in order of the first INVITE, the ladder per Call-ID)."""
    legs: dict[str, dict[str, Any]] = {}
    skip: set[str] = set()
    ladders: dict[str, list[dict[str, Any]]] = {}
    for rec in sip.parse_messages(stdout, FIELDS):
        cid = rec["sip.Call-ID"]
        if cid in skip:
            continue
        method = rec["sip.Method"]
        status = to_int(rec["sip.Status-Code"])
        ts = parse_time(rec["frame.time_epoch"])
        frame = to_int(rec["frame.number"])
        resend = rec["sip.resend"] in ("1", "True")
        leg = legs.get(cid)
        if leg is None:
            if method != "INVITE":
                skip.add(cid)
                continue
            headers = parse_headers(rec["sip.msg_hdr"])
            leg = legs[cid] = {
                "call_id": cid, "frame": frame, "t0": ts, "src": rec["ip.src"], "dst": rec["ip.dst"],
                "from": rec["sip.from.addr"] or None, "to": rec["sip.to.addr"] or None,
                "request_uri": rec["sip.r-uri"] or None,
                "called": normalise_number(rec["sip.r-uri.user"] or rec["sip.to.user"]),
                "p_asserted_identity": rec["sip.P-Asserted-Identity"].split(sip.AGGREGATOR)[0] or None,
                "privacy": (headers.get("privacy") or [None])[0],
                "via_count": _via_count(headers.get("via", [])),
                "record_route_count": _rr_count(headers.get("record-route", [])),
                "keys": link_keys(headers), "media": set(), "codecs": None, "hops": [],
                "invite_cseqs": set(), "finals": {}, "final_info": {}, "first_18x": None, "answer": None,
            }
        ladders.setdefault(cid, []).append(compact({
            "frame": frame, "time": iso(ts), "src": rec["ip.src"], "dst": rec["ip.dst"],
            "message": method or (f'{status} {rec["sip.CSeq.method"]}'.strip() if status is not None else ""),
            "resent": True if resend else None}))
        if resend:
            continue
        cseq = to_int(rec["sip.CSeq.seq"])
        if method == "INVITE":
            if leg["answer"] is None and cseq is not None:
                leg["invite_cseqs"].add(cseq)
            hop = f'{rec["ip.src"]} > {rec["ip.dst"]}'
            if cseq == min(leg["invite_cseqs"], default=cseq) and hop not in leg["hops"]:
                leg["hops"].append(hop)
            text = sdp_mod.extract(sdp_mod.body_text(rec.get("sip.msg_body")))
            if text:
                parsed = sdp_mod.parse(text)
                for media in parsed["media"]:
                    if media.get("address") and media.get("port") and media["address"] not in ("0.0.0.0", "::"):
                        leg["media"].add((media["address"], media["port"]))
                    if leg["codecs"] is None and media.get("media") == "audio":
                        leg["codecs"] = [sdp_mod.codec_label(c) for c in sdp_mod.voice_codecs(media)]
        if status is not None and rec["sip.CSeq.method"] == "INVITE" and cseq in leg["invite_cseqs"]:
            if status in (180, 183) and leg["first_18x"] is None:
                leg["first_18x"] = ts
            if status >= 200 and cseq not in leg["finals"]:
                leg["finals"][cseq] = status
                leg["final_info"][cseq] = {"frame": frame, "time": ts, "src": rec["ip.src"],
                                           "reason": rec["sip.Reason"] or None}
                if 200 <= status < 300 and leg["answer"] is None:
                    leg["answer"] = ts
    out = []
    for leg in legs.values():
        status = sip._outcome(leg["finals"])
        settled = next((cs for cs in sorted(leg["finals"]) if leg["finals"][cs] == status), None)
        info = leg["final_info"].get(settled, {}) if settled is not None else {}
        leg["status"] = status
        leg["final_frame"] = info.get("frame")
        leg["final_time"] = info.get("time")
        leg["responder"] = info.get("src")
        leg["reason"] = info.get("reason")
        if leg["reason"]:
            detail = sip.reason_detail(leg["reason"])
            leg["q850_cause"] = detail.get("q850_cause")
        out.append(leg)
    return out, ladders


def _last9(number: str | None) -> str | None:
    return number[-9:] if number and len(number) >= 6 else None


def find_links(legs: list[dict[str, Any]], window_s: float) -> list[tuple[int, int, str, str | None]]:
    """(earlier leg index, later leg index, method, evidence) for every pair of legs that
    something links, best method only."""
    by_cid = {leg["call_id"]: i for i, leg in enumerate(legs)}
    best: dict[tuple[int, int], tuple[str, str | None]] = {}

    def add(a: int, b: int, method: str, evidence: str | None) -> None:
        if a == b:
            return
        key = (a, b) if (legs[a]["t0"] or 0, a) <= (legs[b]["t0"] or 0, b) else (b, a)
        old = best.get(key)
        if old is None or _ORDER.index(method) < _ORDER.index(old[0]):
            best[key] = (method, evidence)

    def group(values: dict[str, list[int]], method: str) -> None:
        for value, members in values.items():
            for i in range(1, len(members)):
                add(members[0], members[i], method, value)

    icids: dict[str, list[int]] = {}
    sessions: dict[str, list[int]] = {}
    xids: dict[str, list[int]] = {}
    for i, leg in enumerate(legs):
        keys = leg["keys"]
        if keys["icid"]:
            icids.setdefault(keys["icid"], []).append(i)
        for u in sorted(keys["session_ids"]):
            sessions.setdefault(u, []).append(i)
        for x in sorted(keys["x_ids"]):
            if x in by_cid:
                add(i, by_cid[x], "x_call_id", x)
            xids.setdefault(x, []).append(i)
        for method in ("replaces", "target_dialog"):
            ref = keys[method]
            if ref and ref in by_cid:
                add(i, by_cid[ref], method, ref)
    group(icids, "icid")
    group(sessions, "session_id")
    group(xids, "x_call_id")

    order = sorted(range(len(legs)), key=lambda i: (legs[i]["t0"] or 0.0, i))
    for pos, a in enumerate(order):
        ta = legs[a]["t0"]
        if ta is None:
            continue
        for b in order[pos + 1:]:
            tb = legs[b]["t0"]
            if tb is None or tb - ta > window_s:
                break
            shared = legs[a]["media"] & legs[b]["media"]
            if shared:
                addr, port = sorted(shared)[0]
                add(a, b, "same_media_endpoint", f"{addr}:{port}")
            elif ((a, b) not in best and _last9(legs[a]["called"]) is not None
                  and _last9(legs[a]["called"]) == _last9(legs[b]["called"]) and legs[b]["src"] == legs[a]["dst"]):
                add(a, b, "number_and_time", legs[b]["called"])
    return [(a, b, m, ev) for (a, b), (m, ev) in sorted(best.items())]


def _components(n: int, links: list[tuple[int, int, str, str | None]]) -> list[list[int]]:
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for a, b, _, _ in links:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)
    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    return list(groups.values())


def _ms(a: float | None, b: float | None) -> float | None:
    return round((b - a) * 1000.0, 1) if a is not None and b is not None else None


def _failed(leg: dict[str, Any]) -> bool:
    return leg["status"] is not None and leg["status"] >= 300


def _code(leg: dict[str, Any]) -> dict[str, Any]:
    return compact({"status": leg["status"], "q850_cause": leg.get("q850_cause"), "frame": leg["final_frame"]})


def stitch(legs: list[dict[str, Any]], links: list[tuple[int, int, str, str | None]],
           explain: Any = None) -> list[dict[str, Any]]:
    """One row per stitched call (a single unlinked leg is a call of one leg), in order of
    the first INVITE. ``explain(protocol, code)`` returns a short cause explanation or None."""
    explain = explain or (lambda protocol, code: None)
    edges: dict[int, list[tuple[int, str, str | None]]] = {}
    for a, b, method, ev in links:
        edges.setdefault(a, []).append((b, method, ev))
        edges.setdefault(b, []).append((a, method, ev))
    calls = []
    for members in _components(len(legs), links):
        members.sort(key=lambda i: (legs[i]["t0"] or 0.0, i))
        index = {m: k for k, m in enumerate(members)}
        parent: dict[int, int | None] = {}
        rows: list[dict[str, Any]] = []
        depth: dict[int, int] = {}
        for k, m in enumerate(members):
            leg = legs[m]
            cands = [(o, meth, ev) for o, meth, ev in edges.get(m, []) if index.get(o, k) < k]
            link = None
            if cands:
                # The leg it hangs from: strongest link first, then the one this leg's INVITE
                # left from (hop adjacency), then the latest earlier leg.
                cands.sort(key=lambda c: (-_RANK[CONFIDENCE[c[1]]], legs[c[0]]["dst"] != leg["src"], -index[c[0]]))
                o, meth, ev = cands[0]
                parent[m] = o
                depth[m] = depth[o] + 1
                link = compact({"leg": index[o], "method": meth, "confidence": CONFIDENCE[meth], "evidence": ev})
            else:
                parent[m] = None
                depth[m] = 0
            row = compact({
                "leg": k, "call_id": leg["call_id"], "frame": leg["frame"], "time": iso(leg["t0"]),
                "src": leg["src"], "dst": leg["dst"], "hops": leg["hops"] if len(leg["hops"]) > 1 else None,
                "from": leg["from"], "to": leg["to"], "request_uri": leg["request_uri"],
                "status": leg["status"], "final_frame": leg["final_frame"], "responder": leg["responder"],
                "reason": leg["reason"], "q850_cause": leg.get("q850_cause"),
                "no_final_response": True if leg["status"] is None else None,
                "pdd_ms": _ms(leg["t0"], leg["first_18x"]), "linked_by": link, "depth": depth[m],
            })
            if parent[m] is not None:
                up = legs[parent[m]]
                row["added_delay_ms"] = compact({"invite": _ms(up["t0"], leg["t0"]),
                                                 "final_response": _ms(leg["final_time"], up["final_time"])})
                changes = _header_changes(up, leg)
                if changes:
                    row["header_changes"] = changes
            rows.append(row)

        mapping = []
        for m in members:
            p = parent[m]
            if p is None or legs[p]["status"] is None or legs[m]["status"] is None:
                continue
            up, down = legs[p], legs[m]
            if not (_failed(up) or _failed(down)):
                continue
            status_changed = up["status"] != down["status"]
            cause_changed = (up.get("q850_cause") or None) != (down.get("q850_cause") or None)
            entry = {"downstream_leg": index[m], "upstream_leg": index[p], "element": down["src"],
                     "received": _code(down), "sent": _code(up), "rewritten": status_changed or cause_changed}
            entry["note"] = _mapping_note(index[p], index[m], up, down, status_changed, cause_changed)
            mapping.append(entry)

        failed = [m for m in members if _failed(legs[m])]
        where = None
        if failed:
            deepest = max(failed, key=lambda m: (depth[m], -(legs[m]["final_time"] or 0.0)))
            leg = legs[deepest]
            where = compact({"leg": index[deepest], "call_id": leg["call_id"], "status": leg["status"],
                             "q850_cause": leg.get("q850_cause"), "responder": leg["responder"],
                             "frame": leg["final_frame"],
                             "sip": explain("sip", leg["status"]),
                             "q850": explain("q850", leg["q850_cause"]) if leg.get("q850_cause") is not None else None})
        root = legs[members[0]]
        confidences = [r["linked_by"]["confidence"] for r in rows if "linked_by" in r]
        call = compact({
            "first_frame": root["frame"], "time": iso(root["t0"]), "legs_count": len(members),
            "caller_status": root["status"], "caller_q850_cause": root.get("q850_cause"),
            "confidence": min(confidences, key=lambda c: _RANK[c]) if confidences else None,
            "where_it_failed": where, "status_mapping": mapping or None, "legs": rows,
        })
        call["_members"] = [legs[m]["call_id"] for m in members]
        call["_t0"] = root["t0"] or 0.0
        calls.append(call)
    calls.sort(key=lambda c: (c["_t0"], c.get("first_frame") or 0))
    return calls


def _mapping_note(pi: int, ci: int, up: dict[str, Any], down: dict[str, Any], status_changed: bool,
                  cause_changed: bool) -> str:
    def say(leg: dict[str, Any]) -> str:
        cause = f" (Q.850 {leg['q850_cause']})" if leg.get("q850_cause") is not None else ""
        return f"{leg['status']}{cause}"
    if status_changed or cause_changed:
        what = "status" if status_changed else "Q.850 cause"
        return (f"leg {ci} received {say(down)}, leg {pi} sent {say(up)} upstream: the element at {down['src']} "
                f"rewrote the {what}")
    return f"leg {ci} received {say(down)} and the element at {down['src']} passed it upstream unchanged"


def _header_changes(up: dict[str, Any], down: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for header, key in (("From", "from"), ("To", "to"), ("Request-URI", "request_uri"),
                        ("P-Asserted-Identity", "p_asserted_identity"), ("Privacy", "privacy"),
                        ("codecs", "codecs"), ("Via count", "via_count"), ("Record-Route count", "record_route_count")):
        a, b = up.get(key), down.get(key)
        if key == "codecs" and (a is None or b is None):
            continue
        if a != b:
            out.append({"header": header, "upstream": a, "downstream": b})
    return out


def select(calls: list[dict[str, Any]], call_id: str | None, number: str | None,
           legs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if call_id:
        calls = [c for c in calls if call_id in c["_members"]]
    if number:
        hit = {leg["call_id"] for leg in legs
               if any(number in (leg.get(k) or "") for k in ("from", "to", "request_uri", "p_asserted_identity"))}
        calls = [c for c in calls if hit & set(c["_members"])]
    return calls


def summary(calls: list[dict[str, Any]], links: list[tuple[int, int, str, str | None]]) -> dict[str, Any]:
    by_method: dict[str, int] = {}
    for _, _, method, _ in links:
        by_method[method] = by_method.get(method, 0) + 1
    return compact({
        "calls": len(calls),
        "legs": sum(c["legs_count"] for c in calls),
        "multi_leg_calls": sum(1 for c in calls if c["legs_count"] > 1),
        "failed_calls": sum(1 for c in calls if (c.get("caller_status") or 0) >= 300),
        "rewritten_statuses": sum(1 for c in calls for m in c.get("status_mapping", []) if m["rewritten"]),
        "links_by_method": dict(sorted(by_method.items(), key=lambda kv: _ORDER.index(kv[0]))) or None,
    })


def ladder(call: dict[str, Any], ladders: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """The messages of every leg of ``call`` in frame order, each with its leg index."""
    rows = []
    for k, cid in enumerate(call["_members"]):
        rows.extend({**r, "leg": k} for r in ladders.get(cid, []))
    rows.sort(key=lambda r: (r.get("frame") or 0))
    return rows[:MAX_LADDER]


def finish(call: dict[str, Any]) -> dict[str, Any]:
    call.pop("_members", None)
    call.pop("_t0", None)
    return call

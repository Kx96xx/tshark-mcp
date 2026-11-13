"""Reference procedures ("golden flows") and the matcher behind procedure_check.

A procedure is an ordered list of steps. Each step names the event keys that satisfy it, whether
it is required, an optional ``requires`` (the step is only required when that earlier step was
found, as the second REGISTER after a 401 challenge) and the spec reference to quote.

Events are normalised from other tools' rows: ``key`` (``diameter:ULR``, ``gtpv2:Create Session``,
``map:updateLocation``, ``sip:INVITE``, ``sip:401``, ``sip:2xx``), ``frame``, ``ok`` (False when the
answer was an error, None when there is nothing to judge), ``unanswered`` and ``result``.

The matcher walks the steps in order through the events: a step is ``ok``, ``failed`` (the
matching request was answered with an error, or a failure response came where the step's final
answer was expected), ``unanswered``, ``missing`` (required, never seen), ``out_of_order`` (seen,
but before the previous step), or ``not_seen`` (optional and absent). The first step that is not
``ok`` or ``not_seen`` is the first deviation.
"""

from __future__ import annotations

from typing import Any

PROCEDURES: dict[str, dict[str, Any]] = {
    "eps_attach": {
        "title": "LTE (EPS) attach, core network side",
        "source": "trace",
        "ref": "TS 23.401 5.3.2.1",
        "steps": [
            {"name": "Authentication-Information (AIR/AIA)", "keys": ["diameter:AIR"], "required": False,
             "ref": "TS 29.272 5.2.3.1", "note": "skipped when the MME still holds unused vectors"},
            {"name": "Update-Location (ULR/ULA)", "keys": ["diameter:ULR"], "required": True, "ref": "TS 29.272 5.2.1.1"},
            {"name": "Create Session", "keys": ["gtpv2:Create Session"], "required": True, "ref": "TS 29.274 7.2.1"},
            {"name": "Modify Bearer", "keys": ["gtpv2:Modify Bearer"], "required": True, "ref": "TS 29.274 7.2.7",
             "note": "carries the eNodeB S1-U F-TEID once the radio bearer is up"},
        ],
    },
    "location_update": {
        "title": "2G/3G location update over MAP",
        "source": "trace",
        "ref": "TS 23.012, TS 29.002",
        "steps": [
            {"name": "sendAuthenticationInfo", "keys": ["map:sendAuthenticationInfo"], "required": False,
             "ref": "TS 29.002 8.5.2"},
            {"name": "updateLocation or updateGprsLocation", "keys": ["map:updateLocation", "map:updateGprsLocation"],
             "required": True, "ref": "TS 29.002 8.1.2 / 8.1.7"},
        ],
    },
    "sip_register": {
        "title": "SIP / IMS registration",
        "source": "sip",
        "method": "REGISTER",
        "ref": "RFC 3261 10, TS 24.229 5.1.1",
        "steps": [
            {"name": "REGISTER", "keys": ["sip:REGISTER"], "required": True, "ref": "RFC 3261 10.2"},
            {"name": "401/407 challenge", "keys": ["sip:401", "sip:407"], "required": False, "ref": "RFC 3261 22.2",
             "note": "IMS always challenges the first REGISTER (TS 33.203)"},
            {"name": "REGISTER with credentials", "keys": ["sip:REGISTER"], "required": False,
             "requires": "401/407 challenge", "ref": "RFC 3261 22.2"},
            {"name": "200 OK", "keys": ["sip:2xx"], "required": True, "fail_on": ["sip:3xx", "sip:4xx", "sip:5xx", "sip:6xx"],
             "ref": "RFC 3261 10.3"},
        ],
    },
    "sip_call": {
        "title": "SIP call set-up",
        "source": "sip",
        "method": "INVITE",
        "ref": "RFC 3261 13, RFC 3262",
        "steps": [
            {"name": "INVITE", "keys": ["sip:INVITE"], "required": True, "ref": "RFC 3261 13.2"},
            {"name": "100 Trying", "keys": ["sip:100"], "required": False, "ref": "RFC 3261 8.2.6.1"},
            {"name": "180/183 ringing or session progress", "keys": ["sip:180", "sip:183"], "required": False,
             "ref": "RFC 3261 13.3.1.1, RFC 3262"},
            {"name": "200 OK", "keys": ["sip:2xx"], "required": True, "fail_on": ["sip:3xx", "sip:4xx", "sip:5xx", "sip:6xx"],
             "ref": "RFC 3261 13.3.1.4"},
            {"name": "ACK", "keys": ["sip:ACK"], "required": True, "ref": "RFC 3261 13.2.2.4"},
        ],
    },
}


def events_from_trace(timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalised events from trace_subscriber rows (one per request; its answer folded in)."""
    out = []
    for row in timeline:
        proto = str(row.get("protocol") or "").lower()
        msg = str(row.get("message") or "")
        if proto == "diameter":
            name = msg.split("/", 1)[0]
        elif proto in ("gtpv2", "gtpv1"):
            name = msg.removesuffix(" Request").removesuffix(" Response")
            if msg.endswith(" Response"):
                continue  # the answer is folded into its request row
        elif proto == "map":
            verb, _, op = msg.partition(" ")
            if verb != "begin" or not op:
                continue  # end/continue rows answer a begin row already present
            name = op
        else:
            continue
        unanswered = bool(row.get("unanswered"))
        ok = None if unanswered else (False if row.get("failed") else True)
        out.append({"key": f"{proto}:{name}", "frame": row.get("request_frame") or row.get("frame"),
                    "answer_frame": row.get("answer_frame"), "ok": ok, "unanswered": unanswered,
                    "near_capture_end": bool(row.get("near_capture_end")), "result": row.get("result")})
    return out


def events_from_dialog(dialog: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalised events from one sip_dialogs dialog: requests by method, responses by code and class."""
    out = []
    for m in dialog.get("messages") or []:
        if m.get("method"):
            out.append({"key": f"sip:{m['method']}", "keys": [f"sip:{m['method']}"], "frame": m.get("frame"), "ok": None})
        elif m.get("status") is not None:
            try:
                code = int(m["status"])
            except (TypeError, ValueError):
                continue
            # a response is judged by the step it fills (a 401 is the expected challenge), so no ok here;
            # a 3xx-6xx where the final 2xx is expected is caught by that step's fail_on
            out.append({"key": f"sip:{code}", "keys": [f"sip:{code}", f"sip:{code // 100}xx"], "frame": m.get("frame"),
                        "ok": None, "result": str(code)})
    return out


def _keys(event: dict[str, Any]) -> list[str]:
    return event.get("keys") or [event["key"]]


def _matches(event: dict[str, Any], keys: list[str]) -> bool:
    return any(any(k == want or k.startswith(want + " ") for k in _keys(event)) for want in keys)


def check(procedure: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Walk the procedure's steps through ``events``; steps, first deviation and a verdict."""
    spec = PROCEDURES[procedure]
    pos = 0
    found: set[str] = set()
    used: set[int] = set()  # event indexes a step already claimed
    steps = []
    for step in spec["steps"]:
        required = step["required"] or (step.get("requires") in found)
        row: dict[str, Any] = {"step": step["name"], "required": required, "ref": step["ref"]}
        if step.get("note"):
            row["note"] = step["note"]
        hit = next((i for i in range(pos, len(events)) if _matches(events[i], step["keys"])), None)
        fail = None
        if step.get("fail_on"):
            fail = next((i for i in range(pos, len(events)) if _matches(events[i], step["fail_on"])
                         and (hit is None or i < hit)), None)
        if fail is not None:
            e = events[fail]
            row.update(status="failed", frame=e.get("frame"), result=e.get("result"))
            steps.append(row)
            used.add(fail)
            pos = fail + 1
            continue
        if hit is None:
            earlier = next((i for i in range(0, pos) if i not in used and _matches(events[i], step["keys"])), None)
            if earlier is not None and required:
                row.update(status="out_of_order", frame=events[earlier].get("frame"))
            else:
                row["status"] = "missing" if required else "not_seen"
            steps.append(row)
            continue
        e = events[hit]
        found.add(step["name"])
        used.add(hit)
        pos = hit + 1
        row["frame"] = e.get("frame")
        if e.get("answer_frame"):
            row["answer_frame"] = e["answer_frame"]
        if e.get("result") is not None:
            row["result"] = e["result"]
        if e.get("unanswered"):
            row["status"] = "unanswered"
            if e.get("near_capture_end"):
                row["near_capture_end"] = True
        elif e.get("ok") is False:
            row["status"] = "failed"
        else:
            row["status"] = "ok"
        steps.append(row)
    first = next((s for s in steps if s["status"] not in ("ok", "not_seen")), None)
    if first is None:
        verdict = f"{spec['title']}: every required step is present and answered successfully."
    else:
        words = {"failed": "failed", "unanswered": "got no answer", "missing": "is missing",
                 "out_of_order": "came before the step it should follow"}[first["status"]]
        where = f" (frame {first['frame']})" if first.get("frame") else ""
        res = f": {first['result']}" if first.get("result") and first["status"] == "failed" else ""
        tail = " The capture ends right after it." if first.get("near_capture_end") else ""
        verdict = f"{spec['title']}: the first deviation is step '{first['step']}', which {words}{where}{res} ({first['ref']}).{tail}"
    return {"procedure": procedure, "title": spec["title"], "ref": spec["ref"], "steps": steps,
            "first_deviation": first, "conforms": first is None, "verdict": verdict}

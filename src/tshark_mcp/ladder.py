"""Message ladders (sequence diagrams) from the rows other tools already return.

The arrows come from ``trace_subscriber`` (a subscriber's Diameter, GTP, PFCP, SIP, ...
transactions: request and answer as two arrows) or ``call_legs`` (every SIP message of the
legs of one call). Every arrow carries the frame it was read from, so the diagram, the
``arrows`` list and ``packet_detail(path, frame)`` agree. Rendering is deterministic: the
same rows give a byte-identical diagram.

Participants are the addresses in order of first appearance, with a role guessed from what
they send (an S6a Update-Location comes from an MME and goes to an HSS, a Create Session
Request carrying an S11 MME F-TEID comes from an MME, the first INVITE of a call from the
caller, ...) and the evidence for it. Labels are packet text: they are cut to
``LABEL_MAX`` characters and stripped of every character Mermaid or HTML would interpret.
"""

from __future__ import annotations

import re
from typing import Any

LABEL_MAX = 60
FAIL_FILL = "rgb(255, 228, 225)"
_UNSAFE = re.compile(r"[^A-Za-z0-9 _.,:/()+=@'\[\]\-]")

# Request name -> (sender role, receiver role).
DIAMETER_ROLES: dict[str, tuple[str, str]] = {
    "ULR": ("MME", "HSS"), "AIR": ("MME", "HSS"), "PUR": ("MME", "HSS"), "NOR": ("MME", "HSS"),
    "CLR": ("HSS", "MME"), "IDR": ("HSS", "MME"), "DSR": ("HSS", "MME"), "RSR": ("HSS", "MME"),
    "ECR": ("MME", "EIR"), "UAR": ("I-CSCF", "HSS"), "LIR": ("I-CSCF", "HSS"), "MAR": ("S-CSCF", "HSS"),
    "SAR": ("S-CSCF", "HSS"), "RTR": ("HSS", "S-CSCF"), "PPR": ("HSS", "S-CSCF"), "UDR": ("AS", "HSS"),
    "PUR-Sh": ("AS", "HSS"), "AAR": ("P-CSCF", "PCRF"), "STR": ("P-CSCF", "PCRF"),
}
APP_ROLES: dict[str, tuple[str, str]] = {"Gx": ("PGW", "PCRF"), "Gy": ("PGW", "OCS"), "Ro": ("CTF", "OCS"),
                                         "Rx": ("P-CSCF", "PCRF"), "Cx": ("CSCF", "HSS"), "Sh": ("AS", "HSS")}
# F-TEID interface the sender put in its request -> (sender role, receiver role).
FTEID_ROLES: tuple[tuple[str, tuple[str, str]], ...] = (("S11 MME", ("MME", "SGW")), ("S5/S8 SGW", ("SGW", "PGW")),
                                                        ("S4 SGSN", ("SGSN", "SGW")))


def clean(text: Any) -> str:
    """Packet text made safe for a Mermaid label and short enough for one arrow."""
    out = _UNSAFE.sub(" ", str(text if text is not None else "")).strip()
    out = re.sub(r"\s+", " ", out)
    return out if len(out) <= LABEL_MAX else out[: LABEL_MAX - 3] + "..."


def _split(message: str) -> tuple[str, str | None]:
    """"ULR/ULA" -> ("ULR", "ULA"); "Create Session Request" -> (it, Response)."""
    if "/" in message and " " not in message:
        req, _, ans = message.partition("/")
        return req, (ans if ans and ans != "-" else None)
    if message.endswith(" Request"):
        return message, message[: -len("Request")] + "Response"
    return message, None


def from_trace(timeline: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Arrows and role hints from ``trace_subscriber`` timeline rows."""
    arrows: list[dict[str, Any]] = []
    hints: dict[str, dict[str, Any]] = {}
    for row in timeline:
        src, dst = row.get("src"), row.get("dst")
        if not src or not dst:
            continue
        req_name, ans_name = _split(str(row.get("message") or row.get("detail") or row.get("protocol") or "?"))
        proto = str(row.get("protocol") or "")
        req_frame = row.get("request_frame") or row.get("frame")
        failed = bool(row.get("failed"))
        result = row.get("result")
        arrows.append({"frame": req_frame, "time": row.get("time"), "src": src, "dst": dst, "protocol": proto,
                       "label": clean(req_name), "kind": "request"})
        if row.get("answer_frame"):
            label = clean(f"{ans_name or 'answer'} {result or ''}")
            arrows.append({"frame": row["answer_frame"], "time": row.get("time"), "src": dst, "dst": src,
                           "protocol": proto, "label": label, "kind": "answer", "failed": failed or None})
        elif row.get("unanswered"):
            arrows[-1]["note"] = "no answer" + (" (capture ended)" if row.get("near_capture_end") else "")
            arrows[-1]["failed"] = True if not row.get("near_capture_end") else None
        _hint(hints, row, req_name, src, dst, req_frame)
    return arrows, hints


def _hint(hints: dict[str, dict[str, Any]], row: dict[str, Any], req: str, src: str, dst: str, frame: Any) -> None:
    pair = None
    if row.get("protocol") == "diameter":
        pair = DIAMETER_ROLES.get(req)
        app = str(row.get("application") or "")
        for key, roles in APP_ROLES.items():
            if pair is None and app.startswith(key):
                pair = roles
    elif row.get("protocol") in ("gtpv2", "gtp"):
        for f in row.get("request_fteids") or []:
            pair = next((roles for prefix, roles in FTEID_ROLES if str(f.get("interface", "")).startswith(prefix)), None)
            if pair:
                break
    elif row.get("protocol") == "gtpv1" and req.startswith("Create PDP Context"):
        pair = ("SGSN", "GGSN")
    elif row.get("protocol") == "pfcp":
        pair = ("SMF/PGW-C", "UPF")
    if pair:
        for addr, role in ((src, pair[0]), (dst, pair[1])):
            hints.setdefault(addr, {"role": role, "evidence": f"frame {frame}: {clean(req)}"})


def from_call_legs(call: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Arrows and role hints from one ``call_legs`` call with its ladder."""
    arrows = []
    for r in call.get("ladder") or []:
        msg = str(r.get("message") or "")
        code = int(msg.split(" ", 1)[0]) if msg[:3].isdigit() else None
        arrows.append({"frame": r.get("frame"), "time": r.get("time"), "src": r.get("src"), "dst": r.get("dst"),
                       "protocol": "sip", "label": clean(msg + (" (resent)" if r.get("resent") else "")),
                       "kind": "response" if code else "request", "leg": r.get("leg"),
                       "failed": True if code is not None and code >= 400 else None})
    hints: dict[str, dict[str, Any]] = {}
    legs = call.get("legs") or []
    if legs:
        first, last = legs[0], legs[-1]
        hints[first["src"]] = {"role": "caller", "evidence": f"frame {first.get('frame')}: sends the first INVITE"}
        for leg in legs[1:]:
            hints.setdefault(leg["src"], {"role": "SIP proxy", "evidence": f"frame {leg.get('frame')}: forwards the INVITE"})
        hints.setdefault(last["dst"], {"role": "callee side", "evidence": f"frame {last.get('frame')}: last INVITE goes here"})
    failure = call.get("where_it_failed")
    if failure and arrows:
        for a in arrows:
            if a["frame"] == failure.get("frame"):
                sip = (failure.get("sip") or {}).get("name")
                a["note"] = clean(f"failed here: {failure.get('status')} {sip or ''}"
                                  + (f", Q.850 {failure['q850_cause']}" if failure.get("q850_cause") else ""))
                a["failed"] = True
    return arrows, hints


def participants(arrows: list[dict[str, Any]], hints: dict[str, dict[str, Any]], roles: bool) -> list[dict[str, Any]]:
    seen: list[str] = []
    for a in arrows:
        for addr in (a["src"], a["dst"]):
            if addr not in seen:
                seen.append(addr)
    out = []
    for i, addr in enumerate(seen, 1):
        p: dict[str, Any] = {"id": f"P{i}", "address": addr}
        if roles and addr in hints:
            p["role"] = hints[addr]["role"]
            p["role_evidence"] = hints[addr]["evidence"]
        out.append(p)
    return out


def mermaid(arrows: list[dict[str, Any]], parts: list[dict[str, Any]]) -> str:
    ids = {p["address"]: p["id"] for p in parts}
    lines = ["sequenceDiagram", "    autonumber"]
    for p in parts:
        name = clean(f"{p.get('role') + ' ' if p.get('role') else ''}{p['address']}")
        lines.append(f"    participant {p['id']} as {name}")
    for a in arrows:
        s, d = ids[a["src"]], ids[a["dst"]]
        arrow = "->>" if a.get("kind") == "request" else "-->>"
        text = f"    {s}{arrow}{d}: #{a['frame']} {a['label']}"
        if a.get("failed") or a.get("note"):
            lines.append(f"    rect {FAIL_FILL}" if a.get("failed") else "    rect rgb(240, 240, 240)")
            lines.append("    " + text)
            if a.get("note"):
                lines.append(f"        Note over {s},{d}: {clean(a['note'])}")
            lines.append("    end")
        else:
            lines.append(text)
    return "\n".join(lines) + "\n"


def text(arrows: list[dict[str, Any]], parts: list[dict[str, Any]]) -> str:
    names = {p["address"]: clean(f"{p.get('role') + ' ' if p.get('role') else ''}{p['address']}") for p in parts}
    width = max((len(n) for n in names.values()), default=8)
    lines = [f"  {'frame':<6} {'from':<{width}}      {'to':<{width}}  message"]
    for a in arrows:
        mark = "!!" if a.get("failed") else "  "
        lines.append(f"{mark}#{a['frame']:<5} {names[a['src']]:<{width}} ---> {names[a['dst']]:<{width}}  {a['label']}"
                     + (f"   [{clean(a['note'])}]" if a.get("note") else ""))
    return "\n".join(lines) + "\n"

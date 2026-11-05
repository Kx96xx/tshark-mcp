"""sigtran_health: SCTP association, M3UA ASP and SCCP/TCAP health per signalling peer.

One ``-T fields`` pass over ``sctp`` gives a row per packet with every SCTP chunk type,
the ABORT/ERROR cause codes, the M3UA message class and type with its error code, status,
routing context and affected point codes, the SCCP message type and return cause with the
called GT and SSN, and the TCAP P-Abort cause. Rows are grouped by association (the two
address:port endpoints) and replayed through small state machines: SCTP episodes (INIT to
established to ABORT or SHUTDOWN, the gap before the next INIT), heartbeats answered or
not, the M3UA ASP state (down, inactive, active) with acknowledgement times, DUNA/DAVA
outages per point code, and SCCP UDTS/XUDTS return causes per called address.
Content-free: addresses, codes, timings and frames only.
"""

from __future__ import annotations

from typing import Any, Callable

from .fields import iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "sctp.srcport", "sctp.dstport",
    "sctp.chunk_type", "sctp.cause_code",
    "m3ua.message_class", "m3ua.message_type", "m3ua.error_code", "m3ua.status_type", "m3ua.status_info",
    "m3ua.affected_point_code_pc", "m3ua.routing_context", "m3ua.protocol_data_opc", "m3ua.protocol_data_dpc",
    "sccp.message_type", "sccp.return_cause", "sccp.called.digits", "sccp.called.ssn", "sccp.calling.digits",
    "sccp.calling.ssn", "tcap.p_abortCause",
]
_IX = {name: i for i, name in enumerate(FIELDS)}
DISPLAY_FILTER = "sctp"

CHUNKS = {0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT", 5: "HEARTBEAT_ACK", 6: "ABORT",
          7: "SHUTDOWN", 8: "SHUTDOWN_ACK", 9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK", 14: "SHUTDOWN_COMPLETE"}
SCTP_CAUSES = {  # RFC 9260 3.3.10
    1: "Invalid Stream Identifier", 2: "Missing Mandatory Parameter", 3: "Stale Cookie Error", 4: "Out of Resource",
    5: "Unresolvable Address", 6: "Unrecognized Chunk Type", 7: "Invalid Mandatory Parameter",
    8: "Unrecognized Parameters", 9: "No User Data", 10: "Cookie Received While Shutting Down",
    11: "Restart of an Association with New Addresses", 12: "User Initiated Abort", 13: "Protocol Violation",
}
M3UA = {  # RFC 4666 3.1.2: (class, type) -> name
    (0, 0): "ERR", (0, 1): "NTFY", (1, 1): "DATA", (2, 1): "DUNA", (2, 2): "DAVA", (2, 3): "DAUD", (2, 4): "SCON",
    (2, 5): "DUPU", (2, 6): "DRST", (3, 1): "ASPUP", (3, 2): "ASPDN", (3, 3): "BEAT", (3, 4): "ASPUP_ACK",
    (3, 5): "ASPDN_ACK", (3, 6): "BEAT_ACK", (4, 1): "ASPAC", (4, 2): "ASPIA", (4, 3): "ASPAC_ACK", (4, 4): "ASPIA_ACK",
    (9, 1): "REG_REQ", (9, 2): "REG_RSP", (9, 3): "DEREG_REQ", (9, 4): "DEREG_RSP",
}
M3UA_ERRORS = {  # RFC 4666 3.8.1
    0x01: "Invalid Version", 0x03: "Unsupported Message Class", 0x04: "Unsupported Message Type",
    0x05: "Unsupported Traffic Mode Type", 0x06: "Unexpected Message", 0x07: "Protocol Error",
    0x09: "Invalid Stream Identifier", 0x0D: "Refused - Management Blocking", 0x0E: "ASP Identifier Required",
    0x0F: "Invalid ASP Identifier", 0x11: "Invalid Parameter Value", 0x12: "Parameter Field Error",
    0x13: "Unexpected Parameter", 0x14: "Destination Status Unknown", 0x15: "Invalid Network Appearance",
    0x16: "Missing Parameter", 0x19: "Invalid Routing Context", 0x1A: "No Configured AS for ASP",
}
NTFY = {(1, 2): "AS-Inactive", (1, 3): "AS-Active", (1, 4): "AS-Pending", (2, 1): "Insufficient ASP Resources Active",
        (2, 2): "Alternate ASP Active", (2, 3): "ASP Failure"}
SCCP_UDTS = (0x0A, 0x12, 0x14)
REFERENCES = {"sctp": "RFC 9260 3.3.10", "m3ua": "RFC 4666 3.8.1", "sccp_return": "ITU-T Q.713 3.12",
              "tcap_abort": "ITU-T Q.773"}
HEARTBEAT_ANSWER_S = 3.0
FLAP_EPISODES = 2

METHOD = {
    "association": "the two address:port endpoints; an INIT starts an episode, COOKIE_ACK establishes it, ABORT or "
                   "SHUTDOWN_COMPLETE ends it; gap_before_s is the time from the previous end to this INIT",
    "heartbeat": f"a HEARTBEAT with no HEARTBEAT_ACK in the other direction within {HEARTBEAT_ANSWER_S:g} s is a failure",
    "asp_state": "M3UA ASPUP/ASPAC/ASPIA/ASPDN and their ACKs per association (RFC 4666 4.3), reset to down when "
                 "the SCTP association ends",
    "verdict": f"down (ended and not re-established), flapping ({FLAP_EPISODES}+ aborts or shutdowns), degraded "
               "(heartbeat failures, M3UA ERR, a point code unavailable, SCCP returns, TCAP aborts, ASP not active), "
               "healthy otherwise",
}


def _ints(cell: str) -> list[int]:
    return [v for v in (to_int(p.strip()) for p in (cell or "").split(",")) if v is not None]


def _int(cell: str) -> int | None:
    vals = _ints(cell)
    return vals[0] if vals else None


def _str(cell: str) -> str | None:
    first = (cell or "").split(",")[0].strip()
    return first or None


def point_code(pc: int) -> dict[str, Any]:
    """A 14-bit ITU code as 3-8-3 and a 24-bit ANSI code as 8-8-8, side by side."""
    return {"value": pc, "itu_383": f"{(pc >> 11) & 0x7}-{(pc >> 3) & 0xFF}-{pc & 0x7}",
            "ansi_888": f"{(pc >> 16) & 0xFF}-{(pc >> 8) & 0xFF}-{pc & 0xFF}"}


def parse(stdout: str) -> list[dict[str, Any]]:
    rows = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        cells = split_fields_line(line)
        cells += [""] * (len(FIELDS) - len(cells))

        def c(name: str) -> str:
            return cells[_IX[name]]
        frame = _int(c("frame.number"))
        if frame is None:
            continue
        src = _str(c("ip.src")) or _str(c("ipv6.src")) or "?"
        dst = _str(c("ip.dst")) or _str(c("ipv6.dst")) or "?"
        classes, types = _ints(c("m3ua.message_class")), _ints(c("m3ua.message_type"))
        rows.append({
            "frame": frame, "time": parse_time(c("frame.time_epoch")),
            "src": f"{src}:{_int(c('sctp.srcport'))}", "dst": f"{dst}:{_int(c('sctp.dstport'))}",
            "chunks": _ints(c("sctp.chunk_type")), "sctp_causes": _ints(c("sctp.cause_code")),
            "m3ua": list(zip(classes, types)), "m3ua_error": _int(c("m3ua.error_code")),
            "status": (_int(c("m3ua.status_type")), _int(c("m3ua.status_info"))),
            "apcs": _ints(c("m3ua.affected_point_code_pc")), "rc": _ints(c("m3ua.routing_context")),
            "opc": _int(c("m3ua.protocol_data_opc")), "dpc": _int(c("m3ua.protocol_data_dpc")),
            "sccp": _ints(c("sccp.message_type")), "return_cause": _int(c("sccp.return_cause")),
            "called": _str(c("sccp.called.digits")), "called_ssn": _int(c("sccp.called.ssn")),
            "calling": _str(c("sccp.calling.digits")), "calling_ssn": _int(c("sccp.calling.ssn")),
            "p_abort": _int(c("tcap.p_abortCause")),
        })
    return rows


class _Assoc:
    def __init__(self, a: str, b: str) -> None:
        self.endpoints = (a, b)
        self.rows: list[dict[str, Any]] = []


def _assocs(rows: list[dict[str, Any]]) -> list[_Assoc]:
    out: dict[tuple[str, str], _Assoc] = {}
    for r in rows:
        key = tuple(sorted((r["src"], r["dst"])))
        if key not in out:
            first = (r["src"], r["dst"])
            out[key] = _Assoc(*first)
        out[key].rows.append(r)
    return list(out.values())


def analyse(assoc: _Assoc, capture_end: float | None, explain: Callable[[str, int], Any]) -> dict[str, Any]:
    a, b = assoc.endpoints
    episodes: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    last_end: float | None = None
    hb_pending: list[dict[str, Any]] = []
    hb = {"sent": 0, "answered": 0, "failed": 0, "failures": []}
    asp: dict[str, Any] = {"state": "down", "transitions": []}
    pending_asp: dict[str, dict[str, Any]] = {}
    m3ua_errors: list[dict[str, Any]] = []
    notify: list[dict[str, Any]] = []
    outages: dict[int, dict[str, Any]] = {}
    outage_rows: list[dict[str, Any]] = []
    sccp: dict[tuple[str | None, int | None, int | None], dict[str, Any]] = {}
    tcap: dict[int, dict[str, Any]] = {}
    data_msgs = 0
    rcs: set[int] = set()

    def end_episode(row: dict[str, Any], kind: str, cause: int | None = None) -> None:
        nonlocal current, last_end
        if current is None:
            current = {"start_frame": None, "started": "before the capture"}
            episodes.append(current)
        current.update(end_frame=row["frame"], end=kind, ended_by=row["src"])
        if cause is not None:
            current["cause"] = {"code": cause, "name": SCTP_CAUSES.get(cause), "ref": REFERENCES["sctp"]}
        t0 = current.pop("_t", None)
        if t0 is not None and row["time"] is not None:
            current["duration_s"] = round(row["time"] - t0, 3)
        last_end = row["time"]
        current = None
        if asp["state"] != "down":
            asp["transitions"].append({"frame": row["frame"], "to": "down", "why": f"SCTP {kind}"})
            asp["state"] = "down"

    for row in assoc.rows:
        t = row["time"]
        # Heartbeats that aged out before this row.
        for h in list(hb_pending):
            if t is not None and h["time"] is not None and t - h["time"] > HEARTBEAT_ANSWER_S:
                hb_pending.remove(h)
                hb["failed"] += 1
                hb["failures"].append({"frame": h["frame"], "time": iso(h["time"]), "from": h["src"]})
        for ch in row["chunks"]:
            if ch == 1:
                if current is not None and current.get("established_frame"):
                    end_episode(row, "restart (INIT while established)")
                current = {"start_frame": row["frame"], "time": iso(t), "initiated_by": row["src"], "_t": t}
                if last_end is not None and t is not None:
                    current["gap_before_s"] = round(t - last_end, 3)
                episodes.append(current)
            elif ch == 11 and current is not None:
                current["established_frame"] = row["frame"]
            elif ch == 4:
                hb["sent"] += 1
                hb_pending.append(row)
            elif ch == 5:
                match = next((h for h in hb_pending if h["src"] == row["dst"]), None)
                if match is not None:
                    hb_pending.remove(match)
                    hb["answered"] += 1
            elif ch == 6:
                end_episode(row, "ABORT", row["sctp_causes"][0] if row["sctp_causes"] else None)
            elif ch == 14:
                end_episode(row, "SHUTDOWN")
            elif ch == 0 and current is None and not episodes:
                current = {"start_frame": None, "started": "before the capture", "_t": t, "first_frame": row["frame"]}
                episodes.append(current)
        rcs.update(row["rc"])
        for cls, mtype in row["m3ua"]:
            name = M3UA.get((cls, mtype), f"class {cls} type {mtype}")
            if cls == 1:
                data_msgs += 1
            elif cls in (3, 4) and name in ("ASPUP", "ASPDN", "ASPAC", "ASPIA"):
                pending_asp[name] = row
            elif cls in (3, 4) and name.endswith("_ACK") and name != "BEAT_ACK":
                req_name = name[:-4]
                req = pending_asp.pop(req_name, None)
                new = {"ASPUP": "inactive", "ASPDN": "down", "ASPAC": "active", "ASPIA": "inactive"}[req_name]
                tr = {"frame": row["frame"], "message": name, "from_state": asp["state"], "to": new}
                if req is not None and req["time"] is not None and t is not None:
                    tr["ack_ms"] = round((t - req["time"]) * 1000, 1)
                    tr["request_frame"] = req["frame"]
                asp["transitions"].append(tr)
                asp["state"] = new
            elif name == "ERR":
                code = row["m3ua_error"]
                m3ua_errors.append({"frame": row["frame"], "from": row["src"], "code": code,
                                    "name": M3UA_ERRORS.get(code), "ref": REFERENCES["m3ua"]})
            elif name == "NTFY":
                notify.append({"frame": row["frame"], "status": NTFY.get(row["status"], str(row["status"]))})
            elif name in ("DUNA", "DAVA", "SCON", "DUPU", "DRST"):
                for pc in row["apcs"]:
                    if name == "DUNA":
                        outages.setdefault(pc, {"point_code": point_code(pc), "unavailable_frame": row["frame"],
                                                "_t": t, "from": row["src"]})
                    elif name == "DAVA" and pc in outages:
                        o = outages.pop(pc)
                        o["available_frame"] = row["frame"]
                        if o["_t"] is not None and t is not None:
                            o["outage_s"] = round(t - o["_t"], 3)
                        o.pop("_t", None)
                        outage_rows.append(o)
                    else:
                        outage_rows.append({"point_code": point_code(pc), "message": name, "frame": row["frame"],
                                            "from": row["src"]})
        if any(m in SCCP_UDTS for m in row["sccp"]) and row["return_cause"] is not None:
            # A UDTS swaps the addresses: its calling party is the address the message could not reach.
            key = (row["calling"], row["calling_ssn"], row["return_cause"])
            entry = sccp.setdefault(key, {"called_gt": row["calling"], "called_ssn": row["calling_ssn"],
                                          "return_cause": row["return_cause"], "count": 0, "first_frame": row["frame"],
                                          "returned_by": row["src"]})
            entry["count"] += 1
        if row["p_abort"] is not None:
            entry = tcap.setdefault(row["p_abort"], {"p_abort_cause": row["p_abort"], "count": 0,
                                                     "first_frame": row["frame"]})
            entry["count"] += 1
    for h in hb_pending:
        if capture_end is not None and h["time"] is not None and capture_end - h["time"] > HEARTBEAT_ANSWER_S:
            hb["failed"] += 1
            hb["failures"].append({"frame": h["frame"], "time": iso(h["time"]), "from": h["src"]})
    for ep in episodes:
        ep.pop("_t", None)
    for pc, o in outages.items():
        o.pop("_t", None)
        o["still_unavailable"] = True
        outage_rows.append(o)
    for entry in sccp.values():
        entry["explained"] = explain("sccp_return", entry["return_cause"])
    for entry in tcap.values():
        entry["explained"] = explain("tcap_abort", entry["p_abort_cause"])
    for pending in pending_asp.values():
        asp["transitions"].append({"frame": pending["frame"], "message": M3UA.get(pending["m3ua"][0]) if pending["m3ua"]
                                   else None, "unacknowledged": True})
    issues = _issues(episodes, hb, asp, m3ua_errors, outage_rows, sccp, tcap, bool(data_msgs or asp["transitions"]))
    verdict = _verdict(episodes, issues)
    out = {"endpoints": [a, b], "first_frame": assoc.rows[0]["frame"], "last_frame": assoc.rows[-1]["frame"],
           "verdict": verdict, "episodes": episodes, "heartbeat": hb,
           "m3ua": {"asp_state": asp["state"], "transitions": asp["transitions"], "routing_contexts": sorted(rcs),
                    "notify": notify, "errors": m3ua_errors, "data_messages": data_msgs,
                    "point_code_outages": outage_rows},
           "sccp_returns": sorted(sccp.values(), key=lambda e: -e["count"]),
           "tcap_aborts": sorted(tcap.values(), key=lambda e: -e["count"]), "issues": issues}
    return out


def _issues(episodes, hb, asp, errors, outages, sccp, tcap, uses_m3ua) -> list[str]:
    issues = []
    aborts = [e for e in episodes if e.get("end") == "ABORT"]
    for e in aborts:
        cause = e.get("cause") or {}
        issues.append(f"association aborted by {e['ended_by']} at frame {e['end_frame']}"
                      + (f" (cause {cause['code']} {cause['name']})" if cause.get("name") else ""))
    regaps = [e for e in episodes if "gap_before_s" in e]
    for e in regaps:
        issues.append(f"re-established at frame {e['start_frame']} after {e['gap_before_s']:g} s down")
    if hb["failed"]:
        issues.append(f"{hb['failed']} heartbeat(s) unanswered, first at frame {hb['failures'][0]['frame']}")
    for err in errors:
        issues.append(f"M3UA ERR {err['code']}" + (f" {err['name']}" if err.get("name") else "")
                      + f" from {err['from']} at frame {err['frame']}")
    for o in outages:
        pc = o["point_code"]["value"]
        if "outage_s" in o:
            issues.append(f"point code {pc} unavailable for {o['outage_s']:g} s (DUNA frame {o['unavailable_frame']})")
        elif o.get("still_unavailable"):
            issues.append(f"point code {pc} unavailable since frame {o['unavailable_frame']} (no DAVA)")
        else:
            issues.append(f"{o['message']} for point code {pc} at frame {o['frame']}")
    for e in sccp.values():
        name = (e.get("explained") or {}).get("name")
        issues.append(f"{e['count']} SCCP return(s) cause {e['return_cause']}" + (f" {name}" if name else "")
                      + f" for GT {e['called_gt']} SSN {e['called_ssn']}")
    for e in tcap.values():
        name = (e.get("explained") or {}).get("name")
        issues.append(f"{e['count']} TCAP P-Abort(s) cause {e['p_abort_cause']}" + (f" {name}" if name else ""))
    if uses_m3ua and asp["state"] != "active" and not (episodes and episodes[-1].get("end")):
        issues.append(f"M3UA ASP state at the end of the capture: {asp['state']}")
    return issues


def _verdict(episodes, issues) -> str:
    if episodes and episodes[-1].get("end"):
        return "down"
    if sum(1 for e in episodes if e.get("end") in ("ABORT", "SHUTDOWN")) >= FLAP_EPISODES:
        return "flapping"
    return "degraded" if issues else "healthy"


def build(rows: list[dict[str, Any]], capture_end: float | None, explain: Callable[[str, int], Any]) -> list[dict[str, Any]]:
    return [analyse(a, capture_end, explain) for a in _assocs(rows)]


def select(assocs: list[dict[str, Any]], peer: str | None, point_code_: int | None, gt: str | None
           ) -> list[dict[str, Any]]:
    out = []
    for a in assocs:
        if peer and not any(ep.split(":")[0] == peer or ep == peer for ep in a["endpoints"]):
            continue
        if point_code_ is not None and not any(o["point_code"]["value"] == point_code_
                                               for o in a["m3ua"]["point_code_outages"]):
            continue
        if gt and not any(gt in (e["called_gt"] or "") for e in a["sccp_returns"]):
            continue
        out.append(a)
    return out


def summary(assocs: list[dict[str, Any]]) -> dict[str, Any]:
    verdicts: dict[str, int] = {}
    for a in assocs:
        verdicts[a["verdict"]] = verdicts.get(a["verdict"], 0) + 1
    return {"associations": len(assocs), "verdicts": verdicts,
            "aborts": sum(1 for a in assocs for e in a["episodes"] if e.get("end") == "ABORT"),
            "heartbeat_failures": sum(a["heartbeat"]["failed"] for a in assocs),
            "m3ua_errors": sum(len(a["m3ua"]["errors"]) for a in assocs),
            "sccp_returns": sum(e["count"] for a in assocs for e in a["sccp_returns"]),
            "tcap_aborts": sum(e["count"] for a in assocs for e in a["tcap_aborts"])}

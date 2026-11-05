"""diameter_peers: the per-peer view a DRA operator reads first.

One ``-T fields`` pass over ``diameter`` gives a row per message. Messages are grouped by
transport connection (the two IP addresses), requests are paired with answers by command
code and hop-by-hop id in the opposite direction, and per peer the tool reports the
capability exchange (CER/CEA), the watchdog (DWR/DWA cadence, missed answers, the longest
gap), disconnects (DPR with Disconnect-Cause), restarts (Origin-State-Id changes per
Origin-Host), per-application KPIs (requests, answers, success ratio, result classes,
routing errors with the Destination-Realm they named, RTT percentiles, unanswered), the
AVPs named inside Failed-AVP, Error-Message text (capped and marked untrusted) and routing
(Destination-Host set or realm-only, Route-Record depth, redirects). Content-free: hosts,
realms, codes, timings and frames.
"""

from __future__ import annotations

import struct
from typing import Any, Callable

from .fields import iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "diameter.cmd.code", "diameter.flags.request", "diameter.applicationId", "diameter.hopbyhopid",
    "diameter.Origin-Host", "diameter.Origin-Realm", "diameter.Destination-Realm", "diameter.Destination-Host",
    "diameter.Result-Code", "diameter.Experimental-Result-Code", "diameter.Auth-Application-Id",
    "diameter.Acct-Application-Id", "diameter.Origin-State-Id", "diameter.Disconnect-Cause",
    "diameter.Firmware-Revision", "diameter.Product-Name", "diameter.Inband-Security-Id",
    "diameter.Failed-AVP", "diameter.Error-Message", "diameter.Route-Record", "diameter.Redirect-Host",
]
_IX = {name: i for i, name in enumerate(FIELDS)}
DISPLAY_FILTER = "diameter"
CER, DWR, DPR = 257, 280, 282
BASE_COMMANDS = {CER: "CER/CEA", DWR: "DWR/DWA", DPR: "DPR/DPA"}
APPLICATIONS = {0: "base", 3: "base accounting", 4: "Gy/Ro (credit control)", 16777216: "Cx", 16777217: "Sh",
                16777236: "Rx", 16777238: "Gx", 16777251: "S6a/S6d", 16777252: "S13", 16777255: "SLg",
                16777264: "SWm", 16777265: "SWx", 16777267: "S9", 16777272: "S6b", 16777291: "SLh",
                16777302: "Sy", 16777308: "S6c", 16777310: "S6m", 16777312: "SGd", 16777313: "Tsp",
                16777345: "T6a", 4294967295: "relay"}
DISCONNECT_CAUSES = {0: "REBOOTING", 1: "BUSY", 2: "DO_NOT_WANT_TO_TALK_TO_YOU"}
ROUTING_ERRORS = {3002: "DIAMETER_UNABLE_TO_DELIVER", 3003: "DIAMETER_REALM_NOT_SERVED",
                  3004: "DIAMETER_TOO_BUSY", 3005: "DIAMETER_LOOP_DETECTED", 3006: "DIAMETER_REDIRECT_INDICATION"}
AVP_NAMES = {1: "User-Name", 8: "Framed-IP-Address", 25: "Class", 55: "Event-Timestamp", 257: "Host-IP-Address",
             258: "Auth-Application-Id", 260: "Vendor-Specific-Application-Id", 263: "Session-Id",
             264: "Origin-Host", 266: "Vendor-Id", 268: "Result-Code", 277: "Auth-Session-State",
             278: "Origin-State-Id", 283: "Destination-Realm", 293: "Destination-Host", 296: "Origin-Realm",
             415: "CC-Request-Number", 416: "CC-Request-Type", 443: "Subscription-Id", 1032: "RAT-Type",
             1407: "Visited-PLMN-Id", 1405: "ULR-Flags", 1400: "Subscription-Data", 1408: "Requested-EUTRAN-Authentication-Info",
             1028: "QoS-Class-Identifier", 1001: "Charging-Rule-Install", 1027: "IP-CAN-Type", 30: "Called-Station-Id"}
MAX_TEXT = 200
MAX_MESSAGES = 10

METHOD = {
    "peer": "one transport connection (the two IP addresses); hosts are the Origin-Host values each side sent",
    "pairing": "answer = same command code and hop-by-hop id in the opposite direction",
    "watchdog": "DWR/DWA: requests, answers, missed (no DWA), cadence (median DWR interval) and the longest DWR gap",
    "restart": "an Origin-State-Id different from the last one the same Origin-Host sent",
    "verdict": "down (CER refused, or a DPR with no later CER), restarted, degraded (routing errors, 5xxx, "
               "missed watchdogs, unanswered requests), healthy",
}


def _ints(cell: str) -> list[int]:
    return [v for v in (to_int(p.strip()) for p in (cell or "").split(",")) if v is not None]


def _int(cell: str) -> int | None:
    vals = _ints(cell)
    return vals[0] if vals else None


def _str(cell: str) -> str | None:
    first = (cell or "").split(",")[0].strip()
    return first or None


def failed_avp_codes(hex_text: str | None) -> list[int]:
    """The AVP codes inside a Failed-AVP (the grouped AVP's payload as hex)."""
    if not hex_text:
        return []
    try:
        data = bytes.fromhex(hex_text.replace(":", "").split(",")[0].strip())
    except ValueError:
        return []
    out, i = [], 0
    while i + 8 <= len(data) and len(out) < 10:
        code, flags_len = struct.unpack("!II", data[i:i + 8])
        length = flags_len & 0xFFFFFF
        if length < 8:
            break
        out.append(code)
        i += (length + 3) & ~3
    return out


def parse(stdout: str) -> list[dict[str, Any]]:
    rows = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        cells = split_fields_line(line)
        cells += [""] * (len(FIELDS) - len(cells))

        def c(name: str) -> str:
            return cells[_IX[name]]
        frame, cmd = _int(c("frame.number")), _int(c("diameter.cmd.code"))
        if frame is None or cmd is None:
            continue
        rows.append({
            "frame": frame, "time": parse_time(c("frame.time_epoch")),
            "src": _str(c("ip.src")) or _str(c("ipv6.src")), "dst": _str(c("ip.dst")) or _str(c("ipv6.dst")),
            "cmd": cmd, "request": (c("diameter.flags.request").split(",")[0].strip() in ("1", "True", "true")),
            "app": _int(c("diameter.applicationId")), "hbh": c("diameter.hopbyhopid").split(",")[0].strip(),
            "origin_host": _str(c("diameter.Origin-Host")), "origin_realm": _str(c("diameter.Origin-Realm")),
            "dest_realm": _str(c("diameter.Destination-Realm")), "dest_host": _str(c("diameter.Destination-Host")),
            "result": _int(c("diameter.Result-Code")), "exp_result": _int(c("diameter.Experimental-Result-Code")),
            "auth_apps": sorted(set(_ints(c("diameter.Auth-Application-Id")))),
            "acct_apps": sorted(set(_ints(c("diameter.Acct-Application-Id")))),
            "state_id": _int(c("diameter.Origin-State-Id")), "disconnect": _int(c("diameter.Disconnect-Cause")),
            "firmware": _int(c("diameter.Firmware-Revision")), "product": _str(c("diameter.Product-Name")),
            "inband": _int(c("diameter.Inband-Security-Id")),
            "failed_avps": failed_avp_codes(c("diameter.Failed-AVP")),
            "error_message": _str(c("diameter.Error-Message")),
            "route_records": len([p for p in c("diameter.Route-Record").split(",") if p.strip()]),
            "redirect": _str(c("diameter.Redirect-Host")),
        })
    return rows


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    vals = sorted(values)
    k = min(len(vals) - 1, max(0, int(round(q * (len(vals) - 1)))))
    return round(vals[k], 1)


def _app_name(app: int | None) -> str:
    return f"{APPLICATIONS.get(app, 'application')} ({app})" if app is not None else "unknown"


def analyse(peer: tuple[str, str], rows: list[dict[str, Any]], capture_end: float | None,
            explain: Callable[..., Any]) -> dict[str, Any]:
    answers: dict[tuple[int, str, str | None], dict[str, Any]] = {}
    for r in rows:
        if not r["request"]:
            answers.setdefault((r["cmd"], r["hbh"], r["dst"]), r)
    hosts: dict[str, list[str]] = {}
    for r in rows:
        if r["origin_host"] and r["cmd"] in (CER, DWR, DPR):
            hosts.setdefault(r["src"] or "?", [])
            if r["origin_host"] not in hosts[r["src"] or "?"]:
                hosts[r["src"] or "?"].append(r["origin_host"])
    capabilities: list[dict[str, Any]] = []
    watchdog = {"requests": 0, "answered": 0, "missed": [], "_times": []}
    disconnects: list[dict[str, Any]] = []
    restarts: list[dict[str, Any]] = []
    last_state: dict[str, int] = {}
    apps: dict[int | None, dict[str, Any]] = {}
    failed_avps: dict[str, int] = {}
    messages: list[dict[str, Any]] = []
    routing = {"requests_with_destination_host": 0, "realm_routed_requests": 0, "max_route_record_depth": 0,
               "redirects": 0}
    last_cer_ok_t: float | None = None
    last_dpr_t: float | None = None
    cer_refused = None
    for r in rows:
        if r["origin_host"] and r["state_id"] is not None:
            prev = last_state.get(r["origin_host"])
            if prev is not None and prev != r["state_id"]:
                restarts.append({"host": r["origin_host"], "frame": r["frame"], "time": iso(r["time"]),
                                 "origin_state_id": {"before": prev, "after": r["state_id"]}})
            last_state[r["origin_host"]] = r["state_id"]
        if not r["request"]:
            code = r["exp_result"] or r["result"]
            if r["failed_avps"]:
                for code_ in r["failed_avps"]:
                    name = AVP_NAMES.get(code_, f"AVP {code_}")
                    failed_avps[name] = failed_avps.get(name, 0) + 1
            if r["error_message"] and len(messages) < MAX_MESSAGES:
                messages.append({"frame": r["frame"], "result_code": code, "text": r["error_message"][:MAX_TEXT]})
            continue
        ans = answers.get((r["cmd"], r["hbh"], r["src"]))
        code = None if ans is None else (ans["exp_result"] or ans["result"])
        rtt = None if ans is None or ans["time"] is None or r["time"] is None else (ans["time"] - r["time"]) * 1000
        if r["cmd"] == CER:
            cap: dict[str, Any] = {"frame": r["frame"], "time": iso(r["time"]), "from": r["src"],
                                   "host": r["origin_host"], "realm": r["origin_realm"],
                                   "auth_applications": [_app_name(a) for a in r["auth_apps"]],
                                   "acct_applications": [_app_name(a) for a in r["acct_apps"]],
                                   "firmware_revision": r["firmware"], "inband_security_id": r["inband"],
                                   "origin_state_id": r["state_id"]}
            if ans is not None:
                cap.update(answer_frame=ans["frame"], result_code=code,
                           peer_auth_applications=[_app_name(a) for a in ans["auth_apps"]])
                if code is not None and not 2000 <= code < 3000:
                    cap["explained"] = explain("diameter", code)
                    cer_refused = cap
                else:
                    last_cer_ok_t = r["time"]
            else:
                cap["unanswered"] = True
            capabilities.append({k: v for k, v in cap.items() if v not in (None, [])})
            continue
        if r["cmd"] == DWR:
            watchdog["requests"] += 1
            watchdog["_times"].append(r["time"])
            if ans is not None:
                watchdog["answered"] += 1
            else:
                watchdog["missed"].append({"frame": r["frame"], "time": iso(r["time"]), "from": r["src"]})
            continue
        if r["cmd"] == DPR:
            last_dpr_t = r["time"]
            disconnects.append({"frame": r["frame"], "time": iso(r["time"]), "sent_by": r["src"],
                                "host": r["origin_host"], "cause": r["disconnect"],
                                "cause_name": DISCONNECT_CAUSES.get(r["disconnect"]),
                                "answered": ans is not None})
            continue
        a = apps.setdefault(r["app"], {"application": _app_name(r["app"]), "requests": 0, "answers": 0,
                                       "success": 0, "classes": {}, "routing_errors": [], "unanswered": 0,
                                       "_rtts": [], "codes": {}})
        a["requests"] += 1
        if r["dest_host"]:
            routing["requests_with_destination_host"] += 1
        else:
            routing["realm_routed_requests"] += 1
        routing["max_route_record_depth"] = max(routing["max_route_record_depth"], r["route_records"])
        if ans is None:
            a["unanswered"] += 1
            continue
        a["answers"] += 1
        if rtt is not None:
            a["_rtts"].append(rtt)
        if code is None:
            continue
        cls = f"{code // 1000}xxx"
        a["classes"][cls] = a["classes"].get(cls, 0) + 1
        if 2000 <= code < 3000:
            a["success"] += 1
        else:
            a["codes"][code] = a["codes"].get(code, 0) + 1
        if code in ROUTING_ERRORS:
            if code == 3006:
                routing["redirects"] += 1
            a["routing_errors"].append({"frame": ans["frame"], "result_code": code, "name": ROUTING_ERRORS[code],
                                        "destination_realm": r["dest_realm"], "destination_host": r["dest_host"],
                                        "answer_origin_host": ans["origin_host"]})
    out_apps = []
    for a in apps.values():
        rtts = a.pop("_rtts")
        codes = a.pop("codes")
        a["success_pct"] = round(100.0 * a["success"] / a["answers"], 1) if a["answers"] else None
        a["rtt_ms"] = {"p50": _pct(rtts, 0.5), "p95": _pct(rtts, 0.95), "max": round(max(rtts), 1) if rtts else None}
        a["errors"] = [{"result_code": c, "count": n, **({"explained": explain("diameter", c)} if explain("diameter", c)
                                                           else {})} for c, n in sorted(codes.items())]
        a["routing_errors"] = a["routing_errors"][:20]
        out_apps.append(a)
    times = [t for t in watchdog.pop("_times") if t is not None]
    gaps = [b - a for a, b in zip(times, times[1:])]
    watchdog["cadence_s"] = _pct(gaps, 0.5)
    watchdog["longest_gap_s"] = round(max(gaps), 1) if gaps else None
    issues = []
    if cer_refused is not None:
        name = (cer_refused.get("explained") or {}).get("name")
        issues.append(f"capability exchange refused: CEA {cer_refused['result_code']}" + (f" {name}" if name else "")
                      + f" at frame {cer_refused['answer_frame']}")
    for d in disconnects:
        issues.append(f"DPR from {d['host'] or d['sent_by']} at frame {d['frame']}"
                      + (f" ({d['cause_name']})" if d["cause_name"] else ""))
    for rs in restarts:
        issues.append(f"{rs['host']} restarted: Origin-State-Id {rs['origin_state_id']['before']} -> "
                      f"{rs['origin_state_id']['after']} at frame {rs['frame']}")
    if watchdog["missed"]:
        issues.append(f"{len(watchdog['missed'])} DWR(s) unanswered, first at frame {watchdog['missed'][0]['frame']}")
    for a in out_apps:
        realms: dict[tuple[int, str | None], int] = {}
        for e in a["routing_errors"]:
            realms[(e["result_code"], e["destination_realm"])] = realms.get((e["result_code"], e["destination_realm"]), 0) + 1
        for (code, realm), n in realms.items():
            issues.append(f"{n} x {code} {ROUTING_ERRORS[code]} on {a['application']} for realm {realm}")
        fivexxx = sum(e["count"] for e in a["errors"] if e["result_code"] >= 5000)
        if fivexxx:
            issues.append(f"{fivexxx} permanent failure(s) (5xxx) on {a['application']}")
        if a["unanswered"]:
            issues.append(f"{a['unanswered']} request(s) unanswered on {a['application']}")
    if failed_avps:
        issues.append("Failed-AVP named " + ", ".join(f"{k} ({v})" for k, v in failed_avps.items()))
    if cer_refused is not None or (last_dpr_t is not None and (last_cer_ok_t is None or last_cer_ok_t < last_dpr_t)):
        verdict = "down"
    elif restarts:
        verdict = "restarted"
    elif issues:
        verdict = "degraded"
    else:
        verdict = "healthy"
    return {"peer": list(peer), "hosts": hosts, "first_frame": rows[0]["frame"], "last_frame": rows[-1]["frame"],
            "verdict": verdict, "capabilities": capabilities, "watchdog": watchdog, "disconnects": disconnects,
            "restarts": restarts, "applications": out_apps, "failed_avps": failed_avps, "error_messages": messages,
            "routing": routing, "issues": issues}


def build(rows: list[dict[str, Any]], capture_end: float | None, explain: Callable[..., Any]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in rows:
        key = tuple(sorted((r["src"] or "?", r["dst"] or "?")))
        groups.setdefault(key, []).append(r)
    return [analyse(k, v, capture_end, explain) for k, v in groups.items()]


def select(peers: list[dict[str, Any]], host: str | None, realm: str | None, application: int | None
           ) -> list[dict[str, Any]]:
    out = []
    for p in peers:
        names = {h for hs in p["hosts"].values() for h in hs}
        if host and not any(host.lower() in h.lower() for h in names):
            continue
        if realm and not any(realm.lower() == (c.get("realm") or "").lower() for c in p["capabilities"]) and \
                not any((e.get("destination_realm") or "").lower() == realm.lower()
                        for a in p["applications"] for e in a["routing_errors"]):
            continue
        if application is not None and not any(a["application"].endswith(f"({application})") for a in p["applications"]):
            continue
        out.append(p)
    return out


def summary(peers: list[dict[str, Any]]) -> dict[str, Any]:
    verdicts: dict[str, int] = {}
    for p in peers:
        verdicts[p["verdict"]] = verdicts.get(p["verdict"], 0) + 1
    return {"peers": len(peers), "verdicts": verdicts,
            "routing_errors": sum(len(a["routing_errors"]) for p in peers for a in p["applications"]),
            "missed_watchdogs": sum(len(p["watchdog"]["missed"]) for p in peers),
            "restarts": sum(len(p["restarts"]) for p in peers), "disconnects": sum(len(p["disconnects"]) for p in peers)}

"""IoT device sessions: MQTT per TCP connection, CoAP per client and server, LwM2M registrations.

MQTT (3.1.1 and 5.0): the CONNECT (client id, protocol level, keepalive, whether a user name
was sent), the CONNACK result named, PINGREQ cadence against the keepalive
(``keepalive_violated`` when the client went quiet for more than 1.5 times it), PUBLISH counts
per topic (names only), QoS 1 PUBACK latency, DISCONNECT with its reason, and how the
connection ended (FIN or RST and by whom, or still open). Per client id the connections are
counted and ``reconnect_loop`` is set when three or more come within ten minutes.

CoAP (RFC 7252): per client and server, CON/NON/ACK/RST counts, retransmissions, response codes
as class.detail with a name, and ``exhausted`` confirmable requests (retransmitted four times,
MAX_RETRANSMIT, with no ACK or RST). LwM2M over CoAP: Register (POST /rd with ep and lt),
Update, De-register, with ``expired`` when no Update came within the lifetime while the
capture went on.

Traffic inside GTP-U is read the same way (tshark dissects the inner packet) and the row names
the TEID. Payloads (MQTT message bodies, CoAP payloads, LwM2M TLV values) are never read.
"""

from __future__ import annotations

import statistics
from typing import Any

from .fields import iso, to_float, to_int

AGGREGATOR = "|"
MQTT_FILTER = "mqtt"
MQTT_FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
               "tcp.srcport", "tcp.dstport", "mqtt.msgtype", "mqtt.clientid", "mqtt.ver", "mqtt.kalive",
               "mqtt.conack.val", "mqtt.connack.reason_code", "mqtt.conack.flags.sp", "mqtt.disconnect.reason_code",
               "mqtt.topic", "mqtt.qos", "mqtt.msgid", "mqtt.conflag.uname", "gtp.teid"]
END_FILTER = "tcp.flags.fin == 1 || tcp.flags.reset == 1"
END_FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "tcp.srcport", "tcp.flags.fin", "tcp.flags.reset"]
COAP_FILTER = "coap"
COAP_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "udp.srcport",
               "udp.dstport", "coap.type", "coap.code", "coap.mid", "coap.retransmitted", "coap.opt.uri_path",
               "coap.opt.uri_query", "coap.opt.location_path", "gtp.teid"]

MQTT_TYPES = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP",
              8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP",
              14: "DISCONNECT", 15: "AUTH"}
LEVELS = {3: "3.1", 4: "3.1.1", 5: "5.0"}
CONNACK_V3 = {0: "Connection Accepted", 1: "unacceptable protocol version", 2: "identifier rejected",
              3: "server unavailable", 4: "bad user name or password", 5: "not authorized"}
REASON_V5 = {0x00: "Success", 0x04: "Disconnect with Will Message", 0x80: "Unspecified error",
             0x81: "Malformed Packet", 0x82: "Protocol Error", 0x83: "Implementation specific error",
             0x84: "Unsupported Protocol Version", 0x85: "Client Identifier not valid",
             0x86: "Bad User Name or Password", 0x87: "Not authorized", 0x88: "Server unavailable",
             0x89: "Server busy", 0x8A: "Banned", 0x8B: "Server shutting down", 0x8C: "Bad authentication method",
             0x8D: "Keep Alive timeout", 0x8E: "Session taken over", 0x8F: "Topic Filter invalid",
             0x90: "Topic Name invalid", 0x93: "Receive Maximum exceeded", 0x94: "Topic Alias invalid",
             0x95: "Packet too large", 0x96: "Message rate too high", 0x97: "Quota exceeded",
             0x98: "Administrative action", 0x99: "Payload format invalid", 0x9A: "Retain not supported",
             0x9B: "QoS not supported", 0x9C: "Use another server", 0x9D: "Server moved",
             0x9E: "Shared Subscriptions not supported", 0x9F: "Connection rate exceeded",
             0xA0: "Maximum connect time", 0xA1: "Subscription Identifiers not supported",
             0xA2: "Wildcard Subscriptions not supported"}
COAP_TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
COAP_CODES = {"0.01": "GET", "0.02": "POST", "0.03": "PUT", "0.04": "DELETE", "0.05": "FETCH", "0.06": "PATCH",
              "0.07": "iPATCH", "2.01": "Created", "2.02": "Deleted", "2.03": "Valid", "2.04": "Changed",
              "2.05": "Content", "2.31": "Continue", "4.00": "Bad Request", "4.01": "Unauthorized",
              "4.02": "Bad Option", "4.03": "Forbidden", "4.04": "Not Found", "4.05": "Method Not Allowed",
              "4.06": "Not Acceptable", "4.08": "Request Entity Incomplete", "4.09": "Conflict",
              "4.12": "Precondition Failed", "4.13": "Request Entity Too Large", "4.15": "Unsupported Content-Format",
              "5.00": "Internal Server Error", "5.01": "Not Implemented", "5.02": "Bad Gateway",
              "5.03": "Service Unavailable", "5.04": "Gateway Timeout", "5.05": "Proxying Not Supported"}
MAX_RETRANSMIT = 4
LOOP_COUNT, LOOP_WINDOW_S = 3, 600.0
KEEPALIVE_FACTOR = 1.5
TOPICS_MAX = 10


def _rows(stdout: str, fields: list[str]) -> list[dict[str, list[str]]]:
    out = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t") + [""] * len(fields)
        out.append({f: [v for v in parts[i].split(AGGREGATOR) if v != ""] for i, f in enumerate(fields)})
    return out


def _last(rec: dict[str, list[str]], field: str) -> str | None:
    vals = rec.get(field) or []
    return vals[-1] if vals else None   # the innermost header when the packet sits inside a tunnel


def _addr(rec: dict[str, list[str]], side: str) -> str | None:
    return _last(rec, f"ip.{side}") or _last(rec, f"ipv6.{side}")


def _teid(rec: dict[str, list[str]]) -> str | None:
    value = _last(rec, "gtp.teid")
    if not value:
        return None
    try:
        return f"0x{int(value, 16 if value.lower().startswith('0x') else 10):08x}"
    except ValueError:
        return None


def _flag(value: str | None) -> bool:
    return (value or "").strip() in ("1", "True", "true")


def coap_code(value: str | None) -> str | None:
    code = to_int(value)
    if code is None:
        return None
    return f"{code >> 5}.{code & 31:02d}"


# ------------------------------------------------------------------ MQTT
def mqtt_connections(stdout: str, end_stdout: str, capture_end: float | None) -> list[dict[str, Any]]:
    conns: dict[int, dict[str, Any]] = {}
    for rec in _rows(stdout, MQTT_FIELDS):
        stream = to_int(_last(rec, "tcp.stream"))
        frame = to_int(_last(rec, "frame.number"))
        t = to_float(_last(rec, "frame.time_epoch"))
        if stream is None or frame is None:
            continue
        sport, dport = to_int(_last(rec, "tcp.srcport")), to_int(_last(rec, "tcp.dstport"))
        src, dst = _addr(rec, "src"), _addr(rec, "dst")
        c = conns.get(stream)
        types = [to_int(x) for x in rec["mqtt.msgtype"]]
        if c is None:
            from_client = 1 in types or 12 in types or 3 in types
            client, broker = ((f"{src}:{sport}", f"{dst}:{dport}") if from_client else (f"{dst}:{dport}", f"{src}:{sport}"))
            c = conns[stream] = {"tcp_stream": stream, "client": client, "broker": broker, "first_frame": frame,
                                 "_t0": t, "_client_times": [], "_pings": [], "_publish": {}, "_pending": {},
                                 "_puback_ms": [], "publishes": 0, "messages": {}}
        c["last_frame"], c["_t1"] = frame, t
        teid = _teid(rec)
        if teid:
            c["gtpu_teid"] = teid
        by_client = f"{src}:{sport}" == c["client"]
        if by_client and t is not None:
            c["_client_times"].append(t)
        topics = list(rec["mqtt.topic"])
        msgids = list(rec["mqtt.msgid"])
        qos = list(rec["mqtt.qos"])
        for mtype in types:
            name = MQTT_TYPES.get(mtype or 0, f"type {mtype}")
            c["messages"][name] = c["messages"].get(name, 0) + 1
            if mtype == 1:
                c["connect_frame"] = frame
                c["client_id"] = _last(rec, "mqtt.clientid")
                level = to_int(_last(rec, "mqtt.ver"))
                c["protocol_version"] = LEVELS.get(level or 0, str(level))
                c["_level"] = level
                c["keepalive_s"] = to_int(_last(rec, "mqtt.kalive"))
                if _flag(_last(rec, "mqtt.conflag.uname")):
                    c["user_name_sent"] = True
            elif mtype == 2:
                v5 = _last(rec, "mqtt.connack.reason_code")
                code = to_int(v5) if v5 is not None else to_int(_last(rec, "mqtt.conack.val"))
                named = (REASON_V5 if v5 is not None else CONNACK_V3).get(code or 0, f"code {code}")
                c["connack"] = {"code": code, "name": named, "accepted": code == 0, "frame": frame,
                                "session_present": _flag(_last(rec, "mqtt.conack.flags.sp"))}
                if c.get("_t0") is not None and t is not None:
                    c["connack"]["ms_after_syn"] = round((t - c["_t0"]) * 1000, 1)
            elif mtype == 3:
                c["publishes"] += 1
                topic = topics.pop(0) if topics else None
                if topic:
                    c["_publish"][topic] = c["_publish"].get(topic, 0) + 1
                q = to_int(qos.pop(0)) if qos else 0
                if q and msgids and t is not None:
                    c["_pending"][msgids.pop(0)] = t
            elif mtype == 4 and msgids:
                mid = msgids.pop(0)
                sent = c["_pending"].pop(mid, None)
                if sent is not None and t is not None:
                    c["_puback_ms"].append(round((t - sent) * 1000, 1))
            elif mtype == 12 and t is not None:
                c["_pings"].append(t)
            elif mtype == 14:
                code = to_int(_last(rec, "mqtt.disconnect.reason_code"))
                c["disconnect"] = {"frame": frame, "by": "client" if by_client else "broker",
                                   "reason": REASON_V5.get(code or 0, f"code {code}") if code is not None else "normal"}
    for rec in _rows(end_stdout, END_FIELDS):
        stream = to_int(_last(rec, "tcp.stream"))
        c = conns.get(stream) if stream is not None else None
        if c is None or "ended" in c:
            continue
        port = to_int(_last(rec, "tcp.srcport"))
        by = "client" if c["client"].endswith(f":{port}") else "broker"
        kind = "RST" if _flag(_last(rec, "tcp.flags.reset")) else "FIN"
        c["ended"] = {"how": kind, "by": by, "frame": to_int(_last(rec, "frame.number"))}
        c["_t1"] = to_float(_last(rec, "frame.time_epoch")) or c["_t1"]
    out = []
    for c in conns.values():
        out.append(_finish(c, capture_end))
    _reconnects(out)
    out.sort(key=lambda r: r["first_frame"])
    for row in out:
        row["verdict"] = _mqtt_verdict(row)
    return out


def _finish(c: dict[str, Any], capture_end: float | None) -> dict[str, Any]:
    ka = c.get("keepalive_s")
    times = sorted(c.pop("_client_times"))
    pings = c.pop("_pings")
    if ka and len(times) >= 2:
        gaps = [b - a for a, b in zip(times, times[1:])]
        c["longest_client_silence_s"] = round(max(gaps), 1)
        if max(gaps) > KEEPALIVE_FACTOR * ka:
            c["keepalive_violated"] = True
    if pings:
        intervals = [b - a for a, b in zip(pings, pings[1:])]
        c["pings"] = {"count": len(pings), "median_interval_s": round(statistics.median(intervals), 1) if intervals else None}
    publish = c.pop("_publish")
    cid = c.get("client_id")
    if cid and len(cid) >= 3:
        # The client id inside a topic is an identifier: shown as {client_id} so redaction cannot miss it.
        merged: dict[str, int] = {}
        for topic, n in publish.items():
            key = topic.replace(cid, "{client_id}")
            merged[key] = merged.get(key, 0) + n
        publish = merged
    if publish:
        top = sorted(publish.items(), key=lambda kv: (-kv[1], kv[0]))
        c["topics"] = dict(top[:TOPICS_MAX])
        if len(top) > TOPICS_MAX:
            c["topics_more"] = len(top) - TOPICS_MAX
    lat = c.pop("_puback_ms")
    if lat:
        c["puback_ms"] = {"count": len(lat), "median": statistics.median(lat), "max": max(lat)}
    pending = c.pop("_pending")
    if pending:
        c["publishes_unacknowledged"] = len(pending)
    if "ended" not in c:
        c["ended"] = {"how": "open at capture end"}
        if ka and capture_end is not None and c.get("_t1") is not None and capture_end - c["_t1"] > KEEPALIVE_FACTOR * ka:
            c["ended"] = {"how": "idle, then silence", "silent_s": round(capture_end - c["_t1"], 1)}
    t0, t1 = c.pop("_t0"), c.pop("_t1")
    c.pop("_level", None)
    if t0 is not None:
        c["time"] = iso(t0)
        c["_start"] = t0
    if t0 is not None and t1 is not None:
        c["duration_s"] = round(t1 - t0, 3)
    return {k: v for k, v in c.items() if v is not None}


def _reconnects(rows: list[dict[str, Any]]) -> None:
    by_id: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        key = r.get("client_id") or r["client"].rsplit(":", 1)[0]
        by_id.setdefault(key, []).append(r)
    for group in by_id.values():
        group.sort(key=lambda r: r.get("_start") or 0)
        starts = [r.get("_start") for r in group if r.get("_start") is not None]
        loop = any(starts[i + LOOP_COUNT - 1] - starts[i] <= LOOP_WINDOW_S for i in range(len(starts) - LOOP_COUNT + 1))
        for r in group:
            r["connections_of_client"] = len(group)
            if loop:
                r["reconnect_loop"] = True
                gaps = [b - a for a, b in zip(starts, starts[1:])]
                r["reconnect_interval_s"] = {"median": round(statistics.median(gaps), 1), "min": round(min(gaps), 1)}
    for r in rows:
        r.pop("_start", None)


def _mqtt_verdict(r: dict[str, Any]) -> str:
    ca = r.get("connack")
    if ca and not ca["accepted"]:
        return f"refused: CONNACK {ca['name']} (frame {ca['frame']})"
    if r.get("connect_frame") and not ca:
        return "CONNECT never answered"
    parts = []
    if r.get("reconnect_loop"):
        parts.append(f"reconnect loop ({r['connections_of_client']} connections of this client)")
    if r.get("keepalive_violated"):
        parts.append(f"client silent {r['longest_client_silence_s']} s with keepalive {r.get('keepalive_s')} s: "
                     "NAT or tunnel idle timers may drop it")
    end = r.get("ended") or {}
    if end.get("how") == "RST":
        parts.append(f"reset by the {end['by']} (frame {end['frame']})")
    if r.get("publishes_unacknowledged"):
        parts.append(f"{r['publishes_unacknowledged']} QoS 1/2 PUBLISH without acknowledgement")
    return "; ".join(parts) if parts else "healthy"


# ------------------------------------------------------------------ CoAP and LwM2M
def coap_pairs(stdout: str, capture_end: float | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    cons: dict[tuple[str, str, int], dict[str, Any]] = {}
    acks: set[tuple[str, str, int]] = set()
    lwm2m: dict[str, dict[str, Any]] = {}
    location_owner: dict[str, str] = {}
    requests: dict[tuple[str, str, int], dict[str, Any]] = {}
    for rec in _rows(stdout, COAP_FIELDS):
        frame = to_int(_last(rec, "frame.number"))
        t = to_float(_last(rec, "frame.time_epoch"))
        src = f"{_addr(rec, 'src')}:{_last(rec, 'udp.srcport')}"
        dst = f"{_addr(rec, 'dst')}:{_last(rec, 'udp.dstport')}"
        mtype = to_int(_last(rec, "coap.type"))
        code = coap_code(_last(rec, "coap.code"))
        mid = to_int(_last(rec, "coap.mid"))
        if mid is None or mtype is None:
            continue
        request = code is not None and code.startswith("0.") and code != "0.00"
        client, server = (src, dst) if request else (dst, src)
        p = pairs.setdefault((client, server), {"client": client, "server": server, "first_frame": frame,
                                                "types": {}, "retransmissions": 0, "responses": {}})
        teid = _teid(rec)
        if teid:
            p["gtpu_teid"] = teid
        tname = COAP_TYPES.get(mtype, str(mtype))
        p["types"][tname] = p["types"].get(tname, 0) + 1
        if rec["coap.retransmitted"]:
            p["retransmissions"] += 1
        if mtype == 0 and request:
            key = (client, server, mid)
            k = cons.setdefault(key, {"frame": frame, "sends": 0, "code": code, "path": "/".join(rec["coap.opt.uri_path"])})
            k["sends"] += 1
            requests.setdefault(key, {"t": t, "frame": frame, "path": rec["coap.opt.uri_path"],
                                      "query": rec["coap.opt.uri_query"], "code": code})
        if mtype in (2, 3):
            acks.add((dst, src, mid))
        if code is not None and not code.startswith("0."):
            label = f"{code} {COAP_CODES.get(code, '')}".strip()
            p["responses"][label] = p["responses"].get(label, 0) + 1
            req = requests.get((dst, src, mid))
            if req is not None:
                _lwm2m_response(lwm2m, location_owner, req, code, rec["coap.opt.location_path"], frame, dst)
        if request and rec["coap.opt.uri_path"] and rec["coap.opt.uri_path"][0] == "rd":
            _lwm2m_request(lwm2m, location_owner, client, rec, code, frame, t)
    exhausted = []
    for (client, server, mid), k in cons.items():
        if (client, server, mid) in acks:
            continue
        p = pairs[(client, server)]
        if k["sends"] - 1 >= MAX_RETRANSMIT:
            p.setdefault("exhausted", []).append({"mid": mid, "first_frame": k["frame"], "sends": k["sends"],
                                                  "request": f"{COAP_CODES.get(k['code'], k['code'])} /{k['path']}"})
            exhausted.append((client, server))
        else:
            p["unacknowledged"] = p.get("unacknowledged", 0) + 1
    rows = []
    for p in pairs.values():
        if p.get("exhausted"):
            p["verdict"] = (f"{len(p['exhausted'])} confirmable request(s) retransmitted {MAX_RETRANSMIT} times "
                            f"without an ACK: the server or the path drops them (first frame {p['exhausted'][0]['first_frame']})")
        elif any(r.startswith(("4.", "5.")) for r in p["responses"]):
            p["verdict"] = "error responses: " + ", ".join(r for r in p["responses"] if r.startswith(("4.", "5.")))
        elif p.get("unacknowledged"):
            p["verdict"] = f"{p['unacknowledged']} confirmable request(s) not acknowledged yet"
        else:
            p["verdict"] = "healthy"
        rows.append(p)
    return rows, _lwm2m_rows(lwm2m, capture_end)


def _query(values: list[str]) -> dict[str, str]:
    out = {}
    for item in values:
        k, _, v = item.partition("=")
        out[k] = v
    return out


def _lwm2m_request(lwm2m: dict[str, dict[str, Any]], owners: dict[str, str], client: str,
                   rec: dict[str, list[str]], code: str | None, frame: int | None, t: float | None) -> None:
    path = rec["coap.opt.uri_path"]
    q = _query(rec["coap.opt.uri_query"])
    if len(path) == 1 and code == "0.02":
        ep = q.get("ep") or client
        e = lwm2m.setdefault(ep, {"endpoint": ep, "client": client, "registrations": [], "updates": 0})
        e["registrations"].append({"frame": frame, "_t": t, "lifetime_s": to_int(q.get("lt")) or 86400,
                                   "lwm2m_version": q.get("lwm2m"), "binding": q.get("b")})
        e["_last"] = t
        e["_lifetime"] = to_int(q.get("lt")) or 86400
        return
    loc = "/".join(path)
    ep = owners.get(loc)
    if ep is None:
        return
    e = lwm2m[ep]
    if code == "0.02":
        e["updates"] += 1
        e["_last"] = t
        e["last_update_frame"] = frame
        if q.get("lt"):
            e["_lifetime"] = to_int(q["lt"]) or e["_lifetime"]
    elif code == "0.04":
        e["deregistered_frame"] = frame


def _lwm2m_response(lwm2m: dict[str, dict[str, Any]], owners: dict[str, str], req: dict[str, Any], code: str,
                    location: list[str], frame: int | None, client: str) -> None:
    if not req["path"] or req["path"][0] != "rd" or len(req["path"]) != 1:
        return
    ep = _query(req["query"]).get("ep") or client
    e = lwm2m.get(ep)
    if e is None or not e["registrations"]:
        return
    reg = e["registrations"][-1]
    reg["result"] = f"{code} {COAP_CODES.get(code, '')}".strip()
    reg["response_frame"] = frame
    if location:
        reg["location"] = "/" + "/".join(location)
        owners["/".join(location)] = ep


def _lwm2m_rows(lwm2m: dict[str, dict[str, Any]], capture_end: float | None) -> list[dict[str, Any]]:
    rows = []
    for e in lwm2m.values():
        last, lifetime = e.pop("_last", None), e.pop("_lifetime", None)
        for reg in e["registrations"]:
            reg.pop("_t", None)
        regs = e["registrations"]
        ok = any((r.get("result") or "").startswith("2.") for r in regs)
        if not ok:
            e["verdict"] = ("registration refused: " + str(regs[-1].get("result"))) if regs and regs[-1].get("result") \
                else "registration not answered"
        elif e.get("deregistered_frame"):
            e["verdict"] = "deregistered"
        elif last is not None and lifetime and capture_end is not None and capture_end - last > lifetime:
            e["expired"] = True
            e["expired_at"] = iso(last + lifetime)
            e["verdict"] = (f"expired: no Update within the {lifetime} s lifetime "
                            f"(the capture goes on {round(capture_end - last - lifetime, 1)} s past it)")
        else:
            e["verdict"] = "registered"
        rows.append({k: v for k, v in e.items() if v is not None})
    return rows

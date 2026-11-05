"""5G core Service Based Interface (SBI, TS 29.500/29.501): HTTP/2 transactions between NFs.

One transaction is one HTTP/2 stream of one TCP connection: the request HEADERS (method,
``:path``) and the response HEADERS (``:status``), plus the few JSON body members the tool is
allowed to name. Each request is placed in its service (``nnrf-disc``, ``nausf-auth``,
``nudm-sdm``, ``nsmf-pdusession``, ...), which names the producer NF; the consumer comes from
the 3GPP ``User-Agent`` (TS 29.500 5.2.2.2: the NF type) or the NRF discovery's
``requester-nf-type``. A ProblemDetails ``cause`` (TS 29.500 5.2.7) is explained through
cause_lookup's ``http_sbi`` table.

Privacy: bodies are never returned. Only named members are read (identities, DNN, S-NSSAI,
PDU session id, ProblemDetails cause/title/detail, NF profile counts). Authentication material
(``5gAuthData``, ``authenticationVector``, ``kausf``, ``kseaf``, ``rand``, ``autn``,
``hxresStar``, ``xresStar``, ...) is never read into a row, only counted by key name. A SUCI
keeps its MCC, MNC, routing indicator and protection scheme; the scheme output is withheld,
in bodies and in paths. SUPI, GPSI and PEI are returned under the ``supi``, ``gpsi`` and
``pei`` keys so that redaction pseudonymises them with the IMSI, MSISDN and IMEI tokens.

Limits: tshark must see the connection as HTTP/2 (port 80/8080, a preface, or the ``ports``
argument). A header block that refers to HPACK dynamic-table entries the capture never saw
(capture started mid-connection) is counted in ``hpack_state_missing``. TLS without keys is
counted, never guessed. When one TCP segment carries DATA frames of several streams, their
JSON members cannot be split per stream and are left out (``bodies_unattributed``).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from .fields import iso, to_float, to_int

AGGREGATOR = "\x1f"
DISPLAY_FILTER = "http2"
TLS_FILTER = "tls.handshake.type == 1"

FIELDS = [
    "frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "http2.type", "http2.streamid", "http2.headers.method",
    "http2.headers.path", "http2.headers.status", "http2.headers.content_type", "http2.headers.location",
    "http2.headers.user_agent", "http2.rst_stream.error", "http2.goaway.error", "http2.header.name",
    "json.path_with_value",
]
TLS_FIELDS = ["tcp.stream", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
              "tcp.dstport"]

# Service name prefix -> producer NF (TS 29.501 and the per-service specs).
PRODUCERS: dict[str, str] = {
    "nnrf": "NRF", "nausf": "AUSF", "nudm": "UDM", "nudr": "UDR", "nsmf": "SMF", "npcf": "PCF",
    "namf": "AMF", "nchf": "CHF", "nnssf": "NSSF", "nsmsf": "SMSF", "nnef": "NEF", "nbsf": "BSF",
    "nudsf": "UDSF", "nnwdaf": "NWDAF", "nseaf": "SEAF", "n5g-eir": "5G-EIR", "nlmf": "LMF",
    "ngmlc": "GMLC", "nhss": "HSS", "nsepp": "SEPP", "nupf": "UPF", "naf": "AF",
}
NF_TYPES = frozenset({*PRODUCERS.values(), "SCP", "SEPP", "N3IWF", "TNGF", "UE", "GNB"})

# JSON members never read into a row (only counted by name).
WITHHELD = frozenset({
    "5gauthdata", "authenticationvector", "kausf", "kseaf", "rand", "autn", "hxresstar", "xresstar", "xres",
    "res", "resstar", "ck", "ik", "ckprime", "ikprime", "kasme", "auts", "eapPayload".lower(), "sharedkey",
})
# Request members named in a row (leaf path -> row key).
REQUEST_KEYS: dict[str, str] = {
    "supi": "supi", "gpsi": "gpsi", "pei": "pei", "supiorsuci": "supi_or_suci", "servingnetworkname": "serving_network",
    "dnn": "dnn", "pdusessionid": "pdu_session_id", "sst": "sst", "sd": "sd", "antype": "an_type",
    "rattype": "rat_type", "nftype": "nf_type", "requestertype": "requester_type",
}
RESPONSE_KEYS: dict[str, str] = {
    "cause": "cause", "title": "title", "detail": "detail", "authtype": "auth_type", "pdusessionid": "pdu_session_id",
}
H2_ERRORS = {0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT",
             5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL", 9: "COMPRESSION_ERROR",
             10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"}
DISCOVERY_PARAMS = ("target-nf-type", "requester-nf-type", "service-names", "snssais", "dnn", "target-plmn-list",
                    "requester-plmn-list", "tai", "supi", "gpsi")
TEXT_CAP = 200
_SUCI = re.compile(r"suci-(?P<type>\d)-(?P<mcc>\d{3})-(?P<mnc>\d{2,3})-(?P<ri>[0-9A-Fa-f]{1,4})-(?P<scheme>\d{1,2})"
                   r"-(?P<key>\d{1,3})-(?P<out>[0-9A-Za-z]+)")
_ID_PREFIX = re.compile(r"^(imsi|nai|msisdn|extid|imei|imeisv|mac)-(.+)$", re.I)
_SCHEMES = {"0": "null", "1": "profile A", "2": "profile B"}

def _cols(line: str) -> dict[str, list[str]]:
    parts = line.split("\t")
    parts += [""] * (len(FIELDS) - len(parts))
    return {f: ([v for v in parts[i].split(AGGREGATOR)] if parts[i] != "" else []) for i, f in enumerate(FIELDS)}


def _one(rec: dict[str, list[str]], field: str) -> str | None:
    vals = rec.get(field) or []
    return vals[0] if vals else None


def suci_parts(value: str) -> dict[str, Any] | None:
    """MCC, MNC, routing indicator and protection scheme of a SUCI; never the scheme output."""
    m = _SUCI.search(value or "")
    if not m:
        return None
    return {"mcc": m.group("mcc"), "mnc": m.group("mnc"), "routing_indicator": m.group("ri"),
            "protection_scheme": _SCHEMES.get(m.group("scheme"), f"scheme {m.group('scheme')}"),
            "home_network_key_id": to_int(m.group("key"))}


def scrub_suci(text: str) -> str:
    """``text`` with the scheme output of every SUCI replaced."""
    return _SUCI.sub(lambda m: m.group(0)[: m.start("out") - m.start(0)] + "<withheld>", text or "")


def identity(value: str) -> tuple[str, str] | None:
    """(row key, value) of a SBI identity string: imsi-/nai- SUPI, msisdn-/extid- GPSI, imei- PEI."""
    m = _ID_PREFIX.match((value or "").strip())
    if not m:
        return None
    kind, rest = m.group(1).lower(), m.group(2)
    if kind in ("imsi", "nai"):
        return "supi", rest
    if kind in ("msisdn", "extid"):
        return "gpsi", rest
    return "pei", rest


def service_of(path: str) -> tuple[str | None, str | None, str]:
    """(service, version, resource template) of a ``:path``: identities and ids become
    ``{supi}``, ``{gpsi}``, ``{pei}``, ``{suci}`` or ``{id}``."""
    parts = [p for p in urlsplit(path or "").path.split("/") if p]
    if not parts or not parts[0].lower().startswith("n"):
        return None, None, "/" + "/".join(parts)
    service, version = parts[0].lower(), (parts[1] if len(parts) > 1 and re.fullmatch(r"v\d+", parts[1]) else None)
    rest = parts[2:] if version else parts[1:]
    template = []
    for seg in rest:
        seg_d = unquote(seg)
        ident = identity(seg_d)
        if ident:
            template.append("{" + ident[0] + "}")
        elif _SUCI.fullmatch(seg_d):
            template.append("{suci}")
        elif re.fullmatch(r"[0-9a-fA-F-]{8,}|\d+", seg_d):
            template.append("{id}")
        else:
            template.append(seg_d)
    return service, version, "/" + "/".join(template)


def producer_of(service: str | None) -> str | None:
    if not service:
        return None
    for prefix in sorted(PRODUCERS, key=len, reverse=True):
        if service == prefix or service.startswith(prefix + "-"):
            return PRODUCERS[prefix]
    return None


def consumer_of(user_agent: str | None, query: dict[str, str]) -> str | None:
    """The consumer NF type from the 3GPP User-Agent ("AMF", "SMF-<instance>") or requester-nf-type."""
    ua = (user_agent or "").strip().upper()
    head = re.split(r"[-\s/;]", ua, maxsplit=1)[0] if ua else ""
    if head in NF_TYPES:
        return head
    req = (query.get("requester-nf-type") or "").upper()
    return req if req in NF_TYPES else None


def _json_members(values: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Leaf name -> values, and the withheld key names seen (from ``json.path_with_value``)."""
    members: dict[str, list[str]] = {}
    withheld: list[str] = []
    for item in values:
        path, sep, value = item.partition(":")
        if not sep:
            continue
        segs = [s for s in path.split("/") if s and s != "[]"]
        hidden = next((s for s in segs if s.lower() in WITHHELD), None)
        if hidden is not None:
            if hidden not in withheld:
                withheld.append(hidden)
            continue
        if not segs:
            continue
        leaf = segs[-1]
        if segs[0] == "nfInstances" and leaf == "nfInstanceId":
            members.setdefault("_profiles", []).append(value)
            continue
        members.setdefault(leaf.lower(), []).append(value)
    return members, withheld


def parse(stdout: str) -> tuple[dict[tuple[int, int], dict[str, Any]], dict[str, Any]]:
    """Transactions keyed by (tcp stream, HTTP/2 stream id), and per-connection facts."""
    txs: dict[tuple[int, int], dict[str, Any]] = {}
    conns: dict[int, dict[str, Any]] = {}
    stats = {"bodies_unattributed": 0, "hpack_state_missing": 0}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        rec = _cols(line)
        frame = to_int(_one(rec, "frame.number"))
        t = to_float(_one(rec, "frame.time_epoch"))
        tcp = to_int(_one(rec, "tcp.stream"))
        if frame is None or tcp is None:
            continue
        src = _one(rec, "ip.src") or _one(rec, "ipv6.src")
        dst = _one(rec, "ip.dst") or _one(rec, "ipv6.dst")
        sport, dport = to_int(_one(rec, "tcp.srcport")), to_int(_one(rec, "tcp.dstport"))
        conn = conns.setdefault(tcp, {"tcp_stream": tcp, "goaway": [], "first_frame": frame})
        types = [to_int(x) for x in rec["http2.type"]]
        sids = [to_int(x) for x in rec["http2.streamid"]]
        frames = list(zip(types, sids))
        headers = [sid for ftype, sid in frames if ftype == 1 and sid]
        data_streams = {sid for ftype, sid in frames if ftype == 0 and sid}
        methods, paths, statuses = rec["http2.headers.method"], rec["http2.headers.path"], rec["http2.headers.status"]
        names = rec["http2.header.name"]
        unknown = sum(1 for n in names if n.strip() == "<unknown>")

        def tx(sid: int) -> dict[str, Any]:
            return txs.setdefault((tcp, sid), {"tcp_stream": tcp, "stream_id": sid})

        def aligned(field: str) -> list[str | None]:
            vals = rec[field]
            if len(vals) == len(headers):
                return list(vals)
            if len(headers) == 1 and vals:
                return [vals[0]]
            return [None] * len(headers)

        ctypes, locs, uas = aligned("http2.headers.content_type"), aligned("http2.headers.location"), aligned("http2.headers.user_agent")
        kind = "request" if methods else "response" if statuses else None
        for i, sid in enumerate(headers):
            t_x = tx(sid)
            if unknown:
                t_x["hpack_state_missing"] = True
                t_x.setdefault("first_frame", frame)
            if kind == "request" and i < len(methods):
                if "request_frame" not in t_x:
                    t_x.update(request_frame=frame, request_time=t, method=methods[i],
                               path=paths[i] if len(paths) == len(methods) else (paths[0] if len(headers) == 1 and paths else None),
                               consumer_ip=src, producer_ip=dst, producer_port=dport, user_agent=uas[i])
                else:
                    t_x["request_repeats"] = t_x.get("request_repeats", 0) + 1
            elif kind == "response" and i < len(statuses):
                if "response_frame" not in t_x:
                    t_x.update(response_frame=frame, response_time=t, status=to_int(statuses[i]),
                               content_type=ctypes[i], location=locs[i])
                    t_x.setdefault("consumer_ip", dst)
                    t_x.setdefault("producer_ip", src)
                    t_x.setdefault("producer_port", sport)
        if unknown:
            stats["hpack_state_missing"] += 1
        bodies = rec["json.path_with_value"]
        if bodies:
            if len(data_streams) == 1:
                sid = next(iter(data_streams))
                t_x = tx(sid)
                members, withheld = _json_members(bodies)
                side = "request_body" if frame == t_x.get("request_frame") or "response_frame" not in t_x else "response_body"
                bag = t_x.setdefault(side, {})
                for k, v in members.items():
                    bag.setdefault(k, []).extend(v)
                if withheld:
                    w = t_x.setdefault("withheld_keys", [])
                    w.extend(x for x in withheld if x not in w)
            else:
                stats["bodies_unattributed"] += 1
        for ftype, sid in frames:
            if ftype == 3 and sid:
                code = to_int(_one(rec, "http2.rst_stream.error"))
                tx(sid).setdefault("reset", {"error": H2_ERRORS.get(code, f"error {code}") if code is not None else None,
                                             "frame": frame, "by": src})
        for code in rec["http2.goaway.error"]:
            c = to_int(code)
            conn["goaway"].append({"frame": frame, "error": H2_ERRORS.get(c, f"error {c}"), "by": src})
    return txs, {"connections": conns, **stats}


def _member(body: dict[str, list[str]] | None, key: str) -> str | None:
    vals = (body or {}).get(key)
    return vals[0] if vals else None


def _cap(text: str | None) -> str | None:
    if text is None:
        return None
    return text if len(text) <= TEXT_CAP else text[:TEXT_CAP] + "..."


def build_rows(txs: dict[tuple[int, int], dict[str, Any]], explain, capture_end: float | None) -> list[dict[str, Any]]:
    """One row per transaction in request order, with service, roles, latency, cause and identities."""
    rows: list[dict[str, Any]] = []
    for t in txs.values():
        path = t.get("path")
        split = urlsplit(path or "")
        query = {k: v for k, v in parse_qsl(split.query, keep_blank_values=True)}
        service, version, template = service_of(path or "")
        row: dict[str, Any] = {}
        row["method"] = t.get("method")
        if path is not None:
            row["service"] = service
            row["operation"] = f"{t.get('method')} {template}"
            row["uri"] = scrub_suci(unquote(path))
            if version:
                row["version"] = version
        status = t.get("status")
        if status is not None:
            row["status"] = status
            row["status_class"] = f"{status // 100}xx"
        if t.get("request_time") is not None and t.get("response_time") is not None:
            row["latency_ms"] = round((t["response_time"] - t["request_time"]) * 1000, 3)
        req_b, resp_b = t.get("request_body"), t.get("response_body")
        cause = _member(resp_b, "cause")
        if cause:
            row["cause"] = cause
            ex = explain(cause)
            if ex:
                row["cause_explained"] = ex
        for key, out in RESPONSE_KEYS.items():
            if key in ("cause",):
                continue
            val = _member(resp_b, key)
            if val is not None and out not in row:
                row[out] = _cap(val) if key in ("title", "detail") else val
        if resp_b and resp_b.get("_profiles") is not None:
            row["nf_profiles_returned"] = len(resp_b["_profiles"])
        row["consumer"] = consumer_of(t.get("user_agent"), query)
        row["producer"] = producer_of(service)
        row["consumer_ip"], row["producer_ip"], row["producer_port"] = (t.get("consumer_ip"), t.get("producer_ip"),
                                                                        t.get("producer_port"))
        row["tcp_stream"], row["stream_id"] = t["tcp_stream"], t["stream_id"]
        row["request_frame"], row["response_frame"] = t.get("request_frame"), t.get("response_frame")
        if row["request_frame"] is None and row["response_frame"] is None:
            row["first_frame"] = t.get("first_frame")
        if t.get("request_time") is not None:
            row["time"] = iso(t["request_time"])
        if t.get("location"):
            row["location"] = scrub_suci(t["location"])
        if t.get("content_type"):
            row["content_type"] = t["content_type"]
        # Identities: path segments, query and request body.
        for seg in [unquote(s) for s in split.path.split("/") if s] + [query.get("supi", ""), query.get("gpsi", "")]:
            ident = identity(seg)
            if ident and ident[0] not in row:
                row[ident[0]] = ident[1]
        for key, out in REQUEST_KEYS.items():
            val = _member(req_b, key)
            if val is None:
                continue
            if key in ("supi", "gpsi", "pei", "supiorsuci"):
                ident = identity(val)
                if ident:
                    row.setdefault(ident[0], ident[1])
                elif suci_parts(val):
                    row["suci"] = suci_parts(val)
                continue
            row.setdefault(out, val)
        for seg in [unquote(s) for s in split.path.split("/") if s]:
            if "suci" not in row and suci_parts(seg):
                row["suci"] = suci_parts(seg)
        if service == "nnrf-disc":
            disc = {p.replace("-", "_"): query[p] for p in DISCOVERY_PARAMS if p in query}
            if disc:
                row["discovery"] = disc
        if t.get("withheld_keys"):
            row["withheld_keys"] = t["withheld_keys"]
        if t.get("reset"):
            row["reset"] = t["reset"]
        if t.get("hpack_state_missing"):
            row["hpack_state_missing"] = True
        if t.get("request_repeats"):
            row["request_repeats"] = t["request_repeats"]
        row["outcome"] = _outcome(row, t, capture_end)
        rows.append({k: v for k, v in row.items() if v is not None})
    rows.sort(key=lambda r: (r.get("request_frame") or r.get("response_frame") or r.get("first_frame") or 0,
                             r["stream_id"]))
    return rows


def _outcome(row: dict[str, Any], t: dict[str, Any], capture_end: float | None) -> str:
    if row.get("hpack_state_missing") and "method" not in row and "status" not in row:
        return "unreadable"
    if row.get("reset"):
        return f"reset ({row['reset']['error']})"
    status = row.get("status")
    if status is None:
        if "method" not in row:
            return "response_only"
        if capture_end is not None and t.get("request_time") is not None and capture_end - t["request_time"] < 3.0:
            return "in_progress"
        return "no_response"
    if status >= 500:
        return "server_error"
    if status >= 400:
        return "client_error"
    if status >= 300:
        return "redirect"
    return "success"


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return round(s[idx], 3)


def summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per service and operation: calls, 4xx and 5xx shares, latency p50/p95/p99, causes."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        if "operation" not in r:
            continue
        g = groups.setdefault((r.get("service") or "?", r["operation"]),
                              {"service": r.get("service"), "operation": r["operation"], "producer": r.get("producer"),
                               "calls": 0, "c4xx": 0, "c5xx": 0, "unanswered": 0, "resets": 0, "_lat": [], "causes": {}})
        g["calls"] += 1
        st = r.get("status")
        if st is not None and 400 <= st < 500:
            g["c4xx"] += 1
        elif st is not None and st >= 500:
            g["c5xx"] += 1
        if r.get("outcome") == "no_response":
            g["unanswered"] += 1
        if r.get("reset"):
            g["resets"] += 1
        if r.get("latency_ms") is not None:
            g["_lat"].append(r["latency_ms"])
        if r.get("cause"):
            g["causes"][r["cause"]] = g["causes"].get(r["cause"], 0) + 1
    out = []
    for g in groups.values():
        lat = g.pop("_lat")
        calls = g["calls"]
        item = {"service": g["service"], "operation": g["operation"], "producer": g["producer"], "calls": calls,
                "pct_4xx": round(100 * g["c4xx"] / calls, 1), "pct_5xx": round(100 * g["c5xx"] / calls, 1),
                "unanswered": g["unanswered"], "resets": g["resets"],
                "latency_ms": {"p50": _pct(lat, 0.5), "p95": _pct(lat, 0.95), "p99": _pct(lat, 0.99)} if lat else None,
                "causes": g["causes"] or None}
        out.append({k: v for k, v in item.items() if v is not None})
    out.sort(key=lambda s: (-s["calls"], s["operation"]))
    return out


def tls_unreadable(stdout: str, ports: set[int]) -> dict[str, Any]:
    """TLS connections that look like SBI (ALPN h2, an SNI under 3gppnetwork.org, or a ``ports`` port)."""
    streams: set[int] = set()
    for line in stdout.splitlines():
        cols = line.split("\t") + ["", "", "", ""]
        tcp, sni, alpn, dport = to_int(cols[0]), cols[1], cols[2], to_int(cols[3])
        if tcp is None:
            continue
        if "h2" in alpn.split(",") or "3gppnetwork.org" in sni.lower() or (dport in ports):
            streams.add(tcp)
    return {"connections": len(streams)}


def verdict(rows: list[dict[str, Any]], tls_conns: int, hpack_missing: int) -> str:
    if not rows:
        if tls_conns:
            return (f"no readable SBI transaction; {tls_conns} TLS connection(s) that look like SBI are encrypted "
                    "(no keys): errors there cannot be seen")
        return "no SBI (HTTP/2) transaction in the capture; pass ports=[...] if the NFs use a port tshark does not read as HTTP/2"
    failed = [r for r in rows if r.get("outcome") in ("client_error", "server_error", "no_response")
              or str(r.get("outcome", "")).startswith("reset")]
    tail = ""
    if tls_conns:
        tail = f"; {tls_conns} TLS connection(s) are unreadable, so this is not the whole picture"
    if hpack_missing:
        tail += f"; {hpack_missing} packet(s) had header blocks from before the capture started"
    if not failed:
        return f"{len(rows)} SBI transaction(s), all answered with 2xx/3xx{tail}"
    first = failed[0]
    what = (f"{first.get('status')} {first.get('cause') or ''}".strip() if first.get("status")
            else first.get("outcome"))
    return (f"{len(failed)} of {len(rows)} SBI transaction(s) failed; first: {first.get('operation')} to "
            f"{first.get('producer') or first.get('producer_ip')} -> {what} (frame "
            f"{first.get('response_frame') or first.get('request_frame')}){tail}")

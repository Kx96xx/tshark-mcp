"""IMS registration (TS 24.229) per UE, from SIP REGISTER transactions.

A registration is a chain of REGISTER transactions for one public identity (the
To header): the initial REGISTER, the 401 challenge carrying the AKA vector, the
REGISTER with the challenge response, the 200 OK that grants an expiry and lists
the implicitly registered identities (P-Associated-URI), then refreshes and, in
the end, a REGISTER with expiry 0. The S-CSCF copies each successful
registration to application servers with a third-party REGISTER (From is the
S-CSCF, To the user), which is grouped with the user it names.

One REGISTER is usually seen on several legs (UE to P-CSCF, P-CSCF to I-CSCF,
I-CSCF to S-CSCF) with the same Call-ID and CSeq; those legs are one
transaction here. tshark flags a message identical to an earlier one as a
retransmission; one seen again within ``COPY_WINDOW`` seconds on the same leg is
a second copy of the same packet (two capture interfaces), not a resend.

Authentication material (nonce, RAND/AUTN, CK, IK, response) is never copied
into a result: only whether it was there.
"""

from __future__ import annotations

import re
from typing import Any

from . import sip
from .fields import compact, iso, parse_time, to_int

EXTRA_FIELDS = [
    "sip.Expires", "sip.P-Associated-URI", "sip.Service-Route", "sip.Path", "sip.Security-Client",
    "sip.Security-Server", "sip.Security-Verify", "sip.WWW-Authenticate", "sip.auth.digest.response",
    "sip.auth.auts", "sip.Retry-After", "sip.Min-Expires", "sip.Warning", "sip.Status-Line", "sip.User-Agent",
    "sip.Require", "sip.Content-Type", "sip.Event", "sip.Subscription-State", "sip.msg_body",
]
MULTI = ("sip.P-Associated-URI", "sip.Service-Route", "sip.Path", "sip.Contact", "sip.Security-Client",
         "sip.Security-Server", "sip.Security-Verify", "sip.Warning", "sip.Require")
FILTER = 'sip.CSeq.method == "REGISTER" || sip.CSeq.method == "SUBSCRIBE" || sip.CSeq.method == "NOTIFY"'
"""REGISTER transactions, and SUBSCRIBE/NOTIFY (kept when their Event is ``reg``)."""
COPY_WINDOW = 0.005
IN_PROGRESS_WINDOW = 32.0
"""A challenge or request this close to the end of the capture (RFC 3261 Timer F,
64*T1) may still be answered after it: the verdict is ``in_progress``."""

# Why a REGISTER is refused, in IMS terms (TS 24.229, TS 29.228 behind the CSCFs).
STATUS_HINTS = {
    400: "Bad Request: a CSCF could not parse the REGISTER",
    403: "Forbidden: the network refused the identities (IMPI/IMPU not provisioned or not associated, "
         "roaming or the access network not allowed, or the subscription barred)",
    404: "Not Found: the public identity is unknown to the HSS (Cx UAR/MAR user unknown)",
    408: "Request Timeout: a CSCF or the HSS did not answer in time (check the Cx UAR/MAR/SAR)",
    420: "Bad Extension: the UE required an option the network does not support",
    421: "Extension Required: the P-CSCF requires sec-agree (Security-Client and Require: sec-agree missing)",
    423: "Interval Too Brief: the requested expiry is below the network's Min-Expires",
    480: "Temporarily Unavailable: no S-CSCF could take the registration",
    494: "Security Agreement Required: the P-CSCF requires a security mechanism the UE did not offer",
    500: "Server Internal Error: a CSCF failed (often a failed Cx SAR or S-CSCF assignment)",
    503: "Service Unavailable: the CSCF or HSS is overloaded or has no S-CSCF; the UE should wait before retrying",
    504: "Server Time-out: a CSCF got no answer from the next hop or the HSS",
}

MMTEL = "3gpp-service.ims.icsi.mmtel"
_PARAM = re.compile(r';\s*([^=;,\s]+)(?:\s*=\s*("[^"]*"|[^;,]*))?')
_URI = re.compile(r"<([^>]*)>")
_ALGORITHM = re.compile(r'algorithm\s*=\s*"?([A-Za-z0-9\-]+)', re.I)
_MECH = re.compile(r"^\s*([A-Za-z0-9\-]+)")
_ALG = re.compile(r"\balg\s*=\s*([A-Za-z0-9\-]+)", re.I)
_EALG = re.compile(r"\bealg\s*=\s*([A-Za-z0-9\-]+)", re.I)


def _values(text: str) -> list[str]:
    return [v.strip() for v in text.split(sip.AGGREGATOR) if v.strip()] if text else []


def _uris(text: str) -> list[str]:
    """URIs of a header that may list several (``<a>, <b>``), in order, without parameters."""
    out = []
    for value in _values(text):
        found = _URI.findall(value)
        if not found:
            found = [p.split(";")[0].strip() for p in value.split(",")]
        out.extend(u for u in found if u and u not in out)
    return out


def contacts(text: str) -> list[dict[str, Any]]:
    """Contact header values as (uri, params) with parameter names lower-cased."""
    out = []
    for value in _values(text):
        # Split on commas outside <...> and quotes.
        parts, depth, quoted, cur = [], 0, False, ""
        for ch in value:
            if ch == '"':
                quoted = not quoted
            elif ch == "<" and not quoted:
                depth += 1
            elif ch == ">" and not quoted:
                depth -= 1
            if ch == "," and depth == 0 and not quoted:
                parts.append(cur)
                cur = ""
            else:
                cur += ch
        parts.append(cur)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            m = _URI.search(part)
            uri = m.group(1) if m else part.split(";")[0].strip()
            rest = part[m.end():] if m else part[len(part.split(";")[0]):]
            params = {k.lower(): (v or "").strip().strip('"') for k, v in _PARAM.findall(rest)}
            out.append({"uri": uri, "params": params})
    return out


def feature_tags(params: dict[str, str]) -> list[str]:
    """The media feature tags of a Contact (RFC 3840), values kept only where they
    say what service is meant (icsi-ref, iari-ref, accesstype); +sip.instance is
    named without its value (it carries the IMEI)."""
    out = []
    for name, value in params.items():
        if name in ("expires", "q", "transport", "reg-id", "pub-gruu", "temp-gruu", "lr"):
            continue
        if name == "+sip.instance":
            out.append("+sip.instance")
        elif name in ("+g.3gpp.icsi-ref", "+g.3gpp.iari-ref", "+g.3gpp.accesstype"):
            out.append(f"{name}={_unescape(value)}")
        elif name.startswith("+") or name in ("audio", "video", "text", "sms", "g.3gpp.nw-init-ussi"):
            out.append(name)
    return out


def _unescape(value: str) -> str:
    return value.replace("%3A", ":").replace("%3a", ":").replace("%2C", ",").replace("%2c", ",")


def _sec_agree(text: str) -> list[str]:
    out = []
    for value in _values(text):
        for offer in value.split(","):
            m = _MECH.match(offer)
            if not m:
                continue
            label = m.group(1)
            alg, ealg = _ALG.search(offer), _EALG.search(offer)
            if alg:
                label += f" alg={alg.group(1)}"
            if ealg:
                label += f" ealg={ealg.group(1)}"
            if label not in out:
                out.append(label)
    return out


_SPI = re.compile(r"\b(spi-c|spi-s|port-c|port-s)\s*=\s*(\d+)", re.I)


def _spis(text: str) -> dict[str, int] | None:
    """spi-c, spi-s, port-c and port-s of the first sec-agree offer of a header."""
    first = _values(text)[0].split(",")[0] if _values(text) else ""
    found = {k.lower(): int(v) for k, v in _SPI.findall(first)}
    return found or None


def _host(uri: str) -> str:
    text = re.sub(r"^(?i:sips?):", "", uri.strip())
    text = text.split(";")[0].split("@")[-1]
    if text.startswith("["):
        return text[1:].split("]")[0]
    return text.rsplit(":", 1)[0] if text.count(":") == 1 else text


def user_of(uri: str | None) -> str:
    """The user part of a SIP or tel URI, without a leading +, lower-cased; the whole
    value when it has no user part."""
    if not uri:
        return ""
    text = uri.strip().strip("<>\"")
    text = re.sub(r"^(?i:sips?|tel):", "", text)
    text = text.split(";")[0]
    if "@" in text:
        text = text.split("@")[0]
    return text.lstrip("+").lower()


def _expiry(contact_list: list[dict[str, Any]], expires_header: str, match: str | None = None) -> int | None:
    """The expiry of a REGISTER or its 200: the expires parameter of the Contact
    (the one with the REGISTER's URI when known), else the Expires header."""
    chosen = None
    for c in contact_list:
        if match and c["uri"] == match:
            chosen = c
            break
    if chosen is None and contact_list:
        chosen = contact_list[0] if match is None or len(contact_list) == 1 else None
    if chosen is not None and to_int(chosen["params"].get("expires")) is not None:
        return to_int(chosen["params"]["expires"])
    if chosen is None and contact_list:
        found = [to_int(c["params"].get("expires")) for c in contact_list if to_int(c["params"].get("expires")) is not None]
        if found:
            return max(found)
    return to_int(_values(expires_header)[0]) if _values(expires_header) else None


def transactions(stdout: str, fields: list[str]) -> list[dict[str, Any]]:
    """REGISTER transactions (Call-ID, CSeq) from ``-T fields`` output of ``fields``,
    in the order their first request was seen."""
    return _transactions(sip.parse_messages(stdout, fields, MULTI))


def _transactions(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    txs: dict[tuple[str, str], dict[str, Any]] = {}
    for rec in records:
        if rec["sip.CSeq.method"] != "REGISTER":
            continue
        key = (rec["sip.Call-ID"], rec["sip.CSeq.seq"])
        ts = parse_time(rec["frame.time_epoch"])
        frame = to_int(rec["frame.number"])
        leg = (rec["ip.src"], rec["ip.dst"])
        tx = txs.get(key)
        if tx is None:
            tx = txs[key] = {"call_id": key[0], "cseq": to_int(key[1]), "request": None, "time": ts, "frame": frame,
                             "legs": [], "seen": {}, "retransmissions": 0, "copies": 0, "finals": [],
                             "provisional": 0}
        if ts is not None and (tx["time"] is None or ts < tx["time"]):
            tx["time"], tx["frame"] = ts, frame
        status = to_int(rec["sip.Status-Code"])
        kind = ("req" if rec["sip.Method"] else "rsp", status)
        last = tx["seen"].get((leg, kind))
        if rec.get("sip.resend") in ("1", "True") and last is not None:
            if ts is not None and last is not None and abs(ts - last) <= COPY_WINDOW:
                tx["copies"] += 1
            elif rec["sip.Method"]:
                tx["retransmissions"] += 1
            tx["seen"][(leg, kind)] = ts
            continue
        tx["seen"][(leg, kind)] = ts
        if rec["sip.Method"] == "REGISTER":
            if leg not in tx["legs"]:
                tx["legs"].append(leg)
            if tx["request"] is None:
                tx["request"] = rec
        elif status is not None and status >= 200:
            tx["finals"].append({"status": status, "time": ts, "frame": frame, "rec": rec, "leg": leg})
        elif status is not None:
            tx["provisional"] += 1
    out = sorted(txs.values(), key=lambda t: (t["time"] if t["time"] is not None else 0.0, t["frame"] or 0))
    return [_describe(t) for t in out]


def _describe(tx: dict[str, Any]) -> dict[str, Any]:
    req = tx["request"] or (tx["finals"][0]["rec"] if tx["finals"] else {})
    req_contacts = contacts(req.get("sip.Contact", "")) if tx["request"] else []
    first_uri = req_contacts[0]["uri"] if req_contacts else None
    tags = feature_tags(req_contacts[0]["params"]) if req_contacts else []
    frm, to = req.get("sip.from.addr", ""), req.get("sip.to.addr", "")
    third_party = bool(tx["request"]) and bool(frm) and bool(to) and user_of(frm) != user_of(to)
    ue_ip = pcscf_ip = None
    if tx["request"] and tx["legs"] and first_uri and _host(first_uri) == tx["legs"][0][0]:
        ue_ip, pcscf_ip = tx["legs"][0]  # the first leg starts at the Contact address: it is the UE's own
    server_spis = next((_spis(f["rec"].get("sip.Security-Server", "")) for f in tx["finals"]
                        if f["rec"].get("sip.Security-Server")), None)
    out: dict[str, Any] = {
        "ue_ip": ue_ip, "pcscf_ip": pcscf_ip,
        "client_spis": _spis(req.get("sip.Security-Client", "")) if tx["request"] else None,
        "server_spis": server_spis,
        "call_id": tx["call_id"], "cseq": tx["cseq"], "time_epoch": tx["time"], "frame": tx["frame"],
        "from": frm, "to": to, "request_uri": req.get("sip.r-uri", ""), "third_party": third_party,
        "has_request": tx["request"] is not None,
        "legs": len(tx["legs"]) or None, "retransmissions": tx["retransmissions"], "copies": tx["copies"],
        "contact_uri": first_uri, "feature_tags": tags,
        "requested_expires": _expiry(req_contacts, req.get("sip.Expires", "")) if tx["request"] else None,
        "impi": (req.get("sip.auth.username") or "").strip('"') or None,
        "auth_response": bool((req.get("sip.auth.digest.response") or "").strip('"')),
        "auts": bool((req.get("sip.auth.auts") or "").strip('"')),
        "sec_agree": _sec_agree(req.get("sip.Security-Client", "")),
        "security_verify": bool(req.get("sip.Security-Verify")),
        "user_agent": req.get("sip.User-Agent") or None,
    }
    if tx["finals"]:
        tx["finals"].sort(key=lambda f: (f["time"] if f["time"] is not None else 0.0, f["frame"] or 0))
        final = tx["finals"][0]
        rec = final["rec"]
        line = rec.get("sip.Status-Line") or ""
        phrase = line.split(" ", 2)[2] if line.count(" ") >= 2 else None
        rsp_contacts = contacts(rec.get("sip.Contact", ""))
        www = rec.get("sip.WWW-Authenticate", "")
        alg = _ALGORITHM.search(www) if www else None
        out.update({
            "status": final["status"], "reason_phrase": phrase, "status_frame": final["frame"],
            "status_time_epoch": final["time"],
            "rtt_ms": round((final["time"] - tx["time"]) * 1000.0, 3) if final["time"] is not None and tx["time"] is not None else None,
            "granted_expires": _expiry(rsp_contacts, rec.get("sip.Expires", ""), first_uri) if final["status"] < 300 else None,
            "associated_uris": _uris(rec.get("sip.P-Associated-URI", "")),
            "service_route": _uris(rec.get("sip.Service-Route", "")),
            "path_header": _uris(rec.get("sip.Path", "")) or _uris(req.get("sip.Path", "")),
            "challenge_algorithm": alg.group(1) if alg else None,
            "security_server": _sec_agree(rec.get("sip.Security-Server", "")),
            "retry_after": to_int((_values(rec.get("sip.Retry-After", "")) or [""])[0].split(";")[0].split("(")[0].strip()),
            "min_expires": to_int((_values(rec.get("sip.Min-Expires", "")) or [""])[0]),
            "warning": rec.get("sip.Warning") or None,
        })
        others = sorted({f["status"] for f in tx["finals"]} - {final["status"]})
        if others:
            out["other_leg_statuses"] = others
    return out


def _step(tx: dict[str, Any]) -> dict[str, Any]:
    """The per-transaction row shown in a registration."""
    return compact({
        "time": iso(tx["time_epoch"]), "frame": tx["frame"], "kind": tx.get("kind"), "call_id": tx["call_id"],
        "cseq": tx["cseq"], "requested_expires": tx.get("requested_expires"),
        "auth": ("resync (AUTS)" if tx.get("auts") else "challenge response" if tx.get("auth_response") else None),
        "status": tx.get("status"), "reason_phrase": tx.get("reason_phrase"), "status_frame": tx.get("status_frame"),
        "rtt_ms": tx.get("rtt_ms"), "granted_expires": tx.get("granted_expires"),
        "challenge_algorithm": tx.get("challenge_algorithm"), "retry_after": tx.get("retry_after"),
        "min_expires": tx.get("min_expires"), "warning": tx.get("warning"),
        "other_leg_statuses": tx.get("other_leg_statuses"),
        "legs": tx.get("legs") if (tx.get("legs") or 0) > 1 else None,
        "retransmissions": tx.get("retransmissions") or None, "copies": tx.get("copies") or None,
        "no_final_response": True if tx.get("has_request") and tx.get("status") is None else None,
    })


def _steps(own: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Transaction rows; ``call_id`` is shown only where it changes (refreshes reuse it)."""
    out, previous = [], None
    for tx in own:
        step = _step(tx)
        if tx["call_id"] == previous:
            step.pop("call_id", None)
        previous = tx["call_id"]
        out.append(step)
    return out


def registrations(stdout: str, fields: list[str], capture_end: float | None) -> list[dict[str, Any]]:
    """One row per public identity (To of the user's own REGISTERs), with every
    transaction, the third-party REGISTERs that name it, the reg-event SUBSCRIBE and
    NOTIFY that concern it, and a verdict. A UE seen only in reg-event NOTIFYs
    (registered before the capture began) gets a row of its own."""
    records = sip.parse_messages(stdout, fields, MULTI)
    txs = _transactions(records)
    users: dict[str, dict[str, Any]] = {}

    def entry(to: str) -> dict[str, Any]:
        key = to.lower()
        if key not in users:
            users[key] = {"impu": to, "own": [], "third": [], "notify": [], "subscribe": [], "aliases": set(),
                          "contacts": set(), "ue_ips": set()}
        return users[key]

    for tx in txs:
        if not tx["to"]:
            continue
        u = entry(tx["to"])
        (u["third" if tx["third_party"] else "own"]).append(tx)
        if tx["third_party"]:
            continue
        u["aliases"].update(n for n in (user_of(tx["to"]), user_of(tx.get("impi"))) if n)
        if tx.get("status") is not None and 200 <= tx["status"] < 300:
            u["aliases"].update(n for n in map(user_of, tx.get("associated_uris") or []) if n)
        if tx.get("contact_uri"):
            u["contacts"].add(_bare(tx["contact_uri"]))
        if tx.get("ue_ip"):
            u["ue_ips"].add(tx["ue_ip"])
    by_alias: dict[str, dict[str, Any]] = {}
    for u in users.values():
        for name in u["aliases"]:
            by_alias.setdefault(name, u)

    notifies, subscribes = reg_event_transactions(records)
    for n in notifies:
        info = n.get("reginfo") or {}
        aors = [r["aor"] for r in info.get("registrations", []) if r.get("aor")]
        names = [user_of(a) for a in aors] or [user_of(n["to"])]
        u = next((by_alias[x] for x in names if x in by_alias), None)
        if u is None:
            if not aors:
                continue  # nothing says whose registration this is
            u = entry(aors[0])
            u["aliases"].update(x for x in names if x)
            u["aors"] = aors
            for x in names:
                by_alias.setdefault(x, u)
        u["notify"].append(n)
    for sub in subscribes:
        u = by_alias.get(user_of(sub["to"]))
        if u is not None:
            u["subscribe"].append(sub)
    rows = [_registration(u, capture_end) for u in users.values() if u["own"] or u["third"] or u["notify"]]
    rows.sort(key=lambda r: (r.get("first_time") or "", r.get("first_frame") or 0))
    return rows


# ---------------------------------------------------------------- reg event (RFC 3680)
MAX_REGINFO_BYTES = 256 * 1024
MAX_REG_EVENTS = 20
"""Reg-event NOTIFYs listed per UE (the most recent); ``counts.reg_notifications`` has them all."""
TERMINATING_EVENTS = {
    "deactivated": "network-initiated de-registration: the S-CSCF removed the contact (HSS Cx RTR, S-CSCF "
                   "reassignment or an operator action) and the UE is expected to register again",
    "probation": "network-initiated de-registration on probation: the UE should register again later "
                 "(after retry-after when given)",
    "rejected": "the network rejected the registration and removed the contact: the UE should not register "
                "again until the cause is cleared (subscription barred or not allowed)",
    "unregistered": "the contact was removed by a REGISTER with expiry 0 (the UE or a third party de-registered it)",
    "expired": "the contact expired at the S-CSCF without a refresh",
}


def _bare(uri: str | None) -> str:
    """A contact URI without parameters, brackets or case, for comparison."""
    text = (uri or "").strip().strip("<>").split(";")[0]
    return text.lower()


def _event_of(rec: dict[str, Any]) -> str:
    return (rec.get("sip.Event") or "").split(";")[0].strip().lower()


def reginfo(body: bytes) -> dict[str, Any] | None:
    """The registration state document (application/reginfo+xml, RFC 3680) as
    {version, state, registrations: [{aor, state, contacts: [{uri, state, event,
    expires, retry_after}]}]}; None when the body is not one. Documents with a DTD
    or entity declarations, or over :data:`MAX_REGINFO_BYTES`, are not parsed."""
    import xml.etree.ElementTree as ET

    if not body or len(body) > MAX_REGINFO_BYTES or re.search(rb"<!\s*(DOCTYPE|ENTITY)", body, re.I):
        return None
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None

    def local(tag: Any) -> str:
        return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""

    if local(root.tag) != "reginfo":
        return None
    regs = []
    for reg in root:
        if local(reg.tag) != "registration":
            continue
        contacts_out = []
        for ct in reg:
            if local(ct.tag) != "contact":
                continue
            uri = next((("".join(c.itertext())).strip() for c in ct if local(c.tag) == "uri"), "")
            contacts_out.append({"uri": uri, "state": (ct.get("state") or "").lower() or None,
                                 "event": (ct.get("event") or "").lower() or None,
                                 "expires": to_int(ct.get("expires")), "retry_after": to_int(ct.get("retry-after"))})
        regs.append({"aor": (reg.get("aor") or "").strip(), "state": (reg.get("state") or "").lower() or None,
                     "contacts": contacts_out})
    return {"version": to_int(root.get("version")), "state": (root.get("state") or "").lower() or None,
            "registrations": regs}


def _hex_body(text: str | None) -> bytes:
    raw = (text or "").replace(":", "").strip()
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return b""


def reg_event_transactions(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Reg-event NOTIFY and SUBSCRIBE transactions (Call-ID, CSeq), each seen once
    however many legs or copies carried it, with the first final response. A
    transaction is kept when its request says ``Event: reg``."""
    txs: dict[tuple[str, str, str], dict[str, Any]] = {}
    for rec in records:
        method = rec["sip.CSeq.method"]
        if method not in ("NOTIFY", "SUBSCRIBE"):
            continue
        key = (method, rec["sip.Call-ID"], rec["sip.CSeq.seq"])
        ts = parse_time(rec["frame.time_epoch"])
        frame = to_int(rec["frame.number"])
        tx = txs.setdefault(key, {"method": method, "request": None, "finals": [], "time": None, "frame": None})
        if rec["sip.Method"] == method:
            if tx["request"] is None or (ts is not None and tx["time"] is not None and ts < tx["time"]):
                tx["request"], tx["time"], tx["frame"] = rec, ts, frame
        else:
            status = to_int(rec["sip.Status-Code"])
            if status is not None and status >= 200:
                tx["finals"].append((ts if ts is not None else 0.0, frame or 0, status, rec))
    notifies, subscribes = [], []
    for (method, call_id, cseq), tx in txs.items():
        req = tx["request"]
        if req is None or _event_of(req) != "reg":
            continue
        final = min(tx["finals"], key=lambda f: (f[0], f[1])) if tx["finals"] else None
        out: dict[str, Any] = {
            "call_id": call_id, "cseq": to_int(cseq), "time_epoch": tx["time"], "frame": tx["frame"],
            "from": req.get("sip.from.addr", ""), "to": req.get("sip.to.addr", ""),
            "request_uri": req.get("sip.r-uri", ""), "dst": req.get("ip.dst", ""),
            "status": final[2] if final else None, "status_frame": final[1] if final else None,
            "status_time_epoch": final[0] if final else None,
        }
        if method == "NOTIFY":
            body = _hex_body(req.get("sip.msg_body"))
            ctype = (req.get("sip.Content-Type") or "").lower()
            out["subscription_state"] = (req.get("sip.Subscription-State") or "").strip() or None
            out["reginfo"] = reginfo(body) if "reginfo" in ctype or body.lstrip().startswith(b"<") else None
            out["body_unreadable"] = bool(body) and out["reginfo"] is None
            notifies.append(out)
        else:
            out["requested_expires"] = to_int((_values(req.get("sip.Expires", "")) or [""])[0])
            if final is not None and 200 <= final[2] < 300:
                out["granted_expires"] = to_int((_values(final[3].get("sip.Expires", "")) or [""])[0])
            subscribes.append(out)
    notifies.sort(key=lambda n: (n["time_epoch"] or 0.0, n["frame"] or 0))
    subscribes.sort(key=lambda n: (n["time_epoch"] or 0.0, n["frame"] or 0))
    return notifies, subscribes


def _notify_effect(n: dict[str, Any], u: dict[str, Any]) -> dict[str, Any] | None:
    """What a reg-event NOTIFY says about this user's registration: the user's own
    registration element (else the first of its implicit set), and of its contacts
    the UE's own (by Contact URI) when they are listed, else all of them."""
    info = n.get("reginfo")
    if not info:
        return None
    mine = [r for r in info["registrations"] if user_of(r["aor"]) in u["aliases"]]
    if not mine:
        return None
    own_user = user_of(u["impu"])
    reg = next((r for r in mine if user_of(r["aor"]) == own_user), mine[0])
    contacts_all = reg["contacts"]
    ours = [c for c in contacts_all if _bare(c["uri"]) in u["contacts"]]
    chosen = ours or contacts_all
    if reg["state"] == "terminated" or (chosen and all(c["state"] == "terminated" for c in chosen)):
        state = "terminated"
        pick = next((c for c in chosen if c["state"] == "terminated"), None)
    elif reg["state"] == "init" and not chosen:
        return None
    else:
        state = "active"
        active = [c for c in chosen if c["state"] != "terminated"]
        pick = min(active, key=lambda c: c["expires"] if c["expires"] is not None else 1 << 31) if active else None
    return {"state": state, "registration_state": reg["state"], "aor": reg["aor"],
            "event": (pick or {}).get("event"), "expires": (pick or {}).get("expires"),
            "retry_after": (pick or {}).get("retry_after"), "contact_matched": bool(ours)}


def _notify_row(n: dict[str, Any], eff: dict[str, Any] | None, u: dict[str, Any]) -> dict[str, Any]:
    to_ue = n.get("dst") in u["ue_ips"] or _bare(n.get("request_uri")) in u["contacts"]
    info = n.get("reginfo") or {}
    return compact({
        "time": iso(n["time_epoch"]), "frame": n["frame"], "version": info.get("version"),
        "document": info.get("state"), "aor": (eff or {}).get("aor"),
        "registration_state": (eff or {}).get("registration_state"), "contact_state": (eff or {}).get("state"),
        "event": (eff or {}).get("event"), "expires": (eff or {}).get("expires"),
        "retry_after": (eff or {}).get("retry_after"), "subscription_state": n.get("subscription_state"),
        "to_ue": True if to_ue else None, "status": n.get("status"), "status_frame": n.get("status_frame"),
        "body_unreadable": True if n.get("body_unreadable") else None,
        "no_final_response": True if n.get("status") is None else None,
    })


def _registration(u: dict[str, Any], capture_end: float | None) -> dict[str, Any]:
    own: list[dict[str, Any]] = u["own"]
    registered_until: float | None = None
    state = None
    challenges = auth_challenges = 0
    counts = {"initial": 0, "re-registration": 0, "de-registration": 0}
    last_ok: dict[str, Any] | None = None
    attempt_start: float | None = None
    time_to_register = None
    prev_status = None
    reasons: list[str] = []
    pending = [(n, _notify_effect(n, u)) for n in u.get("notify", [])]
    net: dict[str, Any] | None = None  # the last reg-event NOTIFY that changed the state
    shortened: dict[str, Any] | None = None
    notify_rows = []
    dropped: list[dict[str, Any]] = []  # terminating NOTIFYs

    def apply_notifies(before: float | None) -> None:
        nonlocal state, registered_until, net, shortened
        while pending and (before is None or (pending[0][0]["time_epoch"] or 0.0) < before):
            n, eff = pending.pop(0)
            notify_rows.append(_notify_row(n, eff, u))
            if eff is None:
                continue
            t = n["time_epoch"]
            if eff["state"] == "terminated":
                if state == "deregistered" and eff["event"] == "unregistered" and net is None:
                    continue  # the network confirming the UE's own de-registration
                state, registered_until = "deregistered", None
                net = {**eff, "frame": n["frame"], "time": t, "notify": n}
                dropped.append(net)
            elif eff["event"] == "shortened" and eff["expires"] is not None and t is not None:
                state, registered_until = "registered", t + eff["expires"]
                shortened = net = {**eff, "frame": n["frame"], "time": t, "notify": n}
            elif state != "registered" and eff["expires"] and t is not None and eff["event"] in (
                    "registered", "created", "refreshed", None):
                # Registered before the capture (or before the REGISTER the capture holds).
                state, registered_until = "registered", t + eff["expires"]
                net = {**eff, "frame": n["frame"], "time": t, "notify": n}

    for tx in own:
        apply_notifies(tx["time_epoch"])
        net = shortened = None  # a later REGISTER supersedes what a NOTIFY said
        expires = tx.get("requested_expires")
        if expires == 0:
            kind = "de-registration"
        elif prev_status in (401, 407):
            kind = "resync" if tx["auts"] else "authenticated"
        elif state == "registered" and (registered_until is None or tx["time_epoch"] is None or tx["time_epoch"] <= registered_until):
            kind = "re-registration"
        elif state is None and tx.get("auth_response") and tx is own[0]:
            kind = "re-registration"  # credentials without a challenge: the registration began before the capture
        else:
            kind = "initial"
        tx["kind"] = kind
        if kind in counts:
            counts[kind] += 1
        if kind == "initial":
            attempt_start = tx["time_epoch"]
        status = tx.get("status")
        if status is None:
            if tx.get("has_request"):
                prev_status = None
            continue
        prev_status = status
        if status in (401, 407):
            challenges += 1
            if kind in ("authenticated", "resync"):
                auth_challenges += 1
            continue
        if 200 <= status < 300:
            if kind == "de-registration":
                state, registered_until = "deregistered", None
            else:
                state = "registered"
                granted = tx.get("granted_expires")
                granted = granted if granted is not None else tx.get("requested_expires")
                end = tx.get("status_time_epoch") or tx["time_epoch"]
                registered_until = end + granted if end is not None and granted is not None else None
                last_ok = tx
                if kind in ("authenticated", "resync", "initial") and attempt_start is not None and end is not None:
                    time_to_register = round((end - attempt_start) * 1000.0, 3)
        elif status >= 300:
            state = "failed"

    apply_notifies(None)
    last = own[-1] if own else None
    if net is not None and last is not None:
        done = last.get("status_time_epoch") or last["time_epoch"]
        if done is not None and net["time"] is not None and net["time"] < done:
            net = None
    verdict = "unknown"
    # A registration granted earlier still holds while its expiry has not passed.
    still_valid = (state == "registered" and registered_until is not None
                   and (capture_end is None or capture_end <= registered_until))
    pending_since = None
    if last is not None:
        pending_since = last.get("status_time_epoch") if last.get("status") in (401, 407) else last["time_epoch"]
    near_end = (capture_end is not None and pending_since is not None
                and capture_end - pending_since <= IN_PROGRESS_WINDOW)
    probe = None
    if last is not None and last.get("status") in (401, 407) and last.get("ue_ip"):
        probe = {"ue_ip": last["ue_ip"], "pcscf_ip": last["pcscf_ip"], "after": pending_since, "final": None,
                 "frame": last.get("status_frame"), "pcscf_spis": last.get("server_spis")}
    if net is not None and net["state"] == "terminated":
        event = net.get("event")
        verdict = "expired" if event == "expired" else "deregistered"
        text = (f"reg-event NOTIFY at frame {net['frame']}: contact {event or 'terminated'}, registration "
                f"{net.get('registration_state') or 'terminated'}: "
                + TERMINATING_EVENTS.get(event or "", "the network ended the registration"))
        if net.get("retry_after") is not None:
            text += f"; retry-after {net['retry_after']} s"
        reasons.append(text)
        n = net["notify"]
        if n.get("status") is not None and n["status"] >= 300:
            reasons.append(f"the NOTIFY was answered {n['status']} (frame {n.get('status_frame')}): the subscriber "
                           "may not have learnt it is de-registered")
    elif not own and net is not None and state == "registered":
        expired = registered_until is not None and capture_end is not None and capture_end > registered_until
        verdict = "expired" if expired else "registered"
        reasons.append(f"registered before the capture began: the reg-event NOTIFY at frame {net['frame']} says "
                       f"the contact is active ({net.get('event') or 'no event'}, {net.get('expires')} s left)"
                       + (f"; not refreshed before {iso(registered_until)}" if expired else ""))
    elif not own and u.get("notify"):
        reasons.append("only reg-event NOTIFYs name this identity and none of them gives an active or terminated "
                       "contact for it; the user's own REGISTER is not in the capture")
    elif not own:
        reasons.append("only third-party REGISTERs name this identity; the user's own REGISTER is not in the capture")
    elif last.get("status") is None and last.get("has_request"):
        verdict = "registered" if still_valid else "in_progress" if near_end else "failed"
        reasons.append(f"REGISTER at frame {last['frame']} got no final response in the capture"
                       + (f" ({last['retransmissions']} retransmissions)" if last.get("retransmissions") else ""))
    elif last.get("status") in (401, 407):
        loop = auth_challenges >= 2 or (challenges >= 3 and last_ok is None)
        if loop:
            verdict = "challenge-loop"
            reasons.append(f"{challenges} REGISTERs were challenged, {auth_challenges} of them already carrying a "
                           "challenge response: the network rejects the AKA response (wrong K/OPc, IMPI not the one "
                           "the HSS holds) or the UE keeps answering a stale nonce")
            if any(t.get("auts") for t in own):
                reasons.append("the UE sent AUTS: its SQN is out of sync with the HSS (resynchronisation)")
        elif still_valid:
            verdict = "registered"
            reasons.append(f"the last REGISTER was challenged ({last['status']} at frame {last.get('status_frame')}) "
                           f"and the answer is not in the capture; the registration granted at frame "
                           f"{last_ok.get('status_frame')} holds until {iso(registered_until)}")
        elif near_end:
            verdict = "in_progress"
            reasons.append(f"challenged with {last['status']} at frame {last.get('status_frame')}, "
                           f"{round(capture_end - pending_since, 1)} s before the capture ends: the UE's answer may "
                           "simply fall after it")
        else:
            verdict = "failed"
            reasons.append(f"challenged with {last['status']} (frame {last.get('status_frame')}) and the UE never sent "
                           "the authenticated REGISTER: the SIM could not compute the AKA response (no ISIM/USIM "
                           "application, network authentication failed) or the IPsec SAs from Security-Server never "
                           "came up; look for ESP to the protected ports")
    elif last.get("status") is not None and last["status"] >= 300:
        verdict = "failed"
        hint = STATUS_HINTS.get(last["status"]) or f"refused with {last['status']}"
        text = f"{last['status']} at frame {last.get('status_frame')}: {hint}"
        if last.get("retry_after") is not None:
            text += f"; Retry-After {last['retry_after']} s"
        if last.get("min_expires") is not None:
            text += f"; Min-Expires {last['min_expires']} s (asked for {last.get('requested_expires')})"
        reasons.append(text)
        if last_ok is not None:
            reasons.append(f"an earlier registration succeeded at frame {last_ok.get('status_frame')}")
    elif state == "deregistered":
        verdict = "deregistered"
        reasons.append(f"de-registered (expires 0) at frame {last['frame']}")
    elif state == "registered":
        if registered_until is not None and capture_end is not None and capture_end > registered_until:
            verdict = "expired"
            reasons.append(f"registered until {iso(registered_until)} and not refreshed before it lapsed "
                           f"(the capture runs to {iso(capture_end)})")
        else:
            verdict = "registered"
        if shortened is not None:
            reasons.append(f"reg-event NOTIFY at frame {shortened['frame']}: the network shortened the registration "
                           f"to {shortened['expires']} s (event shortened); the UE must re-register (and "
                           f"re-authenticate) before {iso(registered_until)}")

    if verdict == "registered" and last_ok is not None and dropped:
        before = [d for d in dropped if d["time"] is not None and last_ok["time_epoch"] is not None
                  and d["time"] < last_ok["time_epoch"]]
        if before:
            reasons.append(f"the network ended an earlier registration (reg-event NOTIFY at frame {before[-1]['frame']}, "
                           f"{before[-1].get('event') or 'terminated'}) and the UE registered again (200 at frame "
                           f"{last_ok.get('status_frame')})")

    third = []
    for tx in u["third"]:
        third.append(compact({
            "time": iso(tx["time_epoch"]), "frame": tx["frame"], "application_server": tx["request_uri"],
            "from": tx["from"], "requested_expires": tx.get("requested_expires"), "status": tx.get("status"),
            "status_frame": tx.get("status_frame"), "rtt_ms": tx.get("rtt_ms"),
            "no_final_response": True if tx.get("has_request") and tx.get("status") is None else None,
        }))
        if tx.get("status") is not None and tx["status"] >= 300:
            reasons.append(f"third-party REGISTER to {tx['request_uri']} failed with {tx['status']} (frame "
                           f"{tx.get('status_frame')}): that application server does not know the user is registered")
        elif tx.get("has_request") and tx.get("status") is None:
            reasons.append(f"third-party REGISTER to {tx['request_uri']} (frame {tx['frame']}) got no final response")

    reg = last_ok or next((t for t in reversed(own) if t.get("has_request") and t.get("requested_expires") != 0), None)
    tags = (reg or {}).get("feature_tags") or []
    if reg is None:
        tags = next((t["feature_tags"] for t in own if t.get("feature_tags")), [])
    smsip = "+g.3gpp.smsip" in tags
    mmtel = any(t.startswith("+g.3gpp.icsi-ref=") and MMTEL in t for t in tags)
    if own and tags and verdict in ("registered", "expired") and not smsip:
        reasons.append("the Contact has no +g.3gpp.smsip: the UE did not register for SMS over IP, so SMS to it "
                       "is not delivered over IMS")
    if own and tags and verdict in ("registered", "expired") and not mmtel:
        reasons.append("the Contact has no MMTel ICSI (+g.3gpp.icsi-ref=...mmtel): no IMS voice for this UE")
    associated = (last_ok or {}).get("associated_uris")
    subs = []
    for sub in u.get("subscribe", []):
        mine_sub = user_of(sub["from"]) in u["aliases"]
        subs.append(compact({
            "time": iso(sub["time_epoch"]), "frame": sub["frame"], "subscriber": "ue" if mine_sub else "network",
            "from": None if mine_sub else sub["from"], "requested_expires": sub.get("requested_expires"),
            "status": sub.get("status"), "status_frame": sub.get("status_frame"),
            "granted_expires": sub.get("granted_expires"),
            "no_final_response": True if sub.get("status") is None else None,
        }))
        if mine_sub and sub.get("status") is not None and sub["status"] >= 300:
            reasons.append(f"the UE's SUBSCRIBE to the reg event (frame {sub['frame']}) was refused with "
                           f"{sub['status']} (frame {sub.get('status_frame')}): it will not hear of a network-initiated "
                           "de-registration")
    for n, eff in pending:  # NOTIFYs with no time (not expected)
        notify_rows.append(_notify_row(n, eff, u))
    if own:
        first = own[0]
    elif u["third"]:
        first = u["third"][0]
    else:
        first = u["notify"][0]
    if not own and not u["third"] and not associated:
        associated = [a for a in u.get("aors", []) if a.lower() != u["impu"].lower()] or None
    impi = next((t["impi"] for t in own if t.get("impi")), None)
    first_req = next((t for t in own if t.get("has_request")), None)
    every = own + u["third"] + u.get("notify", []) + u.get("subscribe", [])
    times = [t["time_epoch"] for t in every if t["time_epoch"] is not None]
    finals = [t["status_time_epoch"] for t in every if t.get("status_time_epoch") is not None]
    last_time = max(times + finals) if times or finals else None
    row = compact({
        "impu": u["impu"],
        "impi": impi,
        "first_time": iso(first["time_epoch"]), "first_frame": first["frame"], "last_time": iso(last_time),
        "verdict": verdict,
        "reasons": reasons,
        "registered_until": iso(registered_until) if state == "registered" and registered_until is not None else None,
        "time_to_register_ms": time_to_register,
        "user_agent": (first_req or {}).get("user_agent"),
        "contact": (reg or {}).get("contact_uri"),
        "feature_tags": tags,
        "smsip": smsip if own and tags else None,
        "mmtel": mmtel if own and tags else None,
        "sec_agree": (first_req or {}).get("sec_agree"),
        "associated_uris": associated,
        "service_route": (last_ok or {}).get("service_route"),
        "path_header": (last_ok or {}).get("path_header"),
        "counts": compact({
            "transactions": len(own), "initial": counts["initial"], "challenges": challenges,
            "re_registrations": counts["re-registration"], "de_registrations": counts["de-registration"],
            "third_party": len(u["third"]), "reg_notifications": len(notify_rows),
            "reg_subscriptions": len(subs),
        }),
        "transactions": _steps(own),
        "third_party": third,
        "reg_subscriptions": subs[-MAX_REG_EVENTS:],
        "reg_events": notify_rows[-MAX_REG_EVENTS:],
    })
    if "reasons" not in row:  # always present, right after the verdict
        row = {k: v for pair in row.items() for k, v in ((pair,) if pair[0] != "verdict" else (pair, ("reasons", reasons)))}
    if probe is not None and verdict != "challenge-loop":
        probe["final"] = verdict == "failed"
        row["_esp_probe"] = probe
    return row


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


ESP_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "esp.spi", "data.data"]
MAX_ESP_PROBES = 200


def esp_probes(rows: list[dict[str, Any]]) -> set[str]:
    """UE addresses whose last REGISTER was challenged and never answered in clear:
    the ESP they sent after the challenge is looked up (validated IP literals only)."""
    import ipaddress

    out: set[str] = set()
    for row in rows:
        probe = row.get("_esp_probe")
        if not probe:
            continue
        try:
            out.add(str(ipaddress.ip_address(probe["ue_ip"])))
        except ValueError:
            continue
        if len(out) >= MAX_ESP_PROBES:
            break
    return out


def esp_filter(addresses: set[str]) -> str | None:
    v4 = sorted(a for a in addresses if ":" not in a)
    v6 = sorted(a for a in addresses if ":" in a)
    parts = []
    if v4:
        parts.append("(ip.proto == 50 && ip.addr in {" + ", ".join(v4) + "})")
    if v6:
        parts.append("(ipv6.nxt == 50 && ipv6.addr in {" + ", ".join(v6) + "})")
    return " || ".join(parts) or None


def _spi_of(rec: dict[str, str]) -> int | None:
    spi = rec.get("esp.spi", "").split(",")[0].strip()
    if spi:
        try:
            return int(spi, 0)
        except ValueError:
            return None
    raw = rec.get("data.data", "").replace(":", "")
    return int(raw[:8], 16) if len(raw) >= 8 else None


def attach_esp(rows: list[dict[str, Any]], stdout: str | None) -> None:
    """Explain a challenge the UE never answered in clear with the ESP seen after it
    (``stdout`` from :data:`ESP_FIELDS`), and drop the internal probe markers. tshark
    may leave ESP undissected (a Decode As setting), so the SPI is also read from the
    first four bytes of the payload."""
    packets = []
    for line in (stdout or "").splitlines():
        cols = line.split("\t")
        if len(cols) < len(ESP_FIELDS):
            continue
        rec = dict(zip(ESP_FIELDS, cols))
        packets.append({"frame": to_int(rec["frame.number"]), "time": parse_time(rec["frame.time_epoch"]),
                        "src": rec["ip.src"] or rec["ipv6.src"], "dst": rec["ip.dst"] or rec["ipv6.dst"],
                        "spi": _spi_of(rec)})
    for row in rows:
        probe = row.pop("_esp_probe", None)
        if probe is None or stdout is None:
            continue
        after = probe["after"] or 0.0
        up = [p for p in packets if p["src"] == probe["ue_ip"] and p["dst"] == probe["pcscf_ip"]
              and p["time"] is not None and p["time"] >= after]
        down = [p for p in packets if p["src"] == probe["pcscf_ip"] and p["dst"] == probe["ue_ip"]
                and p["time"] is not None and p["time"] >= after]
        offered = probe.get("pcscf_spis") or {}
        expected = sorted({v for k, v in offered.items() if k.startswith("spi")})
        spis = sorted({p["spi"] for p in up if p["spi"] is not None})
        info = compact({
            "packets_from_ue": len(up), "packets_to_ue": len(down),
            "first_frame": up[0]["frame"] if up else None, "last_frame": up[-1]["frame"] if up else None,
            "spis": spis, "pcscf_offered_spis": expected,
        })
        row["esp_after_challenge"] = info
        reasons = row.setdefault("reasons", [])
        if not up:
            reasons.append(f"no ESP from the UE to the P-CSCF after the challenge (frame {probe['frame']}): the UE did "
                           "not bring up the IPsec SAs it negotiated, or this capture point does not see them")
        elif expected and any(spi not in expected for spi in spis):
            reasons.append(f"after the challenge the UE sends ESP with SPI {', '.join(str(x) for x in spis)}, not one "
                           f"the P-CSCF offered in Security-Server ({', '.join(str(x) for x in expected)})")
        elif not down:
            what = (f"the UE sent {_n(len(up), 'ESP packet')} to the P-CSCF after the challenge (frames "
                    f"{up[0]['frame']} to {up[-1]['frame']}"
                    + (f", SPI {', '.join(str(x) for x in spis)} as offered" if expected and spis else "")
                    + ") and got none back")
            if probe.get("final"):
                what += (", and no protected REGISTER left the P-CSCF: the P-CSCF is not accepting traffic on the "
                         "negotiated SA")
            reasons.append(what)
        else:
            reasons.append(f"ESP flows both ways after the challenge ({_n(len(up), 'packet')} from the UE, "
                           f"{len(down)} to it) but no protected REGISTER left the P-CSCF in the capture")


def matches(row: dict[str, Any], impu: str | None, imsi: str | None) -> bool:
    """Whether a registration row names ``impu`` (its user part or the whole URI) or
    ``imsi`` (IMSI-based IMPU or IMPI) in its own or implicit identities."""
    names = [row.get("impu", ""), row.get("impi") or "", *(row.get("associated_uris") or [])]
    if impu:
        want = impu.lower()
        wanted_user = user_of(impu)
        if not any(want in n.lower() or (wanted_user and user_of(n) == wanted_user) for n in names):
            return False
    if imsi and not any(imsi in n for n in names):
        return False
    return True


def aliases(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """User part -> the registration row, for every identity a row names (IMPU,
    IMPI, P-Associated-URI): how sms_over_ims finds the REGISTER of a UE that
    sends or receives SMS under another of its identities."""
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        for name in [row.get("impu"), row.get("impi"), *(row.get("associated_uris") or [])]:
            user = user_of(name)
            if user and user not in out:
                out[user] = row
    return out

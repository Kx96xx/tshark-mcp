"""volte_call_chain: one VoLTE call followed through SIP, Rx, Gx, GTPv2-C, PFCP and RTP.

One ``-T fields`` pass over ``sip || diameter || gtpv2 || pfcp || rtp`` gives a row per
packet. Per INVITE Call-ID the chain is rebuilt in the order the network runs it: the
INVITE and its SDP, the Rx AAR/AAA (P-CSCF to PCRF, found by the icid of
P-Charging-Vector as AF-Charging-Identifier or by the UE address as Framed-IP-Address),
the Gx RAR/RAA installing the voice rule on the UE's Gx session (the session whose CCR
carried that Framed-IP-Address), the GTPv2-C Create Bearer Request/Response on every leg
whose TEID belongs to the UE (a Create Session Response with the UE's PAA names it), the
PFCP Session Modification whose PDR names the UE address, the SIP 183/PRACK/UPDATE/180/
200 timing, the first RTP packet per direction and, at the end, BYE, Rx STR, the Gx
rule removal and Delete Bearer. Content-free: addresses, codes, timings and frames.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from .fields import iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
    "sip.Method", "sip.Status-Code", "sip.Call-ID", "sip.CSeq.method", "sip.P-Charging-Vector", "sip.Require",
    "sdp.connection_info.address", "sdp.media.port", "sdp.media_attr",
    "diameter.cmd.code", "diameter.flags.request", "diameter.applicationId", "diameter.hopbyhopid",
    "diameter.Session-Id", "diameter.Result-Code", "diameter.Experimental-Result-Code",
    "diameter.Framed-IP-Address.IPv4", "diameter.AF-Charging-Identifier", "diameter.QoS-Class-Identifier",
    "diameter.Charging-Rule-Install", "diameter.Charging-Rule-Remove", "diameter.Charging-Rule-Name",
    "gtpv2.message_type", "gtpv2.teid", "gtpv2.seq", "gtpv2.cause", "gtpv2.ebi", "gtpv2.bearer_qos_label_qci",
    "gtpv2.pdn_addr_and_prefix.ipv4",
    "pfcp.msg_type", "pfcp.seqno", "pfcp.cause", "pfcp.ue_ip_addr_ipv4",
    "rtp.ssrc",
]
_IX = {name: i for i, name in enumerate(FIELDS)}
DISPLAY_FILTER = "sip || diameter || gtpv2 || pfcp || rtp"
RX_APP, GX_APP = 16777236, 16777238
_GTP_OK = {16, 17, 18, 19}
_ICID = re.compile(r'icid-value\s*=\s*"?([^";\s]+)"?', re.IGNORECASE)

METHOD = {
    "rx": "Rx AAR whose AF-Charging-Identifier equals the call's icid (found_by icid), else whose "
          "Framed-IP-Address is the UE address (ue_ip), from 1 s before the INVITE to the end of the call",
    "gx": "Gx RAR with Charging-Rule-Install on the UE's Gx session (the session whose CCR carried the UE "
          "address: ue_ip), else the first RAR with a rule install within window_s after the AAR (time)",
    "gtp": "Create Bearer Requests whose header TEID a Create Session Response with the UE's PAA used (ue_ip), "
           "plus the proxy legs sent up to 100 ms before them (time); answers paired by sequence number",
    "pfcp": "PFCP Session Modification Request whose PDR names the UE address, within window_s",
    "rtp": "first RTP packet to and from the UE address after the INVITE",
    "status": "ok; failed (an error code); missing (expected and absent while that protocol is in the "
              "capture); not_captured (the protocol is absent from the whole capture); late (the dedicated "
              "bearer came after the 200 OK)",
}


def _hex_text(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value):
        try:
            return bytes.fromhex(value).decode("utf-8", "replace")
        except ValueError:
            return value
    return value


def _ints(cell: str) -> list[int]:
    return [v for v in (to_int(p.strip()) for p in (cell or "").split(",")) if v is not None]


def _int(cell: str) -> int | None:
    vals = _ints(cell)
    return vals[0] if vals else None


def _list(cell: str) -> list[str]:
    return [p.strip() for p in (cell or "").split(",") if p.strip()]


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
        row: dict[str, Any] = {"frame": frame, "time": parse_time(c("frame.time_epoch")),
                               "src": _list(c("ip.src"))[:1] and _list(c("ip.src"))[0],
                               "dst": _list(c("ip.dst"))[:1] and _list(c("ip.dst"))[0]}
        if c("sip.Call-ID"):
            pcv = c("sip.P-Charging-Vector")
            m = _ICID.search(pcv) if pcv else None
            row.update(kind="sip", call_id=_list(c("sip.Call-ID"))[0], method=_list(c("sip.Method"))[:1] and
                       _list(c("sip.Method"))[0] or None, status=_int(c("sip.Status-Code")),
                       cseq_method=(_list(c("sip.CSeq.method")) or [None])[0], icid=m.group(1) if m else None,
                       sdp_addrs=_list(c("sdp.connection_info.address")), sdp_ports=_ints(c("sdp.media.port")),
                       precondition="precondition" in c("sip.Require").lower()
                       or "qos" in c("sdp.media_attr").lower())
        elif c("diameter.cmd.code"):
            row.update(kind="diameter", cmd=_int(c("diameter.cmd.code")),
                       request=c("diameter.flags.request").split(",")[0].strip() in ("1", "True", "true"),
                       app=_int(c("diameter.applicationId")), hbh=c("diameter.hopbyhopid").split(",")[0].strip(),
                       session=(_list(c("diameter.Session-Id")) or [None])[0],
                       result=_int(c("diameter.Result-Code")), exp_result=_int(c("diameter.Experimental-Result-Code")),
                       framed_ip=(_list(c("diameter.Framed-IP-Address.IPv4")) or [None])[0],
                       af_charging_id=_hex_text((_list(c("diameter.AF-Charging-Identifier")) or [""])[0]) or None,
                       qci=_ints(c("diameter.QoS-Class-Identifier")),
                       install=bool(c("diameter.Charging-Rule-Install")), remove=bool(c("diameter.Charging-Rule-Remove")),
                       rules=[_hex_text(r) for r in _list(c("diameter.Charging-Rule-Name"))])
        elif c("gtpv2.message_type"):
            row.update(kind="gtp", msg=_int(c("gtpv2.message_type")), teid=_int(c("gtpv2.teid")),
                       seq=_int(c("gtpv2.seq")), cause=_int(c("gtpv2.cause")), ebi=_ints(c("gtpv2.ebi")),
                       qci=_ints(c("gtpv2.bearer_qos_label_qci")),
                       paa=(_list(c("gtpv2.pdn_addr_and_prefix.ipv4")) or [None])[0])
        elif c("pfcp.msg_type"):
            row.update(kind="pfcp", msg=_int(c("pfcp.msg_type")), seq=_int(c("pfcp.seqno")),
                       cause=_int(c("pfcp.cause")), ue_ips=_list(c("pfcp.ue_ip_addr_ipv4")))
        elif c("rtp.ssrc"):
            row.update(kind="rtp", ssrc=c("rtp.ssrc").split(",")[0].strip())
        else:
            continue
        rows.append(row)
    return rows


class _Index:
    """The non-SIP rows, indexed for the joins."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.diam = [r for r in rows if r["kind"] == "diameter"]
        self.gtp = [r for r in rows if r["kind"] == "gtp"]
        self.pfcp = [r for r in rows if r["kind"] == "pfcp"]
        self.rtp = [r for r in rows if r["kind"] == "rtp"]
        self.has = {"rx": any(r["app"] == RX_APP for r in self.diam), "gx": any(r["app"] == GX_APP for r in self.diam),
                    "gtp": bool(self.gtp), "pfcp": bool(self.pfcp), "rtp": bool(self.rtp)}
        self.answers: dict[tuple[int | None, str], dict[str, Any]] = {}
        for r in self.diam:
            if not r["request"]:
                self.answers.setdefault((r["cmd"], r["hbh"]), r)
        self.gtp_answers: dict[tuple[int | None, int | None], list[dict[str, Any]]] = {}
        for r in self.gtp:
            if r["msg"] in (96, 100):
                self.gtp_answers.setdefault((r["msg"], r["seq"]), []).append(r)
        self.pfcp_answers = {(r["msg"], r["seq"]): r for r in self.pfcp if r["msg"] == 53}
        self.ue_addresses = {r["framed_ip"] for r in self.diam if r["framed_ip"]} | \
            {r["paa"] for r in self.gtp if r["paa"]} | {ip for r in self.pfcp for ip in r["ue_ips"]}

    def answer(self, req: dict[str, Any]) -> dict[str, Any] | None:
        return self.answers.get((req["cmd"], req["hbh"]))

    def gx_sessions(self, ue: str) -> set[str]:
        return {r["session"] for r in self.diam if r["app"] == GX_APP and r["cmd"] == 272 and r["request"]
                and r["framed_ip"] == ue and r["session"]}

    def ue_teids(self, ue: str) -> set[int]:
        return {r["teid"] for r in self.gtp if r["msg"] == 33 and r["paa"] == ue and r["teid"]}


def _calls(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    calls: dict[str, dict[str, Any]] = {}
    for r in rows:
        if r["kind"] != "sip":
            continue
        call = calls.get(r["call_id"])
        if call is None:
            if r["method"] != "INVITE":
                continue
            call = calls[r["call_id"]] = {"call_id": r["call_id"], "invite": r, "msgs": [], "icid": None,
                                          "addrs": [], "ports": [], "precondition": False}
        call["msgs"].append(r)
        call["icid"] = call["icid"] or r["icid"]
        call["precondition"] = call["precondition"] or r["precondition"]
        for a in r["sdp_addrs"]:
            if a not in call["addrs"]:
                call["addrs"].append(a)
        if r is call["invite"]:
            call["ports"] = r["sdp_ports"]
    return list(calls.values())


def _first(msgs: list[dict[str, Any]], pred: Callable[[dict[str, Any]], bool]) -> dict[str, Any] | None:
    return next((m for m in msgs if pred(m)), None)


def _link(name: str, status: str, row: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"link": name, "status": status}
    if row is not None:
        out["frame"] = row["frame"]
        out["time"] = iso(row["time"])
        out["_t"] = row["time"]
    out.update({k: v for k, v in extra.items() if v is not None})
    return out


def _absent(idx: _Index, proto: str) -> str:
    return "missing" if idx.has[proto] else "not_captured"


def chain(call: dict[str, Any], idx: _Index, ue_ip: str | None, window_s: float,
          explain: Callable[..., Any]) -> dict[str, Any]:
    inv = call["invite"]
    msgs = call["msgs"]
    t_inv = inv["time"] or 0.0
    ue = ue_ip or next((a for a in call["addrs"] if a in idx.ue_addresses), None) or \
        (inv["sdp_addrs"][0] if inv["sdp_addrs"] else None)
    final = _first(msgs, lambda m: m["status"] and m["status"] >= 200 and m["cseq_method"] == "INVITE")
    bye = _first(msgs, lambda m: m["method"] == "BYE")
    t_end = (bye or msgs[-1])["time"] or t_inv
    links: list[dict[str, Any]] = []
    sdp = {"address": inv["sdp_addrs"][0] if inv["sdp_addrs"] else None, "ports": inv["sdp_ports"] or None}
    links.append(_link("invite", "ok", inv, sdp=sdp, icid=call["icid"], precondition=call["precondition"] or None))

    # Rx AAR / AAA
    aars = [r for r in idx.diam if r["app"] == RX_APP and r["cmd"] == 265 and r["request"]
            and r["time"] is not None and t_inv - 1.0 <= r["time"] <= t_end + window_s]
    aar, found = None, None
    if call["icid"]:
        aar = _first(aars, lambda r: r["af_charging_id"] == call["icid"])
        found = "icid" if aar else None
    if aar is None and ue:
        aar = _first(aars, lambda r: r["framed_ip"] == ue)
        found = "ue_ip" if aar else None
    rx_session = aar["session"] if aar else None
    t_anchor = aar["time"] if aar else None
    if aar is None:
        links.append(_link("rx_aar", _absent(idx, "rx")))
    else:
        aaa = idx.answer(aar)
        code = (aaa or {}).get("exp_result") or (aaa or {}).get("result")
        ok = aaa is not None and code is not None and 2000 <= code < 3000
        status = "ok" if ok else ("failed" if aaa is not None else "missing")
        explained = explain("diameter", code, "rx") if code is not None and not ok else None
        links.append(_link("rx_aar", status, aar, found_by=found, answer_frame=(aaa or {}).get("frame"),
                           result_code=code, explained=explained,
                           rtt_ms=_ms(aar, aaa), note=None if aaa else "AAR never answered"))
    rx_ok = links[-1]["status"] == "ok"

    # Gx RAR with a rule install
    bearer_expected = rx_ok
    if t_anchor is not None and rx_ok:
        sessions = idx.gx_sessions(ue) if ue else set()
        rars = [r for r in idx.diam if r["app"] == GX_APP and r["cmd"] == 258 and r["request"] and r["install"]
                and r["time"] is not None and t_anchor <= r["time"] <= t_anchor + window_s]
        rar = _first(rars, lambda r: r["session"] in sessions)
        found = "ue_ip" if rar else None
        if rar is None and not sessions:
            rar, found = (rars[0], "time") if rars else (None, None)
        if rar is None:
            links.append(_link("gx_rar_install", _absent(idx, "gx")))
        else:
            raa = idx.answer(rar)
            code = (raa or {}).get("exp_result") or (raa or {}).get("result")
            ok = raa is not None and code is not None and 2000 <= code < 3000
            links.append(_link("gx_rar_install", "ok" if ok else ("failed" if raa else "missing"), rar, found_by=found,
                               qci=rar["qci"][0] if rar["qci"] else None, rules=rar["rules"] or None,
                               answer_frame=(raa or {}).get("frame"), result_code=code,
                               explained=explain("diameter", code, "gx") if code is not None and not ok else None,
                               rtt_ms=_ms(rar, raa)))
            t_anchor = rar["time"]
    else:
        links.append(_link("gx_rar_install", "skipped", note="no successful Rx authorisation to act on"))

    # GTPv2-C Create Bearer on every leg
    t_200 = final["time"] if final and final["status"] == 200 else None
    bearer_t = None
    if bearer_expected and t_anchor is not None:
        teids = idx.ue_teids(ue) if ue else set()
        reqs = [r for r in idx.gtp if r["msg"] == 95 and r["time"] is not None
                and t_anchor <= r["time"] <= t_anchor + window_s]
        matched = [r for r in reqs if r["teid"] in teids]
        if matched:
            first_t = min(r["time"] for r in matched)
            legs = [(r, "ue_ip" if r in matched else "time") for r in reqs
                    if r in matched or first_t - 0.1 <= r["time"] < first_t]
        elif not teids and reqs:
            legs = [(r, "time") for r in reqs if r["time"] - reqs[0]["time"] <= 0.1]
        else:
            legs = []
        if not legs:
            links.append(_link("gtp_create_bearer", _absent(idx, "gtp")))
        else:
            out_legs, worst = [], "ok"
            for req, how in sorted(legs, key=lambda x: x[0]["time"]):
                answers = idx.gtp_answers.get((96, req["seq"]), [])
                resp = _first(answers, lambda a: a["time"] is not None and a["time"] >= req["time"])
                cause = resp["cause"] if resp else None
                leg = {"request_frame": req["frame"], "teid": f"0x{req['teid']:08x}" if req["teid"] is not None else None,
                       "src": req["src"], "dst": req["dst"], "found_by": how,
                       "qci": req["qci"][0] if req["qci"] else None}
                if resp:
                    leg.update(answer_frame=resp["frame"], cause=cause, rtt_ms=_ms(req, resp),
                               ebi=max(resp["ebi"]) if resp["ebi"] else None)
                    if cause not in _GTP_OK:
                        leg["explained"] = explain("gtpv2", cause)
                        worst = "failed"
                    else:
                        bearer_t = max(bearer_t or 0.0, resp["time"] or 0.0)
                else:
                    leg["unanswered"] = True
                    worst = "failed" if worst == "ok" else worst
                out_legs.append({k: v for k, v in leg.items() if v is not None})
            status = worst
            if status == "ok" and t_200 is not None and bearer_t is not None and bearer_t > t_200:
                status = "late"
            first_req = sorted(legs, key=lambda x: x[0]["time"])[0][0]
            links.append(_link("gtp_create_bearer", status, first_req, legs=out_legs,
                               qci=out_legs[0].get("qci")))
        # PFCP Session Modification
        mods = [r for r in idx.pfcp if r["msg"] == 52 and r["time"] is not None and ue in r["ue_ips"]
                and t_anchor <= r["time"] <= t_anchor + window_s]
        if mods:
            mod = mods[0]
            resp = idx.pfcp_answers.get((53, mod["seq"]))
            cause = (resp or {}).get("cause")
            ok = cause == 1
            links.append(_link("pfcp_modification", "ok" if ok else ("failed" if resp else "missing"), mod,
                               found_by="ue_ip", answer_frame=(resp or {}).get("frame"), cause=cause,
                               explained=explain("pfcp", cause) if cause is not None and not ok else None,
                               rtt_ms=_ms(mod, resp)))
        elif idx.has["pfcp"] and bearer_t is not None:
            links.append(_link("pfcp_modification", "missing"))
    # SIP progress
    for name, pred in (("sip_183", lambda m: m["status"] == 183),
                       ("sip_prack", lambda m: m["method"] == "PRACK"),
                       ("sip_update", lambda m: m["method"] == "UPDATE"),
                       ("sip_180", lambda m: m["status"] == 180)):
        m = _first(msgs, pred)
        if m is not None:
            links.append(_link(name, "ok", m))
    if final is None:
        links.append(_link("sip_final", "missing", note="no final response to the INVITE"))
    else:
        failed = final["status"] >= 300
        links.append(_link("sip_final", "failed" if failed else "ok", final, status_code=final["status"],
                           explained=explain("sip", final["status"]) if failed else None))
    answered = final is not None and final["status"] == 200
    # RTP, first packet per direction
    if answered and ue:
        t0 = final["time"] or t_inv
        for name, pred in (("rtp_from_ue", lambda r: r["src"] == ue), ("rtp_to_ue", lambda r: r["dst"] == ue)):
            pkt = _first(idx.rtp, lambda r: r["time"] is not None and t_inv <= r["time"] <= t_end + 1.0 and pred(r))
            if pkt is None:
                links.append(_link(name, _absent(idx, "rtp") if idx.has["rtp"] else "not_captured"))
            else:
                after = round((pkt["time"] - t0) * 1000, 1)
                on_bearer = None if bearer_t is None else pkt["time"] >= bearer_t
                links.append(_link(name, "ok", pkt, ssrc=pkt["ssrc"], ms_after_200=after,
                                   after_dedicated_bearer=on_bearer))
    if bye is not None:
        links.append(_link("bye", "ok", bye))
        if rx_session:
            str_ = _first(idx.diam, lambda r: r["app"] == RX_APP and r["cmd"] == 275 and r["request"]
                          and r["session"] == rx_session)
            links.append(_link("rx_str", "ok" if str_ else _absent(idx, "rx"), str_))
        if bearer_t is not None:
            t_bye = bye["time"] or 0.0
            remove = _first(idx.diam, lambda r: r["app"] == GX_APP and r["cmd"] == 258 and r["request"] and r["remove"]
                            and r["time"] is not None and t_bye <= r["time"] <= t_bye + window_s)
            links.append(_link("gx_rar_remove", "ok" if remove else _absent(idx, "gx"), remove))
            teids = idx.ue_teids(ue) if ue else set()
            dbr = _first(idx.gtp, lambda r: r["msg"] == 99 and r["time"] is not None
                         and t_bye <= r["time"] <= t_bye + window_s and (not teids or r["teid"] in teids))
            links.append(_link("gtp_delete_bearer", "ok" if dbr else _absent(idx, "gtp"), dbr))
    # Time order, an untimed link staying right after the link before it.
    last = t_inv
    keyed = []
    for i, link in enumerate(links):
        last = link.get("_t", last)
        keyed.append((last, i, link))
    links = [lk for _, _, lk in sorted(keyed, key=lambda x: (x[0], x[1]))]
    prev = None
    for link in links:
        t = link.pop("_t", None)
        if t is not None:
            if prev is not None:
                link["delay_ms"] = round((t - prev) * 1000, 1)
            prev = t
    broken = next((lk for lk in links if lk["status"] in ("failed", "missing", "late")), None)
    out: dict[str, Any] = {"call_id": call["call_id"], "frame": inv["frame"], "time": iso(inv["time"]),
                           "ue_ip": ue, "icid": call["icid"], "final_status": final["status"] if final else None,
                           "links": links}
    if broken is not None:
        out["first_broken_link"] = broken["link"]
    out["verdict"] = _verdict(links, broken, answered)
    return {k: v for k, v in out.items() if v is not None}


def _ms(req: dict[str, Any] | None, ans: dict[str, Any] | None) -> float | None:
    if not req or not ans or req["time"] is None or ans["time"] is None:
        return None
    return round((ans["time"] - req["time"]) * 1000, 1)


def _name(link: dict[str, Any]) -> str:
    e = link.get("explained") or {}
    return f" ({e['name']})" if e.get("name") else ""


def _verdict(links: list[dict[str, Any]], broken: dict[str, Any] | None, answered: bool) -> str:
    by = {lk["link"]: lk for lk in links}
    final = by.get("sip_final", {})
    tail = f"; the call {'was answered' if answered else 'failed with ' + str(final.get('status_code')) if final.get('status_code') else 'got no final response'}"
    if broken is None:
        b = by.get("gtp_create_bearer")
        if b and b["status"] == "ok":
            return f"every link present: dedicated bearer QCI {b.get('qci')} created (frame {b['frame']})" + tail
        return "no broken link among the protocols captured" + tail
    name = broken["link"]
    if name == "rx_aar" and broken["status"] == "failed":
        return (f"the PCRF refused the media authorisation: Rx AAA at frame {broken.get('answer_frame')} answered "
                f"{broken.get('result_code')}{_name(broken)}; no dedicated bearer was requested" + tail)
    if name == "rx_aar":
        return "no Rx AAR for this call (icid and UE address searched): the P-CSCF never asked for a bearer" + tail
    if name == "gx_rar_install":
        if broken["status"] == "failed":
            return (f"the PGW refused the voice rule: Gx RAA at frame {broken.get('answer_frame')} answered "
                    f"{broken.get('result_code')}{_name(broken)}" + tail)
        return "the PCRF authorised the media but no Gx RAR installed a rule on the UE's session" + tail
    if name == "gtp_create_bearer":
        if broken["status"] == "late":
            return (f"the dedicated bearer came after the 200 OK (Create Bearer at frame {broken['frame']}): "
                    "early media and the first audio ran on the default bearer" + tail)
        if broken["status"] == "failed":
            bad = next((leg for leg in broken.get("legs", []) if leg.get("cause") not in _GTP_OK), {})
            what = (f"cause {bad.get('cause')}" + (f" ({bad['explained']['name']})" if bad.get("explained", {}).get("name") else "")
                    if "cause" in bad else "no answer")
            rtp = "" if not answered else (
                "; the UE sent no RTP" if by.get("rtp_from_ue", {}).get("status") in ("missing",) else
                "; media ran on the default bearer")
            return (f"the dedicated bearer was never created: Create Bearer Response at frame "
                    f"{bad.get('answer_frame', bad.get('request_frame'))} {what}, so there was no QCI 1 bearer" + rtp + tail)
        return "no Create Bearer Request reached the UE's tunnels after the Gx install" + tail
    if name == "pfcp_modification":
        return f"the user plane did not take the new rules: PFCP Session Modification {broken['status']}" + tail
    if name == "sip_final":
        return f"the call failed at SIP with {final.get('status_code')}{_name(final)} while the bearer chain was intact"
    if name.startswith("rtp"):
        side = "from the UE" if name == "rtp_from_ue" else "to the UE"
        return f"the call was answered and the bearer chain is intact, but no RTP {side} was captured"
    return f"{name} {broken['status']}" + tail


def select(calls: list[dict[str, Any]], call_id: str | None, ue_ip: str | None, imsi_ips: set[str] | None
           ) -> list[dict[str, Any]]:
    out = []
    for call in calls:
        if call_id and call["call_id"] != call_id:
            continue
        if ue_ip and ue_ip not in call["addrs"] and ue_ip != call["invite"]["src"]:
            continue
        if imsi_ips is not None and not (imsi_ips & set(call["addrs"])):
            continue
        out.append(call)
    return out


def summary(chains: list[dict[str, Any]], idx: _Index) -> dict[str, Any]:
    broken: dict[str, int] = {}
    for ch in chains:
        if "first_broken_link" in ch:
            broken[ch["first_broken_link"]] = broken.get(ch["first_broken_link"], 0) + 1
    return {"calls": len(chains), "intact": sum(1 for c in chains if "first_broken_link" not in c),
            "first_broken_link": broken, "protocols_captured": [k for k, v in idx.has.items() if v]}


def build_index(rows: list[dict[str, Any]]) -> _Index:
    return _Index(rows)


def calls(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _calls(rows)

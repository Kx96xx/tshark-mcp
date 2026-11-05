"""incident_summary: one ranked list of what is wrong in a capture, built from the other tools.

The server runs the passes (pcap_info, capture_quality, conversations, then the protocol
tools the capture has) and hands each result to the rule for that pass here. Every rule
reads the numbers the tool already computed and turns the ones past a fixed threshold into a
finding with a deterministic sentence, the tool call that reproduces it and the frames it
points at. The thresholds live in :data:`THRESHOLDS` so the wording and the cut-offs stay in
one place.
"""

from __future__ import annotations

import re
from typing import Any

SEVERITIES = ("high", "medium", "low")
FOCUSES = ("auto", "web", "dns", "tls", "voip", "mobile")

THRESHOLDS = {
    "tcp_retransmission_share": 0.01,   # retransmitted data segments, capture-wide
    "tcp_min_segments": 20,             # fewer data segments say nothing about a share
    "http_5xx_share": 0.05,             # of answered requests
    "dns_unanswered_share": 0.10,       # of queries, not counting those near the capture end
    "dns_slow_p90_ms": 500.0,
    "voip_ner_pct": 80.0,               # network effectiveness below this is high severity
    "rtp_low_mos": 3.6,
    "tunnel_one_way_packets": 3,        # a one-way tunnel needs this many packets to be a finding
    "sctp_unacked_heartbeats": 2,       # one unanswered heartbeat at the end of a capture is normal
}

# Which passes a focus runs, in order, and the protocols (from the protocol hierarchy) that
# start each one: a pass runs when any of its protocols is present (None: always).
PASSES: dict[str, tuple[str | tuple[str, ...] | None, tuple[str, ...]]] = {
    "tcp_connections": ("tcp", ("web", "tls")),
    "tcp_health": ("tcp", ("web",)),
    "dns_transactions": ("dns", ("web", "dns")),
    "tls_handshakes": ("tls", ("web", "tls")),
    "quic_connections": ("quic", ("web", "tls")),
    "http_transactions": ("http", ("web",)),
    "icmp_errors": ("icmp", ("web", "dns")),
    "tunnels_overview": (("gre", "erspan", "vxlan", "geneve", "esp", "ah", "isakmp", "wg", "openvpn", "l2tp", "gtp"),
                         ("web", "mobile")),
    "call_kpis": ("sip", ("voip",)),
    "rtp_streams": ("rtp", ("voip",)),
    "ims_registration": ("sip", ("voip", "mobile")),
    "diameter_transactions": ("diameter", ("mobile",)),
    "gtp_sessions": ("gtpv2", ("mobile",)),
    "gtpv1_sessions": ("gtp", ("mobile",)),
    "pfcp_sessions": ("pfcp", ("mobile",)),
    "sctp_associations": ("sctp", ("mobile",)),
    "sigtran_messages": ("tcap", ("mobile",)),
    "expert_info": (None, ("web", "dns", "tls", "voip", "mobile")),
}

# Protocols some pass reads; anything else in the hierarchy that is not a carrier goes to
# ``not_analysed`` with the call that shows it.
COVERED = frozenset({
    "tcp", "udp", "dns", "mdns", "tls", "quic", "http", "http2", "icmp", "icmpv6", "sip", "sdp", "rtp", "rtcp",
    "rtpevent", "diameter", "gtpv2", "gtp", "gtpprime", "pfcp", "sctp", "m3ua", "sccp", "tcap", "gsm_map",
    "gsm_old", "gsm_sms", "gsm_sms_ud", "camel", "gre", "erspan", "vxlan", "geneve", "esp", "ah", "isakmp", "wg",
    "openvpn", "l2tp", "grpc", "json", "xml", "mime_multipart", "media", "data-text-lines", "urlencoded-form",
    "x509sat", "x509af", "x509ce", "pkix1explicit", "pkix1implicit",
})
# Link layers, framing, LAN background and payload placeholders: never "not analysed".
CARRIERS = frozenset({
    "frame", "eth", "ethertype", "ip", "ipv6", "sll", "sll2", "vlan", "llc", "null", "loop", "raw", "data",
    "_ws.malformed", "_ws.short", "_ws.expert", "_ws.unreassembled", "_ws.lua", "pkt_comment", "fake-field-wrapper",
    "ipv6.hopopts", "ipv6.routing", "ipv6.fraghdr", "ipv6.dstopts", "pppoes", "ppp", "mpls", "erf", "radiotap",
    "wlan_radio", "wlan", "nflog", "linux_cooked", "vntag", "etag", "stp", "lldp", "cdp", "arp", "tcp.segments",
    "ipcp", "chdlc", "fr", "gtp.ext_hdr", "pdcp-lte", "pdcp-nr",
})
# A protocol with a specialist tool but no pass: that tool is the next call.
SPECIALIST = {
    "s1ap": ("nas_procedures", {}), "nas-eps": ("nas_procedures", {}),
    "sgsap": ("sms_delivery", {"via": "sgs"}), "isup": ("sigtran_messages", {}),
}

_FRAME_IN_TEXT = re.compile(r"\bframes? (\d+)")


def pass_protocols(name: str) -> tuple[str, ...]:
    """The protocols that start a pass (empty: the pass always runs)."""
    proto = PASSES[name][0]
    return () if proto is None else (proto,) if isinstance(proto, str) else proto


def passes_for(focus: str) -> list[str]:
    if focus == "auto":
        return list(PASSES)
    return [name for name, (_proto, focuses) in PASSES.items() if focus in focuses]


def protocols(hierarchy: list[dict[str, Any]]) -> set[str]:
    """Every protocol name in a ``pcap_info`` protocol hierarchy (``eth/ip/tcp/tls`` gives four)."""
    out: set[str] = set()
    for row in hierarchy or []:
        out.update(str(row.get("protocol") or "").split("/"))
    if out & {"icmpv6"}:
        out.add("icmp")
    if out & {"http2"}:
        out.add("http")
    return out


def finding(kind: str, severity: str, text: str, tool: str, args: dict[str, Any], *, frames: list[int] | None = None,
            confidence: str = "high", next_call: dict[str, Any] | None = None,
            details: list[str] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": kind, "severity": severity, "text": text, "confidence": confidence,
                           "evidence": {"tool": tool, "args": args, "frames": sorted(set(f for f in frames or [] if f))[:5]}}
    if not out["evidence"]["frames"]:
        del out["evidence"]["frames"]
    if details:
        out["details"] = details[:3]
    out["next_call"] = next_call or {"tool": tool, "args": args}
    return out


def rank(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """High before medium before low; within one severity, confident findings first, then pass order."""
    conf = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda f: (SEVERITIES.index(f["severity"]), conf.get(f["confidence"], 3)))


def _frames(rows: list[dict[str, Any]] | None, *keys: str) -> list[int]:
    out = []
    for r in rows or []:
        for k in keys or ("frame", "first_frame", "request_frame"):
            if isinstance(r.get(k), int):
                out.append(r[k])
                break
    return out


def _text_frames(texts: list[str]) -> list[int]:
    return [int(m) for t in texts for m in _FRAME_IN_TEXT.findall(t)]


def _pct(part: float, whole: float) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


def trust_confidence(quality: dict[str, Any] | None) -> str:
    """How far loss and timing findings can be trusted, from capture_quality's verdict."""
    verdict = ((quality or {}).get("verdict") or {}).get("loss_conclusions")
    return {"trustworthy": "high", "use with care": "medium", "not trustworthy": "low"}.get(verdict, "medium")


# ------------------------------------------------------------------ rules, one per pass
def from_quality(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    verdict = r.get("verdict") or {}
    if verdict.get("loss_conclusions") != "not trustworthy":
        return []
    reasons = verdict.get("reasons") or []
    return [finding("capture_untrusted", "medium",
                    "The capture itself cannot be trusted for loss or timing conclusions" +
                    (f": {reasons[0]}" if reasons else ""), "capture_quality", args, details=reasons[1:])]


def from_tcp_connections(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    one_sided = [d for d in r.get("destinations") or [] if d.get("one_sided")]
    if one_sided:
        n = sum(d["one_sided"] for d in one_sided)
        out.append(finding("tcp_one_sided", "low",
                           f"{n} TCP connection(s) appear in one direction only: the capture point misses the other "
                           "direction, so no verdict on them is possible", "tcp_connections", args,
                           frames=_frames(one_sided, "first_frame"),
                           details=[i for d in one_sided for i in d.get("issues") or [] if "one direction" in i],
                           next_call={"tool": "capture_quality", "args": {"path": args.get("path")}}))
    for d in r.get("destinations") or []:
        attempts, connected = d.get("attempts") or 0, d.get("connected") or 0
        if not attempts or connected >= attempts:
            continue
        failed = {k: d[k] for k in ("refused", "filtered", "prohibited", "unreachable", "reset_during_handshake",
                                    "handshake_incomplete") if d.get(k)}
        how = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in failed.items()) or "not connected"
        server = d.get("server")
        server_host, _, server_port = str(server).rpartition(":")
        severity = "high" if connected == 0 else "medium"
        text = f"{server}: {connected} of {attempts} connection attempts connected ({how})"
        call_args = {**args, "view": "connections", "server": server_host.strip("[]")}
        if server_port.isdigit():
            call_args["port"] = int(server_port)
        out.append(finding("connect_failures", severity, text, "tcp_connections", args,
                           frames=_frames([d], "first_frame") + _text_frames(d.get("issues") or []),
                           details=d.get("issues"), next_call={"tool": "tcp_connections", "args": call_args}))
    return out[:6]


def from_tcp_health(r: dict[str, Any], args: dict[str, Any], confidence: str) -> list[dict[str, Any]]:
    out = []
    streams = r.get("streams") or []
    segs = retrans = 0
    lossy: list[dict[str, Any]] = []
    for s in streams:
        for k in ("client_to_server", "server_to_client"):
            d = s.get(k) or {}
            segs += d.get("data_segments") or 0
            retrans += d.get("retransmissions") or 0
            if d.get("retransmissions"):
                lossy.append(s)
    if segs >= THRESHOLDS["tcp_min_segments"] and retrans / segs > THRESHOLDS["tcp_retransmission_share"]:
        worst = lossy[0] if lossy else {}
        out.append(finding(
            "tcp_loss", "high",
            f"{_pct(retrans, segs)}% of TCP data segments were retransmitted ({retrans} of {segs}) across "
            f"{len({id(s) for s in lossy})} stream(s)", "tcp_health", args, confidence=confidence,
            frames=_frames(lossy, "first_frame", "frame"),
            details=[i for i in (worst.get("issues") or []) if "retransmitted" in i or "lost" in i],
            next_call={"tool": "tcp_health", "args": {**args, "stream": worst.get("stream")}} if worst.get("stream") is not None
            else None))
    patterns = (
        ("pmtud_black_hole", "high", "black hole", "a path MTU black hole: full-size segments never acknowledged"),
        ("zero_window", "medium", "zero window", "a receiver advertised a zero window: its application stopped reading"),
        ("middlebox_reset", "medium", "middlebox", "resets that most likely came from a middlebox, not the endpoints"),
        ("tcp_unanswered_syn", "medium", "no SYN-ACK", "SYNs without a SYN-ACK"),
    )
    for kind, severity, needle, headline in patterns:
        hit = [s for s in streams if any(needle in i for i in s.get("issues") or [])]
        if not hit:
            continue
        first = hit[0]
        detail = [i for i in first.get("issues") or [] if needle in i]
        out.append(finding(kind, severity, f"{len(hit)} TCP stream(s) show {headline}", "tcp_health", args,
                           confidence=confidence if kind != "pmtud_black_hole" else "high",
                           frames=_frames(hit, "first_frame", "frame") + _text_frames(detail), details=detail,
                           next_call={"tool": "tcp_health", "args": {**args, "stream": first.get("stream")}}
                           if first.get("stream") is not None else None))
    return out


def from_http(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    s = r.get("summary") or {}
    answered = s.get("answered") or 0
    mix = s.get("status_mix") or {}
    errors = mix.get("5xx") or 0
    issues = s.get("issues") or []
    if answered and errors / answered > THRESHOLDS["http_5xx_share"]:
        worst = [e for e in r.get("endpoints") or [] if (e.get("status") or {}).get("5xx")]
        out.append(finding("http_5xx", "high", f"{errors} of {answered} HTTP responses were 5xx ({_pct(errors, answered)}%)",
                           "http_transactions", args, frames=_frames(worst, "slowest_frame", "first_frame"),
                           details=[i for i in issues if "5xx" in i],
                           next_call={"tool": "http_transactions", "args": {**args, "view": "requests", "status": "5xx"}}))
    lost = (s.get("unanswered") or 0) - (s.get("unanswered_near_capture_end") or 0)
    if lost > 0:
        out.append(finding("http_unanswered", "medium", f"{lost} HTTP request(s) got no response in the capture",
                           "http_transactions", args, details=[i for i in issues if "no response" in i],
                           next_call={"tool": "http_transactions", "args": {**args, "view": "requests"}}))
    slow = [i for i in issues if i.startswith("p99 response")]
    if slow:
        out.append(finding("http_slow", "low", slow[0], "http_transactions", args, frames=_text_frames(slow)))
    return out


def from_dns(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    s = r.get("summary") or {}
    issues = r.get("issues") or []
    rows = r.get("transactions") or []
    queries = s.get("queries") or 0
    lost = (s.get("unanswered") or 0) - (s.get("unanswered_near_capture_end") or 0)
    if queries and lost / queries > THRESHOLDS["dns_unanswered_share"]:
        out.append(finding("dns_unanswered", "high", f"{lost} of {queries} DNS queries got no answer ({_pct(lost, queries)}%)",
                           "dns_transactions", args, details=[i for i in issues if "unanswered" in i or "none of" in i],
                           frames=_frames([t for t in rows if t.get("unanswered") and not t.get("near_capture_end")], "frame")))
    rcodes = s.get("rcodes") or {}
    if rcodes.get("SERVFAIL"):
        out.append(finding("dns_servfail", "medium", f"{rcodes['SERVFAIL']} DNS answer(s) were SERVFAIL",
                           "dns_transactions", args, details=[i for i in issues if "SERVFAIL" in i],
                           frames=_frames([t for t in rows if t.get("rcode_name") == "SERVFAIL"], "response_frame", "frame")))
    p90 = (s.get("rtt_ms") or {}).get("p90")
    if isinstance(p90, (int, float)) and p90 > THRESHOLDS["dns_slow_p90_ms"]:
        out.append(finding("dns_slow", "medium", f"DNS answers are slow: 90% within {p90} ms", "dns_transactions", args,
                           details=[i for i in issues if "slow" in i]))
    if rcodes.get("NXDOMAIN"):
        out.append(finding("dns_nxdomain", "low", f"{rcodes['NXDOMAIN']} DNS answer(s) were NXDOMAIN", "dns_transactions",
                           args, details=[i for i in issues if "NXDOMAIN" in i],
                           frames=_frames([t for t in rows if t.get("rcode_name") == "NXDOMAIN"], "response_frame", "frame")))
    return out


def from_tls(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    s = r.get("summary") or {}
    issues = r.get("issues") or []
    outcomes = s.get("outcomes") or {}
    # One-sided connections (only one direction captured) cannot be judged, so they are neither
    # failures nor part of the total. QUIC handshakes are judged by the quic_connections pass (the
    # pass runs with filter "!quic"); a QUIC row that still arrives here never counts.
    quic = [c for c in r.get("connections") or [] if c.get("transport") == "quic"]
    total = sum(outcomes.values()) - (outcomes.get("one_sided") or 0)
    total -= sum(1 for c in quic if c.get("outcome") != "one_sided")
    failed = total - (outcomes.get("established") or 0) + sum(1 for c in quic if c.get("outcome") == "established")
    rows = [c for c in r.get("connections") or [] if c.get("outcome") not in ("established", "one_sided")
            and c.get("transport") != "quic"]
    if failed > 0:
        out.append(finding("tls_failed", "high", f"{failed} of {total} TLS handshakes did not complete",
                           "tls_handshakes", args, frames=_frames(rows, "frame"),
                           details=[i for i in issues if "did not complete" in i or ": " in i][:3]))
    certs = [i for i in issues if "certificate" in i]
    if certs:
        out.append(finding("tls_certificate", "high", certs[0], "tls_handshakes", args, details=certs[1:]))
    return out


def from_icmp(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    rules = (
        ("routing_loop", "high", "routing loop", "icmp_errors"),
        ("path_mtu", "medium", "the path MTU is smaller", "icmp_errors"),
        ("prohibited", "medium", "administratively prohibited", "icmp_errors"),
        ("port_unreachable", "low", "nothing listens there", "icmp_errors"),
        ("echo_loss", "low", "echo requests", "icmp_errors"),
    )
    out = []
    for kind, severity, needle, tool in rules:
        hits = [i for i in r.get("issues") or [] if needle in i]
        if hits:
            out.append(finding(kind, severity, hits[0], tool, args, frames=_text_frames(hits), details=hits[1:]))
    return out


def from_call_kpis(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    s = r.get("summary") or {}
    failed = s.get("failed") or 0
    if not failed:
        return []
    ner = s.get("ner_pct")
    severity = "high" if isinstance(ner, (int, float)) and ner < THRESHOLDS["voip_ner_pct"] else "medium"
    codes = ", ".join(f"{k} x{v}" for k, v in sorted((s.get("failure_codes") or {}).items()))
    return [finding("call_failures", severity,
                    f"{failed} of {s.get('calls')} calls failed (NER {ner}%, ASR {s.get('asr_pct')}%)"
                    + (f"; final responses {codes}" if codes else ""), "call_kpis", args,
                    frames=_frames(r.get("worst_calls"), "frame"),
                    next_call={"tool": "call_kpis", "args": {**args, "group_by": "peer"}})]


def from_rtp(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    s = r.get("summary") or {}
    out = []
    # Streams whose SDP asks for one-way media (a=sendonly / recvonly / inactive) are not a fault.
    one_way = (s.get("one_way") or 0) - (s.get("expected_one_way") or 0)
    if one_way > 0:
        rows = [x for x in r.get("streams") or [] if x.get("one_way") and not x.get("expected_one_way")]
        out.append(finding("one_way_audio", "high", f"{one_way} of {s.get('streams')} RTP streams have no "
                           "reverse stream (one-way audio)", "rtp_streams", args, frames=_frames(rows, "first_frame")))
    if s.get("with_loss"):
        out.append(finding("rtp_loss", "medium", f"{s['with_loss']} RTP stream(s) lost packets", "rtp_streams", args))
    mos = s.get("lowest_mos_estimate")
    if isinstance(mos, (int, float)) and mos < THRESHOLDS["rtp_low_mos"]:
        out.append(finding("rtp_quality", "medium", f"the worst RTP stream has an estimated MOS of {mos}",
                           "rtp_streams", args, confidence="medium"))
    return out


def from_signalling(r: dict[str, Any], args: dict[str, Any], tool: str, what: str) -> list[dict[str, Any]]:
    s = r.get("summary") or {}
    out = []
    rows = r.get("transactions") or []
    if s.get("failed"):
        bad = [t for t in rows if (isinstance(t.get("result_code"), int) and t["result_code"] >= 3000)
               or t.get("experimental_result_code") or (isinstance(t.get("cause"), int) and t["cause"] not in (16, 17, 18, 19))]
        out.append(finding(f"{what.lower()}_failed", "medium", f"{s['failed']} {what} transaction(s) failed",
                           tool, args, frames=_frames(bad, "request_frame", "frame")))
    if s.get("unanswered"):
        out.append(finding(f"{what.lower()}_unanswered", "medium", f"{s['unanswered']} {what} request(s) got no answer",
                           tool, args, frames=_frames([t for t in rows if t.get("unanswered")], "request_frame", "frame")))
    return out


# QUIC outcomes that mean the connection did not work (handshake_only: both handshakes seen,
# no 1-RTT data yet, usually a capture that stopped early).
QUIC_FAILED = ("no_response", "version_negotiation", "retry_unanswered", "handshake_incomplete", "closed_with_error")


def from_quic(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    s = r.get("summary") or {}
    outcomes = s.get("outcomes") or {}
    total = sum(outcomes.values())
    failed = sum(outcomes.get(o) or 0 for o in QUIC_FAILED)
    if not failed:
        return []
    rows = [c for c in r.get("connections") or [] if c.get("outcome") in QUIC_FAILED]
    how = ", ".join(f"{outcomes[o]} {o.replace('_', ' ')}" for o in QUIC_FAILED if outcomes.get(o))
    if s.get("udp_443_blocked_likely"):
        text = (f"QUIC never got an answer from {len(s.get('servers_never_answering') or [])} server(s) and the "
                "clients fell back to TCP: UDP 443 looks blocked on the path")
        kind = "quic_blocked"
    else:
        text = f"{failed} of {total} QUIC connections did not complete ({how})"
        kind = "quic_failed"
    return [finding(kind, "medium", text, "quic_connections", args, frames=_frames(rows, "first_frame"),
                    details=r.get("issues"))]


def from_tunnels(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    rows = r.get("tunnels") or []
    out = []

    def where(t: dict[str, Any]) -> str:
        return f"{t.get('kind')} {t.get('endpoint_a')} <-> {t.get('endpoint_b')}"

    def call(t: dict[str, Any]) -> dict[str, Any]:
        return {"tool": "tunnels_overview", "args": {**args, "endpoint": t.get("endpoint_a")}}

    failed = [t for t in rows if (t.get("handshake") or {}).get("outcome") in ("failed", "no response")]
    if failed:
        t = failed[0]
        out.append(finding("tunnel_handshake_failed", "high",
                           f"{len(failed)} tunnel handshake(s) failed or got no response; first: {where(t)} "
                           f"({t['handshake']['outcome']})", "tunnels_overview", args,
                           frames=_frames(failed, "first_frame"), details=t.get("issues"), next_call=call(t)))
    # A tunnel with one or two packets says nothing about the reverse path.
    one_way = [t for t in rows if t.get("one_way") and t not in failed
               and max(t.get("packets_a_to_b") or 0, t.get("packets_b_to_a") or 0) >= THRESHOLDS["tunnel_one_way_packets"]]
    if one_way:
        t = one_way[0]
        out.append(finding("tunnel_one_way", "medium",
                           f"{len(one_way)} tunnel(s) carry traffic one way only; first: {where(t)}",
                           "tunnels_overview", args, frames=_frames(one_way, "first_frame"),
                           details=t.get("issues"), next_call=call(t)))
    mtu = [t for t in rows if any(k in i for i in t.get("issues") or [] for k in ("MTU", "MSS", "fragmented"))]
    if mtu:
        t = mtu[0]
        out.append(finding("tunnel_mtu", "medium", f"{len(mtu)} tunnel(s) overrun the path MTU; first: {where(t)}",
                           "tunnels_overview", args, frames=_frames(mtu, "first_frame"),
                           details=[i for i in t.get("issues") or [] if "MTU" in i or "MSS" in i or "fragmented" in i],
                           next_call=call(t)))
    return out


def from_ims(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    rows = r.get("registrations") or []
    out = []
    for verdict, kind, severity, words in (("failed", "ims_registration_failed", "high", "failed to register"),
                                           ("challenge-loop", "ims_challenge_loop", "medium",
                                            "were challenged again and again (authentication loop)")):
        hit = [x for x in rows if x.get("verdict") == verdict]
        if not hit:
            continue
        first = hit[0]
        reason = (first.get("reasons") or [None])[0]
        text = f"{len(hit)} of {len(rows)} IMS user(s) {words}" + (f"; first: {reason}" if reason else "")
        nxt = {"tool": "ims_registration", "args": {**args, "impu": first["impu"]}} if first.get("impu") else None
        out.append(finding(kind, severity, text, "ims_registration", args, frames=_frames(hit, "first_frame"),
                           details=(first.get("reasons") or [])[1:], next_call=nxt))
    return out


def _answered_failures(r: dict[str, Any], args: dict[str, Any], tool: str, what: str,
                       failed_row: Any) -> list[dict[str, Any]]:
    """Failed and unanswered requests from a paired-transaction summary; requests the capture
    ended too soon after are not counted as unanswered."""
    s = r.get("summary") or {}
    rows = r.get("transactions") or []
    out = []
    if s.get("failed"):
        out.append(finding(f"{what.lower()}_failed", "medium", f"{s['failed']} {what} request(s) were rejected",
                           tool, args, frames=_frames([t for t in rows if failed_row(t)], "request_frame", "frame")))
    lost = (s.get("unanswered") or 0) - (s.get("unanswered_near_capture_end") or 0)
    if lost > 0:
        out.append(finding(f"{what.lower()}_unanswered", "medium", f"{lost} {what} request(s) got no answer",
                           tool, args, frames=_frames([t for t in rows if t.get("unanswered")
                                                       and not t.get("near_capture_end")], "request_frame", "frame")))
    return out


def from_gtpv1(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    return _answered_failures(r, args, "gtpv1_sessions", "GTPv1-C",
                              lambda t: t.get("accepted") is False)


def from_pfcp(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    out = _answered_failures(r, args, "pfcp_sessions", "PFCP", lambda t: t.get("accepted") is False)
    s = r.get("summary") or {}
    if s.get("peer_restarts"):
        out.append(finding("pfcp_peer_restart", "high", f"{s['peer_restarts']} PFCP peer restart(s): a new Recovery "
                           "Time Stamp, so every session on that node was lost", "pfcp_sessions", args,
                           next_call={"tool": "pfcp_sessions", "args": {**args, "view": "sessions"}}))
    return out


def from_sctp(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    rows = r.get("associations") or []
    out = []

    def ep(a: dict[str, Any]) -> str:
        return f"{a.get('endpoint_a')} <-> {a.get('endpoint_b')}"

    rejected = [a for a in rows if (a.get("chunk_counts") or {}).get("INIT", 0) >= 2
                and (a.get("chunk_counts") or {}).get("ABORT", 0) >= 1]
    if rejected:
        a = rejected[0]
        cc = a["chunk_counts"]
        up = a.get("handshake") == "complete"
        out.append(finding("sctp_init_rejected", "medium" if up else "high",
                           f"{ep(a)}: {cc['INIT']} INITs and {cc['ABORT']} ABORTs"
                           + (" before the association came up" if up else "; the association never came up"),
                           "sctp_associations", args, frames=_frames(rejected, "first_frame", "abort_frame")))
    down = [a for a in rows if a.get("handshake") == "INIT without INIT_ACK" and a not in rejected]
    if down:
        out.append(finding("sctp_no_association", "high", f"{len(down)} SCTP association(s) sent INIT and got no "
                           f"INIT_ACK; first: {ep(down[0])}", "sctp_associations", args,
                           frames=_frames(down, "init_frame", "first_frame")))
    aborted = [a for a in rows if a.get("abort_seen") and a not in rejected]
    if aborted:
        out.append(finding("sctp_abort", "medium", f"{len(aborted)} SCTP association(s) were aborted; first: "
                           f"{ep(aborted[0])}", "sctp_associations", args, frames=_frames(aborted, "abort_frame")))
    hb = [a for a in rows if (a.get("heartbeats_unacked") or 0) >= THRESHOLDS["sctp_unacked_heartbeats"]]
    if hb:
        a = hb[0]
        out.append(finding("sctp_heartbeat_loss", "medium", f"{len(hb)} SCTP association(s) have unacknowledged "
                           f"heartbeats; first: {ep(a)} ({a['heartbeats_unacked']} of {a.get('heartbeats_sent')})",
                           "sctp_associations", args, frames=_frames(hb, "first_frame")))
    rtx = [a for a in rows if a.get("retransmissions")]
    if rtx:
        out.append(finding("sctp_retransmissions", "low", f"{sum(a['retransmissions'] for a in rtx)} SCTP DATA "
                           f"retransmission(s) on {len(rtx)} association(s)", "sctp_associations", args,
                           frames=_frames(rtx, "first_frame")))
    return out


def from_sigtran(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    rows = r.get("messages") or []
    s = r.get("summary") or {}
    out = []
    if s.get("unanswered_begins"):
        out.append(finding("tcap_unanswered", "medium", f"{s['unanswered_begins']} TCAP dialogue(s) were begun and "
                           "never answered", "sigtran_messages", args,
                           frames=_frames([m for m in rows if m.get("unanswered")], "frame")))
    errors: dict[str, int] = {}
    error_rows, reject_rows = [], []
    for m in rows:
        for c in m.get("components") or []:
            if c.get("type") == "returnError":
                errors[str(c.get("error") or c.get("error_code"))] = errors.get(str(c.get("error") or c.get("error_code")), 0) + 1
                error_rows.append(m)
            elif c.get("type") == "reject":
                reject_rows.append(m)
        if m.get("tcap") == "abort":
            reject_rows.append(m)
    if errors:
        names = ", ".join(f"{k} x{v}" for k, v in sorted(errors.items(), key=lambda kv: (-kv[1], kv[0])))
        out.append(finding("map_errors", "medium", f"{sum(errors.values())} MAP/TCAP error(s) returned: {names}",
                           "sigtran_messages", args, frames=_frames(error_rows, "frame")))
    if reject_rows:
        out.append(finding("tcap_rejects", "medium", f"{len(reject_rows)} TCAP reject(s) or abort(s): the peer "
                           "could not parse or refused the dialogue", "sigtran_messages", args,
                           frames=_frames(reject_rows, "frame")))
    return out


def from_expert(r: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    s = r.get("summary") or {}
    errors = (s.get("by_severity") or {}).get("error") or 0
    if not errors:
        return []
    items = [i for i in r.get("items") or [] if i.get("severity") == "error"]
    malformed = s.get("malformed_frames") or 0
    protos = sorted({str(i.get("protocol")) for i in items if i.get("protocol")})
    text = (f"tshark flagged {errors} error(s)" + (f", {malformed} malformed packet(s)," if malformed else "")
            + f" in {', '.join(protos[:5]) or 'the capture'}")
    details = [f"{i.get('protocol')}: {i.get('summary')} (x{i.get('count')})" for i in items[:3]]
    return [finding("expert_errors", "low", text, "expert_info", args, confidence="medium",
                    frames=(s.get("malformed_first_frames") or []) + _frames(items, "first_frame"), details=details)]


def not_analysed(hierarchy: list[dict[str, Any]], args: dict[str, Any]) -> list[dict[str, Any]]:
    """Protocols in the capture that no pass reads, most frames first, each with the call that
    shows them (a specialist tool when one exists, else filter_packets)."""
    frames: dict[str, int] = {}
    for row in hierarchy or []:
        name = str(row.get("protocol") or "").rsplit("/", 1)[-1]
        if not name or name in COVERED or name in CARRIERS or name.startswith("_ws."):
            continue
        frames[name] = max(frames.get(name, 0), int(row.get("frames") or 0))
    out = []
    for name, n in sorted(frames.items(), key=lambda kv: (-kv[1], kv[0]))[:10]:
        tool, extra = SPECIALIST.get(name, ("filter_packets", {"display_filter": name, "limit": 20}))
        out.append({"protocol": name, "frames": n, "next_call": {"tool": tool, "args": {**args, **extra}}})
    return out

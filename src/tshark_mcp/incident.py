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
}

# Which passes a focus runs, in order, and the protocol (from the protocol hierarchy) each needs.
PASSES: dict[str, tuple[str, tuple[str, ...]]] = {
    "tcp_connections": ("tcp", ("web", "tls")),
    "tcp_health": ("tcp", ("web",)),
    "dns_transactions": ("dns", ("web", "dns")),
    "tls_handshakes": ("tls", ("web", "tls")),
    "http_transactions": ("http", ("web",)),
    "icmp_errors": ("icmp", ("web", "dns")),
    "call_kpis": ("sip", ("voip",)),
    "rtp_streams": ("rtp", ("voip",)),
    "diameter_transactions": ("diameter", ("mobile",)),
    "gtp_sessions": ("gtpv2", ("mobile",)),
}

_FRAME_IN_TEXT = re.compile(r"\bframes? (\d+)")


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
    total = sum(outcomes.values())
    # One-sided connections (only one direction captured) cannot be judged, so they are neither
    # failures nor part of the total.
    total -= outcomes.get("one_sided") or 0
    failed = total - (outcomes.get("established") or 0)
    rows = [c for c in r.get("connections") or [] if c.get("outcome") not in ("established", "one_sided")]
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
    if s.get("one_way"):
        rows = [x for x in r.get("streams") or [] if x.get("one_way") or "one-way" in str(x.get("issues") or "")]
        out.append(finding("one_way_audio", "high", f"{s['one_way']} of {s.get('streams')} RTP streams have no "
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

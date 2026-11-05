"""One-line descriptions of every tool argument, for the input schemas.

Directory graders and models read a schema ``description`` per argument (mcp-builder audit
gap G1). The ``_tool`` decorator gives each argument that has no ``Field(description=...)``
the text here: ``"<tool>.<argument>"`` first, then the shared ``"<argument>"`` entry. Keep each
line short (the compact tool list carries them, see tests/test_tool_list.py): what the value
is and its form; the tool description says how it is used. A new tool argument with a name
not listed here fails tests/test_tool_list.py::test_every_argument_has_a_description.
"""

from __future__ import annotations

from . import callkpi, capdiff, expert, icmperr, nasproc, overlays, rates, search, tcpconn, throughput


def _one_of(values: tuple[str, ...], room: int = 100) -> str:
    """The values joined, cut with ", ..." to stay inside the line budget (the error lists them all)."""
    out = ""
    for v in values:
        part = (", " if out else "") + v
        if len(out) + len(part) > room:
            return out + ", ..."
        out += part
    return out

MAX_CHARS = 120

SHARED: dict[str, str] = {
    "path": "Capture file (absolute, in an allowed dir) or open_capture handle",
    "path_a": "First capture (working, or before): absolute path",
    "path_b": "Second capture (failing, or after): absolute path",
    "limit": "Most rows per page",
    "offset": "Rows to skip (next_offset)",
    "filter": "Extra display filter, ANDed",
    "display_filter": "Wireshark display filter selecting the packets",
    "imsi": "IMSI, 6 to 15 digits",
    "msisdn": "MSISDN (E.164 digits, no +)",
    "call_id": "SIP Call-ID of the call",
    "teid": "GTP TEID: an int or hex string such as 0xc001",
    "seid": "PFCP SEID: an int or hex string",
    "apn": "APN (DNN) name, such as internet",
    "number": "Phone number digits found in From, To, Request-URI or P-Asserted-Identity",
    "impu": "IMS public identity (sip: or tel: URI, or part of it)",
    "ue_ip": "UE IP address",
    "session_id": "Diameter Session-Id",
    "command_code": "Diameter command code, such as 316 (ULR) or 272 (CCR)",
    "frame": "Frame number",
    "server": "Server IP address",
    "server_name": "TLS SNI (server name), or part of it",
    "host": "Host name, or part of it",
    "heuristic": "Also decode RTP without SIP/SDP (heuristic RTP over UDP)",
    "mtu": "Path MTU in bytes for the MTU checks",
    "interval": "Bucket size in seconds",
    "window_s": "Seconds within which messages of different legs or interfaces are joined",
    "max_files": "Most files read in this call",
    "method": "SIP method (INVITE, REGISTER, ...)",
    "application": "Diameter application name (s6a, gx, gy, rx, cx, sh, s13, swx) or id",
    "realm": "Diameter realm",
    "name": "DNS name, or the end of it",
    "detail": "key (the AVPs or IEs that explain a result) or full",
    "message": "Message name to keep",
    "query": "Words to search for",
    "protocol": "Protocol name",
    "kind": "Kind to keep",
    "view": "Which rows to return",
}

PER_TOOL: dict[str, str] = {
    # TCP/IP
    "tcp_health.stream": "tcp.stream index of one connection",
    "tcp_connections.port": "Server TCP port",
    "tcp_connections.client": "Client IP address",
    "tcp_connections.outcome": "Keep one outcome: " + _one_of(tcpconn.OUTCOMES, 90),
    "tcp_connections.view": "connections (one row per attempt) or destinations (per server and port)",
    "icmp_errors.sender": "IP address that sent the ICMP errors",
    "icmp_errors.about": "IP address inside the quoted packet",
    "icmp_errors.kind": "Keep one kind: " + _one_of(icmperr.KINDS),
    "http_transactions.path_prefix": "Request path prefix, such as /api",
    "http_transactions.status": "Status code or class: 404, 5xx, 4xx",
    "http_transactions.method": "HTTP method (GET, POST, ...)",
    "http_transactions.min_ms": "Keep requests slower than this many ms",
    "http_transactions.view": "requests (one row each) or endpoints (per method, host and path)",
    "conversations.layer": "ip, ipv6, tcp, udp, sctp or eth",
    "dns_transactions.name": "Query name, or the end of it",
    "tls_certificates.expiring_within_days": "Flag certificates that expire within this many days",
    "throughput_timeline.per": _one_of(throughput.PERS),
    "throughput_timeline.top": "Most series listed when per is not total",
    "tunnels_overview.kind": _one_of(overlays.KINDS),
    "tunnels_overview.endpoint": "Outer IP address of one tunnel end",
    "diff_captures.by": "all or one of " + _one_of(capdiff.SECTIONS),
    "diff_captures.include_same": "Also list keys that did not change",
        # Generic
    "filter_packets.fields": "tshark field names to return per packet (default: a short summary)",
    "packet_detail.layers": "Protocol layers to keep, such as [\"diameter\"]",
    "packet_detail.max_fields": "Most fields returned",
    "expert_info.severity": "Lowest severity listed: " + _one_of(expert.SEVERITIES),
    "find_fields.query": "Words or part of a field name, such as 'result code'",
    "find_fields.protocol": "Keep fields of this protocol (diameter, gtpv2, sip, ...)",
    "check_filter.filter": "Display filter to check",
    "cause_lookup.protocol": "diameter, gtpv2, gtpv1, pfcp, nas_emm, nas_esm, s1ap, ngap, sip, q850, map, ... (see the description)",
    "cause_lookup.code": "The code: 78, \"0x4e\", \"radioNetwork:21\" (s1ap, ngap) or a ProblemDetails cause (http_sbi)",
    "cause_lookup.message": "SIP method the code answered (REGISTER, INVITE, ...)",
    "cause_lookup.query": "Words to search the cause names for",
    "find_identifier.identifier": "IMSI, MSISDN, IP, Call-ID or Diameter Session-Id",
    "find_identifier.kind": _one_of(search.KINDS),
    "find_identifier.path": "Absolute path of a capture file or a directory of captures",
    "capture_index.path": "Absolute path of a directory of capture files",
    "capture_index.start": "Window start: ISO 8601, epoch s, +Ns from the first file, -Ns from the last",
    "capture_index.end": "Window end, same forms as start",
    "capture_index.min_gap_s": "Shortest gap between files reported as a hole, seconds",
    "incident_summary.focus": "auto, web, dns, tls, voip or mobile",
    "incident_summary.budget_s": "Time budget for the whole call, seconds",
    "export_subset.name": "File name to create in the export directory (no path)",
    "export_subset.max_packets": "Most packets written",
    "export_subset.snaplen": "Cut each packet to this many bytes",
    "export_subset.headers_only": "Cut every packet to 96 bytes so no payload leaves",
    # Telecom
    "diameter_avps.max_avps": "Most AVPs per message",
    "gtp_ies.max_ies": "Most IEs per message",
    "gtp_ies.message": "GTPv2-C message name or type number, such as Create Session Request or 32",
    "pfcp_sessions.view": "sessions or transactions",
    "message_rates.protocol": _one_of(rates.PROTOCOLS),
    "message_rates.burst_min": "Fewest messages per interval in a burst",
    "message_rates.storm_min": "Fewest repeats of one request for a subscriber loop",
    "call_kpis.group_by": _one_of(callkpi.GROUP_BY),
    "call_kpis.prefix_len": "Digits of the destination prefix",
    "call_legs.ladder": "Also return a text ladder of the legs",
    "nas_procedures.guti": "M-TMSI: an int or 0x hex",
    "nas_procedures.ue_id": "mme_ue_s1ap_id:enb_ue_s1ap_id, such as 7:3",
    "nas_procedures.procedure": "Keep one kind: " + _one_of(nasproc.KINDS),
    "nas_procedures.null_cipher": "Decode NAS of UEs whose Security Mode Command chose EEA0 (null ciphering)",
    "sigtran_health.peer": "IP address or ip:port of an SCTP peer",
    "sigtran_health.point_code": "Signalling point code (an int)",
    "sigtran_health.gt": "SCCP global title digits",
    "sms_delivery.via": "map or sgs (default: both)",
    "rtp_streams.ssrc": "RTP SSRC: decimal or 0x hex",
    "roaming_attach_check.home_plmn": "Home PLMN as MCC-MNC, such as 001-01 (default: from the IMSI)",
    "compare_captures.imsi_b": "IMSI in the second capture, when it differs",
    "compare_captures.msisdn_b": "MSISDN in the second capture, when it differs",
    "compare_captures.collapse_repeats": "Fold repeated identical messages into one step",
    "diameter_peers.host": "Origin-Host of a peer, or part of it",
}


def describe(tool: str, arg: str) -> str | None:
    """The schema description of ``arg`` of ``tool``, or None when there is none."""
    return PER_TOOL.get(f"{tool}.{arg}") or SHARED.get(arg)

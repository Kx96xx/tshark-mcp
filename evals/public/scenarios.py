"""One scenario per public-validation defect (D2 to D23): the call that showed the defect and the
facts the fixed tool must report on that public capture. ``{captures}`` is the fetch directory;
paths below it are the ``file`` entries of captures.json."""

from __future__ import annotations

from ..harness import Check as C
from ..harness import Scenario, Step

BIG = 200_000  # some results (incident_summary, http on a big file) are large; the budget is not the point here


def _s(id_: str, question: str, *steps: Step) -> Scenario:
    return Scenario(id=id_, question=question, steps=steps, max_calls=len(steps), max_tokens=BIG)


def _p(file: str) -> str:
    return "{captures}/" + file


SCENARIOS: list[Scenario] = [
    _s("D2_one_sided_client", "A client-only TLS 1.3 stream: not filtered, no high-severity failures.",
       Step("tcp_connections", {"path": _p("ndpi/tls_1.3_unidirectional_client.pcapng")},
            (C("connections[0].outcome", "eq", "one_sided"),
             C("connections[0].missing_direction", "eq", "server_to_client"))),
       Step("incident_summary", {"path": _p("ndpi/tls_1.3_unidirectional_client.pcapng")},
            (C("findings[kind=connect_failures]", "absent"), C("findings[kind=tls_failed]", "absent"),
             C("findings[kind=tcp_one_sided].severity", "eq", "low")))),
    _s("D2_one_sided_server", "Server-only streams: one_sided, not handshake_incomplete.",
       Step("tcp_connections", {"path": _p("ndpi/tls_1.2_unidirectional_server.pcapng")},
            (C("connections[0].outcome", "eq", "one_sided"),)),
       Step("tcp_connections", {"path": _p("wireshark-testcaptures/dns-ooo.pcap")},
            (C("connections[0].outcome", "eq", "one_sided"),))),
    _s("D4_quic_same_address", "Loopback QUIC v2 with client and server on ::1: the handshake worked.",
       Step("quic_connections", {"path": _p("ndpi/quic-v2.pcapng")},
            (C("connections[0].outcome", "eq", "established"), C("summary.servers_never_answering", "absent")))),
    _s("D18_gquic", "Google QUIC is counted, not silently ignored.",
       Step("quic_connections", {"path": _p("ndpi/quic.pcap")},
            (C("summary.gquic_packets", "ge", 1), C("issues[*]", "regex", "Google QUIC")))),
    _s("D5_quic_not_copies", "Distinct QUIC packets with one offloaded checksum are not copies.",
       Step("capture_quality", {"path": _p("ndpi/quic-v2.pcapng")}, (C("duplicates.copies", "eq", 0),)),
       Step("capture_quality", {"path": _p("wireshark-testcaptures/quic-with-secrets.pcapng")},
            (C("duplicates.copies", "eq", 0),))),
    _s("D6_identical_rsts", "Byte-identical RSTs from Linux are real repeats, not mirror copies.",
       Step("capture_quality", {"path": _p("wireshark-wiki/chargen-tcp.pcap")},
            (C("duplicates.copies", "eq", 0), C("duplicates.repeated_identical.rsts", "eq", 5)))),
    _s("D7_rtp_attribution", "The second call's stream is not tagged with the first call's Call-ID.",
       Step("rtp_streams", {"path": _p("wireshark-wiki/sip-rtp-g711.pcap"), "call_id": "1-1966@10.0.2.20"},
            (C("streams[*].ssrc", "eq", "0x343da99b"), C("streams[1]", "absent"))),
       Step("media_path_check", {"path": _p("wireshark-wiki/sip-rtp-g711.pcap"), "call_id": "1-1966@10.0.2.20"},
            (C("issues[kind=source_differs_from_sdp]", "absent"), C("issues[kind=payload_type_not_negotiated]", "absent")))),
    _s("D19_rtp_over_turn", "Heuristic RTP finds RTP relayed through TURN.",
       Step("rtp_streams", {"path": _p("ndpi/stun_dtls_rtp_unidir.pcapng"), "heuristic": True},
            (C("summary.streams", "ge", 1),))),
    _s("D9a_http_first_segment", "Responses tshark cannot reassemble are read from their first segment.",
       Step("http_transactions", {"path": _p("wireshark-wiki/http_redirects.pcapng")},
            (C("summary.unanswered", "eq", 0), C("summary.answered", "eq", 48)))),
    _s("D9c_http2_response", "The HTTP/2 response whose HPACK block has a table size update is paired.",
       Step("http_transactions", {"path": _p("wireshark-testcaptures/quic-with-secrets.pcapng")},
            (C("summary.unanswered", "eq", 0), C("requests[0].status", "eq", 200)))),
    _s("D11_ttfb", "A 93 s transfer behind a 451 ms first byte is a slow transfer, not a slow server.",
       Step("http_transactions", {"path": _p("wireshark-wiki/tcp-ecn-sample.pcap")},
            (C("requests[0].ttfb_ms", "le", 1000), C("summary.issues[*]", "startswith", "p99 transfer"))),
       Step("incident_summary", {"path": _p("wireshark-wiki/tcp-ecn-sample.pcap")},
            (C("findings[kind=http_slow]", "absent"),))),
    _s("D10_ike_retry", "An INVALID_KE_PAYLOAD retry followed by IKE_AUTH and ESP both ways is established.",
       Step("tunnels_overview", {"path": _p("ndpi/ipsec_isakmp_esp.pcap")},
            (C("tunnels[*].handshake.outcome", "eq", "established"), C("tunnels[*].handshake.outcome", "ne", "failed"),
             C("tunnels[*].handshake.retried", "present")))),
    _s("D22_teredo", "Teredo is a tunnel kind.",
       Step("tunnels_overview", {"path": _p("wireshark-wiki/Teredo.pcap")}, (C("tunnels[*].kind", "eq", "Teredo"),))),
    _s("D12_ussd_redaction", "redact=ids hides the number typed into a USSD string and drops the packed bytes.",
       Step("filter_packets", {"path": _p("wireshark-wiki/gsm_map_with_ussd_string.pcap"), "display_filter": "gsm_map",
                               "fields": ["gsm_map.ussd_string", "gsm_map.ss.ussd_String"], "redact": "ids"},
            (C("redaction.mode", "eq", "ids"),))),
    _s("D13_camel", "CAMEL operations are named.",
       Step("sigtran_messages", {"path": _p("wireshark-wiki/camel2.pcap")},
            (C("summary.by_operation.initialDP", "eq", 1), C("summary.by_operation.releaseCall", "eq", 1)))),
    _s("D14_sctp_init_abort", "INITs refused with ABORT and the INIT collision are reported.",
       Step("sctp_associations", {"path": _p("wireshark-wiki/SCTP-INIT-Collision.cap")},
            (C("associations[0].inits_aborted", "eq", 8), C("associations[0].init_collision", "eq", True)))),
    _s("D15_dns_lost_query", "A query lost and resent is not a slow resolver.",
       Step("incident_summary", {"path": _p("wireshark-testcaptures/dns+icmp.pcapng")},
            (C("findings[kind=dns_slow]", "absent"),))),
    _s("D16_happy_eyeballs", "An IPv6 refusal followed by an IPv4 connection is low severity.",
       Step("incident_summary", {"path": _p("wireshark-wiki/http2-16-ssl.pcapng")},
            (C("findings[kind=connect_failures].severity", "eq", "low"),))),
    _s("D17_diameter_result", "The command-level Result-Code is the result; MSCC codes are listed apart.",
       Step("diameter_transactions", {"path": _p("wireshark-testcaptures/diameter_coverage.pcapng")},
            (C("transactions[answer_frame=9].result_code", "eq", 2001),
             C("transactions[answer_frame=9].mscc_result_codes", "contains", 4012)))),
    _s("D20_auto_interval", "A capture spanning years gets an interval that fits.",
       Step("throughput_timeline", {"path": _p("ndpi/coap_mqtt.pcap"), "limit": 1},
            (C("interval_auto", "eq", True), C("interval_s", "ge", 3600)))),
    _s("D21_cause_lookup", "cause_lookup knows nas, dns and tls.",
       Step("cause_lookup", {"protocol": "dns", "code": 2}, (C("name", "eq", "SERVFAIL"),)),
       Step("cause_lookup", {"protocol": "tls", "code": 48}, (C("name", "eq", "unknown_ca"),)),
       Step("cause_lookup", {"protocol": "nas", "code": 7}, (C("protocol", "eq", "nas_emm"),))),
    _s("D23_find_identifier", "A directory of subdirectories names them instead of finding nothing silently.",
       Step("find_identifier", {"path": "{captures}", "identifier": "10.0.2.20"},
            (C("subdirectories_with_captures", "contains", "wireshark-wiki"),))),
]

DEFECTS = {s.id: s.id.split("_", 1)[0] for s in SCENARIOS}

# Facts on the text of the results (the check paths cannot name a tshark field with dots in it):
# scenario id -> (patterns that must appear, patterns that must not).
TEXT_CHECKS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "D12_ussd_redaction": ((r"\*140\*msisdn:[0-9a-f]{10}#", r"<redacted: \d+ bytes of packed text>"),
                           (r"\*140\*\d{6,}",)),
}

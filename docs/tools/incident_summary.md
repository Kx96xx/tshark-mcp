---
order: 10
readme: Start here. First call on an unknown capture: ranked findings with evidence frames, confidence and the next call to make, plus the protocols no check covers
llms: START HERE, the first call on a capture nobody has looked at: runs the overview and the protocol tools the capture carries under one time budget and returns `findings` ranked by severity, each one sentence with `evidence` (tool, arguments, frames), `confidence` and `next_call`; plus `capture` (span, trust verdict, what it cannot show), `top_talkers`, `timeline`, `not_checked` and `not_analysed` (protocols present that no check reads, each with a `next_call`). `focus`: auto, web, dns, tls, voip, mobile.
---

"What is wrong in this capture?" under one time budget (`budget_s`, default and maximum the run
timeout). The documented first call on any capture. Runs `pcap_info`, `capture_quality`,
`conversations`, then the protocol tools the protocol hierarchy shows: web, dns and tls
(`tcp_connections`, `tcp_health`, `dns_transactions`, `tls_handshakes`, `quic_connections`,
`http_transactions`, `icmp_errors`, `tunnels_overview`); voip (`call_kpis`, `rtp_streams`,
`ims_registration`); mobile (`diameter_transactions`, `gtp_sessions`, `gtpv1_sessions`,
`pfcp_sessions`, `sctp_associations`, `sigtran_messages`, `ims_registration`, `tunnels_overview`);
and `expert_info` (error level) in every focus, limited by `focus` (auto, web, dns, tls, voip,
mobile). `findings[]` ranked high, medium, low: `kind`, `severity`, `text` (one deterministic
sentence), `confidence` (loss findings take it from capture_quality's verdict), `evidence` (tool,
arguments, up to five frames), `details` (that tool's own sentences), `next_call`. Fixed thresholds
(in `thresholds`): TCP retransmissions above 1% of at least 20 data segments, HTTP 5xx above 5% of
answered requests, more than 10% of DNS queries unanswered (not counting those near the capture
end), DNS p90 above 500 ms, any failed TLS handshake (QUIC handshakes are left to the QUIC pass) or
certificate problem, failed QUIC connections (or UDP 443 blocked with a TCP fallback), any
destination with failed connection attempts, ICMP routing loops, path-MTU and prohibited errors,
failed or unanswered tunnel handshakes (IKE, WireGuard, OpenVPN), tunnels one way only (3 packets or
more), tunnel MTU overruns, failed calls (high below 80% NER), one-way RTP (not when the SDP asks for
it with sendonly, recvonly or inactive), failed IMS registrations and challenge loops, failed or
unanswered Diameter, GTPv2-C, GTPv1-C and PFCP transactions, PFCP peer restarts, SCTP INITs answered
with ABORT, INITs without INIT_ACK, aborts and 2 or more unacknowledged heartbeats, MAP/TCAP errors,
rejects, aborts and unanswered Begins, and tshark's error-level expert items (malformed packets).
Also `capture` (span, packets, protocols, `trust`, `cannot_show`: one-sided streams, encrypted
payloads, a window), `top_talkers` (5 IP conversations), `timeline` (first packet, first problem,
first high finding, last problem, last packet), `not_checked` (pass and reason: protocol absent,
focus, budget, error), `not_analysed` (protocols in the capture that no pass reads, such as DHCP,
MQTT, CoAP, Kerberos or ISUP: protocol, frames and a `next_call`, a specialist tool when one exists
or `filter_packets`; the `summary` sentence ends with "no checks exist for: ...") and `passes` (ms and
status per pass). With `start`/`end` every pass reads only the window and every `next_call` carries
it

---
order: 10
readme: First call on an unknown capture: ranked findings with evidence frames, confidence and the next call to make
llms: the first call on a capture nobody has looked at: runs the overview and the protocol tools the capture carries under one time budget and returns `findings` ranked by severity, each one sentence with `evidence` (tool, arguments, frames), `confidence` and `next_call`; plus `capture` (span, trust verdict, what it cannot show), `top_talkers`, `timeline` and `not_checked`. `focus`: auto, web, dns, tls, voip, mobile.
---

"What is wrong in this capture?" under one time budget (`budget_s`, default and maximum the run
timeout): runs `pcap_info`, `capture_quality`, `conversations`, then the protocol tools the protocol
hierarchy shows (`tcp_connections`, `tcp_health`, `dns_transactions`, `tls_handshakes`,
`http_transactions`, `icmp_errors`; `call_kpis`, `rtp_streams`; `diameter_transactions`,
`gtp_sessions`), limited by `focus` (auto, web, dns, tls, voip, mobile). `findings[]` ranked high,
medium, low: `kind`, `severity`, `text` (one deterministic sentence), `confidence` (loss findings
take it from capture_quality's verdict), `evidence` (tool, arguments, up to five frames), `details`
(that tool's own sentences), `next_call`. Fixed thresholds (in `thresholds`): TCP retransmissions
above 1% of at least 20 data segments, HTTP 5xx above 5% of answered requests, more than 10% of DNS
queries unanswered (not counting those near the capture end), DNS p90 above 500 ms, any failed TLS
handshake or certificate problem, any destination with failed connection attempts, ICMP routing
loops, path-MTU and prohibited errors, failed calls (high below 80% NER), one-way RTP, failed or
unanswered Diameter and GTPv2-C transactions. Also `capture` (span, packets, protocols, `trust`,
`cannot_show`: one-sided streams, encrypted payloads, a window), `top_talkers` (5 IP conversations),
`timeline` (first packet, first problem, first high finding, last problem, last packet),
`not_checked` (pass and reason: protocol absent, focus, budget, error) and `passes` (ms and status
per pass). With `start`/`end` every pass reads only the window and every `next_call` carries it

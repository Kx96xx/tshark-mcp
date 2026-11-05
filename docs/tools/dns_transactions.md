---
order: 310
readme: Queries paired with responses, unanswered ones included, per-server latency, failing names
llms: DNS queries paired with responses, unanswered queries included (which tshark's dns.time cannot show; `near_capture_end` when the capture stopped before the answer was due, as in gtp_sessions): rcode names, RTT, resends and retries, TC answers and TCP fallback, per-server latency percentiles and unanswered share, the failing names, `issues`. `name` matches the name and its subdomains. Use it for "cannot resolve", slow resolvers and SERVFAIL/NXDOMAIN questions, including DNS inside GTP-U tunnels.
---

DNS queries paired with responses by transport, addresses, ports, DNS id and name, unanswered ones
included: type, rcode name, answers and addresses, RTT, `unanswered` (`near_capture_end` when the
capture on that interface stopped before the answer was due), resends with the same id and port,
`retry_of` for a new query after an unanswered or failed one, TC answers and the TCP fallback that
followed; per-server answered share, rcodes and latency min/p50/p90/p99/max (the server's time:
from the last copy of a query sent again, whose row also has `rtt_after_resend_ms`); the names
that failed, were retried or were slow; `issues` (a "slow" percentile needs 10 answers from that
server, fewer slow answers are named one by one, and a query answered quickly after its resend is
reported as a lost query, not a slow server). Copies of one packet (several interfaces, GTP legs) count once,
DNS inside GTP-U is read from the inner packet, and problem transactions come first

- `dns_transactions`: server latency percentiles run from the last copy of a query that was sent
  again (`rtt_after_resend_ms` on the row), a "slow" percentile needs 10 answers from the server,
  and a query answered quickly after its resend is reported as a lost query, not a slow resolver;
  `incident_summary` needs 10 answers before `dns_slow` (public-validation D15).
- `tcp_connections` destinations get `failed_then_connected_elsewhere` (happy eyeballs: the same
  dual-stack client connected to another address on the same port within 1 s), and
  `incident_summary` reports such failures as low severity; `tcp_health` no longer reports SYNs
  refused with a reset as "SYN and no SYN-ACK", so a port scan is not counted twice
  (public-validation D16).

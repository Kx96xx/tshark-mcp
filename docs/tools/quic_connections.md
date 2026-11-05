---
order: 70
readme: QUIC / HTTP/3 per connection from the clear headers: version, Retry, Version Negotiation, handshake both ways, 1-RTT both ways, migration, spin-bit RTT, TCP fallback, UDP 443 blocked
llms: QUIC / HTTP/3 per connection from the clear headers (no keys): version, SNI when tshark decrypts the Initial, `initial_sent`, `server_initial`, `handshake_packets_both_ways`, `one_rtt_both_ways`, `retry`, `version_negotiation` (offered and supported), `zero_rtt`, `connection_close`, `migrated`, `spin_rtt_ms`, `tcp_fallback`, `outcome`; `summary.udp_443_blocked_likely`; Google QUIC (Q0xx) is counted in `summary.gquic_packets`, not analysed.
---

One `-T fields` pass over `quic` and TCP ClientHellos (fields an older tshark lacks are left out).
The side of each packet comes from its address and port, so a client and a server on one address
(loopback) are told apart. Headers only: version, packet type (v1 and v2 numbering), DCID/SCID, Version Negotiation list, Retry
token, spin bit, and when tshark can decrypt the Initial the SNI and a CONNECTION_CLOSE. A
connection starts at a client Initial; later packets join by any connection ID either side used, or
by UDP 4-tuple; joining by CID from a new 4-tuple is `migrated` (`migration_frames`). Per
connection: `client`, `server`, `sni`, `version` and `server_version` when different,
`initial_sent`, `server_initial`, `handshake_packets_both_ways`, `one_rtt_both_ways`, `zero_rtt`,
`retry` (frame, token), `version_negotiation` (offered, supported), `connection_close` (from, code,
name, reason), `spin_rtt_ms` (median time between spin flips in one direction), `packets` per side
and type, `tcp_fallback` (a TLS ClientHello over TCP from the same client to the same server IP or
SNI within 2 s after a failed attempt: frame, stream, server, SNI, `after_ms`), `outcome`
(established, handshake_only, handshake_incomplete, version_negotiation, retry_unanswered,
closed_with_error, no_response) and `issues`. Failed connections first. `summary`: outcomes,
versions, `tcp_fallbacks`, `migrated`, `servers_never_answering`, `udp_443_blocked_likely` (no
server in the result answered and the clients fell back to TCP), `gquic_packets` (Google QUIC
packets, which have other headers and are not analysed; an issue says so)

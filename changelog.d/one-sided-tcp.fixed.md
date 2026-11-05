- `tcp_connections`: a connection captured in one direction only (a one-way tap or asymmetric
  routing) gets the new outcome `one_sided` with `missing_direction`, instead of `filtered` or
  `handshake_incomplete`; it is not counted as a failed attempt (public-validation D2).
- `tcp_health` says "only the client's direction is in the capture" instead of "SYN and no SYN-ACK"
  when the SYN sender went on sending ACKs and data.
- `tls_handshakes`: a TCP connection seen in one direction only gets the outcome `one_sided` (not a
  failure); a SYN-ACK without the SYN now names the client; the summary counts
  `client_hello_missing`.
- `incident_summary` no longer reports high-severity `connect_failures` and `tls_failed` for
  one-sided captures; it reports one low `tcp_one_sided` finding that points to `capture_quality`.

---
order: 360
readme: Every connection attempt: connected, refused, filtered or ICMP-prohibited, who closed it; per destination success rate
llms: one row per TCP connection attempt (mirrored copies dropped; a new ISN on the same ports is a new attempt) with `outcome` connected, refused (reset to the SYN), filtered (no answer; `near_capture_end` when the capture stopped under 3 s after the last SYN), prohibited (ICMP administratively prohibited), unreachable, reset_during_handshake, handshake_incomplete or seen_midway; SYN retries and their gaps, `connect_ms`, bytes each way, duration, `closed_by` (client_fin, server_fin, client_rst, server_rst, open_at_capture_end), frames. `view="destinations"` gives per server:port attempts, success rate, refused/filtered/prohibited counts, connect time, peak concurrency and `issues` (one client dropped while others connect, refusals, ICMP rejects, SYN retries, a new connection per request). Use it for "can X reach Y:port" before tcp_health.
---

One row per TCP connection attempt, copies of the same packet dropped first; a SYN with a new
initial sequence number on the same addresses and ports is a new attempt, the same one a retry.
`outcome`: connected, refused (the server side reset the SYN), filtered (no answer at all;
`near_capture_end` when the capture stopped less than 3 s after the last SYN), prohibited (ICMP
destination unreachable code 9, 10 or 13, ICMPv6 code 1, quoting the SYN), unreachable (other ICMP
unreachable or time exceeded), reset_during_handshake, handshake_incomplete (SYN-ACK never
acknowledged) or seen_midway; SYN retries with the gaps between them, `connect_ms` (first SYN to
SYN-ACK at the capture point), payload bytes each way, duration, `closed_by` (client_fin,
server_fin, client_rst, server_rst, open_at_capture_end), `completeness` (syn, syn_ack, data, fin,
rst seen), ICMP errors with sender and frame; failed attempts first. `view="destinations"`: per
server address and port the attempts, success rate, counts per outcome, SYN retries, connect time
p50/max, median duration, distinct clients, peak concurrent connections and `issues` (one client
dropped while other clients connect, refusals, ICMP rejects with the sender, SYN-ACKs never
acknowledged, SYN retries, a client opening 50 or more short connections: no keep-alive). `server`
and `client` take IP addresses, `port` the server port; the ICMP errors about a selected connection
are kept

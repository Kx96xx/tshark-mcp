---
order: 30
readme: Bytes, goodput, retransmissions, window stalls, SYNs, DNS and ICMP per interval; per-stream verdict (loss, receiver, idle, sender)
llms: when a transfer slowed down and why: per interval bytes, bps, TCP goodput (bytes newly acknowledged), retransmitted bytes, zero windows, window-full events, duplicate ACKs, SYNs (and unanswered), DNS queries, TLS ClientHellos, ICMP errors; `per` = conversation/host/stream adds `series`; `streams` with a verdict (loss-limited, receiver-limited, application-idle, sender-limited, fine) and `issues` in plain words.
---

One `-T fields` pass, computed in the server, copies dropped first (same IP ID, sequence, length and
ACK within 1 s). `intervals[]` every `interval` seconds (default 1, at most 10,000 intervals):
`packets`, `bytes`, `bps`, `goodput_bps` (TCP bytes newly acknowledged, from `tcp.ack_raw`),
`acked_bytes`, `retransmitted_bytes` (segments ending at or before the highest sequence already
sent), `zero_windows`, `window_full`, `duplicate_acks`, `syns`, `syns_unanswered`, `dns_queries`,
`tls_client_hellos`, `icmp_errors` (zero counters left out); paged with `limit`/`offset`. `per` =
conversation, host or stream adds `series` for the `top` keys by bytes (each with its intervals,
peak and mean). `streams[]` per TCP stream: flow, bytes, retransmitted share, peak and mean goodput,
max bytes in flight, max window, `rwnd_limited_share`, `idle_share` and `verdict`: loss-limited
(more than 2% retransmitted), receiver-limited (zero or full window in 20% of active intervals),
application-idle (no packet in half its life), sender-limited (bytes in flight never above a quarter
of the window), fine. `summary`: span, totals, peaks, counters, idle intervals, copies dropped.
`issues`: where goodput fell below a quarter of its usual level and why, the stream verdicts, idle
time, bursts (a counter at three times its usual rate and at least 10 in one interval), unanswered
SYNs

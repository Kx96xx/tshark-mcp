---
order: 20
readme: Before and after a change: per destination, DNS name and resolver, SNI, HTTP endpoint and TCP server, what appeared, vanished, got worse or better
llms: before versus after a change (deploy, firewall rule, DNS switch, MTU change) for TCP/IP: per destination, DNS name and resolver, TLS SNI, HTTP endpoint and TCP server the metrics in each capture, the delta and `change` (worse, vanished, appeared, better, same) with one sentence, worst first; `first_differences` lists the top five. For a telecom procedure's ladder use `compare_captures`.
---

What changed between a capture from before a change (`path_a`) and one from after (`path_b`) for
TCP/IP services. `by`: destinations (`tcp_connections` per server: attempts, success rate, connect
time p50), dns (`dns_transactions`: per name the answered share, usual rcode and answer time; per
resolver the answered share and p50), tls (`tls_handshakes` per SNI: established share, usual
outcome, version, cipher suite, certificate expiry), http (`http_transactions` endpoints: 5xx and
4xx share, p50/p99), tcp (`tcp_health` per server: retransmitted share, handshake RTT p50, zero
windows, resets, server MSS) or all. `differences[]`: `section`, `key`, `a`, `b`, `delta`, `change`
(worse, vanished, appeared, better, same), `sentence`, `rate_per_min` (volume per minute in each
capture, as the two differ in length), worst first; rows without a change only with `include_same`.
A share must move 10 points (5 for 5xx, 1 for retransmissions) and a time by half and at least 20
ms. `first_differences` (top five sentences), `summary` (changes per section), `a`/`b` (span,
packets), `not_compared` (sections skipped or read in part). `filter` goes to the dns, tls, http and
tcp passes; `start`/`end` apply to both captures. Separate from `compare_captures`, which aligns one
telecom procedure's ladder

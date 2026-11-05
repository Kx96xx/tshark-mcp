---
order: 350
readme: Per-stream loss by location, resets with their likely source, windows, MTU black holes
llms: per TCP stream with mirror/SPAN copies dropped: handshake RTT split at the capture point, MSS, window scale; retransmissions by where the loss happened (before the capture point, after it, or only missing from the capture), reordering, duplicate ACKs, zero windows; who sent each reset (endpoint or a middlebox, by TTL and MAC) and the idle time before it; ICMP errors about the stream (mirrored copies counted once); MSS too large for `mtu` and the PMTUD black-hole pattern. Use it instead of tshark's tcp.analysis flags, which count copies as retransmissions.
---

Per TCP stream, with copies of the same packet dropped first (tshark counts them as
retransmissions): handshake with SYN retries, the SYN to SYN-ACK and SYN-ACK to ACK halves of the
RTT, MSS, window scale and SACK; per direction data segments and retransmissions split by where the
loss happened (`lost_before_capture`, `retransmitted_after_capture`, `missed_by_capture` when the
receiver acknowledged bytes the file lacks), reordering told apart by IP ID or TCP timestamp,
duplicate ACKs, zero windows, keep-alives; `resets` with `likely_from` endpoint or middlebox from
the reset's TTL and source MAC against that side's other packets, and the idle time before it; ICMP
errors about the stream (a mirrored copy counts once); MSS above `mtu`, DF packets above it and the
PMTUD black-hole pattern (full-size segments retransmitted and never acknowledged while small ones
pass); `issues` in plain words

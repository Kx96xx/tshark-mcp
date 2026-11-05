---
order: 280
readme: Inner TCP loss, reordering, MSS/MTU and ICMP per GTP-U tunnel
llms: user-plane health per GTP-U tunnel: inner TCP retransmissions (split by loss before or after the capture point, as in tcp_health), reordering, resets and the MSS in SYNs against the tunnel overhead and path MTU, inner and outer ICMP errors (fragmentation needed), one-way tunnels, all summed up in `issues`. Use it for slow or stalled data sessions instead of raw tshark; it ignores duplicate copies of packets, which tshark's own analysis counts as retransmissions.
---

User-plane health per GTP-U tunnel from the packets inside it: inner TCP flows, SYN/SYN-ACK MSS,
retransmissions and their share of data segments split like `tcp_health` (`lost_before_capture` when
the resend filled a gap, `retransmitted_after_capture` when the capture had already seen the bytes),
out-of-order segments (filled a gap but were overtaken, not lost), keep-alives, duplicate ACKs, zero
windows, resets; inner ICMP by type with the fragmentation-needed MTU; largest outer and inner
packets, tunnel overhead and DF packets above `mtu`; whether the reverse direction carries traffic;
`issues` in plain words; ICMP errors sent about the tunnel packets themselves (`outer_icmp`). Copies
of the same packet (a capture on several interfaces) are counted once

---
order: 125
readme: The same traffic captured at two points (client and server side, either side of a firewall or NAT): packets lost between them, NAT rewrites, hops, DSCP changes, clock offset and delay variation
llms: matches the packets of two captures of the same traffic taken at two points on its path: `lost_between` (A packets inside B's span that never reached B) per flow, NAT `rewrites`, `ttl_drop`, `dscp_changes`, `clock_offset_ms`, `delay_variation_ms`, `issues` and a `verdict`.
---

Matches the packets of two captures of the same traffic taken at two points on its path: A
upstream, B downstream (client side and server side, before and after a firewall, NAT or tunnel).
A packet's identity leaves addresses and ports out so it survives NAT: IP protocol, IP ID and IP
length, plus the raw TCP sequence and acknowledgement numbers, or the UDP length. A key that
appears more than once on one side (IP ID reuse, retransmissions) is counted as `ambiguous` and
not matched. From the matched pairs: `clock_offset_ms` (median of B minus A), `delay_variation_ms`
(p50, p95, max around that offset), `rewrites` (address and port mappings: NAT), `ttl_drop` (hops
between the points) and `dscp_changes`. A packets that fall inside B's capture span once the offset
is applied but never reach B are `lost_between`, listed per flow in `lost_flows` with the first A
frame; packets only in B are `only_b_flows`. `filter` is ANDed with `ip && !icmp` on both sides.

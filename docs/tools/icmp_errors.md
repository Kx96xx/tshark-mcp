---
order: 370
readme: Every ICMP/ICMPv6 error by sender, kind and quoted flow: fragmentation needed, rejects, routing loops, lost pings
llms: every ICMP and ICMPv6 error grouped per sender, kind and quoted flow (source, destination, protocol, destination ports): net/host/port/protocol unreachable, frag_needed and packet_too_big with the MTU, admin_prohibited, ttl_exceeded, redirect, source_quench, parameter_problem, no_route, address_unreachable; `quoted_flow_seen` gives the frame of the original packet when the capture holds it (IPv4); mirrored copies count once. `by_sender` (hop distance from the TTL, endpoint or on_path), `echo` (requests, replies, lost, RTT per source and destination) and `issues` (MTU problems, routing loops told apart from traceroutes, firewall rejects, closed ports, lost pings). `about` is an address or address:port of the quoted flow.
---

Every ICMP and ICMPv6 error, read with the packet it quotes and grouped per sender, `kind` and
quoted flow (source, destination, protocol; destination ports listed, at most 10): net_unreachable,
host_unreachable, protocol_unreachable, port_unreachable, frag_needed (with `mtu`), packet_too_big
(ICMPv6, with `mtu`), admin_prohibited (codes 9, 10, 13 to 15; ICMPv6 1, 5, 6), ttl_exceeded,
reassembly_timeout, source_quench, redirect, parameter_problem, no_route, address_unreachable,
source_route_failed; count, first/last frame, the quoted IP ID and `quoted_flow_seen` (the frame of
the quoted original when the capture holds it, from one bounded pass over at most 32 IPv4 originals;
false when it does not). Mirrored copies of one error count once. `by_sender`: errors and kinds per
sender, its TTL, hop distance from the capture point and `role` (endpoint when it is a destination
the packets were addressed to, else on_path). `echo`: echo requests paired with replies by
identifier and sequence per source and destination, lost requests with frames, RTT min/p50/max.
`issues`: fragmentation needed with the MTU, a routing loop (TTL exceeded from two routers
alternating for one flow) told apart from a traceroute (three or more routers in turn),
administrative rejects, no route, closed ports, redirects and lost echoes. `sender` is an IP
address, `about` an address or address:port at either end of the quoted flow

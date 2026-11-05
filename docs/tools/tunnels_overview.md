---
order: 40
readme: GRE, ERSPAN, VXLAN, Geneve, IP-in-IP, IPsec (IKE/ESP), WireGuard, OpenVPN, L2TP and GTP-U tunnels: endpoints, traffic each way, inner protocols, overhead against the MTU, handshake outcome
llms: every tunnel or overlay (GRE, ERSPAN, VXLAN, Geneve, IP-in-IP, IPsec with IKE/ESP/AH, WireGuard, OpenVPN, L2TP, GTP-U): outer endpoints, key/VNI, packets and bytes each way, `one_way`, inner protocols and conversations, `overhead_bytes`, DF packets above `mtu`, inner SYN MSS against the overhead, `handshake` (IKE exchanges and error notifies, WireGuard initiations and responses, OpenVPN resets) and `esp_sas`; `issues` in plain words.
---

One `-T fields` pass over the tunnel protocols (unknown fields of an older tshark are left out).
Kinds: GRE, ERSPAN, VXLAN, Geneve, IP-in-IP (4in4, 6in4, ...), IPsec (IKE, ESP, AH, NAT-T on UDP
4500), WireGuard, OpenVPN, L2TP, GTP-U. A row per tunnel: GRE/VXLAN/Geneve/L2TP by outer endpoint
pair and key, VNI or tunnel id; IPsec and GTP-U by the pair; WireGuard and OpenVPN by pair and UDP
ports. `endpoint_a` sent first. `packets_a_to_b`/`b_to_a`, `bytes_*` (frame bytes), `one_way`,
first/last and frames; clear kinds add `inner_protocols`, `inner_conversations` (top three),
`inner_ethernet`; encrypted kinds `inner: "encrypted"`. `overhead_bytes` is the outer minus the
inner IP length (most common value), `largest_outer_ip_len`, `df_above_mtu` (outer DF packets above
`mtu`, default 1500), `fragmented_outer` (reassembled outer packets), `inner_syn_mss`. IPsec:
`esp_sas` (SPI, direction, packets, bytes, first frame), `esp_pairs` (both directions or one
direction only), `ah_spis`, `nat_traversal`, `handshake` (IKEv1/IKEv2 exchanges, `error_notifies` by
name, unanswered requests paired by initiator SPI and message id, `dpd_unanswered`, `outcome`
established, failed, no response or incomplete). WireGuard `handshake`: initiations, responses,
cookie replies, unanswered initiations (sender index never acknowledged), keepalives, data each way,
`outcome`. OpenVPN: opcodes, client and server resets, data each way, `outcome`. GTP-U: `teids` (use
`gtp_tunnel_health` for the inner TCP). `issues`: unanswered WireGuard initiations or OpenVPN
resets, IKE error notifies with the usual cause, IKE_SA_INIT never answered, unanswered DPD, an ESP
SA with no return SA, a tunnel carrying traffic one way, inner MSS plus 40 (60 for IPv6) plus the
overhead above `mtu`, DF packets above `mtu`, outer fragmentation. Tunnels with issues come first.
`summary`: tunnels per kind, packets, with issues, one way

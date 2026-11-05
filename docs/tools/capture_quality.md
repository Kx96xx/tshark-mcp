---
order: 120
readme: Can loss and timing conclusions be drawn from this file? Verdict with reasons
llms: can missing packets and retransmissions in this file be read as network faults? Duplicate copies of the same packet and their cause (without an IP ID, ICMP errors from one router about different probes, and SCTP packets with different TSNs, are not copies), TCP bytes the receiver acknowledged that the capture never saw (the capture dropped them), gaps a retransmission filled (lost before the capture point), snaplen-truncated frames, segmentation-offload packets above 1500 bytes, bad checksums and whether they are offload artifacts, one-direction TCP streams, backwards or coarse timestamps; `verdict.loss_conclusions` is trustworthy, use with care or not trustworthy, with reasons. Call it before blaming the network for loss.
---

Whether loss and timing conclusions can be drawn from the capture: duplicate copies of the same
packet with the likely cause (two VLANs or interfaces, a Linux any capture, tunnelled and
decapsulated, rebuilt copies with zeroed TCP headers; without an IP ID a copy also needs to arrive
within 5 ms of the first sighting with the same TCP, UDP or ICMP checksum, an ICMP error the same
quoted packet, and SCTP the same TSNs, acknowledged TSN and heartbeat information; a UDP copy also
needs the same QUIC packet number, RTP sequence number and SSRC or DNS ID when tshark reads one;
identical TCP RSTs and pure ACKs without an IP ID and without a link-layer difference are real
repeats, counted in `duplicates.repeated_identical`); TCP bytes the receiver acknowledged that
the capture never saw (dropped by the capture, or the file was filtered) versus gaps a
retransmission filled (lost on the network before the capture point); frames cut to the snapshot
length; packets above 1500 bytes (segmentation offload); bad IP/TCP/UDP checksums and whether they
are offload artifacts (one sender, data acknowledged anyway); TCP streams seen in one direction only
and unanswered SYNs; timestamps going backwards, identical stamps, resolution, longest silence; a
`verdict` (trustworthy, use with care, not trustworthy) with the reasons

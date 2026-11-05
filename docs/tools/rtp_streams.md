---
order: 460
readme: Per-stream loss, jitter, RTCP and an E-model MOS estimate, linked to the call
llms: RTP streams per SSRC linked to the SIP Call-ID through the SDP addresses and ports, with codec, packets, loss, sequence errors, jitter, deltas, duration, the reverse stream or `one_way`, RTCP reports (loss, jitter, round trip) and a `mos_estimate`. The MOS is a simplified G.107 E-model estimate from network metrics, returned with its method and inputs; never present it as a measured MOS. Set `heuristic=true` when the capture has RTP but not the SIP/SDP.
---

Per RTP stream (SSRC and source/destination address:port): the SIP Call-ID whose SDP advertised its
destination (or source) address and port, payload type and codec from the SDP rtpmap or the static
table, packets, expected, lost and lost %, duplicates, sequence errors, out-of-order packets,
max/mean interarrival delta, RFC 3550 max/mean jitter, duration, first and last frame, the reverse
stream or `one_way` (with `expected_one_way` when the SDP asks for one-way media), RTCP reception reports about it (fraction and cumulative lost, jitter, round
trip where the LSR matches a captured SR), RTCP XR VoIP metrics as reported, and `mos_estimate`: a
simplified ITU-T G.107 E-model score from loss, jitter, delay and the codec's G.113 Ie/Bpl, returned
with its method and inputs because it is an estimate, not a measured MOS. `call_id` reads the RTP to
or from the call's SDP addresses, so a NATed source is still found; each stream is still linked
against every SDP in the capture (the most recent advertisement of its address and port before it
starts), and a call whose BYE or CANCEL came before a stream started never owns it, so a later call
that reuses a port keeps its own stream; `heuristic` decodes RTP without SDP in the capture, over
plain UDP and inside STUN/TURN (WebRTC through a relay). Packets, lost, max delta and max jitter match `tshark -z rtp,streams`

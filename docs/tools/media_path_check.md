---
order: 450
readme: SDP-negotiated media against the RTP seen: one-way audio, NAT, 488
llms: why a call has one-way, no audio or a 488: the SDP-negotiated addresses, ports and codecs against the RTP seen in each direction, with `issues` (NAT not latched, one-way media, RTP to the wrong address, hold, codec mismatch) and a one-sentence `verdict`.
---

One call's SDP offer and answer (the last completed exchange, so a re-INVITE wins) against the RTP
captured in each direction: per direction the expected source and destination, the streams seen and
a status (as negotiated, arrives from another source, sent elsewhere, missing); `issues` such as
no_rtp, one_way_media, source_differs_from_sdp, nat_not_latched (a private SDP address the far end
keeps sending to), rtp_to_wrong_address, private_sdp_address, media_direction (hold),
media_rejected, payload_type_not_negotiated, codec_mismatch (no codec in common between the offer
and the answer or a 488's SDP) and no_answer; `verdict` in one sentence

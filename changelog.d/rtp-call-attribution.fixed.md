- `rtp_streams` and `media_path_check` with a `call_id`: a later call that reuses the offerer's
  address and port no longer has its RTP tagged with this Call-ID. Streams are linked against
  every SDP in the capture, and a call whose BYE or CANCEL came before a stream started never owns
  it. This removes false "NAT or media relay rewrote it" and "payload type that neither SDP
  lists" issues (public-validation D7).
- `rtp_streams`, `dtmf_events` and `media_path_check` with `heuristic=true` also find RTP inside
  STUN/TURN (WebRTC through a relay), when the tshark in use has the STUN dissectors
  (public-validation D19).

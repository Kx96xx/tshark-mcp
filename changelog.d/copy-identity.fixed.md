- `capture_quality` and every tool that drops capture copies: distinct UDP packets of one flow
  (QUIC, RTP, DNS) that share a size and an offloaded checksum are no longer taken for copies; the
  copy key now holds the QUIC packet number, RTP sequence number and SSRC or DNS ID, and the 5 ms
  window is measured from the first sighting instead of chaining from copy to copy
  (public-validation D5).
- `capture_quality`: byte-identical TCP RSTs and pure ACKs with IP ID 0 and no link-layer
  difference (interface, VLAN, MAC pair, SLL direction) are counted in
  `duplicates.repeated_identical`, not as mirror copies (public-validation D6).

- `quic_connections`: when the client and the server share an address (a loopback capture), each
  packet's side is taken from its address and port; before, every server packet counted as the
  client's and a working handshake read as "no answer: UDP 443 blocked" (public-validation D4).
  The "no answer" issue names the server's real UDP port.
- `quic_connections`: Google QUIC (gQUIC) packets are counted in `summary.gquic_packets` with an
  issue saying they are not analysed, instead of an empty result (public-validation D18).

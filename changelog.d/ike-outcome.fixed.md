- `tunnels_overview`: an IKEv2 negotiation where the responder answered INVALID_KE_PAYLOAD (asking for
  another DH group) and the initiator retried is `established` when IKE_AUTH was answered without
  an error or ESP flows both ways; the retry is listed in `handshake.retried`, not as an issue
  (public-validation D10).
- `tunnels_overview`: Teredo (IPv6 over UDP 3544) is a tunnel kind (`kind="teredo"`), and a capture
  without any tunnel this tool reads gets a `summary.note` saying that an undecoded tunnel shows up
  as plain UDP or TCP (public-validation D22).

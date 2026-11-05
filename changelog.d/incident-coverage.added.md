- `incident_summary` covers more of the capture (public-validation D3): new passes for
  `quic_connections`, `tunnels_overview`, `ims_registration`, `gtpv1_sessions`, `pfcp_sessions`,
  `sctp_associations`, `sigtran_messages` and error-level `expert_info`, so SCTP INIT/ABORT storms,
  unanswered heartbeats, MAP errors, TCAP rejects and unanswered Begins, GTPv1-C and PFCP rejects,
  PFCP peer restarts, failed IKE/WireGuard/OpenVPN handshakes, one-way tunnels, failed QUIC
  connections, failed IMS registrations and malformed packets are findings now. A new
  `not_analysed` list names the protocols in the file that no check reads (DHCP, MQTT, CoAP, ...)
  with the call that shows them, and the summary says "no checks exist for: ...".
- `incident_summary` is the documented front door: server instructions, prompts, AGENTS.md
  ("Start here") and the README point to it first.
- `rtp_streams`: a stream without a reverse stream gets `expected_one_way` (and
  `summary.expected_one_way`) when the call's SDP asks for one-way media (sendonly, recvonly,
  inactive).

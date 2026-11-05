- `sigtran_messages`: CAMEL (CAP, TS 29.078) components are read from tshark's `camel` layer and named
  (initialDP, requestReportBCSMEvent, applyCharging, ...), with CAP error names and
  `application: "camel"`; before, `by_operation` was empty on CAMEL traffic (public-validation D13).
- `sctp_associations`: `inits_aborted`, `init_collision` and `issues` ("N INITs answered with ABORT",
  "INIT collision", 3 or more unacknowledged heartbeats); an association that came up after a run
  of refused INITs no longer reads as a clean handshake (public-validation D14).

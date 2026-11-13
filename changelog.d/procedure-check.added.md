- `procedure_check` (toolset `mobile`): does a capture follow the standard flow, and which step
  goes wrong first? Reference flows as data in `tshark_mcp/procedure.py`: `eps_attach` (S6a AIR
  optional, ULR, GTPv2 Create Session, Modify Bearer) and `location_update` (MAP) from the
  subscriber's trace_subscriber timeline; `sip_register` (REGISTER, optional 401/407 challenge,
  REGISTER with credentials, 200) and `sip_call` (INVITE, optional 100 and 180/183, 200, ACK)
  from sip_dialogs, for one Call-ID or every dialog of the method (up to 20). Each step is ok,
  failed, unanswered, missing, out_of_order or not_seen, with frames and the spec clause;
  `first_deviation` and a one-sentence `verdict`.

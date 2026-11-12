- `ims_registration`: reg-event SUBSCRIBEs per user in `reg_subscriptions` (UE or network
  subscriber, status, requested and granted expiry; a refused or unanswered one is named in
  `reasons`). Reg-event NOTIFY rows now carry the final response (`status`,
  `no_final_response`), `subscription_state`, `retry_after` and `contact_matched`; the UE's own
  contact (by its REGISTER Contact URI) decides when a NOTIFY lists several, so a contact ended
  on its own while another device keeps the registration active is a de-registration, and
  another device's contact ending is not. A contact event `shortened` brings the registration
  expiry forward (verdict `expired` when the UE does not re-register in time). A decisive
  NOTIFY the UE refused (481) or never answered is named in `reasons`.

- Diameter tools (`diameter_transactions`, `diameter_sessions`, `trace_subscriber`,
  `roaming_attach_check`, ...): the result is the command-level Result-Code or Experimental-Result-Code;
  a Result-Code nested in a Multiple-Services-Credit-Control or Proxy-Info no longer replaces it, and
  an Experimental-Result beside a Result-Code no longer overrides it (public-validation D17).
- `diameter_transactions`: `mscc_result_codes` lists the Result-Code of each MSCC of a credit-control
  answer and `mscc_results` names the failed ones (for example DIAMETER_CREDIT_LIMIT_REACHED).
- `roaming_attach_check` calls an application-4 CCR-I "Gy/Ro CCR-I/CCA-I" (and looks causes up in the
  Gy table), as `diameter_transactions` does; "Gx" is kept for application 16777238.

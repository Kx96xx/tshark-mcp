- `esp_null` argument on `sip_dialogs`, `sip_call_detail`, `call_legs`, `ims_registration`,
  `sms_over_ims`, `volte_call_chain` and `trace_subscriber`: reads SIP between UE and P-CSCF
  inside IPsec ESP with NULL encryption (RFC 2410) by switching on tshark's NULL-ESP heuristic.
  No keys are accepted.
- `ipsec` block on those tools when the capture carries ESP: packets, SPIs, how many were read
  as NULL encryption and how many stay unreadable, with a hint such as "SIP may be inside 1,240
  ESP packets on SPI 0x...". `pcap_info` names ESP the same way.

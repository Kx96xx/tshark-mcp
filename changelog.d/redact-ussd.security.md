- Redaction (`redact="ids"` or `--redact ids`): a number typed into a USSD string or SMS text
  (`*140*<number>#`) is replaced like any other number, the pre-scan learns it, and the packed
  GSM 7-bit bytes field of the same text is dropped. Before, `packet_detail` and `filter_packets`
  returned both in clear next to a redacted IMSI and MSISDN (public-validation D12).

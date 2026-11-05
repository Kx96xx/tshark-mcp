- `sbi_transactions`: 5G core SBI (HTTP/2 between network functions) per request: service,
  operation, consumer and producer NF, status, latency, ProblemDetails cause explained, resets,
  NRF discovery parameters and profile count, per-operation 4xx/5xx share and latency
  percentiles. SUPI, GPSI and PEI are redacted with the IMSI, MSISDN and IMEI tokens; the SUCI
  scheme output and authentication material are never returned; TLS without keys is counted.

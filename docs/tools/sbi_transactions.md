---
order: 295
readme: 5G core SBI (HTTP/2 between NFs): per request the service, consumer and producer NF, status, latency, ProblemDetails cause explained, resets, NRF discovery; TLS without keys is counted, not read
llms: per 5G SBI HTTP/2 request between NFs (nnrf-disc, nausf-auth, nudm-*, nsmf-pdusession, npcf-*, ...): service, operation template, consumer and producer NF, status, `latency_ms`, ProblemDetails `cause` explained, RST_STREAM `reset`, SUPI/GPSI/PEI (redactable), SUCI routing parts only, NRF discovery parameters and profile count, per-operation 4xx/5xx share and p50/p95/p99, `tls_unreadable` and a `verdict`. Cleartext h2c only; `ports` for non-standard ports.
---

Reads cleartext SBI only: TLS connections without keys are counted in `summary.tls_unreadable`
(ALPN h2 or an SNI under 3gppnetwork.org) and the `verdict` then never claims there were no
errors. One row per HTTP/2 stream of a TCP connection: `service` (nnrf-disc, nausf-auth, nudm-sdm,
nsmf-pdusession, npcf-smpolicycontrol, ...), `operation` (method plus the path with identities and ids
as `{supi}`, `{gpsi}`, `{suci}`, `{id}`), `uri` (untrusted text), `producer` (from the service) and
`consumer` (from the 3GPP User-Agent or `requester-nf-type`), their addresses, `status`, `latency_ms`,
`outcome` (success, client_error, server_error, redirect, reset, no_response, in_progress,
unreadable), the ProblemDetails `cause` with `cause_explained` (TS 29.500 and the service's table, as
cause_lookup http_sbi), `title` and `detail`, `location`, `reset` (RST_STREAM error name and
sender), `supi`, `gpsi`, `pei`, `suci` (MCC, MNC, routing indicator and protection scheme; the scheme
output is withheld, in the URI too), `dnn`, `pdu_session_id`, `sst`/`sd`, NRF `discovery`
parameters and `nf_profiles_returned`. Bodies are never returned; authentication material
(5gAuthData, kausf, kseaf, rand, autn, hxresStar, xresStar, ...) is only named in `withheld_keys`.
`hpack_state_missing` marks header blocks that refer to HPACK state from before the capture started.
`summary`: transactions per outcome, `services` (per operation: calls, 4xx and 5xx share,
unanswered, resets, latency p50/p95/p99, causes), `nrf_discovery`, GOAWAYs. Filters: `service`
(prefix), `status` (404, 4xx, 5xx, error), `supi` (digits of a SUPI, GPSI or PEI); `ports` reads more
TCP ports as HTTP/2 (decode-as)

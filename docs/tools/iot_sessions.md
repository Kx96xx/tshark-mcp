---
order: 375
readme: IoT devices: MQTT connections (CONNACK named, keepalive violations, reconnect loops, PUBACK latency, how it ended), CoAP retransmissions and exhausted requests, LwM2M registrations and expiry; GTP-U inner traffic names its TEID; payloads never read
llms: per MQTT connection (client id, level, keepalive, CONNACK named, `keepalive_violated`, topics counted, PUBACK latency, DISCONNECT reason, `ended`, `reconnect_loop`), per CoAP client/server (CON/NON/ACK/RST, retransmissions, response codes, `exhausted`), per LwM2M endpoint (Register lifetime, Updates, `expired`), each with a `verdict`; `gtpu_teid` when inside GTP-U. Narrow with `client` or `protocol`.
---

One row per MQTT connection, CoAP client and server pair, and LwM2M endpoint, with `protocol` and a
`verdict`. MQTT 3.1.1 and 5.0: `client_id`, `protocol_version`, `keepalive_s`, `user_name_sent`,
`connack` (code, name from the 3.1.1 return codes or the 5.0 reason codes, session present),
`messages` per type, `topics` counted (names only; the client id inside a topic shows as
`{client_id}`), `puback_ms` and unacknowledged QoS 1/2 PUBLISHes, `pings`, `longest_client_silence_s`
and `keepalive_violated` (silent for more than 1.5 times the keepalive: NAT or GTP idle timers may drop
the session), `disconnect` (reason, by whom), `ended` (FIN or RST and by whom, open at capture end, or
idle then silence), `connections_of_client` and `reconnect_loop` (three or more connections of one
client within ten minutes) with `reconnect_interval_s`. CoAP: `types` (CON, NON, ACK, RST),
`retransmissions`, `responses` as class.detail with the RFC 7252 name, `exhausted` confirmable
requests (retransmitted four times with no ACK or RST) and `unacknowledged`. LwM2M: `endpoint`,
`registrations` (lifetime, version, binding, result, location), `updates`, `deregistered_frame`,
`expired` with `expired_at` when no Update came within the lifetime while the capture went on.
MQTT or CoAP inside GTP-U gives `gtpu_teid`. Payloads (MQTT message bodies, CoAP payloads, LwM2M TLV
values) and passwords are never read; client ids and endpoint names are redacted like user names.
`summary`: rows per protocol, unhealthy rows, MQTT refusals, reconnect loops, keepalive violations
and the worst rows. MQTT over TLS (8883) is not read here: use tls_handshakes and tcp_health

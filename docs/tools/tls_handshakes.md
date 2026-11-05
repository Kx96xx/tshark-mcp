---
order: 320
readme: Client offer versus server choice, alerts, certificate, outcome per connection
llms: per TLS (TCP) or QUIC connection, the ClientHello offer against the ServerHello choice, alerts and who sent them, the certificate (TLS 1.2 and older), and an `outcome` with a plain-words `note`; `issues` flags expired certificates, SNI not covered by the certificate, deprecated versions and HelloRetryRequest. No decryption. Use it for "TLS handshake failed", "certificate error" and "which app servers did the UE fail to reach"; `server_name` matches the SNI and its subdomains. Copies of the same packet (mirror, two tunnel legs, a tap's decapsulated copy) are counted in `duplicate_copies`, not as resent messages.
---

TLS over TCP and QUIC per connection, from the clear part of the handshake (no decryption, no key
material): the client's offer (SNI, ALPN, versions, cipher-suite count without GREASE, fallback
SCSV) against the server's choice (version, suite, ALPN when in clear), HelloRetryRequest,
SYN-to-ClientHello and ClientHello-to-ServerHello times, alerts with level, name and sender (QUIC
CONNECTION_CLOSE too), the leaf certificate for TLS 1.2 and older (subject, issuer, SAN, validity,
chain length), and an `outcome`: established, alert, no_server_hello, reset_by_server,
closed_by_server, client_gave_up, client_rejected_likely (TLS 1.3 alert-sized record instead of
Finished), unreadable, incomplete, one_sided (only one direction of the TCP connection is in the
capture, so the handshake cannot be judged; not counted as a failure), or server_hello for QUIC; `issues` names expired certificates,
SNI/SAN mismatches, deprecated or unoffered versions and repeated ClientHellos. A connection whose
ClientHello is not readable is still listed (`client_hello_missing`, counted in the summary) when its ServerHello,
certificate or alerts are. Copies of the same packet are found with the same rule as `tcp_health`
(same IP ID and transport header, or with IP ID 0 the same checksum within a few milliseconds), plus
a tap's copies with the TCP header or the IP ID zeroed; they are counted in `duplicate_copies` and
never taken for a resent ClientHello or alert

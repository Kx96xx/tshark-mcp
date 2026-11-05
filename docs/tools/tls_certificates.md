---
order: 60
readme: Certificate chains servers sent (TLS 1.2 and older): expiry and days left, SAN against SNI, self-signed, missing or misordered intermediates, weak signatures and keys, OCSP stapling, clients that refused them
llms: the certificate chains servers sent (TLS 1.2 and older; TLS 1.3 encrypts them and they are counted as skipped) per server, SNI and leaf: subject, issuer, SANs, validity, `days_left`, key and signature algorithm, self-signed, fingerprint; intermediates, `order_ok`, `missing_intermediate`, `expired`, `name_matches`, `ocsp_stapled`, `clients_rejected`; `issues` in plain words. No private keys, no decryption.
---

The same pass and connection rebuild as `tls_handshakes` (copies dropped, TLS inside GTP-U from the
inner packet); every certificate of each Certificate message is parsed from its DER bytes in the
server, without a trust store, private key or decryption. `chains[]` per server, SNI and leaf
fingerprint: `leaf` (`subject_cn`/`subject_o`, `issuer_cn`/`issuer_o`, `san` (20 names, 5 IPs) and
`san_total`, `not_before`/`not_after`, `days_left` at the handshake and `days_left_now`,
`key_algorithm`, `key_bits`, `key_curve`, `signature_algorithm`, `self_signed`, `is_ca`, `wildcard`,
`serial`, `fingerprint_sha256`), `intermediates` (subject, issuer, not after, signature algorithm,
CA flag), `chain_length`, `order_ok` (each certificate issued by the next), `missing_intermediate`
(no certificate in the chain issued the leaf and it is not self-signed), `self_signed`, `expired`,
`not_yet_valid`, `name_matches` (SNI against SAN, or CN without SAN, wildcards included),
`ocsp_stapled` (a CertificateStatus message), `connections`, `frames` (first five), `tls_versions`,
`alerts`, `clients_rejected` and `rejected_frames` (a client alert bad_certificate,
unsupported_certificate, certificate_revoked, certificate_expired, certificate_unknown, unknown_ca
or access_denied, or `client_rejected_likely`). `issues`: expired, not yet valid, expiring within 30
days, SAN/CN mismatch, self-signed, missing intermediate, out-of-order chain, MD5 or SHA-1
signatures below a self-signed root, RSA keys under 2048 bits, expired intermediates, client
rejections. `summary`: chains, connections, expired, expiring within 30 days, self-signed, name
mismatch, missing intermediate, weak signature, `tls13_connections_skipped`,
`connections_without_certificate`, versions. `expiring_within_days` keeps chains with at most that
many days left at the handshake (and expired ones); `server` is the server's IP. Certificate text is
listed in `untrusted_text_fields`

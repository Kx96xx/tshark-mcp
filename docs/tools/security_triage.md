---
order: 365
readme: Defensive triage: port scans, host sweeps, SYN floods, beaconing (RITA-style score with raw interval and size statistics), DNS tunnel hints, TLS clients by JA4/JA3 and servers by JA3S, ARP conflicts, cleartext credentials (counts only)
llms: defensive triage of the capturing network: `findings` (port_scan, host_sweep, syn_flood, beacon, dns_tunnel_hint, rare_tls_client, arp_conflict, cleartext_credentials) ranked by severity with frames; `beacon_candidates` with interval/size statistics and a score; `tls_clients` by JA4 (JA3 fallback), `tls_servers` by JA3S, `dns_zones`. `kinds` selects checks; no lookups, no credential values.
---

Heuristics with fixed thresholds, each finding with `kind`, `severity` (high, medium, low),
`summary`, `subject` and `evidence` (counts, statistics, the first frame). Scans: one source probing
20 or more TCP ports on one host (`port_scan`, with the ports that answered and how many were refused)
or one port on 20 or more hosts (`host_sweep`); 200 or more SYNs to one server port (`syn_flood`).
Beaconing: per client, server and service (the TLS SNI, else tcp/<port>; DNS names too) with at
least 12 connection starts, the interval median, MAD and Bowley skew, the same for connection sizes
(from conv,tcp), and a score (an approximation of RITA's: 0.45 interval regularity, 0.35 size
regularity, 0.20 how much of the capture the series covers); `beacon` from 0.7. `beacon_candidates`
keeps the statistics even when the score is low (jittered or agent-like traffic). DNS: per zone,
queries, distinct names, mean length and entropy of the leftmost label, TXT/NULL queries;
`dns_tunnel_hint` at 30 or more distinct names with labels of 20 characters or more or entropy of
3.5 bits or more. TLS: `tls_clients` grouped by JA4 (JA3 when this tshark has no JA4) with hosts and
SNIs, `rare_tls_client` for a fingerprint one host uses a handful of times; `tls_servers` by JA3S;
`raw=true` adds JA4_r. ARP: one IPv4 address answered by two or more MACs (`arp_conflict`).
Credentials: FTP USER/PASS, HTTP Basic, POP3, IMAP LOGIN and SMTP AUTH in clear, counted per client
and server; the values are never returned. `kinds` picks checks (scans, beacons, dns_tunnels,
tls_fingerprints, arp, cleartext_credentials). No threat-intelligence or fingerprint lookups (no
network egress) and no attribution

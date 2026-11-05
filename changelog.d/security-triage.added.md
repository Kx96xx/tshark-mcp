- `security_triage`: defensive triage of a capture: port scans, host sweeps and SYN floods,
  beaconing with a RITA-style score and the raw interval and size statistics, DNS tunnel hints,
  TLS clients grouped by JA4 (JA3 fallback) and servers by JA3S, ARP conflicts, and cleartext
  credentials (protocol, peers and counts only, never the values). No lookups outside the capture.

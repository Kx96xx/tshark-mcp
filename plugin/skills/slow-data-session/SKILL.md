---
name: slow-data-session
description: A mobile data session is up but slow, stalls or carries no data. Use for GTP-U, MTU and throughput problems.
---

# Slow or stalled data session

Get the server's `slow_data_session` prompt (`path`, `teid`, `ue_ip`), or:

1. `gtp_user_plane(path)` to find the tunnel, then `gtp_tunnel_health(path)` for inner TCP
   loss, MSS/MTU and ICMP.
2. `pfcp_sessions(path)` for the N4/Sx side.
3. `throughput_timeline(path, interval=1)` for when it slowed, and `tcp_health(path)`.

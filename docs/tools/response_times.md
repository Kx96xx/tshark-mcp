---
order: 340
readme: Network, server and receiver time per TCP flow (HTTP/1, HTTP/2, gRPC)
llms: for slow TCP applications, splits each request/response into network round trips, server time and transfer time, names the stalls (retransmission, zero window, server pause) and gives a verdict per flow (server-bound, network-bound, receiver-bound, fast, idle-or-push). Use it to prove whether the network or the server is slow; give `filter` such as `tcp.port == 443` or `ip.addr == ...`. HTTP/2 and gRPC (when tshark can read them: cleartext h2c on any port with tshark 4.4.0 and later, only on an HTTP port such as 80 or 8080 with tshark 4.2; or TLS with keys) are timed per stream (`h2_stream`, `grpc_status`), so concurrent requests on one connection are not lumped together.
---

Where the time goes per TCP flow: each connection cut into exchanges (client data, then the server's
answer) with think time, `server_ms` (think time less the capture-to-server round trip, so it holds
at any capture point), transfer time, retransmissions and out-of-order segments (told apart by IPv4
ID), stalls with their cause (retransmission, zero_window, server_pause), HTTP/1.x method, URI and
status when dissected; on HTTP/2 and gRPC that tshark dissects (cleartext h2c on any port with
tshark 4.4.0 and later; tshark 4.2 finds it only on an HTTP port such as 80 or 8080; TLS only with
keys) one exchange per stream (`h2_stream`) labelled with :method, :path, :authority, :status and
`grpc_status`, RST_STREAM as `stream_reset_by`, pushed streams as `server_pushes`; per flow the
handshake (or ACK) round trip, lost SYNs or SYN-ACKs with the time to connect, which side the
capture sits near, `time_split_ms` and a `verdict`: server-bound, network-bound, receiver-bound,
fast, idle-or-push (answers only after 10 s: long polls, push channels) or no-response; per-server
server_ms percentiles, SYNs never answered or refused (`not_opened`). One connection split over
several tcp.stream numbers by a tap's copies is joined

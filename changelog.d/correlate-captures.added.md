- `correlate_captures` (toolset `network`): the same traffic captured at two points on its path
  (client and server side, either side of a firewall, NAT or tunnel), matched packet by packet on
  an identity that survives NAT (IP protocol, ID and length plus TCP raw sequence and ack, or UDP
  length). Returns packets lost between the points per flow, NAT address and port rewrites, the
  TTL drop (hops), DSCP changes, the clock offset between the captures and the delay variation
  around it, with `issues` and a `verdict`.

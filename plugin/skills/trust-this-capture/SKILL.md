---
name: trust-this-capture
description: Decide whether loss, retransmissions and missing answers in a capture are real or artefacts of how it was taken. Use before blaming the network.
---

# Can this capture be trusted?

Get the server's `trust_this_capture` prompt (`path`), or:

1. `capture_metadata(path)`: interface drops, snaplen, capture filter.
2. `capture_quality(path)`: read its `verdict` (copies, snaplen cuts, capture-side loss).
3. `pcap_info(path)` for the span; `expert_info(path)` for what tshark itself flags.

Say what the capture can and cannot show before drawing conclusions from it.

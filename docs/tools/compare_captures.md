---
order: 550
readme: A working and a failing capture side by side, with the first divergence
llms: a working and a failing capture of the same procedure: aligned message ladders, the first divergence, the AVP/IE differences of each changed step and the timing gaps. Give `imsi_b` when the failing capture is another subscriber; with no identity every transaction is compared.
---

A working and a failing capture of the same procedure side by side: both message ladders (the
subscriber trace, or every transaction without an identity), keepalives dropped, identical retries
merged with a `repeat` count, aligned by protocol and message; `first_divergence`, every step as
same, changed, replaced, only_a or only_b, the `differences` of changed steps (result, pairing, key
Diameter AVPs, GTP IEs; identities ignored) and the largest round-trip and offset gaps

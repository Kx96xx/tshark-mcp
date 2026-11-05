---
order: 160
readme: tshark's expert warnings, errors and malformed packets, with frames
llms: tshark's expert warnings, errors and malformed packets (`-z expert`) by severity, group, protocol and summary, with counts and the frames behind each. Check it when a decode looks wrong or before blaming the network for what tshark could not parse.
---

tshark's own expert information (`-z expert`): warnings, errors and malformed-packet flags grouped
by severity, group (Malformed, Undecoded, Sequence, Protocol, ...), protocol and summary, with the
count, first frame and up to five sample frames of each; `summary` counts by severity and protocol
and the malformed frames. Check it before trusting a decode

---
order: 150
readme: One frame's full dissection, as in Wireshark's details pane
llms: one frame's full dissection (every layer and field, enumerations named), bounded to `max_fields` leaf fields with the innermost layers kept first. Use it to verify a row: every row carries `frame`, `request_frame`/`answer_frame` or `first_frame`/`last_frame`.
---

One frame's full dissection as tshark decodes it, every layer and field nested as in Wireshark's
details pane; `layers` keeps only the protocols named; at most `max_fields` leaf fields (default
300, server cap 2000), the innermost layers first, with `fields_dropped` for the rest; `malformed`
when tshark flagged the packet. Use it to verify any row: rows carry `frame`,
`request_frame`/`answer_frame` or `first_frame`/`last_frame`

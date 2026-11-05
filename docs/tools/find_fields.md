---
order: 170
readme: Search tshark's field names without reading a capture
llms: search tshark's field names, e.g. "result code" with protocol "diameter" gives `diameter.Result-Code`. No capture is read.
---

Search the fields and protocols this tshark knows (`tshark -G fields`): every word of `query` must
appear in the abbreviation, name or description; `protocol` keeps one protocol's fields; rows give
the abbreviation, name, type, protocol, display base and description, exact matches first. No
capture is read

---
order: 180
readme: Compile a display filter and name its fields without reading a capture
llms: tshark's own verdict on a display filter (errors with the span they point at, dftest warnings such as deprecated names when available) and the fields it names. No capture is read.
---

Check a display filter without reading a capture: the server lint, then tshark compiles it against
an empty capture and its own error comes back with the offset and length it points at; dftest
warnings (deprecated names) when dftest is installed beside tshark (`warnings_checked`); the fields
the filter names, with their types

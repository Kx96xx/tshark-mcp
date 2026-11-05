- Every argument of every tool has a one-line schema `description`, in the compact and the full
  tool list (mcp-builder audit G1). The compact tool list grows from about 2,890 to 3,210 bytes
  per tool on average.
- Tool results carry their text content as compact JSON (no indentation): about 30% fewer bytes
  for the same `structuredContent` (G2).
- Paged results return `has_more` next to `next_offset`: true when more rows exist, false on the
  last page (G4).
- `columns` lists its valid row keys as `items.enum` in the full schema (`schema://tools/<name>`,
  `--schema-profile full`); the compact list leaves the enum out (G7).
- `output="summary"` is capped at 8 KB instead of 4 KB, so it keeps its three rows on wide rows
  such as `ims_registration` and `call_legs`, where it used to return one (G11).

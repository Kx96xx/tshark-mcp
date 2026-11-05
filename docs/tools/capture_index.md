---
order: 90
readme: A directory of ring-buffer files in time order: span, packets, holes and overlaps between files, which files cover an incident window
llms: the capture files of a directory (a ring buffer) in time order from capinfos: first/last packet, duration, packets, bytes, interfaces, the hole or overlap against the previous file; `summary` with holes, overlaps, whether name order is time order, and with a window the files that cover it and whether they cover it whole. Call it before opening files for an incident at a known time.
---

A directory of capture files (a ring buffer, rotated files) indexed by capinfos without decoding a
packet, in time order: per file `first`/`last` (ISO and epoch), `duration_s`, `packets`, `bytes`,
`interfaces`, `file_type`, `link_type`, `gap_before_s` (hole after the previous file's last packet)
or `overlap_before_s`, and with a window `covers_window`. `summary`: span, totals, `holes` (gaps
longer than `min_gap_s`, default 1 s; `in_window` when inside the window), `overlaps`, `ordering`
(name order versus time order: a wrapped ring), and with a window `window_files` and
`window_covered`. `max_files` files per call (server cap `--max-files`) from `offset` in name order,
under one shared time budget; relative bounds are taken from the earliest and latest file indexed

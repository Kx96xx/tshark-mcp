---
order: 80
readme: Which captures in a directory mention an IMSI, MSISDN, IP, Call-ID or Session-Id
llms: which files in a directory mention an IMSI, MSISDN, IP address, SIP Call-ID or Diameter Session-Id; hit counts, first/last timestamps, protocol breakdown per file. Call this first when you do not know which capture to open.
---

Which captures in a directory (or one file) mention an IMSI, MSISDN, IP address, SIP Call-ID or
Diameter Session-Id: hits, first/last timestamp and protocol breakdown per file, bounded by a
file-count cap and one shared time budget; files without hits that were only read up to the frame
cap are listed in `partially_scanned`. Hits count packets that carry the identifier, so for Diameter
they count requests (answers carry no User-Name)

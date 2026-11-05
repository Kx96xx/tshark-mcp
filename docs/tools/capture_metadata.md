---
order: 110
readme: pcapng writer, interfaces, snaplen, capture filter and the drop counters tshark cannot show
llms: what a pcapng file says about itself, read from its blocks in Python without decoding a packet: format, version, sections, compression; the writer (application, OS, hardware, comment); per interface the name, description, link type, snaplen, timestamp resolution, capture filter, the Interface Statistics Block counters tshark has no field for (received, dropped by the interface, dropped by the OS, accepted by the filter, delivered), packets, bytes, first/last packet, packets cut to the snaplen; `drops_total`, packet comments and `issues`. A legacy pcap gives its header with `metadata_available: false`. `pcap_info` also reports `metadata_available` and `interface_drops`.
---

The pcapng blocks walked in pure Python (no tshark run, packet bytes skipped, never decoded; bounded
by the file size cap and the run timeout): `file` (format, version, byte order, gzip or other
compression, sections), `writer` (the section header's application, OS, hardware and comment),
`interfaces[]` (id, section, name, description, link type, snaplen, timestamp resolution and offset,
capture filter, FCS length, speed; `statistics` from the last Interface Statistics Block: received,
dropped_by_interface, dropped_by_os, accepted_by_filter, delivered and its timestamps; packets,
bytes, first and last packet, `truncated_packets` cut to the snaplen, `timestamps_backwards`,
`first_packet_after_interface_0_s`), `drops_total`, `packet_comments` (count and the first five with
their frame), `issues` (drops, snaplen of 256 or less, a capture filter, no statistics block,
several sections) and `read_warnings` when a damaged block ended the walk. A legacy pcap returns its
header (version, snaplen, link type, timestamp precision) with `metadata_available: false`; strings
from the file are listed in `untrusted_text_fields`. `pcap_info` gains `metadata_available` and
`interface_drops`

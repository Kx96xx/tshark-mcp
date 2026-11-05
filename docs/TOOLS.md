# Tools

The reference for every tool of tshark-mcp: arguments, what each returns, the output
contract they share, and worked examples with real output on synthetic captures. The
[README](../README.md) has the one-line summary of each; [SAFETY.md](SAFETY.md) has the caps
and the redaction rules.

## Every tool, its arguments and what it returns

Every tool with `limit` also takes three output arguments, left out of the table below:

- `columns`: the row keys to keep, such as `["message", "response"]`. Frame keys (`frame`,
  `*_frame`, `frames`) always stay, so a row can still be opened with `packet_detail`. A name
  the rows never have is an `invalid_argument` error that lists the valid ones (for
  `filter_packets` the columns are the `fields` asked for).
- `output`: `"rows"` (default) or `"summary"`: everything but the row list plus its first three
  rows, fitted into 8 KB, with `output: "summary"` in the result and `next_offset` /
  `truncated_reason` pointing at the rest. Call it first on a big capture.
- `max_output_kb`: lowers the server's output cap (`--max-output-kb`) for this call, at least
  1 KB; a larger value than the server cap changes nothing.

Every successful result carries `tokens_estimate`: its JSON size divided by 3.6.

<!-- BEGIN GENERATED: tools-reference (python scripts/gen_docs.py; edit docs/tools/<name>.md, not here) -->

| Tool | What it returns |
| --- | --- |
| `incident_summary(path, focus, budget_s)` | "What is wrong in this capture?" under one time budget (`budget_s`, default and maximum the run timeout). The documented first call on any capture. Runs `pcap_info`, `capture_quality`, `conversations`, then the protocol tools the protocol hierarchy shows: web, dns and tls (`tcp_connections`, `tcp_health`, `dns_transactions`, `tls_handshakes`, `quic_connections`, `http_transactions`, `icmp_errors`, `tunnels_overview`); voip (`call_kpis`, `rtp_streams`, `ims_registration`); mobile (`diameter_transactions`, `gtp_sessions`, `gtpv1_sessions`, `pfcp_sessions`, `sctp_associations`, `sigtran_messages`, `ims_registration`, `tunnels_overview`); and `expert_info` (error level) in every focus, limited by `focus` (auto, web, dns, tls, voip, mobile). `findings[]` ranked high, medium, low: `kind`, `severity`, `text` (one deterministic sentence), `confidence` (loss findings take it from capture_quality's verdict), `evidence` (tool, arguments, up to five frames), `details` (that tool's own sentences), `next_call`. Fixed thresholds (in `thresholds`): TCP retransmissions above 1% of at least 20 data segments, HTTP 5xx above 5% of answered requests, more than 10% of DNS queries unanswered (not counting those near the capture end), DNS p90 above 500 ms, any failed TLS handshake (QUIC handshakes are left to the QUIC pass) or certificate problem, failed QUIC connections (or UDP 443 blocked with a TCP fallback), any destination with failed connection attempts, ICMP routing loops, path-MTU and prohibited errors, failed or unanswered tunnel handshakes (IKE, WireGuard, OpenVPN), tunnels one way only (3 packets or more), tunnel MTU overruns, failed calls (high below 80% NER), one-way RTP (not when the SDP asks for it with sendonly, recvonly or inactive), failed IMS registrations and challenge loops, failed or unanswered Diameter, GTPv2-C, GTPv1-C and PFCP transactions, PFCP peer restarts, SCTP INITs answered with ABORT, INITs without INIT_ACK, aborts and 2 or more unacknowledged heartbeats, MAP/TCAP errors, rejects, aborts and unanswered Begins, and tshark's error-level expert items (malformed packets). Also `capture` (span, packets, protocols, `trust`, `cannot_show`: one-sided streams, encrypted payloads, a window), `top_talkers` (5 IP conversations), `timeline` (first packet, first problem, first high finding, last problem, last packet), `not_checked` (pass and reason: protocol absent, focus, budget, error), `not_analysed` (protocols in the capture that no pass reads, such as DHCP, MQTT, CoAP, Kerberos or ISUP: protocol, frames and a `next_call`, a specialist tool when one exists or `filter_packets`; the `summary` sentence ends with "no checks exist for: ...") and `passes` (ms and status per pass). With `start`/`end` every pass reads only the window and every `next_call` carries it |
| `diff_captures(path_a, path_b, by, filter, include_same, limit, offset)` | What changed between a capture from before a change (`path_a`) and one from after (`path_b`) for TCP/IP services. `by`: destinations (`tcp_connections` per server: attempts, success rate, connect time p50), dns (`dns_transactions`: per name the answered share, usual rcode and answer time; per resolver the answered share and p50), tls (`tls_handshakes` per SNI: established share, usual outcome, version, cipher suite, certificate expiry), http (`http_transactions` endpoints: 5xx and 4xx share, p50/p99), tcp (`tcp_health` per server: retransmitted share, handshake RTT p50, zero windows, resets, server MSS) or all. `differences[]`: `section`, `key`, `a`, `b`, `delta`, `change` (worse, vanished, appeared, better, same), `sentence`, `rate_per_min` (volume per minute in each capture, as the two differ in length), worst first; rows without a change only with `include_same`. A share must move 10 points (5 for 5xx, 1 for retransmissions) and a time by half and at least 20 ms. `first_differences` (top five sentences), `summary` (changes per section), `a`/`b` (span, packets), `not_compared` (sections skipped or read in part). `filter` goes to the dns, tls, http and tcp passes; `start`/`end` apply to both captures. Separate from `compare_captures`, which aligns one telecom procedure's ladder |
| `throughput_timeline(path, interval, per, top, filter, limit, offset)` | One `-T fields` pass, computed in the server, copies dropped first (same IP ID, sequence, length and ACK within 1 s). `intervals[]` every `interval` seconds (default 1, at most 10,000 intervals): `packets`, `bytes`, `bps`, `goodput_bps` (TCP bytes newly acknowledged, from `tcp.ack_raw`), `acked_bytes`, `retransmitted_bytes` (segments ending at or before the highest sequence already sent), `zero_windows`, `window_full`, `duplicate_acks`, `syns`, `syns_unanswered`, `dns_queries`, `tls_client_hellos`, `icmp_errors` (zero counters left out); paged with `limit`/`offset`. `per` = conversation, host or stream adds `series` for the `top` keys by bytes (each with its intervals, peak and mean). `streams[]` per TCP stream: flow, bytes, retransmitted share, peak and mean goodput, max bytes in flight, max window, `rwnd_limited_share`, `idle_share` and `verdict`: loss-limited (more than 2% retransmitted), receiver-limited (zero or full window in 20% of active intervals), application-idle (no packet in half its life), sender-limited (bytes in flight never above a quarter of the window), fine. `summary`: span, totals, peaks, counters, idle intervals, copies dropped. `issues`: where goodput fell below a quarter of its usual level and why, the stream verdicts, idle time, bursts (a counter at three times its usual rate and at least 10 in one interval), unanswered SYNs |
| `tunnels_overview(path, kind, endpoint, mtu, filter, limit, offset)` | One `-T fields` pass over the tunnel protocols (unknown fields of an older tshark are left out). Kinds: GRE, ERSPAN, VXLAN, Geneve, IP-in-IP (4in4, 6in4, ...), IPsec (IKE, ESP, AH, NAT-T on UDP 4500), WireGuard, OpenVPN, L2TP, GTP-U. A row per tunnel: GRE/VXLAN/Geneve/L2TP by outer endpoint pair and key, VNI or tunnel id; IPsec and GTP-U by the pair; WireGuard and OpenVPN by pair and UDP ports. `endpoint_a` sent first. `packets_a_to_b`/`b_to_a`, `bytes_*` (frame bytes), `one_way`, first/last and frames; clear kinds add `inner_protocols`, `inner_conversations` (top three), `inner_ethernet`; encrypted kinds `inner: "encrypted"`. `overhead_bytes` is the outer minus the inner IP length (most common value), `largest_outer_ip_len`, `df_above_mtu` (outer DF packets above `mtu`, default 1500), `fragmented_outer` (reassembled outer packets), `inner_syn_mss`. IPsec: `esp_sas` (SPI, direction, packets, bytes, first frame), `esp_pairs` (both directions or one direction only), `ah_spis`, `nat_traversal`, `handshake` (IKEv1/IKEv2 exchanges, `error_notifies` by name, unanswered requests paired by initiator SPI and message id, `dpd_unanswered`, `outcome` established, failed, no response or incomplete). WireGuard `handshake`: initiations, responses, cookie replies, unanswered initiations (sender index never acknowledged), keepalives, data each way, `outcome`. OpenVPN: opcodes, client and server resets, data each way, `outcome`. GTP-U: `teids` (use `gtp_tunnel_health` for the inner TCP). `issues`: unanswered WireGuard initiations or OpenVPN resets, IKE error notifies with the usual cause, IKE_SA_INIT never answered, unanswered DPD, an ESP SA with no return SA, a tunnel carrying traffic one way, inner MSS plus 40 (60 for IPv6) plus the overhead above `mtu`, DF packets above `mtu`, outer fragmentation. Tunnels with issues come first. `summary`: tunnels per kind, packets, with issues, one way |
| `export_subset(path, display_filter, name, max_packets, snaplen, headers_only)` | The one tool that writes, off unless the server was started with `--export-dir DIR` (`export_disabled` otherwise). A `-T fields` pass lists the frames matching `display_filter` (required) and the window under the frame cap; the first `max_packets` (default 10,000, at most 100,000) that fit in `--export-max-mb` (default 50) are written by tshark (`-F pcapng -w`, argv built by the runner, never by the agent) to a temporary file the server created with O_EXCL in the export directory, cut by `editcap -s` when `headers_only` (96 bytes) or `snaplen` (64 to 262,144) is given, then hard-linked to `name` (reduced to `[A-Za-z0-9._-]`, `.pcapng` appended, no leading dot, at most 100 characters). An existing file or symlink under that name is `file_exists`: nothing is ever replaced. Returns `written` (`path`, `name`, `packets`, `bytes`, `sha256`, `first`/`last`, `first_frame`/`last_frame`, `snaplen`), `capped` and `capped_reason`, `export_dir`, `max_export_bytes` and a `reminder` that the file still holds addresses and identifiers (redaction rewrites results, not packets). The audit log gets a `write` record with source, file, packets, bytes, sha256 and filter. Annotated `readOnlyHint: false`, `destructiveHint: false` |
| `tls_certificates(path, server_name, server, expiring_within_days, filter, limit, offset)` | The same pass and connection rebuild as `tls_handshakes` (copies dropped, TLS inside GTP-U from the inner packet); every certificate of each Certificate message is parsed from its DER bytes in the server, without a trust store, private key or decryption. `chains[]` per server, SNI and leaf fingerprint: `leaf` (`subject_cn`/`subject_o`, `issuer_cn`/`issuer_o`, `san` (20 names, 5 IPs) and `san_total`, `not_before`/`not_after`, `days_left` at the handshake and `days_left_now`, `key_algorithm`, `key_bits`, `key_curve`, `signature_algorithm`, `self_signed`, `is_ca`, `wildcard`, `serial`, `fingerprint_sha256`), `intermediates` (subject, issuer, not after, signature algorithm, CA flag), `chain_length`, `order_ok` (each certificate issued by the next), `missing_intermediate` (no certificate in the chain issued the leaf and it is not self-signed), `self_signed`, `expired`, `not_yet_valid`, `name_matches` (SNI against SAN, or CN without SAN, wildcards included), `ocsp_stapled` (a CertificateStatus message), `connections`, `frames` (first five), `tls_versions`, `alerts`, `clients_rejected` and `rejected_frames` (a client alert bad_certificate, unsupported_certificate, certificate_revoked, certificate_expired, certificate_unknown, unknown_ca or access_denied, or `client_rejected_likely`). `issues`: expired, not yet valid, expiring within 30 days, SAN/CN mismatch, self-signed, missing intermediate, out-of-order chain, MD5 or SHA-1 signatures below a self-signed root, RSA keys under 2048 bits, expired intermediates, client rejections. `summary`: chains, connections, expired, expiring within 30 days, self-signed, name mismatch, missing intermediate, weak signature, `tls13_connections_skipped`, `connections_without_certificate`, versions. `expiring_within_days` keeps chains with at most that many days left at the handshake (and expired ones); `server` is the server's IP. Certificate text is listed in `untrusted_text_fields` |
| `quic_connections(path, server_name, server, filter, limit, offset)` | One `-T fields` pass over `quic` and TCP ClientHellos (fields an older tshark lacks are left out). The side of each packet comes from its address and port, so a client and a server on one address (loopback) are told apart. Headers only: version, packet type (v1 and v2 numbering), DCID/SCID, Version Negotiation list, Retry token, spin bit, and when tshark can decrypt the Initial the SNI and a CONNECTION_CLOSE. A connection starts at a client Initial; later packets join by any connection ID either side used, or by UDP 4-tuple; joining by CID from a new 4-tuple is `migrated` (`migration_frames`). Per connection: `client`, `server`, `sni`, `version` and `server_version` when different, `initial_sent`, `server_initial`, `handshake_packets_both_ways`, `one_rtt_both_ways`, `zero_rtt`, `retry` (frame, token), `version_negotiation` (offered, supported), `connection_close` (from, code, name, reason), `spin_rtt_ms` (median time between spin flips in one direction), `packets` per side and type, `tcp_fallback` (a TLS ClientHello over TCP from the same client to the same server IP or SNI within 2 s after a failed attempt: frame, stream, server, SNI, `after_ms`), `outcome` (established, handshake_only, handshake_incomplete, version_negotiation, retry_unanswered, closed_with_error, no_response) and `issues`. Failed connections first. `summary`: outcomes, versions, `tcp_fallbacks`, `migrated`, `servers_never_answering`, `udp_443_blocked_likely` (no server in the result answered and the clients fell back to TCP), `gquic_packets` (Google QUIC packets, which have other headers and are not analysed; an issue says so) |
| `find_identifier(path, identifier, kind, max_files, offset)` | Which captures in a directory (or one file) mention an IMSI, MSISDN, IP address, SIP Call-ID or Diameter Session-Id: hits, first/last timestamp and protocol breakdown per file, bounded by a file-count cap and one shared time budget; files without hits that were only read up to the frame cap are listed in `partially_scanned`. Hits count packets that carry the identifier, so for Diameter they count requests (answers carry no User-Name) |
| `capture_index(path, start, end, max_files, min_gap_s, offset)` | A directory of capture files (a ring buffer, rotated files) indexed by capinfos without decoding a packet, in time order: per file `first`/`last` (ISO and epoch), `duration_s`, `packets`, `bytes`, `interfaces`, `file_type`, `link_type`, `gap_before_s` (hole after the previous file's last packet) or `overlap_before_s`, and with a window `covers_window`. `summary`: span, totals, `holes` (gaps longer than `min_gap_s`, default 1 s; `in_window` when inside the window), `overlaps`, `ordering` (name order versus time order: a wrapped ring), and with a window `window_files` and `window_covered`. `max_files` files per call (server cap `--max-files`) from `offset` in name order, under one shared time budget; relative bounds are taken from the earliest and latest file indexed |
| `pcap_info(path)` | Packet count, duration, first/last timestamp, size, link type, top 15 protocol-hierarchy entries, active limits; `window_hint` (first and last packet to pass as `start`/`end`); with a window, `frames_in_window` |
| `capture_metadata(path)` | The pcapng blocks walked in pure Python (no tshark run, packet bytes skipped, never decoded; bounded by the file size cap and the run timeout): `file` (format, version, byte order, gzip or other compression, sections), `writer` (the section header's application, OS, hardware and comment), `interfaces[]` (id, section, name, description, link type, snaplen, timestamp resolution and offset, capture filter, FCS length, speed; `statistics` from the last Interface Statistics Block: received, dropped_by_interface, dropped_by_os, accepted_by_filter, delivered and its timestamps; packets, bytes, first and last packet, `truncated_packets` cut to the snaplen, `timestamps_backwards`, `first_packet_after_interface_0_s`), `drops_total`, `packet_comments` (count and the first five with their frame), `issues` (drops, snaplen of 256 or less, a capture filter, no statistics block, several sections) and `read_warnings` when a damaged block ended the walk. A legacy pcap returns its header (version, snaplen, link type, timestamp precision) with `metadata_available: false`; strings from the file are listed in `untrusted_text_fields`. `pcap_info` gains `metadata_available` and `interface_drops` |
| `capture_quality(path)` | Whether loss and timing conclusions can be drawn from the capture: duplicate copies of the same packet with the likely cause (two VLANs or interfaces, a Linux any capture, tunnelled and decapsulated, rebuilt copies with zeroed TCP headers; without an IP ID a copy also needs to arrive within 5 ms of the first sighting with the same TCP, UDP or ICMP checksum, an ICMP error the same quoted packet, and SCTP the same TSNs, acknowledged TSN and heartbeat information; a UDP copy also needs the same QUIC packet number, RTP sequence number and SSRC or DNS ID when tshark reads one; identical TCP RSTs and pure ACKs without an IP ID and without a link-layer difference are real repeats, counted in `duplicates.repeated_identical`); TCP bytes the receiver acknowledged that the capture never saw (dropped by the capture, or the file was filtered) versus gaps a retransmission filled (lost on the network before the capture point); frames cut to the snapshot length; packets above 1500 bytes (segmentation offload); bad IP/TCP/UDP checksums and whether they are offload artifacts (one sender, data acknowledged anyway); TCP streams seen in one direction only and unanswered SYNs; timestamps going backwards, identical stamps, resolution, longest silence; a `verdict` (trustworthy, use with care, not trustworthy) with the reasons |
| `conversations(path, layer, filter, limit, offset)` | Top talkers at `ip`, `ipv6`, `tcp`, `udp`, `sctp` or `eth` with frames and bytes per direction, optionally restricted by a display filter |
| `filter_packets(path, display_filter, fields, limit, offset)` | Rows of fields for packets matching a display filter; field names are validated against `tshark -G fields` |
| `packet_detail(path, frame, layers, max_fields)` | One frame's full dissection as tshark decodes it, every layer and field nested as in Wireshark's details pane; `layers` keeps only the protocols named; at most `max_fields` leaf fields (default 300, server cap 2000), the innermost layers first, with `fields_dropped` for the rest; `malformed` when tshark flagged the packet. Use it to verify any row: rows carry `frame`, `request_frame`/`answer_frame` or `first_frame`/`last_frame` |
| `expert_info(path, severity, filter, limit, offset)` | tshark's own expert information (`-z expert`): warnings, errors and malformed-packet flags grouped by severity, group (Malformed, Undecoded, Sequence, Protocol, ...), protocol and summary, with the count, first frame and up to five sample frames of each; `summary` counts by severity and protocol and the malformed frames. Check it before trusting a decode |
| `find_fields(query, protocol, limit, offset)` | Search the fields and protocols this tshark knows (`tshark -G fields`): every word of `query` must appear in the abbreviation, name or description; `protocol` keeps one protocol's fields; rows give the abbreviation, name, type, protocol, display base and description, exact matches first. No capture is read |
| `check_filter(filter)` | Check a display filter without reading a capture: the server lint, then tshark compiles it against an empty capture and its own error comes back with the offset and length it points at; dftest warnings (deprecated names) when dftest is installed beside tshark (`warnings_checked`); the fields the filter names, with their types |
| `cause_lookup(protocol, code, application, message, query, limit, offset)` | What a cause or result code means, without a capture: the name from tshark's own value strings (`tshark -G values`; SIP, MAP, CP, TP-Status and SBI causes from the server's table), the meaning, the spec reference (`ref`), `typical_causes`, `related` codes and `check_next` tool calls. Protocols: diameter, gtpv2, gtpv1, pfcp, nas_emm, nas_esm, nas_5gmm, nas_5gsm, s1ap and ngap (`code="radioNetwork:21"`), sip, q850, isup, camel_release, map, tcap_abort, sccp_return, sgsap, rp, cp, tp_status, http_sbi (ProblemDetails cause strings). Diameter: `application` (s6a, gx, rx, cx, sh, ...) reads the code as an Experimental-Result-Code (5004 is DIAMETER_INVALID_AVP_VALUE as a Result-Code and ROAMING_NOT_ALLOWED in S6a), and a code found in both says so in `also`. `message` (REGISTER, INVITE) adds the per-message note. `explained: false` means only the name is known; `known: false` that no table names it or it is reserved. `query` lists codes whose name or meaning holds every word |
| `diameter_peers(path, host, realm, application, filter, limit, offset)` | One row per Diameter peer connection (the two IP addresses) with a `verdict` (healthy, degraded: routing errors, 5xxx, missed watchdogs or unanswered requests; restarted: an Origin-State-Id changed; down: the CER refused, or a DPR with no later successful CER) and `issues`. `hosts`: Origin-Host per address. `capabilities`: each CER with its CEA result (explained when refused), advertised Auth and Acct applications by name, the peer's applications, Firmware-Revision, Inband-Security-Id, Origin-State-Id. `watchdog`: DWR requests, answered, `missed` (no DWA), `cadence_s` (median interval), `longest_gap_s`. `disconnects`: DPR with Disconnect-Cause named (REBOOTING, BUSY, DO_NOT_WANT_TO_TALK_TO_YOU), sender, answered. `restarts`: Origin-State-Id before and after per Origin-Host. `applications`: per application id: requests, answers, `success_pct`, result classes, `errors` explained through cause_lookup, `routing_errors` (3002, 3003, 3004, 3005, 3006 with the Destination-Realm and Destination-Host the request named), `rtt_ms` p50/p95/max, unanswered. `failed_avps`: AVP names inside Failed-AVP, counted. `error_messages`: Error-Message text, capped, untrusted. `routing`: requests with Destination-Host versus realm-only, deepest Route-Record, redirects. Answers pair by command code and hop-by-hop id in the opposite direction. Filters: `host` (part of an Origin-Host), `realm`, `application`. `summary`: peers per verdict, routing errors, missed watchdogs, restarts, disconnects |
| `diameter_transactions(path, filter, limit, offset)` | Requests paired with answers by Hop-by-Hop/End-to-End id and Session-Id: command name, application, hosts, realms, User-Name, Result-Code or Experimental-Result-Code with name, RTT, `unanswered` (`near_capture_end` too when the capture stopped before the answer was due, counted apart) |
| `diameter_sessions(path, session_id, imsi, command_code, filter, limit, offset)` | Diameter grouped by Session-Id: application, hosts, realms, User-Name, first/last time, request and answer command codes, every Result-Code, unanswered (and near the capture end) and failed counts, worst RTT, and the paired transactions |
| `diameter_avps(path, session_id, imsi, command_code, frame, filter, detail, max_avps, limit, offset)` | The AVPs of paired Diameter transactions. `detail="key"`: Result-Code and Experimental-Result, ULR/ULA/CLR/PUR/PUA/IDR/NOR flags with bit names, Cancellation-Type, RAT-Type, Visited-PLMN-Id, AIR vectors, Gx CC-Request-Type, Event-Trigger, rule reports and QoS, and a Subscription-Data digest (MSISDN, status, ODB, access restrictions, AMBR, one line per APN with PDN type, QCI, ARP, AMBR and PGW). Per application, picked by application id, a digest: `gy` for Gy/Ro (request type and number, Service-Context-Id, Subscription-Id, per Multiple-Services-Credit-Control the rating group, service id, requested, granted and used units with reporting reason, validity time, quota holding time, thresholds, Final-Unit-Indication action and redirect address, MSCC Result-Code), `rx` (Rx-Request-Type, UE address, AF identifiers, per Media-Component-Description the media type, flow status, first line of each Codec-Data, bandwidths and flow count, Specific-Action, Abort-Cause), `cx` (User-Authorization-Type, Server-Assignment-Type, IMPI, IMPUs, Server-Name or capability counts, SIP-Number-Auth-Items, authentication scheme and item count, associated identities, Deregistration-Reason), `sh` (User-Identity, Data-Reference names, requested domain, Current-Location, Identity-Set, Sh-User-Data as size, root and child element names) and `s13` (IMEI, software version, Equipment-Status). Each digest's `results` names the Result-Code and Experimental-Result-Code; a failed one carries `explained` (meaning and reference from cause_lookup, Experimental codes looked up for that application). `detail="full"`: every AVP as a nested tree, capped at `max_avps` leaves per message (server cap 2000); enumerated values are named. In both views authentication material (RAND, XRES, AUTN, KASME, SRES, Kc, CK, IK, SIP-Authenticate, SIP-Authorization) reads `withheld (authentication material)` and Sh-User-Data is never returned as a body |
| `gtp_sessions(path, imsi, apn, teid, filter, limit, offset)` | GTPv2-C requests paired with responses by sequence and peer (across a NAT too, with `response_path`): message name, IMSI, MSISDN, APN, F-TEIDs with interface names, cause code and name, PAA, RTT, `unanswered` (legs of a proxy chain answered elsewhere get `leg_without_response` and a `note` instead, or `near_capture_end` when the capture on that leg's interface stopped before the response could be relayed, counted apart; a request no leg answered that the capture stopped too soon after keeps `unanswered` and gets `near_capture_end`, counted in `unanswered_near_capture_end`; packets captured twice `duplicate_of_frame`; Modify Bearer, Delete Session and other requests without an IMSI are tied to their legs through the TEIDs the Create announced, or the same sequence number and TEID on both legs); the structured filters keep both halves of each transaction, and `apn` given as a network identifier also matches it with the operator identifier appended |
| `gtp_ies(path, imsi, teid, frame, message, filter, detail, max_ies, limit, offset)` | The IEs of paired GTPv2-C requests and responses, selected by `imsi`, `teid` (header or F-TEID), `frame` or `message` (type number or name; a request name selects its response too). `detail="key"`: `request_ies` and `response_ies` with IMSI, MSISDN, MEI, APN, selection mode, PDN type, PAA, APN restriction, serving network (MCC-MNC), RAT, ULI (TAI, ECGI with eNB and cell id, CGI, SAI, RAI, LAI), UE time zone, indication flags that are set, charging characteristics and ID, recovery, APN-AMBR, F-TEIDs by interface, PCO option names (PAP and CHAP payloads are never returned), bearer contexts (EBI, QCI, ARP PL/PCI/PVI, MBR/GBR, F-TEIDs, cause), the cause with `offending_ie` (named from the request) and `source` (CS bit: this node or relayed), the RAN/NAS cause of a Delete Session with a `cause_lookup` call, and the names of other IEs. Rejects (and 18/19) get `likely_causes` built from the request. Enumerations use tshark's own display text. `detail="full"`: every IE as a tree, at most `max_ies` per message (cap 2000), `*_ies_dropped` for the rest |
| `gtpv1_sessions(path, imsi, apn, teid, filter, limit, offset)` | GTPv1-C (Gn/Gp) requests paired with responses by sequence and peer (across a proxy too, with `response_path`): Create/Update/Delete PDP Context and the rest, IMSI, MSISDN, APN, NSAPI, RAT type, IMEISV, TEID-C/TEID-U and GSN address on each side, end-user address, cause code and name, RTT, `unanswered`, and the same proxy-chain fields as gtp_sessions |
| `gtp_user_plane(path, teid, limit, offset)` | GTP-U per TEID: packets, bytes, first/last time, outer endpoints, inner IP addresses |
| `gtp_tunnel_health(path, teid, mtu, limit, offset)` | User-plane health per GTP-U tunnel from the packets inside it: inner TCP flows, SYN/SYN-ACK MSS, retransmissions and their share of data segments split like `tcp_health` (`lost_before_capture` when the resend filled a gap, `retransmitted_after_capture` when the capture had already seen the bytes), out-of-order segments (filled a gap but were overtaken, not lost), keep-alives, duplicate ACKs, zero windows, resets; inner ICMP by type with the fragmentation-needed MTU; largest outer and inner packets, tunnel overhead and DF packets above `mtu`; whether the reverse direction carries traffic; `issues` in plain words; ICMP errors sent about the tunnel packets themselves (`outer_icmp`). Copies of the same packet (a capture on several interfaces) are counted once |
| `pfcp_sessions(path, seid, ue_ip, view, filter, limit, offset)` | PFCP (N4/Sxa/Sxb, TS 29.244) requests paired with responses and grouped into sessions by their CP and UP F-SEIDs. `view="sessions"`: per session the SEIDs and addresses, UE IP, network instance/DNN, establishment and deletion results, modifications (and rejected ones), Session Report counts by type (DLDR, USAR, ERIR, UPIR), summed usage-report volumes, `state` and `issues` (a rejection with its cause, a FAR switched to BUFF or DROP, 'Session context not found', requests without a response). `view="transactions"`: cause code and name, offending IE, rule counts, FAR apply actions, report types and usage reports per pair; copies of one packet are marked. `nodes`: association result, heartbeats and Recovery Time Stamp changes (peer restarts). `seid` or `ue_ip` select one session, both sides |
| `message_rates(path, protocol, interval, imsi, filter, burst_min, storm_min, limit, offset)` | Diameter, GTPv2-C, GTPv1-C, SIP and MAP messages counted by name per interval: total and distinct (a message seen on both legs of a relay or retransmitted counts once), peak and when, mean rate; `bursts` (three times the usual rate or more), `subscriber_loops` (one subscriber repeating a request, with the gap between repeats, whether it is regular, and the sending and receiving nodes: SCCP global titles for MAP (the subscriber's MGT labelled `MGT`), Origin-Host and Destination-Host or realm for Diameter, else IP addresses; `alternating` marks a ping-pong between two nodes), a per-interval `timeline` and one-line `storms`. MAP messages are tied to the IMSI named anywhere in their TCAP dialogue, GTP responses to the IMSI of their request |
| `dns_transactions(path, name, filter, limit, offset)` | DNS queries paired with responses by transport, addresses, ports, DNS id and name, unanswered ones included: type, rcode name, answers and addresses, RTT, `unanswered` (`near_capture_end` when the capture on that interface stopped before the answer was due), resends with the same id and port, `retry_of` for a new query after an unanswered or failed one, TC answers and the TCP fallback that followed; per-server answered share, rcodes and latency min/p50/p90/p99/max; the names that failed, were retried or were slow; `issues`. Copies of one packet (several interfaces, GTP legs) count once, DNS inside GTP-U is read from the inner packet, and problem transactions come first |
| `tls_handshakes(path, server_name, filter, limit, offset)` | TLS over TCP and QUIC per connection, from the clear part of the handshake (no decryption, no key material): the client's offer (SNI, ALPN, versions, cipher-suite count without GREASE, fallback SCSV) against the server's choice (version, suite, ALPN when in clear), HelloRetryRequest, SYN-to-ClientHello and ClientHello-to-ServerHello times, alerts with level, name and sender (QUIC CONNECTION_CLOSE too), the leaf certificate for TLS 1.2 and older (subject, issuer, SAN, validity, chain length), and an `outcome`: established, alert, no_server_hello, reset_by_server, closed_by_server, client_gave_up, client_rejected_likely (TLS 1.3 alert-sized record instead of Finished), unreadable, incomplete, one_sided (only one direction of the TCP connection is in the capture, so the handshake cannot be judged; not counted as a failure), or server_hello for QUIC; `issues` names expired certificates, SNI/SAN mismatches, deprecated or unoffered versions and repeated ClientHellos. A connection whose ClientHello is not readable is still listed (`client_hello_missing`, counted in the summary) when its ServerHello, certificate or alerts are. Copies of the same packet are found with the same rule as `tcp_health` (same IP ID and transport header, or with IP ID 0 the same checksum within a few milliseconds), plus a tap's copies with the TCP header or the IP ID zeroed; they are counted in `duplicate_copies` and never taken for a resent ClientHello or alert |
| `http_transactions(path, host, path_prefix, status, method, min_ms, view, filter, limit, offset)` | HTTP/1.x requests paired with their responses by tshark's own `http.request_in` (pipelining and several messages per segment included) and HTTP/2 / gRPC followed per stream from the frames tshark dissects; copies of the same packet count once. `view="requests"`: request and response frame, TCP stream and `h2_stream`, client, server, version, method, host (or :authority), `uri` (the path; the query string kept apart in `query`, capped at 128 characters), status and reason, Content-Type, request and response bytes (Content-Length for HTTP/1.x, DATA bytes for HTTP/2), `response_ms` (tshark's http.time: request to the frame that completed the response; HTTP/2: request HEADERS to the server's END_STREAM), `ttfb_ms` (HTTP/2: request HEADERS to response HEADERS), `grpc`, `grpc_status` and its name, `stream_reset_by` and `reset_error` (RST_STREAM code named), `unanswered` with `near_capture_end` when the capture stopped less than 5 s after the request. `view="endpoints"`: per host, method and path with numbers, UUIDs and long hex ids collapsed to `{id}`: count, status classes, unanswered, response_ms p50/p90/p99/max, response bytes p50/max, gRPC status names, servers, slowest and first frame. `summary`: requests, answered, unanswered, status mix, versions, requests per server, HTTP/2 connections, gRPC calls and `issues` (5% or more 5xx on an endpoint, p99 of 1 s or more, unanswered requests, gRPC errors, reset streams, undissected HTTP). Filters: `host` (name and subdomains), `path_prefix`, `method`, `status` (a code or a class such as `5xx`), `min_ms`. tshark finds HTTP/1.x on its HTTP ports and with its HTTP-over-TCP heuristic, HTTP/2 in clear on HTTP ports with tshark 4.2 and anywhere from 4.4.0; a second bounded pass lists in `undissected_http` the server ports whose TCP payload starts with an HTTP method or the HTTP/2 preface on streams tshark left raw (Decode As is not offered yet). No decryption |
| `response_times(path, filter, limit, offset)` | Where the time goes per TCP flow: each connection cut into exchanges (client data, then the server's answer) with think time, `server_ms` (think time less the capture-to-server round trip, so it holds at any capture point), transfer time, retransmissions and out-of-order segments (told apart by IPv4 ID), stalls with their cause (retransmission, zero_window, server_pause), HTTP/1.x method, URI and status when dissected; on HTTP/2 and gRPC that tshark dissects (cleartext h2c on any port with tshark 4.4.0 and later; tshark 4.2 finds it only on an HTTP port such as 80 or 8080; TLS only with keys) one exchange per stream (`h2_stream`) labelled with :method, :path, :authority, :status and `grpc_status`, RST_STREAM as `stream_reset_by`, pushed streams as `server_pushes`; per flow the handshake (or ACK) round trip, lost SYNs or SYN-ACKs with the time to connect, which side the capture sits near, `time_split_ms` and a `verdict`: server-bound, network-bound, receiver-bound, fast, idle-or-push (answers only after 10 s: long polls, push channels) or no-response; per-server server_ms percentiles, SYNs never answered or refused (`not_opened`). One connection split over several tcp.stream numbers by a tap's copies is joined |
| `tcp_health(path, filter, stream, mtu, limit, offset)` | Per TCP stream, with copies of the same packet dropped first (tshark counts them as retransmissions): handshake with SYN retries, the SYN to SYN-ACK and SYN-ACK to ACK halves of the RTT, MSS, window scale and SACK; per direction data segments and retransmissions split by where the loss happened (`lost_before_capture`, `retransmitted_after_capture`, `missed_by_capture` when the receiver acknowledged bytes the file lacks), reordering told apart by IP ID or TCP timestamp, duplicate ACKs, zero windows, keep-alives; `resets` with `likely_from` endpoint or middlebox from the reset's TTL and source MAC against that side's other packets, and the idle time before it; ICMP errors about the stream (a mirrored copy counts once); MSS above `mtu`, DF packets above it and the PMTUD black-hole pattern (full-size segments retransmitted and never acknowledged while small ones pass); `issues` in plain words |
| `tcp_connections(path, server, port, client, outcome, view, filter, limit, offset)` | One row per TCP connection attempt, copies of the same packet dropped first; a SYN with a new initial sequence number on the same addresses and ports is a new attempt, the same one a retry. `outcome`: connected, refused (the server side reset the SYN), filtered (no answer at all; `near_capture_end` when the capture stopped less than 3 s after the last SYN), prohibited (ICMP destination unreachable code 9, 10 or 13, ICMPv6 code 1, quoting the SYN), unreachable (other ICMP unreachable or time exceeded), reset_during_handshake, handshake_incomplete (SYN-ACK never acknowledged), one_sided (only one direction is in the capture: the SYN sender went on with ACKs or data without a SYN-ACK in the file, or the server sent data after its SYN-ACK without the client's ACK in the file; `missing_direction` names the absent direction; not counted as an attempt or a failure) or seen_midway; SYN retries with the gaps between them, `connect_ms` (first SYN to SYN-ACK at the capture point), payload bytes each way, duration, `closed_by` (client_fin, server_fin, client_rst, server_rst, open_at_capture_end), `completeness` (syn, syn_ack, data, fin, rst seen), ICMP errors with sender and frame; failed attempts first. `view="destinations"`: per server address and port the attempts, success rate, counts per outcome, SYN retries, connect time p50/max, median duration, distinct clients, peak concurrent connections and `issues` (one client dropped while other clients connect, refusals, ICMP rejects with the sender, SYN-ACKs never acknowledged, SYN retries, a client opening 50 or more short connections: no keep-alive). `server` and `client` take IP addresses, `port` the server port; the ICMP errors about a selected connection are kept |
| `icmp_errors(path, sender, about, kind, filter, limit, offset)` | Every ICMP and ICMPv6 error, read with the packet it quotes and grouped per sender, `kind` and quoted flow (source, destination, protocol; destination ports listed, at most 10): net_unreachable, host_unreachable, protocol_unreachable, port_unreachable, frag_needed (with `mtu`), packet_too_big (ICMPv6, with `mtu`), admin_prohibited (codes 9, 10, 13 to 15; ICMPv6 1, 5, 6), ttl_exceeded, reassembly_timeout, source_quench, redirect, parameter_problem, no_route, address_unreachable, source_route_failed; count, first/last frame, the quoted IP ID and `quoted_flow_seen` (the frame of the quoted original when the capture holds it, from one bounded pass over at most 32 IPv4 originals; false when it does not). Mirrored copies of one error count once. `by_sender`: errors and kinds per sender, its TTL, hop distance from the capture point and `role` (endpoint when it is a destination the packets were addressed to, else on_path). `echo`: echo requests paired with replies by identifier and sequence per source and destination, lost requests with frames, RTT min/p50/max. `issues`: fragmentation needed with the MTU, a routing loop (TTL exceeded from two routers alternating for one flow) told apart from a traceroute (three or more routers in turn), administrative rejects, no route, closed ports, redirects and lost echoes. `sender` is an IP address, `about` an address or address:port at either end of the quoted flow |
| `sip_dialogs(path, call_id, number, method, filter, limit, offset)` | Messages grouped by Call-ID: method chain, From, To, Request-URI, P-Asserted-Identity, final status, outcome after any 401/407 challenge, retransmission count, time to final response, dialog duration; a TCP segment carrying several SIP messages is split so each message joins its own dialog |
| `sip_call_detail(path, call_id)` | One INVITE call by Call-ID, built on the `sip_dialogs` row: the ladder with the messages that carry SDP marked, `outcome`, final response with its reason phrase, post-dial delay (INVITE to the first 180/183, or to the failure response as RFC 6076 defines it), ringing, answer and setup times, early media, call duration from 200 OK to BYE, retransmissions per message, Reason headers with the Q.850 cause named, Warning headers, whether the caller or the callee sent BYE or CANCEL (by From tag), and each SDP with its offer/answer role, address, port, codecs, direction and ptime, plus the codecs offer and answer (or a 488's SDP) have in common |
| `call_kpis(path, group_by, prefix_len, interval, filter, number, limit, offset)` | Call KPIs for the SIP INVITE calls, per `group_by`: peer (where the first INVITE went), trunk (source > destination), destination_prefix or source_prefix (first `prefix_len` digits, + and 00 stripped, tel parameters dropped), user_agent, interval (`interval` seconds). Each group: calls, answered, failed, `asr_pct`, `ser_pct` and `ser_without_487_pct` (RFC 6076 SER, 3xx left out of the denominator, then 487 too), `ner_pct` (answered plus 486/600/603, and 480/408/487 after a 180/183, over calls), `pdd_ms` p50/p90/p99/max (first INVITE to first 180/183, or to the failure response without one: RFC 6076 Session Request Delay), `answer_without_ringing_ms`, `ringing_ms` (18x to 200), `acd_s` mean and median (200 to BYE), `answered_without_bye`, `failure_codes`, `q850_causes` (from Reason headers), `no_final_response`, `near_capture_end` (no final and the capture ended within Timer B, 32 s, of the INVITE, or Timer C, 180 s, after a provisional; left out of every ratio), `first_frame`. `summary` gives the same for the whole file, `method` the definitions, `worst_calls` up to ten failed or slowest calls with Call-ID and frame. A 401/407 challenge and the retried INVITE are one call; retransmissions and re-INVITEs do not count |
| `call_legs(path, call_id, number, window_s, ladder, filter, limit, offset)` | The legs of one call that a B2BUA, SBC or the P-/S-CSCF/TAS chain gave different Call-IDs, stitched into one row per call (a leg nothing links is a call of one leg). A leg is one Call-ID whose first request is an INVITE; a proxy that keeps the Call-ID adds `hops` to it. Links, strongest first: `icid` (P-Charging-Vector icid-value), `session_id` (a shared RFC 7989 UUID, the null UUID ignored), `x_call_id` (an X- header whose name holds Call-ID or CID naming the other leg's Call-ID, or the same value on both), `replaces` and `target_dialog` (all high), `same_media_endpoint` (the same SDP address and port offered within `window_s`: medium), `number_and_time` (same called number by its last nine digits, the later INVITE leaving the address the earlier went to, within `window_s`: low, check it). Per leg: Call-ID, src > dst, From, To, R-URI, `status`, `final_frame`, `responder`, Reason and `q850_cause`, `pdd_ms`, `linked_by` {leg, method, confidence, evidence}, `depth` (hops from the caller; forks keep both branches), `added_delay_ms` (INVITE in to INVITE out, final response in to out) and `header_changes` against its parent (From, To, R-URI, P-Asserted-Identity, Privacy, offered codecs, Via and Record-Route counts). Per call: the weakest `confidence`, `caller_status`, `status_mapping` (received and sent status and Q.850 cause per element, `rewritten`, a `note`) and `where_it_failed` (the deepest failed leg, its responder and the SIP and Q.850 name, meaning and reference from cause_lookup). `call_id` returns the call holding that leg with its merged `ladder` (leg index per message); `ladder=true` adds it to every call in the page. `summary` counts calls, legs, multi-leg calls, rewritten statuses and links per method over the whole file |
| `volte_call_chain(path, call_id, ue_ip, window_s, filter, limit, offset)` | One row per INVITE call with its `links` in time order: `invite` (SDP address and ports, icid from P-Charging-Vector, preconditions), `rx_aar` (Rx AAR/AAA, found by the icid as AF-Charging-Identifier or by the UE address as Framed-IP-Address), `gx_rar_install` (the Gx RAR with Charging-Rule-Install on the UE's Gx session, the one whose CCR carried the UE address, else the first install after the AAR: QCI, rule names, RAA result), `gtp_create_bearer` (every Create Bearer leg whose header TEID a Create Session Response with the UE's PAA used, plus proxy legs up to 100 ms before them: TEID, QCI, cause, EBI, round trip), `pfcp_modification` (the Session Modification whose PDR names the UE address), `sip_183`, `sip_prack`, `sip_update`, `sip_180`, `sip_final`, `rtp_from_ue` and `rtp_to_ue` (first packet, ms after the 200 OK, before or after the dedicated bearer), then `bye`, `rx_str`, `gx_rar_remove` and `gtp_delete_bearer`. Each link has a `status` (ok, failed, missing: the protocol is in the capture but not this call's message, not_captured: the protocol is absent from the file, late: the bearer came after the 200 OK, skipped), the frame, `found_by` (icid, ue_ip or time), the result or cause named through cause_lookup (`explained`) and `delay_ms` from the link before. Per call: `ue_ip` (the argument, else the SDP address that Diameter, GTP or PFCP names as a UE, else the INVITE's SDP address), `icid`, `final_status`, `first_broken_link` and a `verdict` sentence. `summary`: calls, intact chains, first broken links, protocols captured. `window_s` (10) bounds each join |
| `sigtran_health(path, peer, point_code, gt, filter, limit, offset)` | One row per SCTP association (the two address:port endpoints) with a `verdict` (healthy; degraded: heartbeat failures, M3UA ERR, a point code unavailable, SCCP returns, TCAP aborts or an ASP not active; flapping: two or more aborts or shutdowns; down: the last episode ended and none followed) and `issues` in plain words. `episodes`: INIT, established (COOKIE_ACK), ended by ABORT (the SCTP error cause named, RFC 9260 3.3.10), SHUTDOWN or a restart INIT, who ended it, `duration_s`, `gap_before_s` before the next INIT; an association up before the capture starts with `started`. `heartbeat`: sent, answered, failures (no HEARTBEAT_ACK in the other direction within 3 s). `m3ua`: `asp_state` at the end and `transitions` (ASPUP, ASPAC, ASPIA, ASPDN acknowledged, with `ack_ms`; down when SCTP ends; unacknowledged requests), routing contexts, NTFY status, ERR with the error code named (RFC 4666 3.8.1), `point_code_outages` (DUNA to DAVA with `outage_s`, still unavailable without a DAVA, SCON/DUPU/DRST), point codes as value, ITU 3-8-3 and ANSI 8-8-8. `sccp_returns`: UDTS/XUDTS/LUDTS per unreachable GT and SSN (the UDTS calling address) with the return cause named (Q.713 3.12) and count. `tcap_aborts`: P-Abort causes (Q.773) with counts. Filters: `peer` (an IP or ip:port), `point_code` (associations with an outage for it), `gt` (digits in an SCCP return). `summary`: associations per verdict, aborts, heartbeat failures, M3UA errors, SCCP returns, TCAP aborts |
| `sms_delivery(path, imsi, msisdn, via, filter, limit, offset)` | One row per SMS attempt: `path` (map or sgs), `direction` (mt, mo), `imsi`, `msisdn`, `steps` in order and a `verdict` (delivered, rejected, absent_subscriber, paging_failed, no_response, in_progress: unanswered and the capture ended within 10 s) with `reasons` and `ref`. MAP: TCAP dialogues paired by transaction id; sendRoutingInfoForSM, the mt-forwardSM to the IMSI it returned (`routed_to_imsi`) and reportSM-DeliveryStatus for the same MSISDN within 60 s are one attempt; mo-forwardSM, informServiceCentre, alertServiceCentre and readyForSM join by IMSI or MSISDN. Each MAP step: operation, result (ok, error, tcap_abort, reject, no_response), `error_code` named through cause_lookup, `delivery_failure_cause` (memoryCapacityExceeded, equipmentProtocolError, ...), absent-subscriber diagnostic, `rtt_ms`. SGs: per IMSI, a PAGING-REQUEST for SMS or the first CP-DATA starts an attempt; steps PAGING-REQUEST (service indicator), SERVICE-REQUEST, PAGING-REJECT (SGs cause named, TS 29.118), DOWNLINK/UPLINK-UNITDATA with the CP message (CP-DATA, CP-ACK, CP-ERROR and cause), RP message and RP-MR, RP cause named (TS 24.011), TPDU type and TP-MR. Content-free: never the text, TP-OA or TP-DA; IMSI and MSISDN follow the redaction rules. SMS over IMS is `sms_over_ims` |
| `media_path_check(path, call_id, heuristic)` | One call's SDP offer and answer (the last completed exchange, so a re-INVITE wins) against the RTP captured in each direction: per direction the expected source and destination, the streams seen and a status (as negotiated, arrives from another source, sent elsewhere, missing); `issues` such as no_rtp, one_way_media, source_differs_from_sdp, nat_not_latched (a private SDP address the far end keeps sending to), rtp_to_wrong_address, private_sdp_address, media_direction (hold), media_rejected, payload_type_not_negotiated, codec_mismatch (no codec in common between the offer and the answer or a 488's SDP) and no_answer; `verdict` in one sentence |
| `rtp_streams(path, call_id, ssrc, heuristic, filter, limit, offset)` | Per RTP stream (SSRC and source/destination address:port): the SIP Call-ID whose SDP advertised its destination (or source) address and port, payload type and codec from the SDP rtpmap or the static table, packets, expected, lost and lost %, duplicates, sequence errors, out-of-order packets, max/mean interarrival delta, RFC 3550 max/mean jitter, duration, first and last frame, the reverse stream or `one_way` (with `expected_one_way` when the SDP asks for one-way media), RTCP reception reports about it (fraction and cumulative lost, jitter, round trip where the LSR matches a captured SR), RTCP XR VoIP metrics as reported, and `mos_estimate`: a simplified ITU-T G.107 E-model score from loss, jitter, delay and the codec's G.113 Ie/Bpl, returned with its method and inputs because it is an estimate, not a measured MOS. `call_id` reads the RTP to or from the call's SDP addresses, so a NATed source is still found; each stream is still linked against every SDP in the capture (the most recent advertisement of its address and port before it starts), and a call whose BYE or CANCEL came before a stream started never owns it, so a later call that reuses a port keeps its own stream; `heuristic` decodes RTP without SDP in the capture, over plain UDP and inside STUN/TURN (WebRTC through a relay). Packets, lost, max delta and max jitter match `tshark -z rtp,streams` |
| `dtmf_events(path, call_id, heuristic, limit, offset)` | DTMF digits in time order from RFC 4733/2833 telephone-events (one row per digit however many update and end packets: duration, volume, end packets, payload type, SSRC, call) and SIP INFO (application/dtmf-relay, application/dtmf, KPML) with the INFO's response status; each RTP event is checked against the telephone-event payload type the call's SDP negotiated, and `issues` flag an unnegotiated payload type, a digit without an end packet, or a rejected or unanswered INFO; `calls` gives the digits per call and method and notes calls that use both |
| `ims_registration(path, impu, imsi, filter, limit, offset)` | IMS registration per public identity from every REGISTER transaction (the legs of one REGISTER through the CSCFs count once; copies are told from retransmissions): each transaction's kind (initial, authenticated after a 401, resync with AUTS, re-registration, de-registration), status, requested and granted expiry, RTT, challenge algorithm; the IMPI, Contact feature tags (`smsip` for +g.3gpp.smsip, `mmtel` for the MMTel ICSI), sec-agree mechanisms, P-Associated-URI (implicit IMPU set), Service-Route and Path; third-party REGISTERs to application servers with their status; when a 401 is never answered in clear, the ESP the UE sent to the P-CSCF afterwards and its SPI against the ones offered in Security-Server; reg-event NOTIFYs (RFC 3680) about the user with the registration state and contact event they report, a terminated one after the last successful REGISTER ending the registration; a `verdict` (registered, expired, deregistered by the UE or by the network, challenge-loop, failed, in_progress near the end of the capture) with `reasons` naming 403, 404, 408, 421, 423, 500, 503 with Retry-After in IMS terms. Nonces, AKA vectors and CK/IK are never returned |
| `sms_over_ims(path, number, imsi, filter, limit, offset)` | SMS over IMS: one row per SIP MESSAGE carrying RP-DATA or RP-SMMA (application/vnd.3gpp.sms), legs through the CSCFs counted once: MO or MT, RP message reference, SMSC address, the TPDU (SMS-SUBMIT, SMS-DELIVER or SMS-STATUS-REPORT with TP-MR, TP-OA/TP-DA, status report requested, concatenation, TP-Status; never the text), the SIP response with its frame and delay; `ack`: the RP-ACK or RP-ERROR answering it (paired by RP-MR and the UE's identity, including the identities its REGISTER associated) with RP cause named and the SIP response to the MESSAGE that carried it; `status_report` for a submit that asked for one; `ue_registration` with whether the UE registered with +g.3gpp.smsip; a `verdict` (accepted, delivered, rejected, ack_not_delivered, sip_failed, not_registered_for_sms, no_rp_ack, no_response, in_progress, rp_unknown, orphan_ack) with `reasons`, including an RP-ACK coded for the wrong direction |
| `sctp_associations(path, limit, offset)` | Per endpoint pair: handshake state, initiate tags, DATA chunks, heartbeats sent vs acked, retransmissions, ABORT/SHUTDOWN seen |
| `sigtran_messages(path, filter, limit, offset)` | M3UA/SCCP/TCAP/MAP: SCCP type and segmentation, calling/called GT and SSN, point codes, TCAP primitive and ids, components with MAP operation name, IMSI, MSISDN; Begins linked to their End |
| `trace_subscriber(path, imsi, msisdn, limit, offset)` | One time-ordered timeline for a subscriber across Diameter, GTPv2-C and GTPv1-C (following control-plane TEIDs), PFCP (by IMSI or the UE address GTP allocated, then by SEID), MAP and SIP, each row with protocol, message, result and pairing; all passes share one time budget and a spent budget returns the partial timeline with `truncated` |
| `nas_procedures(path, imsi, guti, ue_id, procedure, null_cipher, filter, limit, offset)` | EMM, ESM and S1AP procedures per UE from S1-MME captures. S1 UE contexts (an InitialUEMessage opens one on its association and eNB-UE-S1AP-ID, the MME-UE-S1AP-ID joins on the first downlink message, UE Context Release Complete closes it) are joined into one UE by IMSI or by the M-TMSI an Attach or TAU Accept assigned and a later S-TMSI or GUTI names. Per UE: `imsi`, `guti` (MME code and M-TMSI), `contexts` (id pair, eNB, first and last frame, `release_cause` as group:value), `procedures` in time order and a `verdict`. Procedure kinds: attach, tau, service_request, detach, pdn_connectivity, dedicated_bearer_activation, bearer_modification, bearer_deactivation, pdn_disconnect, bearer_resource_allocation, bearer_resource_modification, handover (S1 with HandoverType, or X2 path switch), ue_context_release (who asked, cause). Each: `outcome` (accepted on the Accept and Complete or, for a service request, the Initial Context Setup Response; rejected on a Reject, a Setup or Preparation Failure, an Authentication or Security mode reject; abandoned when another procedure or a release came first or its timer ran out; in_progress when the capture ended inside T3410/T3430 15 s, T3417 5 s or the ESM 8 s), EMM or ESM `cause` and `esm_cause` (an ESM reject inside an Attach Reject), `s1ap_cause` (group and value), each named with meaning and reference from cause_lookup (TS 24.301 Annex A/B, TS 36.413 9.2.1.3), `timing_ms`, `completed` for an accepted attach, `paging_response`, and `steps` (frame, direction, S1AP message, NAS message, security header, causes). NAS with security header 2 or 4 is counted in `ciphered_count` and not read; `null_cipher=true` sets nas-eps.null_decipher and reads it only for a UE whose Security Mode Command selected EEA0. `pending_paging`: a Paging for the UE's S-TMSI with no service request within 10 s. `summary`: UEs, procedures per kind and outcome, reject causes, ciphered messages, pagings. NGAP and NAS 5GS are not read yet |
| `roaming_attach_check(path, imsi, msisdn, home_plmn, limit, offset)` | Why a roamer cannot attach or get a bearer. The subscriber's steps (S6a AIR/AIA and ULR/ULA, MAP sendAuthenticationInfo, updateLocation and updateGprsLocation, GTPv2-C Create Session and Modify Bearer, Gx CCR-I/CCA-I, PFCP Session Establishment) grouped into `attempts` in time order (a new attempt when authentication or a location update follows a location update or PDN step, or a Create Session repeats an APN). Each attempt: `visited_plmn` (ULR Visited-PLMN-Id, GTPv2 Serving Network, or the MAP peer GT) with `visited_source`, `roaming`, `access` (RAT, TAI, ECGI), `steps` with result, code, `ref`, `cause_lookup` call, Error-Diagnostic, offending IE and `likely_causes` of a GTP reject, the ULA `subscription` digest (`subscription_from_earlier_attempt` when this attempt had no ULA), the Create Session `request`, `checks` (`pass`, `warn`, `fail` or `unknown`: authentication, location update, Create Session, ODB, RAT against Access-Restriction-Data, APN subscribed or wildcard, PDN type requested against subscribed, routing: home routed or local breakout from the APN operator identifier against VPLMN-Dynamic-Address-Allowed, APN-AMBR within the subscription), `first_failure` and a one-sentence `verdict`. `home_plmn` ("MCC-MNC") overrides the home network read from the IMSI (the MNC length follows the MCC). Content-free: authentication vectors are counted, never returned |
| `compare_captures(path_a, path_b, imsi, msisdn, imsi_b, msisdn_b, collapse_repeats, limit, offset)` | A working and a failing capture of the same procedure side by side: both message ladders (the subscriber trace, or every transaction without an identity), keepalives dropped, identical retries merged with a `repeat` count, aligned by protocol and message; `first_divergence`, every step as same, changed, replaced, only_a or only_b, the `differences` of changed steps (result, pairing, key Diameter AVPs, GTP IEs; identities ignored) and the largest round-trip and offset gaps |

<!-- END GENERATED: tools-reference -->

Every tool returns JSON and publishes a typed `outputSchema`, a title and the MCP
annotations `readOnlyHint`, `idempotentHint` and `openWorldHint: false` (all but `export_subset`, which writes a new file and is `readOnlyHint: false`, `destructiveHint: false`).

`tools/list` is compact by default (less than half the size of the full list): each output
schema keeps its top-level keys with their JSON types, a list of rows is `array` of `object`
with a description naming the row keys, and the keys every result may carry and the server
instructions explain (`truncated`, `warnings`, `trimmed`, `untrusted_text_fields`,
`text_values_shortened`, `redaction`) are left out; input schemas lose the generated titles
and write an optional argument as `"type": ["string", "null"]`; `additionalProperties`
stays true, so a result valid against the full schema is valid against the compact one. Long descriptions keep
what an agent needs to choose the tool and move the rest (how pairing works, every flag) to
the resource. The full description, input schema and output schema of any tool are the
resource `schema://tools/<name>` (one per tool, in `resources/list`) in either profile;
`--schema-profile full` (or `TSHARK_MCP_SCHEMA_PROFILE=full`) publishes the full list as
before. `tests/test_tool_list.py` keeps the compact list within budget: at most 2,750 bytes
per tool on average and 4,608 for any tool, descriptions at most 1,500 characters (a longer
one moves its detail after a `Details:` line in the docstring), instructions at most 3,900.

Failures come back as `{"error": {"type": ..., "message": ..., "fix": ...}}` with `isError: true` on the MCP
result (the same JSON is in `structuredContent` and in the text content), never as protocol
errors. `fix` is one sentence saying what to change or which tool to call next. Some types
add a list: `path_not_allowed` keeps `allowed_dirs`; `not_found` and `not_a_file` add
`candidates` (up to 10 capture files in the allowed directory the path pointed into);
`invalid_filter` and `unknown_field` add `suggestions` (up to 5 field names close to the
unknown one); `timeout` and `output_too_large` name the arguments of that tool that narrow
the call; `unknown_token` says tokens live for one server run.

Cancelling a call (`notifications/cancelled`, a client timeout, Escape in the client) kills
tshark within a quarter of a second; the audit log records the call as `cancelled`. A client
that sends a `progressToken` gets `notifications/progress`: `find_identifier` reports files
done out of files planned (`"3/12 files, 2 with hits"`), every other tool one notification per
finished tshark run, at most one per second.

Every tool that reads a capture (all but `find_fields`, `check_filter`, `cause_lookup`,
`packet_detail` and `capture_metadata`) takes `start` and `end`: ISO 8601 (no zone means UTC),
epoch seconds, `"+120s"` after the capture's first packet or `"-30s"` before its last (units
ms, s, m, h). The window becomes `frame.time_epoch >= A && frame.time_epoch <= B` ahead of the
tool's own filter on every tshark run, including the `-z` statistics behind `conversations`,
`expert_info` and `pcap_info`, and relative bounds are resolved per file (capinfos). The result
carries `window`: the arguments, the resolved bounds, the filter clause, the capture's first and
last packet and `overlaps_capture` (`captures` per file when the call read several); a window
that misses the capture adds a warning. Packets before the window are still dissected for
context (TCP analysis, request and answer pairing) but not reported. `find_identifier` skips the
files a window cannot touch (`files_outside_window`).

Every tool that takes a `limit` also takes an `offset` and returns one page:
`total_matched` rows were found, `returned` of them are in this page starting at `offset`,
`dropped` come after it, and `next_offset` (present only when more rows exist) fetches the
next page with the same arguments (`count` and `total_found` are the older names of
`returned` and `total_matched`). `"truncated": true` always comes with a `truncated_reason`
that says how to get the rest. `total_is_lower_bound: true` means a packet or frame cap
stopped the scan, so more rows exist than were counted and paging cannot reach them:
narrow the filter. The output cap (30 KB by default, about 8k tokens) keeps the longest
prefix of rows that fits and moves `next_offset` to the first row it left out; an inner
list it had to shorten is named in `trimmed` with how many items were kept. In
`find_identifier` the offset counts files of the directory, not rows.

Rows carry the frame numbers they were built from: `frame` on per-packet rows (including
`filter_packets` rows when `frame.number` was not one of the fields), `request_frame` and
`answer_frame` on paired transactions, `first_frame` and `last_frame` on aggregates
(tunnels, SCTP associations, files found by `find_identifier`, message types and
subscriber loops in `message_rates`). `packet_detail(path, frame)` opens any of them.

A capture that ends in the middle of a packet (a ring-buffer file copied while it was being
written) is read up to the damage, and the result carries `"warnings"` saying so. See
[EXAMPLE.md](EXAMPLE.md) for a worked investigation with real output, and
[../llms.txt](../llms.txt) for a one-page description aimed at agents.

## Prompts

The server also publishes six prompts (`prompts/list`, `prompts/get`). Each returns one user
message with the ordered tool calls, the stop conditions (`near_capture_end`,
`total_is_lower_bound`, redaction tokens) and the shape of the final answer. `completion/complete`
on a prompt's `path`, `path_a` or `path_b` argument lists capture files (`.pcap`, `.pcapng`,
`.cap`) and subdirectories that start with the typed value, inside the allowed directories only
(symlinks resolved, hidden files skipped, at most 50 values with `hasMore`).

| Prompt | Arguments | Walks through |
| --- | --- | --- |
| `one_way_audio` | `path`, `call_id` | media_path_check, sip_call_detail, rtp_streams |
| `subscriber_cannot_attach` | `path`, `imsi` / `msisdn`, `home_plmn` | trace_subscriber, diameter_sessions, roaming_attach_check, gtp_sessions, gtp_ies, cause_lookup |
| `trust_this_capture` | `path` | pcap_info, capture_metadata, capture_quality, expert_info |
| `working_vs_failing` | `path_a`, `path_b`, `imsi` | compare_captures, then the protocol tool at the first divergence |
| `ims_registration_or_sms` | `path`, `imsi` / `impu` / `number` | ims_registration, sms_over_ims, sip_dialogs |
| `slow_data_session` | `path`, `teid` / `ue_ip` | capture_quality, gtp_user_plane, gtp_tunnel_health, pfcp_sessions, tcp_health |

## Examples

### Diagnosing one-way audio, step by step

[`examples/sip_one_way_audio.pcap`](../examples/sip_one_way_audio.pcap) is a synthetic
257-packet capture of one SIP call: INVITE, 100, 180, 200 OK with SDP, ACK, five seconds of
PCMA audio from the caller, BYE. The called side never sends media. The agent finds the call
with `sip_dialogs`, then asks `media_path_check` to hold the SDP against the RTP that was
captured. This is the real output, trimmed; the allowed directory is shown as `/captures`:

```
media_path_check(path="/captures/sip_one_way_audio.pcap", call_id="one-way-audio-1@ue.example")
```

```json
{
  "offer":  {"message": "INVITE", "sdp_frame": 1, "media_endpoint": "198.51.100.9:40010",
             "codecs": ["PCMA/8000", "telephone-event/8000"], "direction": "sendrecv"},
  "answer": {"message": "200 INVITE", "sdp_frame": 4, "media_endpoint": "192.0.2.70:30010",
             "codecs": ["PCMA/8000", "telephone-event/8000"], "direction": "sendrecv"},
  "common_codecs": ["PCMA/8000"],
  "directions": [
    {"direction": "offerer to answerer", "expected": "198.51.100.9:40010 > 192.0.2.70:30010",
     "streams": [{"ssrc": "0x6a6a6a6a", "src": "198.51.100.9:40010", "dst": "192.0.2.70:30010",
                  "packets": 250, "codec": "PCMA/8000", "first_frame": 6}],
     "status": "as negotiated"},
    {"direction": "answerer to offerer", "expected": "192.0.2.70:30010 > 198.51.100.9:40010",
     "streams": [], "status": "missing"}
  ],
  "issues": [{"kind": "one_way_media",
              "detail": "no RTP seen answerer to offerer (192.0.2.70:30010 > 198.51.100.9:40010): one-way audio as captured"}],
  "verdict": "no RTP seen answerer to offerer (192.0.2.70:30010 > 198.51.100.9:40010): one-way audio as captured"
}
```

The SDP negotiated a `sendrecv` PCMA stream both ways, the caller's RTP arrived exactly
where the answer asked for it, and nothing ever came back from the media gateway. That
rules out the caller's NAT, a codec mismatch and a hold: the fault is behind 192.0.2.70.
Two more calls close the loop. `rtp_streams` shows the one stream is clean, so the caller's
side is not the problem, and `sip_call_detail` shows the signalling was normal:

```
rtp_streams(path="/captures/sip_one_way_audio.pcap")
```

```json
{
  "streams": [{"ssrc": "0x6a6a6a6a", "call_id": "one-way-audio-1@ue.example", "linked_by": "sdp_destination",
               "codec": "PCMA/8000", "packets": 250, "expected": 250, "lost": 0, "out_of_order": 0,
               "max_jitter_ms": 0.0, "duration_s": 4.98, "first_frame": 6, "last_frame": 255,
               "mos_estimate": {"value": 4.39, "r_factor": 92.5, "estimate": true,
                                "method": "simplified ITU-T G.107 E-model", "...": "..."},
               "one_way": true, "issues": ["no RTP seen in the reverse direction"]}],
  "summary": {"streams": 1, "one_way": 1, "with_loss": 0, "rtcp_packets": 0, "lowest_mos_estimate": 4.39}
}
```

```
sip_call_detail(path="/captures/sip_one_way_audio.pcap", call_id="one-way-audio-1@ue.example")
```

```json
{
  "call": {"outcome": "answered", "final_response": {"status": 200, "reason_phrase": "OK", "frame": 4},
           "timing": {"post_dial_delay_ms": 900.0, "ringing_ms": 900.0, "answer_ms": 2400.0,
                      "setup_ms": 2420.0, "call_duration_s": 5.2},
           "ended_by": {"method": "BYE", "by": "caller", "frame": 256},
           "media": {"common_codecs": ["PCMA/8000"], "negotiated_codec": "PCMA/8000", "...": "..."},
           "...": "..."}
}
```

Every row carries the frame numbers it was built from (`sdp_frame: 4`, `first_frame: 6`),
so `packet_detail(path, frame)` can show the packet behind any claim. The other two sample
captures are a Diameter Update-Location answered with error 5420 and a GTPv2 Create Session
rejected with cause 78 (see [examples/README.md](../examples/README.md));
`tests/test_examples.py` regenerates all three and keeps this output true.
[EXAMPLE.md](EXAMPLE.md) walks through a failed attach across Diameter, GTP and
SCTP the same way.

### One call per question

Which file in the ring buffer has the subscriber, and when:

```
find_identifier(path="/pcaps/signalling", identifier="001010123456789")
-> {"kind": "subscriber", "files_scanned": 7, "files_with_hits": 4,
    "files": [{"path": ".../all.pcap", "hits": 5, "first": "...T22:13:20.000Z", "last": "...T22:21:41.000Z",
               "protocols": {"DIAMETER": 2, "GTPv2": 1, "GSM MAP": 1, "GSM SMS": 1}}, ...]}
```

Every Diameter session of one IMSI, answers included, with the codes that came back:

```
diameter_sessions(path="/pcaps/diameter.pcap", imsi="001010123456789")
-> {"sessions": [{"session_id": "mme01...;1700000000;1", "application": "S6a/S6d", "request_codes": [316],
                  "answer_codes": [316], "result_codes": [2001], "unanswered": 0, "failed": 0, "max_rtt_ms": 48.0,
                  "transactions": [{"request": "ULR", "answer": "ULA", "result": "DIAMETER_SUCCESS", "rtt_ms": 48.0}]},
                 {"session_id": "mme01...;1700000000;3", "request_codes": [318], "unanswered": 1, ...}]}
```

Everything that touched one PGW control TEID, including the Delete Session that never got a response:

```
gtp_sessions(path="/pcaps/gtpv2.pcap", teid="0xc001")
-> {"transactions": [{"message": "Create Session Request", "response": "Create Session Response", "cause_name": "Request accepted", ...},
                     {"message": "Delete Session Request", "teid": "0x0000c001", "unanswered": true}]}
```

The REGISTER dialogs, with their final responses kept (a raw `sip.Method == "REGISTER"` filter would drop the 401):

```
sip_dialogs(path="/pcaps/sip.pcap", method="REGISTER")
-> {"dialogs": [{"call_id": "reg-77@ue.example", "initial_method": "REGISTER", "final_status": 401,
                 "time_to_final_ms": 40.0, "duration_ms": 40.0, "methods": ["REGISTER"]}]}
```

What the HSS sent back in the Update-Location answer, and why the MME asked:

```
diameter_avps(path="/pcaps/diameter.pcap", command_code=316)
-> {"transactions": [{"request": "ULR", "answer": "ULA", "result": "DIAMETER_SUCCESS",
     "request_avps": {"ULR-Flags": "34 [S6a/S6d-Indicator, Initial-Attach-Indicator]", "RAT-Type": "EUTRAN (1004)", ...},
     "answer_avps": {"Result-Code": 2001, "subscription": {"MSISDN": "15550100123", "Subscriber-Status": "SERVICE_GRANTED (0)",
                     "apns": [{"context": 1, "apn": "internet.test", "pdn_type": "IPv4v6 (2)", "qci": 9, ...}]}}}]}
```

Why the dedicated bearer for a VoLTE call was never set up (synthetic Rx exchange):

```
diameter_avps(path="/pcaps/ims/diameter_apps.pcap", command_code=265)
-> {"transactions": [{"request": "AAR", "answer": "AAA", "result": "IP-CAN_SESSION_NOT_AVAILABLE",
     "request_avps": {"rx": {"request_type": "INITIAL_REQUEST (0)", "framed_ip_address": "100.64.0.7",
                             "media_components": [{"number": 1, "media_type": "AUDIO (0)", "flow_status": "ENABLED (2)",
                                                   "codec_data": ["uplink"], "flow_descriptions": 2, ...}], ...}},
     "answer_avps": {"rx": {"results": [{"code": 5065, "avp": "Experimental-Result-Code",
                                         "name": "IP-CAN_SESSION_NOT_AVAILABLE",
                                         "explained": {"meaning": "Rx: no IP-CAN session exists for the UE address the AF named.",
                                                       "ref": "TS 29.214 5.5.3 (Experimental-Result-Code)"}}]}}}]}
```

Where a failing attach first departs from a working one:

```
compare_captures(path_a="/pcaps/working.pcap", path_b="/pcaps/failing.pcap", imsi="001010123456789")
-> {"summary": {"same": 0, "changed": 2, "replaced": 0, "only_a": 0, "only_b": 0},
    "first_divergence": {"op": "changed", "a": {"message": "ULR/ULA", ...}, "b": {"message": "ULR/ULA", ...},
                         "differences": {"answer_avps.subscription.apns[ims].apn": {"a": "ims", "b": null}, ...}},
    "ladder": [..., {"op": "changed", "a": {"message": "Create Session Request", "result": "Request accepted"},
                     "b": {"message": "Create Session Request", "result": "Missing or unknown APN"},
                     "differences": {"result": {...}, "paa_allocated": {"a": true, "b": false}, ...}}]}
```

Why a bearer is slow: the MSS the UE announced does not fit the tunnelled path:

```
gtp_tunnel_health(path="/pcaps/userplane.pcap")
-> {"tunnels": [{"teid": "0x00001001", "tunnel_overhead": 36, "max_outer_ip_len": 1476,
                 "tcp": {"syn": 1, "mss_in_syn": {"1460": 1}, "data_segments": 27, "data_retransmissions": 3, ...},
                 "issues": ["MSS 1460 in a SYN on this tunnel lets the peer send inner packets of 1500 bytes, 1536 bytes
                            once tunnelled (36 bytes of overhead), above the 1500-byte path MTU; an MSS of at most 1424 fits"]}],
    "outer_icmp": [{"error": "fragmentation needed", "mtu": 1450, "count": 1, "teids": ["0x00001001"]}]}
```

Can a missing packet in this file be read as network loss?

```
capture_quality(path="/pcaps/span.pcap")
-> {"duplicates": {"copies": 10, "share": 0.2857, "causes": {"seen on two VLANs (SPAN of both ingress and egress)": 10}, ...},
    "tcp_capture_gaps": {"missed_by_capture": 1, "missed_bytes": 400, "lost_before_capture": 0, ...},
    "checksums": {"bad": {"tcp": 10}, "bad_tcp_segments_acknowledged": 10, "likely_offload": true, ...},
    "verdict": {"loss_conclusions": "not trustworthy",
                "reasons": ["10 duplicate copies (28.6% of IP packets; seen on two VLANs ...): raw tshark retransmission and duplicate-ACK flags count these copies ...",
                            "the capture missed 1 TCP gap (400 bytes) that the receiver acknowledged: the capture dropped them ..."],
                "notes": ["bad checksums are checksum offload: ... Not a network fault"]}}
```

Why does the upload stall after the handshake?

```
tcp_health(path="/pcaps/upload.pcap", mtu=1400)
-> {"streams": [{"stream": 0, "client": "192.0.2.90:40001", "server": "198.51.100.90:443",
     "handshake": {"server_side_rtt_ms": 30.0, "client_side_rtt_ms": 2.0, "rtt_ms": 32.0, "client_mss": 1460, "server_mss": 1460, ...},
     "server_to_client": {"data_segments": 7, "max_segment": 1460, "retransmissions": 3, "retransmitted_after_capture": 3, ...},
     "icmp": [{"from": "203.0.113.1", "error": "fragmentation needed", "mtu": 1400, "count": 1}],
     "issues": ["the client announced MSS 1460: the server may send packets of 1500 bytes, above the 1400-byte path MTU; an MSS of at most 1360 fits", ...,
                "server to client: full-size segments (1460 bytes) were retransmitted 3 times and never acknowledged while smaller packets got through: a path MTU black hole ..."]}]}
```

Who reset the connection?

```
tcp_health(path="/pcaps/idle.pcap")
-> {"streams": [{"resets": [{"from": "server", "ttl": 61, "usual_ttl": 50, "mac": "02:00:00:00:00:99", "usual_mac": "02:00:00:00:00:02",
                             "idle_before_s": 3600.01, "likely_from": "middlebox", ...}, {"from": "client", "likely_from": "middlebox", ...}],
     "issues": [..., "resets towards both ends that neither end sent: typical of a firewall or IPS tearing the connection down"]}]}
```

Is this a purge storm, and how fast is it looping?

```
message_rates(path="/pcaps/dra.pcap", interval=10)
-> {"messages": 577, "distinct_messages": 317, "copies": 260,
    "by_message": [{"message": "AIR", "total": 113, "distinct": 57, "peak": 2, ...}, ...],
    "subscriber_loops": [{"subscriber": "001010123456789", "message": "PUR", "count": 6, "median_gap_s": 10.0, "regular": true,
                          "from_nodes": [{"node": "mme01.example.org", "count": 6}], "to_nodes": [...]}],
    "storms": ["6 ULR for 001010123456789 over 50.0 s, about every 10.0 s, from mme01.example.org, to realm example.org", ...]}
```

Why can three UEs not register on IMS, and is the fourth really registered?

```
ims_registration(path="/pcaps/ims_register.pcap")
-> {"registrations": [
     {"impu": "sip:001010000000101@ims.mnc001.mcc001.3gppnetwork.org", "verdict": "registered", "time_to_register_ms": 1600.0,
      "registered_until": "...T07:38:20.040Z", "smsip": true, "mmtel": true, "sec_agree": ["ipsec-3gpp alg=hmac-sha-1-96 ealg=null"],
      "associated_uris": ["sip:+15550100123@ims.mnc001.mcc001.3gppnetwork.org", "tel:+15550100123"],
      "counts": {"transactions": 3, "initial": 1, "challenges": 1, "re_registrations": 1, "third_party": 2, ...},
      "reasons": ["third-party REGISTER to sip:as2.ims.mnc001.mcc001.3gppnetwork.org failed with 500 (frame 12): that application server does not know the user is registered"], ...},
     {"impu": "sip:001010000000102@...", "verdict": "challenge-loop",
      "reasons": ["3 REGISTERs were challenged, 2 of them already carrying a challenge response: the network rejects the AKA response (wrong K/OPc, IMPI not the one the HSS holds) or the UE keeps answering a stale challenge",
                  "the UE sent AUTS: its SQN is out of sync with the HSS (resynchronisation)"], ...},
     {"impu": "sip:001010000000103@...", "verdict": "failed",
      "reasons": ["403 at frame 20: Forbidden: the network refused the identities (IMPI/IMPU not provisioned or not associated, roaming or the access network not allowed, or the subscription barred)"], ...},
     {"impu": "sip:001010000000105@...", "verdict": "expired", ...}]}
```

Where did the SMS go: rejected by the SMSC, or never deliverable to that UE?

```
sms_over_ims(path="/pcaps/ims_sms.pcap")
-> {"messages": [
     {"direction": "MO", "rp_message": "RP-DATA (MS to network)", "smsc_digits": "15550100900",
      "tpdu": {"type": "SMS-SUBMIT", "tp_mr": 11, "tp_da": "15550100300", ...}, "sip_response": 200,
      "ack": {"rp_message": "RP-ERROR (network to MS)", "frame": 17, "delay_ms": 300.0, "rp_cause": 21, "rp_cause_name": "Short message transfer rejected", ...},
      "verdict": "rejected", "reasons": ["RP-ERROR at frame 17, cause 21 (Short message transfer rejected)"]},
     {"direction": "MT", "rp_message": "RP-DATA (network to MS)", "tpdu": {"type": "SMS-DELIVER", "tp_oa": "15550100300", ...},
      "sip_response": 488, "ue_registration": {"impu": "sip:001010000000202@...", "verdict": "registered", "smsip": false},
      "verdict": "not_registered_for_sms",
      "reasons": ["the MESSAGE was answered 488 (frame 30): Not Acceptable Here: the recipient's registration does not cover SMS over IP",
                  "the UE registered without +g.3gpp.smsip (REGISTER at frame 3): the network should not use SMS over IMS for it, which explains the failure"]}, ...]}
```

Which resolver is failing, and for which names?

```
dns_transactions(path="/pcaps/dns.pcap")
-> {"summary": {"queries": 10, "answered": 7, "unanswered": 3, "unanswered_near_capture_end": 1,
                "rcodes": {"NOERROR": 5, "NXDOMAIN": 1, "SERVFAIL": 1}, "retransmissions": 1, "retries": 1,
                "truncated_tc": 1, "tcp_fallbacks": 1, "icmp_errors": 1, "rtt_ms": {"p50": 15.0, "p90": 1500.0, "max": 1500.0}},
    "issues": ["192.0.2.53 left 2 of 8 queries unanswered", "192.0.2.99 answered none of 1 queries",
               "1 ICMP errors came back for queries to 192.0.2.99 (port unreachable or filtered)",
               "192.0.2.54 is slow: 90% of answers within 1500.0 ms", "1 answers were SERVFAIL (e.g. broken.example.net)",
               "1 truncated UDP answers were followed by the same query over TCP", ...],
    "transactions": [{"frame": 3, "client": "198.51.100.20:40002", "server": "192.0.2.53:53", "transport": "udp", "id": "0x1002",
                      "name": "missing.example.com", "type": "A", "response_frame": 4, "rcode_name": "NXDOMAIN", "rtt_ms": 20.0}, ...]}
```

What a code means, with the reference for the vendor ticket (no capture is read):

```
cause_lookup(protocol="diameter", code=5004, application="s6a")
-> {"avp": "Experimental-Result-Code", "name": "DIAMETER_ERROR_ROAMING_NOT_ALLOWED", "name_source": "tshark",
    "ref": "TS 29.272 7.4.3 (Experimental-Result-Code)", "meaning": "Roaming is not allowed.",
    "application_note": "S6a (TS 29.272 7.4.3.3): the visited PLMN is not allowed; an Error-Diagnostic AVP may say ODB_ALL_APN, ...",
    "related": ["5420", "EMM 11", "EMM 14"],
    "check_next": ["diameter_transactions(path, filter='diameter.Experimental-Result-Code == 5004')", ...]}
ASR and post-dial delay per destination prefix (`examples`-style synthetic mix of ten calls):

```
call_kpis(path="/pcaps/voice/call_mix.pcap", group_by="destination_prefix")
-> {"groups": [{"destination_prefix": "4477", "calls": 5, "answered": 2, "asr_pct": 40.0, "ser_without_487_pct": 50.0,
                "ner_pct": 80.0, "pdd_ms": {"p50": 550.0, "p90": 740.0, "max": 800.0, "calls": 4},
                "acd_s": {"mean": 45.0, "median": 45.0, "calls": 2}, "failure_codes": {"486": 1, "487": 1, "503": 1},
                "q850_causes": {"17 User busy": 1, "34 No circuit/channel available": 1}}, ...],
    "summary": {"calls": 10, "answered": 4, "near_capture_end": 1, "asr_pct": 44.4, ...},
    "worst_calls": [{"call_id": "mix-4@sbc.example", "frame": 17, "status": 487, "pdd_ms": 600.0}, ...]}
Which hop failed the call and who rewrote the status (synthetic B2BUA chain):

```
call_legs(path="/pcaps/voice/call_legs.pcap", call_id="legs-a1@ue.example")
-> {"calls": [{"legs_count": 3, "caller_status": 503, "confidence": "high",
      "where_it_failed": {"leg": 2, "status": 480, "q850_cause": 18, "responder": "203.0.113.10",
                          "sip": {"name": "Temporarily Unavailable", ...}, "q850": {"name": "No user responding", ...}},
      "status_mapping": [{"downstream_leg": 1, "upstream_leg": 0, "element": "192.0.2.90",
                          "received": {"status": 480, "q850_cause": 18}, "sent": {"status": 503, "q850_cause": 34},
                          "rewritten": true, "note": "leg 1 received 480 (Q.850 18), leg 0 sent 503 (Q.850 34) upstream: ..."}, ...],
      "legs": [{"leg": 0, "call_id": "legs-a1@ue.example", "status": 503, ...},
               {"leg": 1, "call_id": "legs-a2@sbc.example", "linked_by": {"leg": 0, "method": "icid", "confidence": "high"},
                "added_delay_ms": {"invite": 30.0, "final_response": 150.0}, ...}, ...],
      "ladder": [{"frame": 1, "src": "198.51.100.70", "dst": "192.0.2.90", "message": "INVITE", "leg": 0}, ...]}]}
```

Where a VoLTE call setup broke (synthetic capture):

```
volte_call_chain(path="/pcaps/volte/volte_chain.pcap", call_id="volte-bearer-3@ue.example")
-> {"calls": [{"call_id": "volte-bearer-3@ue.example", "ue_ip": "100.64.1.23", "icid": "icid-volte-bearer-3", "final_status": 200,
      "links": [{"link": "invite", "status": "ok", "frame": 55, "sdp": {"address": "100.64.1.23", "ports": [4006]}, ...},
                {"link": "rx_aar", "status": "ok", "found_by": "icid", "result_code": 2001, ...},
                {"link": "gx_rar_install", "status": "ok", "found_by": "ue_ip", "qci": 1, "rules": ["volte-voice"], ...},
                {"link": "gtp_create_bearer", "status": "failed", "legs": [{"teid": "0x00001103", "cause": 73, "found_by": "ue_ip", ...}, ...]},
                ..., {"link": "rtp_from_ue", "status": "missing"}, ...],
      "first_broken_link": "gtp_create_bearer",
      "verdict": "the dedicated bearer was never created: Create Bearer Response at frame 65 cause 73 (...), so there was no QCI 1 bearer; the UE sent no RTP; the call was answered"}]}
```

What the MME asked for and why the gateway said no:

```
gtp_ies(path="/pcaps/gtpv2.pcap", message="Create Session Request")
-> {"transactions": [..., {"message": "Create Session Request", "response": "Create Session Response", "cause": 78,
      "request_ies": {"imsi": "001010987654321", "apn": "bogus.apn", "pdn_type": "IPv4 (1)", "rat_type": "EUTRAN (6)",
                      "fteids": [{"interface": "S5/S8 SGW GTP-C", "teid": "0x0000a002", "ipv4": "192.0.2.30"}],
                      "bearer_contexts": [{"ebi": 5, ...}]},
      "response_ies": {"cause": {"value": 78, "name": "Missing or unknown APN", "source": "the node that sent this message (CS=0)"}},
      "likely_causes": ["the gateway does not know the APN 'bogus.apn': check the APN configured on this PGW, ..."]}]}
```

Why a roamer gets no bearer, held against the subscription:

```
roaming_attach_check(path="/pcaps/roaming.pcap", imsi="001010123456789")
-> {"home_plmn": "001-01", "summary": {"attempts": 1, "failed": 1, ...},
    "attempts": [{"visited_plmn": "001-02", "roaming": true, "access": {"rat": "EUTRAN (1004)"},
      "steps": [{"step": "AIR/AIA", "result": "DIAMETER_SUCCESS", "vectors_returned": 1, ...},
                {"step": "ULR/ULA", "result": "DIAMETER_SUCCESS", ...},
                {"step": "Create Session", "result": "Missing or unknown APN", "code": 78, "ref": "TS 29.274 8.4 (Table 8.4-1)", ...}],
      "subscription": {"apns": [{"apn": "data.test", "pdn_type": "IPv4 (0)", "vplmn_dynamic_address": "NOTALLOWED (0)", ...}], ...},
      "request": {"apn": "internet", "pdn_type": "IPv4v6 (3)", "serving_network": "001-02", ...},
      "checks": [{"check": "apn_subscribed", "result": "fail", "detail": "'internet' requested but the subscription holds ['data.test']"}, ...],
      "verdict": "Create Session failed: Missing or unknown APN (TS 29.274 8.4 (Table 8.4-1)): 'internet' requested but the subscription holds ['data.test']"}],
    "verdict": "1 attempt(s), 1 with a failure; latest: Create Session failed: ..."}
```

Why the attach, TAU or service request failed on S1-MME (synthetic capture):

```
nas_procedures(path="/pcaps/ran/s1ap_nas.pcap", imsi="001010987654321")
-> {"ues": [{"imsi": "001010987654321", "contexts": [{"mme_ue_s1ap_id": 103, "enb_ue_s1ap_id": 3, "release_cause": "nas:3", ...}],
      "procedures": [{"kind": "attach", "outcome": "rejected", "start_frame": 21, "end_frame": 22, "timing_ms": 300.0,
                      "cause": {"protocol": "nas_emm", "code": 15, "name": "No Suitable Cells In tracking area",
                                "ref": "TS 24.301 9.9.3.9 and Annex A", ...},
                      "steps": [{"frame": 21, "dir": "ul", "s1ap": "InitialUEMessage",
                                 "nas": "Attach request + PDN connectivity request", "security": "plain"}, ...]}, ...],
      "ciphered_count": 0, "verdict": "attach rejected: EMM 15 No Suitable Cells In tracking area (frame 22)"}],
    "summary": {"ues": 4, "procedures": {"attach": {"accepted": 1, "rejected": 2, "in_progress": 1}, ...}, ...}}
```

Top talkers on the Diameter port only:

```
conversations(path="/pcaps/all.pcap", layer="sctp", filter="sctp.port == 3868")
-> {"conversations": [{"a": "192.0.2.10:3868", "b": "192.0.2.20:3868", "frames_total": 7, "bytes_total": 1970, ...}],
    "total_frames": 7}
```

## How the tools are tested

The suite runs in about a minute; CI runs it on Python 3.10 to 3.13 with
the tshark that Ubuntu 24.04 ships (4.2). The tests build their own synthetic captures with
scapy at run time (among them Diameter ULR/ULA and an unanswered AIR, GTPv2-C Create
Session with cause 16 and 78, GTP-U, a SIP INVITE dialog, SIP calls with RTP, RTCP, RFC 4733 events and SIP INFO DTMF (loss,
reordering, jitter, NAT, one-way media, a 488), IMS REGISTER flows (AKA challenge, challenge loop,
403, 503, expiry, ESP after a challenge, third-party REGISTER), SMS over IMS (MO and MT with
RP-ACK, RP-ERROR, status reports, a wrongly coded RP-ACK, a UE without smsip), an SCTP handshake with an
unanswered heartbeat, MAP updateLocation and mo-forwardSM over M3UA, and test-range IMSI,
MSISDN, IMEISV and UE address values for the redaction tests), and the three captures
committed under `examples/` come from the same generator, so nothing in the repository
contains traffic from a real network. The task-success scenarios in `evals/`
([EVALS.md](EVALS.md)) run over the stdio server in the same suite.

# Worked example: "why did IMSI 001010123456789 fail to attach?"

The capture below is the merged synthetic file the test-suite generates
(`tests/pcapgen.py`): 42 packets covering Diameter S6a, GTPv2-C, GTP-U, SIP, SCTP and
MAP over M3UA, all with documentation addresses and the test PLMN 001/01. Every JSON
block is the real output of the tool against that file.

## 1. Orientation: `pcap_info`

```json
{
  "path": "/captures/all.pcap",
  "file_size_bytes": 10468,
  "file_type": "pcapng",
  "link_type": "ether",
  "packets": 42,
  "duration_s": 502.0,
  "first_packet": "2023-11-14T22:13:20.000Z",
  "last_packet": "2023-11-14T22:21:42.000Z",
  "protocol_hierarchy": [
    {"protocol": "eth/ip/udp/sip", "frames": 9, "bytes": 3483},
    {"protocol": "eth/ip/sctp/diameter", "frames": 7, "bytes": 1970},
    {"protocol": "eth/ip/udp/gtpv2", "frames": 7, "bytes": 626},
    {"protocol": "eth/ip/udp/gtp", "frames": 6, "bytes": 918},
    {"protocol": "eth/ip/sctp/m3ua/sccp/tcap", "frames": 3, "bytes": 506}
  ],
  "limits": {"max_file_mb": 500.0, "max_packets": 500, "max_scan_packets": 20000, "max_output_kb": 200.0, "timeout_seconds": 60.0}
}
```

(The hierarchy is trimmed here; the tool returns the top 15 entries.)

## 2. The headline call: `trace_subscriber(path, imsi="001010123456789")`

The tool runs two bounded passes per protocol: first it finds the Diameter Session-Ids,
GTP sequence numbers and TEIDs, TCAP transaction ids and SIP Call-IDs that name the
subscriber, then it fetches every message of those sessions so answers that carry no
identity are still paired with their requests. For GTPv2-C it also follows the
control-plane TEIDs learnt from the responses, which is how the Delete Session below is
found even though it carries no IMSI.

```json
{
  "timeline": [
    {
      "time": "2023-11-14T22:13:20.000Z",
      "protocol": "diameter",
      "message": "ULR/ULA",
      "detail": "Update-Location",
      "result": "DIAMETER_SUCCESS",
      "identity": "001010123456789",
      "src": "192.0.2.10",
      "dst": "192.0.2.20",
      "request_frame": 1,
      "answer_frame": 2,
      "rtt_ms": 48.0,
      "application": "S6a/S6d",
      "origin_host": "mme01.epc.mnc001.mcc001.3gppnetwork.org"
    },
    {
      "time": "2023-11-14T22:13:22.000Z",
      "protocol": "diameter",
      "message": "AIR/-",
      "detail": "Authentication-Information",
      "identity": "001010123456789",
      "src": "192.0.2.10",
      "dst": "192.0.2.20",
      "request_frame": 5,
      "unanswered": true,
      "application": "S6a/S6d",
      "origin_host": "mme01.epc.mnc001.mcc001.3gppnetwork.org"
    },
    {
      "time": "2023-11-14T22:15:01.000Z",
      "protocol": "gtpv2",
      "message": "Create Session Request",
      "detail": "Create Session Response",
      "result": "Request accepted",
      "identity": "001010123456789",
      "src": "192.0.2.30",
      "dst": "192.0.2.40",
      "request_frame": 10,
      "answer_frame": 11,
      "rtt_ms": 120.0,
      "apn": "internet.test.apn",
      "paa": "100.64.0.7",
      "teid": "0x00000000",
      "request_fteids": [
        {"interface": "S5/S8 SGW GTP-C", "teid": "0x0000a001", "ipv4": "192.0.2.30"},
        {"interface": "S5/S8 SGW GTP-U", "teid": "0x0000b001", "ipv4": "192.0.2.30"}
      ],
      "response_fteids": [
        {"interface": "S5/S8 PGW GTP-C", "teid": "0x0000c001", "ipv4": "192.0.2.40"},
        {"interface": "S5/S8 PGW GTP-U", "teid": "0x0000d001", "ipv4": "192.0.2.40"}
      ]
    },
    {
      "time": "2023-11-14T22:15:03.000Z",
      "protocol": "gtpv2",
      "message": "Delete Session Request",
      "src": "192.0.2.30",
      "dst": "192.0.2.40",
      "request_frame": 14,
      "unanswered": true,
      "teid": "0x0000c001"
    },
    {
      "time": "2023-11-14T22:21:40.000Z",
      "protocol": "map",
      "message": "begin updateLocation",
      "detail": "15550109001 > 15550109002",
      "identity": "001010123456789",
      "src": "192.0.2.60",
      "dst": "192.0.2.61",
      "frame": 39,
      "sccp": "UDT",
      "answered_in_frame": 40
    },
    {
      "time": "2023-11-14T22:21:40.200Z",
      "protocol": "map",
      "message": "end updateLocation",
      "detail": "15550109002 > 15550109001",
      "result": "returnResult",
      "src": "192.0.2.61",
      "dst": "192.0.2.60",
      "rtt_ms": 200.0,
      "frame": 40,
      "sccp": "UDT",
      "in_response_to_frame": 39
    },
    {
      "time": "2023-11-14T22:21:41.000Z",
      "protocol": "map",
      "message": "begin mo-forwardSM",
      "detail": "15550109001 > 15550109003",
      "identity": "001010123456789",
      "src": "192.0.2.60",
      "dst": "192.0.2.61",
      "unanswered": true,
      "frame": 41,
      "sccp": "UDT"
    }
  ],
  "count": 7,
  "total_found": 7,
  "identity": {"imsi": "001010123456789", "msisdn": null},
  "by_protocol": {"diameter": 2, "gtpv2": 2, "map": 3},
  "failures": 3,
  "passes": {
    "diameter": {"sessions": 2, "truncated": false},
    "gtpv2": {"seed_messages": 1, "sequence_numbers": 1, "control_teids": 2, "truncated": false},
    "map": {"transactions": 2, "truncated": false},
    "sip": {"dialogs": 0, "truncated": false}
  }
}
```

Reading it: the subscriber's Update-Location succeeded, the data session was created and
given 100.64.0.7, but the second Authentication-Information Request (frame 5) never got
an answer, the Delete Session Request towards the PGW (frame 14) never got an answer, and
the MO-ForwardSM Begin (frame 41) was never ended. `failures: 3` counts exactly those.
No SIP dialog named this IMSI, so the SIP pass reports zero dialogs rather than guessing.

## 3. Drilling in: `diameter_transactions`

The agent now wants everything about the unanswered AIR. The Session-Id from the trace
goes straight into a display filter (semicolons inside a quoted string are fine; the
filter is compiled by tshark before the capture is touched):

```
diameter_transactions(path, filter='diameter.Session-Id == "mme01.epc.mnc001.mcc001.3gppnetwork.org;1700000000;3"')
```

```json
{
  "transactions": [
    {
      "time": "2023-11-14T22:13:22.000Z",
      "src": "192.0.2.10",
      "dst": "192.0.2.20",
      "request_frame": 5,
      "unanswered": true,
      "command_code": 318,
      "command": "Authentication-Information",
      "request": "AIR",
      "application_id": 16777251,
      "application": "S6a/S6d",
      "session_id": "mme01.epc.mnc001.mcc001.3gppnetwork.org;1700000000;3",
      "hop_by_hop": "0x00001003",
      "end_to_end": "0x0000a003",
      "origin_host": "mme01.epc.mnc001.mcc001.3gppnetwork.org",
      "origin_realm": "epc.mnc001.mcc001.3gppnetwork.org",
      "destination_realm": "epc.mnc001.mcc001.3gppnetwork.org",
      "user_name": "001010123456789"
    }
  ],
  "count": 1,
  "total_found": 1,
  "packets_scanned": 1,
  "summary": {"by_message": {"AIR": 1}, "unanswered": 1, "failed": 0}
}
```

For comparison, the same tool without a filter shows what a failed answer looks like.
The other subscriber in the capture got an AIA with `Experimental-Result-Code` 5001:

```json
{
  "time": "2023-11-14T22:13:21.000Z",
  "request_frame": 3,
  "answer_frame": 4,
  "rtt_ms": 31.0,
  "command_code": 318,
  "command": "Authentication-Information",
  "request": "AIR",
  "answer": "AIA",
  "application": "S6a/S6d",
  "user_name": "001010987654321",
  "answer_origin_host": "hss01.epc.mnc001.mcc001.3gppnetwork.org",
  "experimental_result_code": 5001,
  "result": "DIAMETER_ERROR_USER_UNKNOWN",
  "success": false
}
```

## 4. Checking the transport: `sctp_associations`

An unanswered Diameter request is often a transport problem, so the last step is the SCTP
view. Here the Diameter association between the MME and HSS carried seven DATA chunks and
its handshake predates the capture; the signalling-transfer-point association shows one
heartbeat that was never acknowledged:

```json
[
  {"endpoint_a": "192.0.2.10:3868", "endpoint_b": "192.0.2.20:3868", "handshake": "not in capture", "data_chunks": 7, "heartbeats_unacked": 0},
  {"endpoint_a": "192.0.2.60:2905", "endpoint_b": "192.0.2.61:2905", "handshake": "complete", "data_chunks": 4, "heartbeats_unacked": 1}
]
```

## What a refusal looks like

Every guard rail returns a structured error instead of raising, so the agent can correct
itself:

```json
{"error": {"type": "path_not_allowed", "message": "/etc/passwd resolves to /private/etc/passwd, which is outside the allowed directories", "allowed_dirs": ["/captures"]}}
{"error": {"type": "invalid_filter", "message": "display filter contains ';', '`' or '$' outside a quoted string"}}
{"error": {"type": "invalid_filter", "message": "tshark: \"nosuch.field\" is not a valid protocol or protocol field.", "display_filter": "nosuch.field == 1"}}
{"error": {"type": "unknown_field", "message": "unknown tshark field(s): diameter.nosuch", "unknown_fields": ["diameter.nosuch"]}}
{"error": {"type": "file_too_large", "message": "big.pcap is 734003200 bytes; the limit is 524288000 bytes", "size_bytes": 734003200, "max_file_bytes": 524288000}}
{"error": {"type": "timeout", "message": "tshark exceeded 60.0s and was killed", "timeout_seconds": 60.0}}
```

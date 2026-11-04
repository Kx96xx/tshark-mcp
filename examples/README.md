# Sample captures

Three small synthetic captures to try the server on. They are built packet by packet by
`tests/pcapgen.py` (`python examples/generate.py` rewrites them) from documentation
addresses (RFC 5737), the test PLMN 001/01 and reserved telephone numbers. Nothing in
them comes from a real network, and `tests/test_examples.py` fails if the committed files
ever differ from the generator or the tools stop reading them as described here.

| File | Story | Tools to try |
| --- | --- | --- |
| `sip_one_way_audio.pcap` | One SIP call (INVITE, 100, 180, 200 with SDP, ACK, 5 s of PCMA RTP, BYE) where the called side never sends media | `media_path_check(path, call_id="one-way-audio-1@ue.example")`, `rtp_streams(path)`, `sip_call_detail(path, call_id=...)` |
| `diameter_error_answer.pcap` | S6a Update-Location: one subscriber answered DIAMETER_SUCCESS, a second answered with Experimental-Result 5420 (DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION), plus a watchdog exchange | `diameter_transactions(path)`, `diameter_avps(path, imsi="001010222333444")` |
| `gtpv2_create_session_rejected.pcap` | S5/S8: an Echo, a Create Session accepted with a PDN address, a second Create Session rejected with cause 78 (Missing or unknown APN), the first session deleted | `gtp_sessions(path)`, `gtp_sessions(path, imsi="001010987654321")` |

Run the server on this directory:

```sh
tshark-mcp --allow-dir /path/to/tshark-mcp/examples
```

Or without an MCP client, straight from Python:

```sh
python -c '
from pathlib import Path
from tshark_mcp import server
examples = Path("examples").resolve()   # paths must be absolute and inside an allowed directory
server.configure([str(examples)])
print(server.media_path_check(str(examples / "sip_one_way_audio.pcap"), "one-way-audio-1@ue.example")["verdict"])
'
```

# PcapBench

Does a model answer packet-capture questions better with tshark-mcp's tools than with plain
tshark? PcapBench asks the same questions through two arms and measures it.

| Arm | What the model gets |
| --- | --- |
| `tshark-mcp` | this server, every toolset listed |
| `tshark-only` | one tool, `run_tshark(path, args)` (`evals/tshark_only.py`): `tshark -n -r <path> <args>` under the same sandbox (allowed directories, read-only argv check, time, output and concurrency caps, stdout cut to 30 KB) |

**Questions.** The 16 task-success scenarios (`evals/scenarios.py`) and the 19 mcp-builder XML
questions (`evals/tshark_mcp_eval.xml`): 35 in all. They cover Diameter S6a/Gy, GTPv2-C, GTP-U,
SIP and RTP, IMS registration, SMS over IMS, SIGTRAN, SCTP, redaction and error recovery. Every
capture is synthetic (`tests/pcapgen.py`). No real capture is committed or sent to a model.

**Scoring.** A question passes when every one of these holds:

- the answer matches (the XML answers exactly);
- the model called the tools the question needs (`run_tshark` in the baseline arm);
- the calls stay inside the call and result-token budgets.

For each arm and question the run records the calls, the model's input and output tokens (from
the API `usage`), the summed result size, wall time and refused calls (`path_not_allowed`,
forbidden arguments).

```sh
python -m evals.bench                                  # scripted driver, tshark-mcp arm: CI, no cost
python -m evals.bench --driver llm --model claude-opus-5-5 --max-runs 70 \
    --price-in <USD/MTok> --price-out <USD/MTok> --max-usd 20 --out evals/results/<date>.json
```

**Cost guard.** A model run must state `--max-runs`, the cap on questions x arms x repeats; a
larger plan is refused before any call. With prices, the run stops before the next question once
the measured cost passes `--max-usd`, and records the questions it skipped. Results go to
`evals/results/<date>-<driver>.json` (`meta`, `summary` per arm, `rows`) and the table below.

## Results

Scripted driver, 2026-11-05 (proves every answer is in the tool output; no model):

| Arm | Success | Mean calls | Mean result tokens | Model input / output tokens | Cost (USD) | Mean s |
| --- | --- | --- | --- | --- | --- | --- |
| tshark-mcp | 35/35 (100.0%) | 1.23 | 1,388 | - | - | 0.37 |

Model runs (both arms): not run yet. The environment that built this page had no API
credentials. The command above produces them, and the PR that adds them reports the cost.

## Demo script (90 seconds)

1. 0 to 10 s: "Packet captures from a mobile core are huge and multi-protocol; here an AI reads
   them safely."
2. 10 to 25 s: `claude mcp add tshark-mcp -- uvx --from tshark-mcp-server tshark-mcp --allow-dir ./examples`.
3. 25 to 55 s: "What is wrong in this capture?" The agent calls `incident_summary`, then each
   finding's `next_call` (`diameter_transactions`, `diameter_avps`). It answers with
   Experimental-Result 5001, the spec reference and frame numbers.
4. 55 to 75 s: "And this call has no audio?" The agent calls `media_path_check` on
   `examples/sip_one_way_audio.pcap`.
5. 75 to 90 s: the table above, and "read-only by construction, MIT, runs locally".

The recorded terminal session is `docs/media/demo.tape` (vhs). It is rendered to
`docs/media/demo.gif` without an API key.

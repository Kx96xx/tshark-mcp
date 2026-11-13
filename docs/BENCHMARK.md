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

- the answer matches (the XML answers exactly) and says nothing the question forbids;
- the model called at least one tool;
- the calls stay inside the call and result-token budgets.

Both arms are judged the same way. A model is not held to the path the scripted driver takes
through tshark-mcp's tools (the scripted driver still checks every step and fact); the baseline
arm, with its one tool, could not be held to anything comparable.

For each arm and question the run records the calls, the model's input and output tokens, the
summed result size, wall time and refused calls (`path_not_allowed`, forbidden arguments).

Three drivers:

```sh
python -m evals.bench                                  # scripted: tshark-mcp arm, CI, no cost
python -m evals.bench --driver llm --model claude-opus-5-5 --max-runs 70 \
    --price-in <USD/MTok> --price-out <USD/MTok> --max-usd 20   # Messages API, ANTHROPIC_API_KEY
python -m evals.bench --driver claude-code --model claude-sonnet-5-5 --max-runs 70 --max-usd 15
```

`claude-code` runs each question as one `claude -p` session on a Claude subscription (the logged-in
CLI, or `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`), with only the arm's MCP server: no
built-in tools, settings or other servers. Its input tokens include Claude Code's own framing and
cached tokens, so compare its rows with each other, not with the `llm` driver's.

**Cost guard.** A model run must state `--max-runs`, the cap on questions x arms x repeats; a
larger plan is refused before any call. The run stops before the next question once the cost
passes `--max-usd`: priced from `--price-in`/`--price-out`, or the cost a `claude-code` session
reports. Skipped questions are recorded. Results go to
`evals/results/<date>-<driver>.json` (`meta`, `summary` per arm, `rows`) and the table below.

## Results

Scripted driver, 2026-11-05 (proves every answer is in the tool output; no model):

| Arm | Success | Mean calls | Mean result tokens | Model input / output tokens | Cost (USD) | Mean s |
| --- | --- | --- | --- | --- | --- | --- |
| tshark-mcp | 35/35 (100.0%) | 1.23 | 1,388 | - | - | 0.37 |

Claude Code driver, Sonnet 5.5, 2026-11-12, one run per question
([results](../evals/results/2026-11-12-claude-code.json)):

| Arm | Success | Mean calls | Mean result tokens | Model input / output tokens | Cost (USD, reported) | Mean s |
| --- | --- | --- | --- | --- | --- | --- |
| tshark-mcp | 30/35 (85.7%) | 2.51 | 1,637 | 6,259,135 / 22,513 | 1.63 | 13.55 |
| tshark-only | 27/35 (77.1%) | 3.26 | 1,616 | 439,422 / 41,825 | 1.17 | 16.97 |

What it says:

- With tshark-mcp the model answered 3 more questions, with a quarter fewer calls and in less
  time. The baseline missed where the answer has to be assembled across packets or files: which
  captures hold a subscriber, a subscriber's Diameter session found through a redacted IMSI (it
  also leaked the IMSI), the false-alarm Delete Session at the capture's end, the trunk with the lowest
  ASR, failed IMS registrations.
- tshark-mcp sends far more input tokens: every tool definition (61 with `--toolsets all`) rides
  along on every turn. Most are cache reads, so the reported cost is 1.4 times the baseline's,
  not 14 times. The default toolset (34 tools) lists fewer.
- tshark-mcp's five misses: two call budgets overrun (4 calls for 3 finding a subscriber's files,
  9 for 8 to a PAA), a wrong GTP-U byte count after a detour, a tool name it invented, and an
  unanswered-AIR answer that named neither the command nor its frame. None was a wrong tool result.
- One run per question: a model's path varies between runs, so a difference of one or two
  questions is noise. `--repeats` reruns each question.

Scoring note: this run's own scorer read only the `<response>` value, which failed free-text
answers that wrap a short value in the tags (`one_way_audio` on both arms). The rule was changed
to accept the value or the whole reply, and the same transcripts were rescored without another
model call: tshark-mcp 26 to 30, baseline 24 to 27.

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

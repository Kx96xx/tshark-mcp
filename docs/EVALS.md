# Task-success evals

The unit tests prove each tool against raw tshark. The evals in `evals/` check the next step:
given an operator's question about a capture, the right tool answers it with the right facts.
Each scenario is a question, the calls that answer it and the facts the results must hold
(a verdict, a cause code, a frame number), plus a budget for calls and tokens.

```sh
python -m evals                          # all scenarios, scripted driver, no API cost
python -m evals --only one_way_audio     # one scenario
python -m evals --list                   # ids and questions
python -m evals --json /tmp/evals.json   # per-scenario results and the calls made
python -m evals --report docs/EVALS.md   # rewrite the table below
```

The captures are the synthetic ones `tests/pcapgen.py` builds (written to a temporary
directory per run). The harness starts the server over stdio as a client does; pass any other
stdio command after `--` (with `--server-dir`, the capture directory as that server sees it), for
example the Docker image.

## What a scenario is scored on

- every tool it calls is in `tools/list`, and the tools the scenario expects were called;
- every check on every result holds; checks walk the structured result (`a.b`, `a[0]`, `a[*]` for
  any element, `a[key=value]` for the first matching element) with `eq`, `ne`, `contains`,
  `startswith`, `regex`, `ge`, `le`, `present` and `absent`;
- a step that must fail (a path outside the allowed directories) returns that error type;
- the summed `tokens_estimate` of the results and the number of calls stay within the budget;
- the answer matches every `answer` pattern and no `forbidden` pattern (for the scripted driver,
  the scenario's reference answer, so the patterns themselves are tested).

`tests/test_evals.py` runs every scenario over the stdio server in CI, and runs deliberately
broken scenarios (a wrong fact, an unknown tool, a forbidden conclusion, a missing error, a blown
budget) to prove the harness catches each.

## The model driver (optional, off by default)

`--driver llm` lets a model choose the calls from the question alone: a Messages API tool-use
loop where the tools are the server's own `tools/list` entries, each `tool_use` block becomes one
`tools/call` and the result goes back as a `tool_result`. The final text is scored against
`answer` and `forbidden`. It needs `pip install anthropic` and credentials (`ANTHROPIC_API_KEY`
or an `ant auth login` profile), and every run costs tokens, so CI never runs it.

```sh
python -m evals --driver llm --model claude-opus-5-5 --min-pass 0.85 --json /tmp/llm.json
python -m evals --driver llm --model scripted    # the offline stand-in: same loop, no network
```

`--min-pass` sets the fraction that must pass for exit status 0 (default 1.0). Model results
vary between runs; keep the JSON transcripts when comparing tool descriptions or models.

## Results (scripted driver)

Token counts are approximate: results that carry file paths grow with the length of the
temporary directory.

<!-- evals:begin -->
| Scenario | Question | Tools | Calls | Tokens | Result |
| --- | --- | --- | --- | --- | --- |
| `one_way_audio` | On examples/sip_one_way_audio.pcap the caller hears nothing. Which direction of the media is missing? | `sip_dialogs`, `media_path_check` | 2 | 818 | pass |
| `codec_mismatch_488` | A call in voice/voice_problems.pcap was rejected with 488. Why? | `sip_dialogs`, `media_path_check` | 2 | 384 | pass |
| `unknown_eps_subscription` | Why does the attach in examples/diameter_error_answer.pcap fail? | `diameter_transactions` | 1 | 625 | pass |
| `gtp_cause_78` | Which Create Session in examples/gtpv2_create_session_rejected.pcap was rejected, and why? | `gtp_sessions` | 1 | 566 | pass |
| `unanswered_air` | Did every Diameter request in diameter.pcap get an answer? Which one did not? | `diameter_transactions` | 1 | 779 | pass |
| `cause_lookup_5001` | What does Diameter Experimental-Result 5001 on S6a mean? | `cause_lookup` | 1 | 212 | pass |
| `ims_challenge_loop` | Why can 001010000000102 not register on IMS (ims/ims_register.pcap)? | `ims_registration` | 1 | 554 | pass |
| `sms_rp_error` | Was every SMS that 001010000000201 sent over IMS accepted (ims/ims_sms.pcap)? | `sms_over_ims` | 1 | 2256 | pass |
| `find_subscriber_files` | Which capture files mention IMSI 001010987654321? | `find_identifier` | 1 | 445 | pass |
| `trace_subscriber_failures` | Everything that happened to 001010987654321 in all.pcap: where did it fail? | `trace_subscriber` | 1 | 377 | pass |
| `redaction_join` | With identifiers redacted, trace 001010987654321 in all.pcap and then list its Diameter sessions by the token. | `trace_subscriber`, `diameter_sessions` | 2 | 875 | pass |
| `truncated_page_not_absent` | Did any call in voice/call_legs.pcap fail? Look at every call, not only the first page. | `call_legs` | 2 | 2820 | pass |
| `wrong_dir_recovers` | Summarise /etc/hosts as a capture, and if that is refused, summarise diameter.pcap instead. | `pcap_info` | 2 | 280 | pass |
| `call_kpis_worst_peer` | Which carrier in voice/call_mix.pcap has the lower answer-seizure ratio? | `call_kpis` | 1 | 1148 | pass |
| `b2bua_status_rewrite` | In voice/call_legs.pcap the caller got 503. Which hop failed, and who rewrote the status? | `call_legs` | 1 | 1316 | pass |
| `dtmf_wrong_payload_type` | Why are some DTMF digits lost in voice/voice_dtmf.pcap? | `dtmf_events` | 1 | 512 | pass |

16 of 16 scenarios pass.
<!-- evals:end -->

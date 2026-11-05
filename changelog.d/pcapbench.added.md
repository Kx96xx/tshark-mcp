- PcapBench (`python -m evals.bench`, docs/BENCHMARK.md): the 35 eval questions answered through
  two arms, tshark-mcp and a `run_tshark(path, args)` baseline under the same sandbox
  (`evals/tshark_only.py`). Each run records success, calls, model tokens, cost and time. A model
  run must state `--max-runs` up front and can stop at `--max-usd`. CI runs the scripted driver.

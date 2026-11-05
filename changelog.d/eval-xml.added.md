- `evals/tshark_mcp_eval.xml`: 19 verified questions in the evaluation format of Anthropic's
  mcp-builder skill (exact-string answers, several multi-hop, one True/False trap), and
  `evals/xml_bridge.py`: `python -m evals --xml evals/tshark_mcp_eval.xml` runs them on the
  harness (scripted driver in CI, `--driver llm` for a model score). docs/EVALS.md has the
  reference-harness command and its known limits.

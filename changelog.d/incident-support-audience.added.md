- `incident_summary(audience="support")` adds `explanation`: the same findings in plain words for
  a support agent or a ticket. Each point says what happened, what it means for the user and which
  team usually owns it, with its frames; a headline, caveats (an untrusted capture, protocols no
  check reads, findings beyond the first five) and `ticket_lines` ready to paste. No new judgement:
  the findings are identical to the default `audience="engineer"`.

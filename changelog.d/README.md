# changelog.d

One file per pull request: `changelog.d/<topic>.<section>.md`, for example
`fix-dns-pairing.fixed.md` or `sbi-transactions.added.md`. The section is one of `added`,
`changed`, `deprecated`, `removed`, `fixed` or `security` (the Keep a Changelog headings). The
file holds one or more Markdown bullets, written for a user of the server:

```markdown
- `dns_transactions`: a response that arrives after the capture's last query is paired again
  (public-validation D7).
```

No headings, no version, no date: at release, `python scripts/changelog.py --release X.Y.Z`
writes them into `CHANGELOG.md` under `## X.Y.Z - <date>`, grouped by section, and deletes the
fragments (see [RELEASING.md](https://github.com/Kx96xx/tshark-mcp/blob/main/RELEASING.md)).
`python scripts/changelog.py --preview` prints what the next release section would say.

CI (`changelog` job) fails a pull request that changes `src/` without adding a fragment, unless
the pull request carries the label `no-changelog` (a refactor or test change users cannot see).
It also fails when an entry is written under `## Unreleased` in `CHANGELOG.md` directly:
that section stays empty so that no two pull requests edit the same lines.

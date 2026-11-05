# Releasing

A release is one pull request that bumps the version and assembles the changelog, then a
GitHub release on its merge commit. `publish.yml` does the uploads.

## 1. Release branch

```sh
git fetch origin
git switch -c release/vX.Y.Z origin/main
```

## 2. Bump the version in every file that carries it

| File | Field |
| --- | --- |
| `pyproject.toml` | `[project] version` |
| `src/tshark_mcp/__init__.py` | `__version__` |
| `server.json` | `version` (top level) **and** `packages[0].version` |
| `mcpb/manifest.json` | `version` (or run `python mcpb/build.py --update`, which also refreshes the tools list) |
| `plugin/.claude-plugin/plugin.json` | `version` |

`tests/test_server_json.py`, `tests/test_mcpb.py` and `tests/test_plugin.py` fail when one of
them differs from the package version, and `publish.yml` refuses a tag that does not match
`pyproject.toml` and both `server.json` versions.

## 3. Assemble the changelog

```sh
python scripts/changelog.py --preview            # what the section will say
python scripts/changelog.py --release X.Y.Z      # writes "## X.Y.Z - <today>" into CHANGELOG.md
                                                 # and deletes the fragments in changelog.d/
```

Read the new section once: merge bullets that say the same thing twice, and check that each
names the tool and what a user sees. Edit `CHANGELOG.md` directly at this step only.

## 4. Pull request, CI, merge

```sh
pytest && python scripts/changelog.py --check
git add -A && git commit -m "Release X.Y.Z: version bump and changelog section"
git push -u origin release/vX.Y.Z
gh pr create --title "Release X.Y.Z" --body "..."
```

The release pull request has no fragment of its own (it deletes them all); label it
`no-changelog`. Merge it when CI is green on its head.

## 5. Tag and publish

```sh
gh release create vX.Y.Z --target <merge commit sha> --title "vX.Y.Z" --notes-file <the CHANGELOG section>
```

`publish.yml` runs on the release: it checks the tag against the versions, builds the sdist
and wheel, uploads them to PyPI (`tshark-mcp-server`, trusted publishing) and publishes
`server.json` to the MCP Registry (`io.github.Kx96xx/tshark-mcp`, GitHub OIDC). The PyPI simple
index can lag a minute or two behind the upload.

## 6. Check

```sh
uvx --from tshark-mcp-server==X.Y.Z tshark-mcp --version
curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=io.github.Kx96xx/tshark-mcp" | python -m json.tool | grep '"version"'
```

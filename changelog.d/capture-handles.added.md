- `open_capture(path, filter=None, start=, end=)`: a handle (`cap:...`) that every capture tool
  takes in place of `path` (also `path_a`/`path_b`). It pins the file, and optionally a display
  filter and a time window, for every later call on it. A changed file gives `stale_handle`; a
  restarted server gives `unknown_handle`.
- A memory cache of finished tshark and capinfos runs, keyed by file identity and the full argv
  (`--cache-mb`, default 256, 0 off, env `TSHARK_MCP_CACHE_MB`). A repeated call, or two tools that
  issue the same run, read the file once; such a result carries `cache: {hits, misses}`. On a
  37 MB capture a second `incident_summary` took 3.9 s instead of 11.6 s (9 of 9 runs cached).

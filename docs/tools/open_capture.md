---
order: 15
readme: Pin one capture (and a filter and time window) under a handle every capture tool takes as `path`; repeated runs come from a memory cache
llms: pin one capture for several calls: returns a `handle` ("cap:...") that every capture tool takes as `path` (or `path_a`/`path_b`); a `filter` and a `start`/`end` window given here apply to every later call on it; repeated tshark runs on the same file come from a memory cache (`cache` in a result). `stale_handle` when the file changed, `unknown_handle` after a restart: open it again.
---

Returns `handle` (`cap:` and 16 hex characters), `path`, `size_bytes`, `mtime`, `packets`,
`first_packet`, `last_packet`, and the `filter`, `start` and `end` that every later call on the
handle reads (a call's own `start`/`end` replaces the window, its own `filter` is ANDed with the
pinned one). The handle pins the file's identity (real path, device, inode, size, mtime): a call
on a file that changed fails with `stale_handle`; a handle from another server run, or one of the
64 kept that was dropped, is `unknown_handle`. Independently of handles, the server keeps the
output of finished tshark and capinfos runs in a memory LRU (`--cache-mb`, default 256, 0 off,
env `TSHARK_MCP_CACHE_MB`) keyed by the file identity and the full argv, so a repeated call, or two
tools issuing the same run, read the file once; such a result carries `cache: {hits, misses}`.
Nothing is written to disk and the cache never leaves the process; redaction is applied after it

---
name: working-vs-failing
description: Compare a working and a failing capture of the same procedure, or a capture before and after a change. Use when the user has two captures.
---

# Working versus failing

Get the server's `working_vs_failing` prompt (`path_a`, `path_b`, `imsi`), or:

1. `compare_captures(path_a, path_b, imsi=...)` for signalling procedures.
2. `diff_captures(path_a, path_b)` for TCP/IP services (DNS, TLS, HTTP, TCP).
3. Open the first difference with the protocol tool and `packet_detail(path, frame)`.

Name the first point where the two differ, with frames from both files.

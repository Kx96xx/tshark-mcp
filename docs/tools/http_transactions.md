---
order: 330
readme: HTTP/1.x pairs and HTTP/2 / gRPC streams: status, size, timing; per-endpoint 5xx share and p99
llms: HTTP/1.x requests paired with responses by tshark (pipelining included) and HTTP/2 / gRPC per stream: method, host or :authority, `uri` (query kept apart in `query`), status and reason, Content-Type, request and response bytes, `response_ms` (request to the end of the response), `ttfb_ms` (HTTP/2), gRPC status name, RST_STREAM by whom and why, `unanswered` (`near_capture_end` within 5 s of the end). `view="endpoints"` groups by host, method and path with ids collapsed to `{id}`: status classes, response_ms p50/p90/p99/max, bytes, gRPC statuses, slowest frame. `summary.issues` names 5xx-heavy endpoints, slow p99, unanswered requests, gRPC errors and reset streams. tshark finds HTTP on its ports and by heuristics; `undissected_http` names ports carrying HTTP it left raw (no Decode As yet). No decryption.
---

HTTP/1.x requests paired with their responses by tshark's own `http.request_in` (pipelining and
several messages per segment included) and HTTP/2 / gRPC followed per stream from the frames tshark
dissects; copies of the same packet count once. `view="requests"`: request and response frame, TCP
stream and `h2_stream`, client, server, version, method, host (or :authority), `uri` (the path; the
query string kept apart in `query`, capped at 128 characters), status and reason, Content-Type,
request and response bytes (Content-Length for HTTP/1.x, DATA bytes for HTTP/2), `response_ms`
(tshark's http.time: request to the frame that completed the response; HTTP/2: request HEADERS to
the server's END_STREAM), `ttfb_ms` (HTTP/2: request HEADERS to response HEADERS), `grpc`,
`grpc_status` and its name, `stream_reset_by` and `reset_error` (RST_STREAM code named),
`unanswered` with `near_capture_end` when the capture stopped less than 5 s after the request.
`view="endpoints"`: per host, method and path with numbers, UUIDs and long hex ids collapsed to
`{id}`: count, status classes, unanswered, response_ms p50/p90/p99/max, response bytes p50/max, gRPC
status names, servers, slowest and first frame. `summary`: requests, answered, unanswered, status
mix, versions, requests per server, HTTP/2 connections, gRPC calls and `issues` (5% or more 5xx on
an endpoint, p99 of 1 s or more, unanswered requests, gRPC errors, reset streams, undissected HTTP).
Filters: `host` (name and subdomains), `path_prefix`, `method`, `status` (a code or a class such as
`5xx`), `min_ms`. tshark finds HTTP/1.x on its HTTP ports and with its HTTP-over-TCP heuristic,
HTTP/2 in clear on HTTP ports with tshark 4.2 and anywhere from 4.4.0; a second bounded pass lists
in `undissected_http` the server ports whose TCP payload starts with an HTTP method or the HTTP/2
preface on streams tshark left raw (Decode As is not offered yet). No decryption

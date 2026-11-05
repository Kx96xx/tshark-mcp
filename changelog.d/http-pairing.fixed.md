- `http_transactions`: a response tshark cannot reassemble in one pass (headers split over many
  segments, segments out of order) is now read from its first segment with TCP reassembly off and
  paired, with `response_decoded_from: "first_segment"`, instead of leaving the request
  "unanswered" (public-validation D9a).
- `http_transactions`: a response without `http.request_in` is paired with the oldest open request on
  its connection (`paired_by: "stream_order"`) (public-validation D9b).
- `http_transactions`: an HTTP/2 response whose HPACK block includes a table-size update (header
  count larger than the headers listed) is no longer missed (public-validation D9c, HTTP/2 part).
- `http_transactions` gives `ttfb_ms` for HTTP/1.x too, and endpoints get `ttfb_ms` p50/p99. The
  slow-endpoint issue uses the time to first byte; a slow body transfer behind a fast first byte is
  reported as "p99 transfer ..., but the first byte came within N ms", which `incident_summary` no
  longer reports as a slow server (public-validation D11).

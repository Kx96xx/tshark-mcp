"""Hygiene for text copied out of packets.

Packet contents are written by whoever sent the packet. A SIP display name, a
Diameter host or Error-Message, a DNS name or a TLS certificate field can carry
text aimed at the model reading the result ("ignore your instructions ..."),
control characters, or bidirectional overrides that make text read differently
from what it is. Every tool result goes through :func:`apply` before it is
returned:

* every string loses control characters (newlines and tabs become spaces),
  bidirectional overrides and isolates, and zero-width characters;
* strings under a key known to carry packet text (``FREE_TEXT_KEYS``), or anywhere
  inside a container of packet values (``PACKET_CONTAINERS``), are capped in length
  with a marker saying how much was cut;
* the result names those keys in ``untrusted_text_fields`` so the reader knows
  which values are data from the network and never instructions.
"""

from __future__ import annotations

import re
from typing import Any

FREE_TEXT_KEYS: frozenset[str] = frozenset({
    # SIP
    "from", "to", "p_asserted_identity", "request_uri", "reason", "text", "header", "user_agent", "call_id",
    # Diameter
    "session_id", "origin_host", "origin_realm", "destination_host", "destination_realm", "answer_origin_host",
    "host", "realm", "user_name", "error_message",
    # DNS, TLS
    "name", "cnames", "answers", "sni", "san", "subject_cn", "subject_o", "issuer_cn", "issuer_o", "alpn",
    # GTP, trace rows, expert info
    "apn", "identity", "detail", "summary",
    # call_legs: the icid, Session-ID, X- header or number a link was made on
    "evidence",
    # IMS registration and SMS over IMS
    "impu", "impi", "associated_uris", "service_route", "path_header", "contact", "application_server", "warning",
    "feature_tags", "sec_agree", "reason_phrase",
    # capture_metadata: strings the capture file's writer stored (interface names are under "name")
    "description", "capture_filter", "comment",
    # HTTP (host and reason are listed above)
    "uri", "query", "content_type",
})
"""Keys whose string values are copied from packets (anywhere in a result)."""

PACKET_CONTAINERS: frozenset[str] = frozenset({
    "layers",                          # packet_detail: the whole dissection
    "packets",                         # filter_packets: values of the fields asked for
    "request_avps", "answer_avps",     # diameter_avps, trace and compare rows
    "request_ies", "response_ies",     # gtp_ies
    "subscription",                    # roaming_attach_check: the ULA subscription digest
    "header_changes",                  # call_legs: header values of both legs
    "differences",                     # compare_captures: values from both captures
    "writer",                          # capture_metadata: application, OS, hardware of the file's writer
    "hosts",                           # diameter_peers: Origin-Host values per address
    "auth_applications", "acct_applications", "peer_auth_applications",  # diameter_peers: CER/CEA
})
"""Keys under which every string is packet content."""

MULTILINE_KEYS: frozenset[str] = frozenset({"diagram"})
"""Top-level keys whose value is a multi-line rendering (call_ladder's Mermaid or text diagram):
each line is cleaned on its own and the line breaks are kept; the key is labelled as packet text."""
TEXT_CAP = 256
CONTAINER_CAP = 512

_SPACE = re.compile(r"[\t\n\r\v\f]+")
_MARK = re.compile(r"\.\.\.\[\+\d+ chars\]$")
_STRIP = re.compile("[\x00-\x08\x0e-\x1f\x7f-\x9f​-‏ -‮⁠-⁩﻿]")


def clean(text: str, cap: int | None) -> tuple[str, bool]:
    """``text`` without control, bidi and zero-width characters, cut to ``cap``
    characters when given. Returns (text, whether it was shortened)."""
    out = _STRIP.sub("", _SPACE.sub(" ", text)) if (_SPACE.search(text) or _STRIP.search(text)) else text
    if cap is not None and len(out) > cap:
        mark = _MARK.search(out)
        if mark and mark.start() <= cap:
            return out, False  # already cut to this cap or a tighter one
        return f"{out[:cap]}...[+{len(out) - cap} chars]", True
    return out, False


def _text(value: Any) -> bool:
    return isinstance(value, str) or (isinstance(value, list) and all(isinstance(v, str) for v in value))


def apply(result: dict[str, Any]) -> dict[str, Any]:
    """Clean every string in ``result`` and label the packet text it carries."""
    labels: set[str] = set()
    shortened = 0

    def walk(node: Any, label: str | None, cap: int | None, depth: int) -> Any:
        nonlocal shortened
        if isinstance(node, str):
            text, cut = clean(node, cap)
            if label is not None:
                labels.add(label)
            shortened += cut
            return text
        if isinstance(node, dict):
            out = {}
            for key, value in node.items():
                if depth == 0 and key in MULTILINE_KEYS and isinstance(value, str):
                    out[key] = "\n".join(clean(line, None)[0] for line in value.split("\n"))
                    labels.add(key)
                elif label is None and key in PACKET_CONTAINERS and isinstance(value, (dict, list)):
                    out[key] = walk(value, key, CONTAINER_CAP, depth + 1)
                elif label is None and depth > 0 and key in FREE_TEXT_KEYS and _text(value):
                    # Top-level keys are the tool's own echo of its arguments, never packet text.
                    out[key] = walk(value, key, TEXT_CAP, depth + 1)
                else:
                    out[key] = walk(value, label, cap, depth + 1)
            return out
        if isinstance(node, list):
            return [walk(item, label, cap, depth) for item in node]
        return node

    cleaned = walk(result, None, None, 0)
    if labels:
        cleaned["untrusted_text_fields"] = sorted(labels)
    if shortened:
        cleaned["text_values_shortened"] = shortened
    return cleaned

"""Toolsets: which tools ``tools/list`` shows.

Agents pick worse from long tool lists, and every listed tool costs context on every session.
The server registers every tool but lists only the active toolsets (``--toolsets``, env
``TSHARK_MCP_TOOLSETS``, comma-separated):

* ``default`` (always on): the front door ``incident_summary``, the capture overview and
  generic tools, the most used TCP/IP tools and the most used telecom tools (with every tool
  the prompts one_way_audio, subscriber_cannot_attach, trust_this_capture, working_vs_failing
  and ims_registration_or_sms name);
* ``mobile``: the rest of the mobile core (PFCP, GTPv1-C, GTP-U, S1-MME NAS, SIGTRAN, SMS
  over MAP/SGs, DRA peers, message rates);
* ``voice``: call KPIs, call legs, the VoLTE chain and DTMF;
* ``network``: response times, throughput, certificates, QUIC, tunnels, diff_captures and
  export_subset;
* ``all``: every tool.

A tool outside the active toolsets is not listed but still answers a call by name, so a
``next_call`` from incident_summary never fails; the result of such a pointer names the toolset.

A tool defined in server.py gets its toolset from :data:`SERVER_TOOLS`; a module of
``tshark_mcp/tools/`` names its own with a module-level ``TOOLSET = "<name>"``.
``tests/test_toolsets.py`` fails for a tool that has neither.
"""

from __future__ import annotations

import sys
from typing import Any

DEFAULT = "default"
OPTIONAL = ("mobile", "voice", "network")
NAMES = (DEFAULT, *OPTIONAL, "all")

# The toolset of every tool defined in server.py.
SERVER_TOOLS: dict[str, str] = {
    # default: overview and generic
    "incident_summary": DEFAULT, "pcap_info": DEFAULT, "capture_quality": DEFAULT, "capture_metadata": DEFAULT,
    "capture_index": DEFAULT, "find_identifier": DEFAULT, "conversations": DEFAULT, "filter_packets": DEFAULT,
    "packet_detail": DEFAULT, "expert_info": DEFAULT, "find_fields": DEFAULT, "check_filter": DEFAULT,
    "cause_lookup": DEFAULT,
    # default: TCP/IP
    "tcp_connections": DEFAULT, "tcp_health": DEFAULT, "dns_transactions": DEFAULT, "tls_handshakes": DEFAULT,
    "http_transactions": DEFAULT, "icmp_errors": DEFAULT,
    # default: telecom
    "trace_subscriber": DEFAULT, "diameter_transactions": DEFAULT, "diameter_sessions": DEFAULT,
    "diameter_avps": DEFAULT, "gtp_sessions": DEFAULT, "gtp_ies": DEFAULT, "roaming_attach_check": DEFAULT,
    "sip_dialogs": DEFAULT, "sip_call_detail": DEFAULT, "media_path_check": DEFAULT, "rtp_streams": DEFAULT,
    "ims_registration": DEFAULT, "sms_over_ims": DEFAULT, "compare_captures": DEFAULT,
    # mobile
    "gtpv1_sessions": "mobile", "pfcp_sessions": "mobile", "gtp_user_plane": "mobile", "gtp_tunnel_health": "mobile",
    "nas_procedures": "mobile", "sigtran_messages": "mobile", "sigtran_health": "mobile",
    "sctp_associations": "mobile", "sms_delivery": "mobile", "message_rates": "mobile",
    # voice
    "call_kpis": "voice", "call_legs": "voice", "volte_call_chain": "voice", "dtmf_events": "voice",
    # network
    "response_times": "network", "throughput_timeline": "network", "tls_certificates": "network",
    "quic_connections": "network", "tunnels_overview": "network", "diff_captures": "network",
    "export_subset": "network",
}

_ACTIVE: frozenset[str] = frozenset({DEFAULT})


def parse(text: str | None) -> frozenset[str]:
    """``"mobile,voice"`` -> the active toolsets (``default`` always included). ValueError on an unknown name."""
    names = {n.strip().lower() for n in (text or "").replace(" ", ",").split(",") if n.strip()}
    unknown = sorted(names - set(NAMES))
    if unknown:
        raise ValueError(f"unknown toolset(s) {', '.join(unknown)}; choose from {', '.join(NAMES)}")
    if "all" in names:
        return frozenset({DEFAULT, *OPTIONAL})
    return frozenset({DEFAULT, *names})


def set_active(names: frozenset[str]) -> None:
    global _ACTIVE
    _ACTIVE = frozenset(names) | {DEFAULT}


def active() -> frozenset[str]:
    return _ACTIVE


def of(tool: str, fn: Any = None) -> str | None:
    """The toolset of ``tool``: its module's ``TOOLSET``, else :data:`SERVER_TOOLS`; None when it has none."""
    module = sys.modules.get(getattr(fn, "__module__", "") or "")
    named = getattr(module, "TOOLSET", None) if module is not None and module.__name__ != "tshark_mcp.server" else None
    return named or SERVER_TOOLS.get(tool)


def listed(tool: str, fn: Any = None) -> bool:
    """True when ``tools/list`` shows ``tool`` under the active toolsets (a tool without a toolset is listed)."""
    name = of(tool, fn)
    return name is None or name in _ACTIVE


def describe() -> str:
    return ",".join(n for n in NAMES if n in _ACTIVE)

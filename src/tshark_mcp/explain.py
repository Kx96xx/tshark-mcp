"""Plain-language wording of incident_summary findings, for readers who are not packet experts.

``incident_summary(audience="support")`` adds ``explanation``: the same findings, no new
judgement, reworded for a support agent or a ticket. Each kind of finding maps to what it means
for the user and which team usually owns it. The wording is fixed text per kind, so it is
deterministic; a kind without a sentence here gets a generic one built from its severity.
"""

from __future__ import annotations

from typing import Any

# kind -> (what it means for the user, who usually fixes it)
PLAIN: dict[str, tuple[str, str]] = {
    "capture_untrusted": ("The capture itself is incomplete or distorted, so missing or repeated packets may not "
                          "be real network problems.", "whoever took the capture"),
    "tcp_one_sided": ("Only one direction of some connections was captured; that is how the capture was taken, "
                      "not a failure.", "whoever took the capture"),
    "connect_failures": ("Some connections could not be opened: the server refused them, a firewall blocked them, "
                         "or the server did not answer.", "network or firewall team"),
    "tcp_loss": ("Data had to be sent again because packets were lost on the way, which makes things slow.",
                 "network team"),
    "pmtud_black_hole": ("Large packets are silently dropped somewhere on the path, so big transfers stall while "
                         "small requests work.", "network team"),
    "zero_window": ("A receiving program stopped reading data fast enough, so the sender had to wait.",
                    "server or application owner"),
    "middlebox_reset": ("A device in the middle of the path (firewall, load balancer, proxy) cut connections.",
                        "network or firewall team"),
    "tcp_unanswered_syn": ("Some connection attempts got no reply at all.", "network or firewall team"),
    "http_5xx": ("The web server returned errors (5xx): the problem is on the server side, not the user's.",
                 "server or application owner"),
    "http_slow": ("Some web requests were slow to get a first answer from the server.", "server or application owner"),
    "http_unanswered": ("Some web requests never got a response.", "server or application owner"),
    "dns_unanswered": ("Name lookups went unanswered, so apps could not find the servers they need.",
                       "DNS or network team"),
    "dns_servfail": ("The DNS server failed to resolve some names (SERVFAIL).", "DNS team"),
    "dns_slow": ("Name lookups were slow, which delays the start of every connection.", "DNS team"),
    "dns_nxdomain": ("Some names do not exist (NXDOMAIN); often harmless, sometimes a typo or wrong setting.",
                     "application owner"),
    "tls_failed": ("Secure connections (TLS) failed to set up, so the app could not talk to the server securely.",
                   "server or application owner"),
    "tls_certificate": ("A server certificate has a problem (expired, wrong name or incomplete chain).",
                        "server or certificate owner"),
    "quic_blocked": ("HTTP/3 (QUIC over UDP 443) looks blocked on the path; browsers fall back to slower TCP.",
                     "network or firewall team"),
    "quic_failed": ("Some HTTP/3 (QUIC) connections did not complete.", "network or server team"),
    "routing_loop": ("Packets are going round in circles between routers and never arrive.", "network team"),
    "path_mtu": ("The path cannot carry full-size packets, and routers say so.", "network team"),
    "prohibited": ("A router or firewall is rejecting traffic by policy.", "network or firewall team"),
    "port_unreachable": ("Traffic was sent to a port where nothing is listening.", "server or application owner"),
    "echo_loss": ("Some pings went unanswered.", "network team"),
    "tunnel_handshake_failed": ("A VPN or tunnel could not be set up.", "network or VPN team"),
    "tunnel_one_way": ("A VPN or tunnel carries traffic in one direction only.", "network or VPN team"),
    "tunnel_mtu": ("Packets are too big for a tunnel and may be dropped.", "network or VPN team"),
    "call_failures": ("Phone calls failed to connect.", "voice team"),
    "one_way_audio": ("On some calls only one side can be heard.", "voice team"),
    "rtp_loss": ("Call audio lost packets, so voices break up.", "voice or network team"),
    "rtp_quality": ("Call audio quality was poor (loss or jitter).", "voice or network team"),
    "ims_registration_failed": ("Some phones could not register for calls and texts over the mobile network (IMS).",
                                "mobile core or IMS team"),
    "ims_challenge_loop": ("Some phones keep failing authentication when registering for calls and texts.",
                           "mobile core or IMS team"),
    "pfcp_peer_restart": ("A packet gateway restarted; data sessions through it were dropped.", "mobile core team"),
    "sctp_no_association": ("Two core network nodes could not connect to each other.", "mobile core team"),
    "sctp_abort": ("A link between core network nodes was torn down.", "mobile core team"),
    "sctp_heartbeat_loss": ("A link between core network nodes stopped answering keep-alives.", "mobile core team"),
    "sctp_init_rejected": ("A core network node refused link set-up attempts.", "mobile core team"),
    "sctp_retransmissions": ("Messages between core network nodes had to be resent.", "mobile core team"),
    "map_errors": ("2G/3G subscriber or SMS operations returned errors.", "mobile core team"),
    "tcap_rejects": ("2G/3G signalling messages were rejected.", "mobile core team"),
    "tcap_unanswered": ("2G/3G signalling requests got no answer.", "mobile core team"),
    "expert_errors": ("tshark found malformed or undecodable packets; some results may be incomplete.",
                      "whoever took the capture"),
}

# protocol-named kinds: <protocol>_failed / <protocol>_unanswered
PROTOCOL_WORDS = {
    "diameter": "subscriber checks with the core (Diameter)",
    "gtpv2-c": "data session set-up (GTP)",
    "gtpv1-c": "2G/3G data session set-up (GTP)",
    "pfcp": "packet gateway control (PFCP)",
}

SEVERITY_WORDS = {"high": "Serious", "medium": "Worth fixing", "low": "Minor"}


def plain(kind: str, severity: str) -> tuple[str, str]:
    """(what it means, who to involve) for one finding kind."""
    if kind in PLAIN:
        return PLAIN[kind]
    for proto, words in PROTOCOL_WORDS.items():
        if kind == f"{proto}_failed":
            return f"Some {words} requests were rejected.", "mobile core team"
        if kind == f"{proto}_unanswered":
            return f"Some {words} requests got no answer.", "mobile core team"
    return (f"{SEVERITY_WORDS.get(severity, 'A')} problem of type {kind.replace('_', ' ')}.",
            "the engineer who owns this service")


def explanation(findings: list[dict[str, Any]], capture: dict[str, Any] | None,
                not_analysed: list[dict[str, Any]] | None, limit: int = 5) -> dict[str, Any]:
    """The support view of an incident summary: a headline, up to ``limit`` points and caveats."""
    points = []
    for f in findings[:limit]:
        means, who = plain(f["kind"], f["severity"])
        point = {"severity": SEVERITY_WORDS.get(f["severity"], f["severity"]), "what_happened": f["text"],
                 "what_it_means": means, "who_to_involve": who}
        frames = (f.get("evidence") or {}).get("frames")
        if frames:
            point["frames"] = frames
        points.append(point)
    if points:
        headline = f"Main problem: {points[0]['what_it_means']} Who to involve: {points[0]['who_to_involve']}."
    else:
        headline = "Nothing in this capture failed the checks that ran."
    caveats = []
    trust = ((capture or {}).get("trust") or {}).get("loss_conclusions")
    if trust and trust != "trustworthy":
        caveats.append(f"The capture's loss figures are '{trust}': missing packets may be capture artifacts.")
    if len(findings) > limit:
        caveats.append(f"{len(findings) - limit} more finding(s) are in `findings`.")
    unread = [u["protocol"] for u in not_analysed or [] if u.get("protocol")]
    if unread:
        caveats.append("Not checked (no automatic check exists): " + ", ".join(unread) + ".")
    lines = [headline] + [f"- {p['severity']}: {p['what_happened']}. {p['what_it_means']} "
                          f"Who: {p['who_to_involve']}." + (f" (frames {', '.join(map(str, p['frames']))})"
                                                             if p.get("frames") else "") for p in points] + caveats
    return {"headline": headline, "points": points, "caveats": caveats, "ticket_lines": lines}

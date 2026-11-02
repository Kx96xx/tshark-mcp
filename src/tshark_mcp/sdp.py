"""SDP (RFC 4566, offer/answer RFC 3264) read from the raw SIP message body.

tshark's ``sdp.*`` fields lose which attribute belongs to which ``m=`` line once a
body has more than one media section, so the body is fetched as bytes
(``sip.msg_body``) and parsed here in order. Multipart bodies (IMS INVITEs carry
SDP next to other parts) are handled by taking the part that starts with ``v=``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# RFC 3551 static payload types: name and RTP clock rate.
STATIC_PT: dict[int, tuple[str, int]] = {
    0: ("PCMU", 8000), 3: ("GSM", 8000), 4: ("G723", 8000), 5: ("DVI4", 8000), 6: ("DVI4", 16000),
    7: ("LPC", 8000), 8: ("PCMA", 8000), 9: ("G722", 8000), 10: ("L16", 44100), 11: ("L16", 44100),
    12: ("QCELP", 8000), 13: ("CN", 8000), 14: ("MPA", 90000), 15: ("G728", 8000), 16: ("DVI4", 11025),
    17: ("DVI4", 22050), 18: ("G729", 8000), 25: ("CelB", 90000), 26: ("JPEG", 90000), 28: ("nv", 90000),
    31: ("H261", 90000), 32: ("MPV", 90000), 33: ("MP2T", 90000), 34: ("H263", 90000),
}

# Formats that are not a voice codec in their own right: they never make two
# offers compatible on their own.
NON_CODECS = frozenset({"TELEPHONE-EVENT", "CN", "RED", "ULPFEC", "RTX", "COMFORT-NOISE"})

DIRECTIONS = ("sendrecv", "sendonly", "recvonly", "inactive")

_BOUNDARY = re.compile(r"\r?\n--")


def body_text(hex_body: str | None) -> str:
    """The SIP body as text from a ``sip.msg_body`` hex value (with or without colons)."""
    if not hex_body:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", hex_body)
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        return bytes.fromhex(cleaned).decode("utf-8", "replace")
    except ValueError:
        return ""


def extract(body: str) -> str | None:
    """The SDP part of a body (plain or multipart), or None."""
    if not body:
        return None
    if body.startswith("v="):
        start = 0
    else:
        m = re.search(r"(?:^|\n)v=\d", body)
        if not m:
            return None
        start = m.start() + (1 if body[m.start()] == "\n" else 0)
    text = body[start:]
    cut = _BOUNDARY.search(text)
    return text[:cut.start()] if cut else text


def _address(conn: str) -> str | None:
    # "IN IP4 192.0.2.1" or "IN IP4 233.252.0.1/127/3"
    parts = conn.split()
    if len(parts) < 3:
        return None
    return parts[2].split("/")[0]


def parse(sdp: str) -> dict[str, Any]:
    """Parse one SDP: origin, session connection and direction, and per media section the
    port, protocol, formats in order with their codec names and clock rates, the
    connection address, direction, ptime, fmtp, the RTCP port and whether SDES-SRTP keys
    are offered."""
    session: dict[str, Any] = {"origin": None, "origin_version": None, "address": None, "direction": None, "media": []}
    media: dict[str, Any] | None = None
    for raw in sdp.splitlines():
        line = raw.strip()
        if len(line) < 2 or line[1] != "=":
            continue
        key, value = line[0], line[2:].strip()
        if key == "o":
            parts = value.split()
            if len(parts) >= 6:
                session["origin"] = parts[5]
                session["origin_version"] = f"{parts[1]}/{parts[2]}"
        elif key == "c":
            addr = _address(value)
            if media is None:
                session["address"] = addr
            else:
                media["address"] = addr
        elif key == "m":
            parts = value.split()
            port = None
            if len(parts) >= 2:
                try:
                    port = int(parts[1].split("/")[0])
                except ValueError:
                    port = None
            media = {
                "media": parts[0] if parts else "", "port": port, "proto": parts[2] if len(parts) > 2 else "",
                "formats": parts[3:], "address": None, "direction": None, "rtpmap": {}, "fmtp": {},
                "ptime": None, "rtcp_port": None, "crypto": False,
            }
            session["media"].append(media)
        elif key == "a":
            name, _, arg = value.partition(":")
            name = name.strip().lower()
            target = media if media is not None else session
            if name in DIRECTIONS:
                target["direction"] = name
            elif media is None:
                continue
            elif name == "rtpmap":
                pt, _, enc = arg.partition(" ")
                bits = enc.strip().split("/")
                try:
                    rate = int(bits[1]) if len(bits) > 1 else None
                except ValueError:
                    rate = None
                media["rtpmap"][pt.strip()] = (bits[0], rate)
            elif name == "fmtp":
                pt, _, params = arg.partition(" ")
                media["fmtp"][pt.strip()] = params.strip()
            elif name == "ptime":
                try:
                    media["ptime"] = int(float(arg))
                except ValueError:
                    pass
            elif name == "rtcp":
                try:
                    media["rtcp_port"] = int(arg.split()[0])
                except (ValueError, IndexError):
                    pass
            elif name == "crypto":
                media["crypto"] = True
    for m in session["media"]:
        m["address"] = m["address"] or session["address"]
        m["direction"] = m["direction"] or session["direction"] or "sendrecv"
        if m["port"] is not None and m["port"] > 0 and m["rtcp_port"] is None:
            m["rtcp_port"] = m["port"] + 1
        m["codecs"] = [codec(m, f) for f in m["formats"]]
    return session


def codec(media: dict[str, Any], fmt: str) -> dict[str, Any]:
    """Name and clock rate for one payload format of a media section."""
    entry: dict[str, Any] = {"pt": int(fmt) if fmt.isdigit() else fmt}
    mapped = media["rtpmap"].get(fmt)
    if mapped:
        entry["name"], entry["rate"] = mapped[0], mapped[1]
    elif fmt.isdigit() and int(fmt) in STATIC_PT:
        entry["name"], entry["rate"] = STATIC_PT[int(fmt)]
    if fmt in media["fmtp"]:
        entry["fmtp"] = media["fmtp"][fmt]
    return entry


def codec_label(entry: dict[str, Any]) -> str:
    name = entry.get("name")
    if not name:
        return f"PT {entry['pt']}"
    return f"{name}/{entry['rate']}" if entry.get("rate") else str(name)


def voice_codecs(media: dict[str, Any]) -> list[dict[str, Any]]:
    """The media section's real codecs: telephone-event, comfort noise, RED and FEC left out."""
    return [c for c in media.get("codecs", []) if str(c.get("name", "")).upper() not in NON_CODECS]


def codec_key(entry: dict[str, Any]) -> tuple[str, int | None]:
    return (str(entry.get("name") or f"PT{entry['pt']}").upper(), entry.get("rate"))


def common_codecs(a: dict[str, Any], b: dict[str, Any]) -> list[str]:
    """Voice codecs (name and clock rate) present in both media sections."""
    keys_b = {codec_key(c) for c in voice_codecs(b)}
    return [codec_label(c) for c in voice_codecs(a) if codec_key(c) in keys_b]


def telephone_event_pts(media: dict[str, Any]) -> list[int]:
    return [c["pt"] for c in media.get("codecs", [])
            if str(c.get("name", "")).upper() == "TELEPHONE-EVENT" and isinstance(c["pt"], int)]


# RFC 1918, carrier-grade NAT (RFC 6598), loopback, link-local and IPv6 unique-local.
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128",
)]


def is_private(address: str | None) -> bool:
    """True for addresses that are not routable across a NAT boundary (RFC 1918, CGNAT,
    loopback, link-local, IPv6 ULA). Documentation ranges are treated as public."""
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in _PRIVATE_NETS)


def summary(media: dict[str, Any]) -> dict[str, Any]:
    """A compact view of one media section for tool output."""
    out: dict[str, Any] = {
        "media": media.get("media"),
        "address": media.get("address"),
        "port": media.get("port"),
        "proto": media.get("proto"),
        "codecs": [codec_label(c) for c in media.get("codecs", [])],
        "direction": media.get("direction"),
    }
    if media.get("ptime"):
        out["ptime_ms"] = media["ptime"]
    if media.get("crypto") or "SAVP" in str(media.get("proto", "")):
        out["srtp"] = True
    if media.get("port") == 0:
        out["rejected"] = True
    if is_private(media.get("address")):
        out["private_address"] = True
    return {k: v for k, v in out.items() if v not in (None, "", [])}

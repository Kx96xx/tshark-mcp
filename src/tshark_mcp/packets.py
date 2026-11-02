"""Generic per-packet records from ``-T fields`` output (any link, IP, TCP, UDP).

Fields are requested with ``occurrence=a`` so a tunnelled packet (GTP-U, GRE,
IP-in-IP) yields one value per layer. ``frame.protocols`` tells the layers apart:
the IP layer that carries the transport is the innermost one, and an ICMP error
that quotes a packet (``ip:icmp:ip:tcp``) is kept as an ICMP record rather than
mistaken for a TCP segment.
"""

from __future__ import annotations

from typing import Any

from .fields import parse_time, split_fields_line, to_int

AGGREGATOR = "|"

LINK_LAYERS = ("eth", "ethertype", "sll", "vlan", "frame", "mpls", "erspan", "vxlan", "gre", "geneve", "llc", "null",
               "loop", "raw", "pkt-meta")
TRANSPORTS = ("tcp", "udp", "sctp", "icmp", "icmpv6")


def _truthy(value: str) -> bool:
    return value in ("1", "True", "true")


def _nth(values: list[str], n: int) -> str:
    return values[n] if 0 <= n < len(values) else ""


def ns_fraction(text: str) -> int | None:
    """Nanoseconds of the fractional part of an epoch timestamp printed by tshark."""
    if not text or "." not in text:
        return 0 if text else None
    frac = text.split(".", 1)[1]
    if not frac.isdigit():
        return None
    return int((frac + "000000000")[:9])


def epoch_ns(text: str) -> int | None:
    """An epoch timestamp printed by tshark as integer nanoseconds."""
    if not text:
        return None
    head = text.split(".", 1)[0]
    frac = ns_fraction(text)
    try:
        return int(head) * 1_000_000_000 + (frac or 0)
    except ValueError:
        return None


def parse(stdout: str, fields: list[str]) -> list[dict[str, Any]]:
    """One record per line of ``-T fields`` output requested with ``fields``."""
    out = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(fields):
            continue
        raw = {k: (v.split(AGGREGATOR) if v else []) for k, v in zip(fields, cols)}
        out.append(record(raw))
    return out


def get(raw: dict[str, list[str]], name: str, n: int = 0) -> str:
    return _nth(raw.get(name, []), n)


def record(raw: dict[str, list[str]]) -> dict[str, Any]:
    protocols = get(raw, "frame.protocols")
    all_layers = protocols.split(":") if protocols else []
    layers = [p for p in all_layers if p not in LINK_LAYERS]
    time_text = get(raw, "frame.time_epoch")
    rec: dict[str, Any] = {
        "frame": to_int(get(raw, "frame.number")),
        "time": parse_time(time_text) if time_text else None,
        "time_text": time_text,
        "len": to_int(get(raw, "frame.len"), 0) or 0,
        "cap_len": to_int(get(raw, "frame.cap_len"), 0) or 0,
        "iface": get(raw, "frame.interface_id"),
        "protocols": protocols,
        "link": all_layers[1] if len(all_layers) > 1 and all_layers[0] == "frame" else (all_layers[0] if all_layers else ""),
        "vlan": tuple(raw.get("vlan.id", [])),
        "mac_src": get(raw, "eth.src") or get(raw, "sll.src.eth"),
        "mac_dst": get(raw, "eth.dst"),
        "sll_type": get(raw, "sll.pkttype"),
    }
    ip_layers = [p for p in layers if p in ("ip", "ipv6")]
    if not ip_layers:
        return rec
    first_icmp = min((layers.index(p) for p in ("icmp", "icmpv6") if p in layers), default=None)
    transports = [i for i, p in enumerate(layers) if p in TRANSPORTS]
    if first_icmp is not None and transports and transports[-1] > first_icmp:
        # An ICMP error quoting a packet: the IP layer that carries the ICMP is the one that counts.
        before = layers[:first_icmp]
        carrier = [p for p in before if p in ("ip", "ipv6")]
        if not carrier:
            return rec
        family = carrier[-1]
        idx = before.count(family) - 1
        rec.update(_ip(raw, family, idx, outer=_outer_family(layers)))
        rec["icmp_error"] = _icmp(raw, layers[first_icmp])
        rec["quoted"] = _quoted(raw, layers, first_icmp)
        return rec
    family = ip_layers[-1]
    idx = layers.count(family) - 1
    rec.update(_ip(raw, family, idx, outer=_outer_family(layers)))
    at = len(layers) - 1 - layers[::-1].index(family)
    transport = layers[at + 1] if at + 1 < len(layers) else None
    rec["proto"] = transport
    rec["tunnelled"] = len(ip_layers) > 1
    if transport == "tcp":
        n = layers.count("tcp") - 1
        flags = to_int(get(raw, "tcp.flags", n), 0) or 0
        rec["tcp"] = {
            "sport": get(raw, "tcp.srcport", n), "dport": get(raw, "tcp.dstport", n),
            "seq": to_int(get(raw, "tcp.seq_raw", n)), "ack_no": to_int(get(raw, "tcp.ack_raw", n)),
            "len": to_int(get(raw, "tcp.len", n), 0) or 0,
            "window": to_int(get(raw, "tcp.window_size_value", n)),
            "window_scaled": to_int(get(raw, "tcp.window_size", n)),
            "fin": bool(flags & 0x01), "syn": bool(flags & 0x02), "rst": bool(flags & 0x04),
            "ack": bool(flags & 0x10),
            "mss": to_int(get(raw, "tcp.options.mss_val", n)),
            "wscale": to_int(get(raw, "tcp.options.wscale.shift", n)),
            "sack_perm": bool(raw.get("tcp.options.sack_perm")),
            "checksum": get(raw, "tcp.checksum.status", n),
            "checksum_value": get(raw, "tcp.checksum", n),
            "tsval": to_int(get(raw, "tcp.options.timestamp.tsval", n)),
            "stream": to_int(get(raw, "tcp.stream", n)),
        }
    elif transport == "udp":
        n = layers.count("udp") - 1
        rec["udp"] = {
            "sport": get(raw, "udp.srcport", n), "dport": get(raw, "udp.dstport", n),
            "len": to_int(get(raw, "udp.length", n)), "checksum": get(raw, "udp.checksum.status", n),
            "checksum_value": get(raw, "udp.checksum", n),
        }
    elif transport in ("icmp", "icmpv6"):
        rec["icmp"] = _icmp(raw, transport)
    elif transport == "sctp":
        # Every chunk of the packet: one SCTP layer, several chunks (bundled DATA, SACK + DATA).
        rec["sctp"] = {"vtag": get(raw, "sctp.verification_tag"), "chunks": tuple(raw.get("sctp.chunk_type", [])),
                       "tsns": tuple(raw.get("sctp.data_tsn_raw", [])),
                       "cum_tsn": get(raw, "sctp.sack_cumulative_tsn_ack_raw"), "a_rwnd": get(raw, "sctp.sack_a_rwnd"),
                       "heartbeat": get(raw, "sctp.parameter_heartbeat_information")}
    rec["outer_checksums"] = _outer_checksums(raw, layers)
    return rec


def _outer_family(layers: list[str]) -> str | None:
    return next((p for p in layers if p in ("ip", "ipv6")), None)


def _ip(raw: dict[str, list[str]], family: str, idx: int, outer: str | None) -> dict[str, Any]:
    if family == "ipv6":
        plen = to_int(get(raw, "ipv6.plen", idx))
        ip = {"family": "ipv6", "src": get(raw, "ipv6.src", idx), "dst": get(raw, "ipv6.dst", idx),
              "id": "", "ip_len": plen + 40 if plen is not None else None, "ttl": to_int(get(raw, "ipv6.hlim", idx)),
              "df": True, "ip_checksum": ""}
    else:
        ip = {"family": "ip", "src": get(raw, "ip.src", idx), "dst": get(raw, "ip.dst", idx),
              "id": get(raw, "ip.id", idx), "ip_len": to_int(get(raw, "ip.len", idx)), "ttl": to_int(get(raw, "ip.ttl", idx)),
              "df": _truthy(get(raw, "ip.flags.df", idx)), "ip_checksum": get(raw, "ip.checksum.status", idx)}
    if outer == "ipv6":
        plen = to_int(get(raw, "ipv6.plen", 0))
        ip["outer_len"] = plen + 40 if plen is not None else None
        ip["outer_src"] = get(raw, "ipv6.src", 0)
    elif outer == "ip":
        ip["outer_len"] = to_int(get(raw, "ip.len", 0))
        ip["outer_src"] = get(raw, "ip.src", 0)
    return ip


def _icmp(raw: dict[str, list[str]], key: str) -> dict[str, Any]:
    return {"family": key, "type": to_int(get(raw, f"{key}.type")), "code": to_int(get(raw, f"{key}.code")),
            "mtu": to_int(get(raw, f"{key}.mtu")), "checksum": get(raw, f"{key}.checksum")}


def _quoted(raw: dict[str, list[str]], layers: list[str], icmp_at: int) -> dict[str, Any]:
    """Addresses and ports of the packet an ICMP error quotes (the last IP and transport layers)."""
    inner = layers[icmp_at + 1:]
    q: dict[str, Any] = {}
    fam = next((p for p in inner if p in ("ip", "ipv6")), None)
    if fam:
        idx = layers.count(fam) - 1
        key = "ipv6" if fam == "ipv6" else "ip"
        q["src"], q["dst"] = get(raw, f"{key}.src", idx), get(raw, f"{key}.dst", idx)
        q["len"] = to_int(get(raw, "ip.len", idx)) if fam == "ip" else None
        q["id"] = get(raw, "ip.id", idx) if fam == "ip" else None
    if "tcp" in inner:
        n = layers.count("tcp") - 1
        q["proto"], q["sport"], q["dport"] = "tcp", get(raw, "tcp.srcport", n), get(raw, "tcp.dstport", n)
        q["seq"] = get(raw, "tcp.seq_raw", n)
    elif "udp" in inner:
        n = layers.count("udp") - 1
        q["proto"], q["sport"], q["dport"] = "udp", get(raw, "udp.srcport", n), get(raw, "udp.dstport", n)
    elif "icmp" in inner or "icmpv6" in inner:
        # A quoted echo request (an ICMP traceroute probe). The error itself carries no
        # identifier or sequence number, so the last value is the quoted one.
        key = "icmpv6" if "icmpv6" in inner else "icmp"
        seqs = raw.get("icmpv6.echo.sequence_number" if key == "icmpv6" else "icmp.seq", [])
        q["proto"], q["seq"] = key, seqs[-1] if seqs else ""
    return q


def _outer_checksums(raw: dict[str, list[str]], layers: list[str]) -> list[tuple[str, str, str]]:
    """(layer, status, sender) for every checksum tshark validated on this packet."""
    out = []
    ip_idx = {"ip": 0, "ipv6": 0}
    last_src = ""
    tcp_n = udp_n = 0
    for p in layers:
        if p in ("ip", "ipv6"):
            key = "ipv6" if p == "ipv6" else "ip"
            last_src = get(raw, f"{key}.src", ip_idx[p])
            if p == "ip":
                status = get(raw, "ip.checksum.status", ip_idx[p])
                if status:
                    out.append(("ip", status, last_src))
            ip_idx[p] += 1
        elif p == "tcp":
            status = get(raw, "tcp.checksum.status", tcp_n)
            tcp_n += 1
            if status:
                out.append(("tcp", status, last_src))
        elif p == "udp":
            status = get(raw, "udp.checksum.status", udp_n)
            udp_n += 1
            if status:
                out.append(("udp", status, last_src))
    return out


def zeroed_tcp_header(rec: dict[str, Any]) -> bool:
    """A TCP segment with no flags and zero sequence and acknowledgement numbers.

    No TCP stack sends this. Some capture tools write a decapsulated copy of a
    tunnelled packet with a rebuilt IP/TCP header of zeros around the original
    payload; it is a copy, not traffic."""
    tcp = rec.get("tcp")
    return bool(tcp) and not (tcp["syn"] or tcp["ack"] or tcp["fin"] or tcp["rst"]) and not tcp["seq"] and not tcp["ack_no"]

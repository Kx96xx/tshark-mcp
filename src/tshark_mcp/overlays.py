"""tunnels_overview: every tunnel and overlay in a capture from one ``-T fields`` pass.

A tunnel is a pair of outer endpoints plus the identifier the encapsulation carries (GRE key,
VXLAN or Geneve VNI); IPsec, WireGuard, OpenVPN, L2TP and GTP-U are grouped per endpoint pair
because their identifiers (SPI, sender index, TEID) change per direction or per session and
are reported inside the row. The outer layer is the first IP layer in ``frame.protocols``; the
inner one is the first IP layer after the encapsulation, so each packet's inner addresses,
lengths and SYN MSS are read from the right occurrence of a repeated field.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .fields import compact, iso, parse_time, split_fields_line, to_int

AGGREGATOR = "|"

KINDS = ("gre", "erspan", "vxlan", "geneve", "ipip", "ipsec", "wireguard", "openvpn", "l2tp", "gtpu", "teredo")
KIND_NAMES = {"gre": "GRE", "erspan": "ERSPAN", "vxlan": "VXLAN", "geneve": "Geneve", "ipip": "IP-in-IP",
              "ipsec": "IPsec", "wireguard": "WireGuard", "openvpn": "OpenVPN", "l2tp": "L2TP", "gtpu": "GTP-U",
              "teredo": "Teredo"}

# Field names that differ between tshark releases: the first one the binary knows is used.
FIELD_ALTERNATIVES = {"isakmp.exchangetype": ("isakmp.exchangetype", "isakmp.exchtype")}

BASE_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "ip.src", "ip.dst", "ip.len", "ip.flags.df", "ip.fragment.count", "ipv6.src", "ipv6.dst", "ipv6.plen",
    "udp.srcport", "udp.dstport", "tcp.flags.syn", "tcp.options.mss_val",
    "gre.proto", "gre.key", "vxlan.vni", "geneve.vni", "esp.spi", "esp.sequence", "ah.spi",
    "isakmp.ispi", "isakmp.rspi", "isakmp.version", "isakmp.exchangetype", "isakmp.flag_r", "isakmp.messageid",
    "isakmp.notify.msgtype", "wg.type", "wg.sender", "wg.receiver", "wg.keepalive", "openvpn.opcode",
    "l2tp.type", "l2tp.tunnel", "gtp.teid", "gtp.message",
]

# Protocols the display filter selects; each is kept only if the binary knows it.
FILTER_PROTOCOLS = ("gre", "vxlan", "geneve", "esp", "ah", "isakmp", "wg", "openvpn", "l2tp", "teredo")
IPIP_FILTER = "ip.proto == 4 || ip.proto == 41 || ipv6.nxt == 4 || ipv6.nxt == 41"
GTPU_FILTER = "gtp.message == 0xff"

# Bytes outside the inner IP packet when no packet showed both lengths (outer IPv4).
DEFAULT_OVERHEAD = {"gre": 24, "erspan": 50, "vxlan": 50, "geneve": 50, "ipip": 20, "gtpu": 36, "l2tp": 40,
                    "teredo": 28}
ENCRYPTED = ("ipsec", "wireguard", "openvpn")

IKE_EXCHANGES = {2: "Main Mode", 4: "Aggressive Mode", 5: "Informational (v1)", 32: "Quick Mode",
                 34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}
IKE_ERRORS = {1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION",
              7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN",
              17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
              35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE", 37: "FAILED_CP_REQUIRED",
              38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS", 43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND"}
IKE_ERROR_HINTS = {
    14: "the two ends share no encryption, integrity or DH proposal",
    24: "the pre-shared key, certificate or identity does not match",
    17: "the responder wants another DH group; the initiator should retry with it",
    38: "the traffic selectors (subnets) differ between the two configurations",
}
# IKEv2 error notifies that ask the initiator to try again rather than end the negotiation (RFC 7296 1.3, 2.7):
# INVALID_KE_PAYLOAD names the DH group the responder wants; the initiator retries IKE_SA_INIT with it.
IKE_RETRY_ERRORS = {17}

OPENVPN_OPCODES = {1: "control_hard_reset_client_v1", 2: "control_hard_reset_server_v1", 3: "control_soft_reset",
                   4: "control", 5: "ack", 6: "data_v1", 7: "control_hard_reset_client_v2",
                   8: "control_hard_reset_server_v2", 9: "data_v2", 10: "control_hard_reset_client_v3",
                   11: "control_wkc"}
OPENVPN_CLIENT_RESETS = (1, 7, 10)
OPENVPN_SERVER_RESETS = (2, 8)
OPENVPN_DATA = (6, 9)


def kind_arg(value: object) -> str | None:
    """A ``kind`` argument (``ipsec``, ``IP-in-IP``, ``GTP-U``, ...) as a key of KINDS, or None."""
    text = str(value).strip().lower().replace("-", "").replace("_", "")
    text = {"ipinip": "ipip", "wg": "wireguard", "gtp": "gtpu"}.get(text, text)
    return text if text in KINDS else None


def fields(known: frozenset[str] | set[str]) -> list[str]:
    """The fields to ask for, with per-release alternatives resolved and unknown ones left out."""
    out = []
    for f in BASE_FIELDS:
        name = next((n for n in FIELD_ALTERNATIVES.get(f, (f,)) if n in known), None)
        if name:
            out.append(name)
    return out


def display_filter(known: frozenset[str] | set[str]) -> str:
    parts = [p for p in FILTER_PROTOCOLS if p in known]
    parts += [IPIP_FILTER, GTPU_FILTER]
    return " || ".join(f"({p})" if " " in p else p for p in parts)


def _truthy(value: str) -> bool:
    return value in ("1", "True", "true")


def _nth(values: list[str], n: int) -> str:
    return values[n] if 0 <= n < len(values) else ""


def _layers(protocols: str) -> list[str]:
    return [p for p in protocols.split(":") if p not in ("frame", "ethertype", "sll", "vlan")]


def _kind(layers: list[str]) -> tuple[str | None, int]:
    """(kind, index of the encapsulation layer) for the outermost tunnel in the layer list."""
    first_ip = next((i for i, p in enumerate(layers) if p in ("ip", "ipv6")), None)
    if first_ip is None:
        return None, -1
    for i in range(first_ip + 1, len(layers)):
        p = layers[i]
        if p == "gre":
            return ("erspan" if "erspan" in layers[i + 1:i + 2] else "gre"), i
        if p in ("vxlan", "geneve", "l2tp", "openvpn"):
            return p, i
        if p == "wg":
            return "wireguard", i
        if p in ("esp", "ah", "isakmp"):
            return "ipsec", i
        if p == "gtp":
            return "gtpu", i
        if p == "teredo":
            return "teredo", i
        if p in ("ip", "ipv6") and i == first_ip + 1:
            return "ipip", first_ip
        if p in ("tcp", "sctp", "icmp", "icmpv6"):
            return None, -1
    return None, -1


def parse(stdout: str, names: list[str]) -> list[dict[str, Any]]:
    """One record per tunnelled packet, outer and inner layers told apart."""
    recs = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(names):
            continue
        raw = {k: (v.split(AGGREGATOR) if v else []) for k, v in zip(names, cols)}
        for alt, choices in FIELD_ALTERNATIVES.items():
            for c in choices:
                if c in raw and c != alt:
                    raw[alt] = raw.pop(c)
        layers = _layers(_nth(raw["frame.protocols"], 0))
        kind, at = _kind(layers)
        if kind is None:
            continue
        if kind == "gtpu" and _nth(raw.get("gtp.message", []), 0) not in ("0xff", "0x000000ff", "255"):
            continue
        outer_v6 = next(p for p in layers if p in ("ip", "ipv6")) == "ipv6"
        rec: dict[str, Any] = {
            "kind": kind,
            "frame": to_int(_nth(raw["frame.number"], 0)),
            "time": parse_time(_nth(raw["frame.time_epoch"], 0)),
            "frame_len": to_int(_nth(raw["frame.len"], 0), 0) or 0,
        }
        if outer_v6:
            rec["src"], rec["dst"] = _nth(raw["ipv6.src"], 0), _nth(raw["ipv6.dst"], 0)
            plen = to_int(_nth(raw["ipv6.plen"], 0))
            rec["outer_len"] = plen + 40 if plen is not None else None
            rec["df"] = True
        else:
            rec["src"], rec["dst"] = _nth(raw["ip.src"], 0), _nth(raw["ip.dst"], 0)
            rec["outer_len"] = to_int(_nth(raw["ip.len"], 0))
            rec["df"] = _truthy(_nth(raw["ip.flags.df"], 0))
            rec["fragmented"] = bool(_nth(raw.get("ip.fragment.count", []), 0))
        uses_udp = "udp" in layers[:at]
        if uses_udp:
            rec["sport"], rec["dport"] = _nth(raw["udp.srcport"], 0), _nth(raw["udp.dstport"], 0)
        _ids(rec, raw, kind, layers)
        _inner(rec, raw, layers, at)
        recs.append(rec)
    return recs


def _ids(rec: dict[str, Any], raw: dict[str, list[str]], kind: str, layers: list[str]) -> None:
    g = lambda f: _nth(raw.get(f, []), 0)  # noqa: E731
    if kind in ("gre", "erspan"):
        rec["id"] = to_int(g("gre.key")) if g("gre.key") else None
        rec["gre_proto"] = g("gre.proto")
    elif kind in ("vxlan", "geneve"):
        rec["id"] = to_int(g(f"{kind}.vni"))
    elif kind == "ipsec":
        if "esp" in layers:
            rec["esp_spi"] = g("esp.spi")
        if "ah" in layers:
            rec["ah_spi"] = g("ah.spi")
        if "isakmp" in layers:
            rec["ike"] = {
                "ispi": g("isakmp.ispi"), "rspi": g("isakmp.rspi"), "version": g("isakmp.version"),
                "exchange": to_int(g("isakmp.exchangetype")), "response": _truthy(g("isakmp.flag_r")),
                "msgid": g("isakmp.messageid"),
                "notify": [n for n in (to_int(v) for v in raw.get("isakmp.notify.msgtype", [])) if n is not None],
            }
    elif kind == "wireguard":
        rec["wg"] = {"type": to_int(g("wg.type")), "sender": g("wg.sender"), "receiver": g("wg.receiver"),
                     "keepalive": _truthy(g("wg.keepalive"))}
    elif kind == "openvpn":
        rec["opcode"] = to_int(g("openvpn.opcode"))
    elif kind == "l2tp":
        rec["control"] = g("l2tp.type") in ("1", "True", "true")
        rec["id"] = to_int(g("l2tp.tunnel"))
    elif kind == "gtpu":
        rec["teid"] = g("gtp.teid")


def _inner(rec: dict[str, Any], raw: dict[str, list[str]], layers: list[str], at: int) -> None:
    """Inner IP addresses, length, transport and SYN MSS when the payload is in clear."""
    inner_at = next((i for i in range(at + 1, len(layers)) if layers[i] in ("ip", "ipv6")), None)
    if inner_at is None:
        return
    family = layers[inner_at]
    n = layers[:inner_at].count(family)
    if family == "ip":
        rec["inner_src"], rec["inner_dst"] = _nth(raw["ip.src"], n), _nth(raw["ip.dst"], n)
        rec["inner_len"] = to_int(_nth(raw["ip.len"], n))
    else:
        rec["inner_src"], rec["inner_dst"] = _nth(raw["ipv6.src"], n), _nth(raw["ipv6.dst"], n)
        plen = to_int(_nth(raw["ipv6.plen"], n))
        rec["inner_len"] = plen + 40 if plen is not None else None
    rec["inner_family"] = "ipv6" if family == "ipv6" else "ipv4"
    rec["inner_proto"] = layers[inner_at + 1] if inner_at + 1 < len(layers) else family
    rec["inner_eth"] = "eth" in layers[at + 1:inner_at]
    if rec["inner_proto"] == "tcp" and _truthy(_nth(raw["tcp.flags.syn"], 0)):
        rec["syn_mss"] = to_int(_nth(raw["tcp.options.mss_val"], 0))


def _key(rec: dict[str, Any]) -> tuple[Any, ...]:
    pair = tuple(sorted((rec["src"], rec["dst"])))
    if rec["kind"] in ("gre", "erspan", "vxlan", "geneve", "l2tp"):
        return (rec["kind"], *pair, rec.get("id"))
    if rec["kind"] in ("wireguard", "openvpn"):
        ends = sorted(((rec["src"], rec.get("sport")), (rec["dst"], rec.get("dport"))))
        return (rec["kind"], *ends[0], *ends[1])
    return (rec["kind"], *pair)


def summarise(recs: list[dict[str, Any]], mtu: int) -> list[dict[str, Any]]:
    buckets: dict[tuple[Any, ...], dict[str, Any]] = {}
    for rec in recs:
        k = _key(rec)
        b = buckets.get(k)
        if b is None:
            b = buckets[k] = {
                "kind": rec["kind"], "a": rec["src"], "b": rec["dst"], "id": rec.get("id"),
                "ports": Counter(), "pk": Counter(), "by": Counter(), "first": rec["time"], "last": rec["time"],
                "first_frame": rec["frame"], "last_frame": rec["frame"], "inner_protocols": Counter(),
                "inner_conv": Counter(), "overheads": Counter(), "max_outer": 0, "df_above": 0, "fragmented": 0,
                "mss": Counter(), "families": Counter(), "esp": {}, "ah": set(), "ike": [], "wg": [],
                "opcodes": Counter(), "teids": set(), "l2tp": Counter(), "gre_proto": Counter(), "eth": 0,
            }
        d = "a_to_b" if rec["src"] == b["a"] else "b_to_a"
        b["pk"][d] += 1
        b["by"][d] += rec["frame_len"]
        if rec["time"] is not None:
            b["first"] = rec["time"] if b["first"] is None else min(b["first"], rec["time"])
            b["last"] = rec["time"] if b["last"] is None else max(b["last"], rec["time"])
        b["last_frame"] = rec["frame"]
        if rec.get("dport"):
            b["ports"][int(rec["dport"]) if rec["dport"].isdigit() else rec["dport"]] += 1
        ol = rec.get("outer_len")
        if ol:
            b["max_outer"] = max(b["max_outer"], ol)
            if rec.get("df") and ol > mtu:
                b["df_above"] += 1
        if rec.get("fragmented"):
            b["fragmented"] += 1
        if rec.get("inner_len") is not None:
            if ol:
                b["overheads"][ol - rec["inner_len"]] += 1
            b["inner_protocols"][rec["inner_proto"]] += 1
            b["inner_conv"][" <-> ".join(sorted((rec["inner_src"], rec["inner_dst"])))] += 1
            b["families"][rec["inner_family"]] += 1
            if rec.get("inner_eth"):
                b["eth"] += 1
        if rec.get("syn_mss"):
            b["mss"][rec["syn_mss"]] += 1
        if rec.get("gre_proto"):
            b["gre_proto"][rec["gre_proto"]] += 1
        if rec.get("esp_spi"):
            sa = b["esp"].setdefault(rec["esp_spi"], {"spi": rec["esp_spi"], "src": rec["src"], "dst": rec["dst"],
                                                       "packets": 0, "bytes": 0, "first_frame": rec["frame"]})
            sa["packets"] += 1
            sa["bytes"] += rec["frame_len"]
        if rec.get("ah_spi"):
            b["ah"].add(rec["ah_spi"])
        if rec.get("ike"):
            b["ike"].append({**rec["ike"], "frame": rec["frame"], "from_a": d == "a_to_b", "port": rec.get("dport")})
        if rec.get("wg"):
            b["wg"].append({**rec["wg"], "frame": rec["frame"], "from_a": d == "a_to_b"})
        if rec.get("opcode") is not None:
            b["opcodes"][(rec["opcode"], d)] += 1
        if rec.get("teid"):
            b["teids"].add(rec["teid"])
        if rec["kind"] == "l2tp":
            b["l2tp"]["control" if rec.get("control") else "data"] += 1
    rows = [_row(b, mtu) for b in buckets.values()]
    rows.sort(key=lambda r: (not r.get("issues"), r.get("first_frame") or 0))
    return rows


def _row(b: dict[str, Any], mtu: int) -> dict[str, Any]:
    kind = b["kind"]
    one_way = not b["pk"]["b_to_a"]
    overhead = b["overheads"].most_common(1)[0][0] if b["overheads"] else None
    row: dict[str, Any] = {
        "kind": KIND_NAMES[kind], "endpoint_a": b["a"], "endpoint_b": b["b"],
        "packets_a_to_b": b["pk"]["a_to_b"], "packets_b_to_a": b["pk"]["b_to_a"],
        "bytes_a_to_b": b["by"]["a_to_b"], "bytes_b_to_a": b["by"]["b_to_a"], "one_way": one_way,
        "first": iso(b["first"]), "last": iso(b["last"]), "first_frame": b["first_frame"], "last_frame": b["last_frame"],
        "largest_outer_ip_len": b["max_outer"] or None, "overhead_bytes": overhead,
        "df_above_mtu": b["df_above"] or None, "fragmented_outer": b["fragmented"] or None,
    }
    if kind in ("gre", "erspan"):
        row["key"] = b["id"]
        row["gre_protocols"] = dict(b["gre_proto"]) or None
    elif kind in ("vxlan", "geneve"):
        row["vni"] = b["id"]
    elif kind == "l2tp":
        row["tunnel_id"] = b["id"]
        row["l2tp_messages"] = dict(b["l2tp"])
    elif kind == "gtpu":
        row["teids"] = len(b["teids"])
    if b["ports"] and kind in ("vxlan", "geneve", "wireguard", "openvpn", "l2tp", "gtpu", "ipsec", "teredo"):
        row["udp_ports"] = sorted(b["ports"], key=str)[:5]
    if kind in ENCRYPTED:
        row["inner"] = "encrypted"
    elif b["inner_protocols"]:
        row["inner_protocols"] = dict(b["inner_protocols"].most_common(8))
        row["inner_conversations"] = [{"pair": p, "packets": n} for p, n in b["inner_conv"].most_common(3)]
        if b["eth"]:
            row["inner_ethernet"] = True
    if b["mss"]:
        row["inner_syn_mss"] = {str(k): v for k, v in sorted(b["mss"].items())}
    if kind == "ipsec":
        row.update(_ipsec(b))
    elif kind == "wireguard":
        row["handshake"] = _wireguard(b)
    elif kind == "openvpn":
        row["handshake"] = _openvpn(b)
    row["issues"] = _issues(row, b, overhead, mtu)
    return compact(row)


def _ipsec(b: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    sas = list(b["esp"].values())
    if sas:
        out["esp_sas"] = [{**sa, "direction": "a_to_b" if sa["src"] == b["a"] else "b_to_a"} for sa in sas]
        for sa in out["esp_sas"]:
            sa.pop("src")
            sa.pop("dst")
        dirs = {sa["direction"] for sa in out["esp_sas"]}
        out["esp_pairs"] = "both directions" if len(dirs) == 2 else "one direction only"
    if b["ah"]:
        out["ah_spis"] = sorted(b["ah"])
    if b["ike"]:
        out["handshake"] = _ike(b["ike"], esp_both_ways=out.get("esp_pairs") == "both directions")
    nat_t = 4500 in b["ports"]
    if nat_t:
        out["nat_traversal"] = True
    return out


def _ike(msgs: list[dict[str, Any]], esp_both_ways: bool = False) -> dict[str, Any]:
    """IKE per tunnel. The outcome follows how the negotiation ended, not the first error on the way:
    an IKE_AUTH answered without an error, or ESP flowing both ways, is ``established`` even after an
    INVALID_KE_PAYLOAD retry (``retried`` names it)."""
    exchanges: Counter = Counter()
    errors: Counter = Counter()
    retries: Counter = Counter()
    requests: dict[tuple[str, str], dict[str, Any]] = {}
    answered: set[tuple[str, str]] = set()
    v2 = any(m["version"].startswith("0x2") or m["version"] == "2.0" for m in msgs)
    auth_ok = False
    for m in msgs:
        name = IKE_EXCHANGES.get(m["exchange"], f"exchange {m['exchange']}")
        exchanges[name] += 1
        for n in m["notify"]:
            if n < 16384:
                errors[IKE_ERRORS.get(n, f"error notify {n}")] += 1
                if n in IKE_RETRY_ERRORS:
                    retries[IKE_ERRORS[n]] += 1
        key = (m["ispi"], m["msgid"])
        if m["response"]:
            answered.add(key)
            if m["exchange"] == 35 and not any(n < 16384 for n in m["notify"]):
                auth_ok = True
        else:
            requests.setdefault(key, m)
    unanswered = [m for k, m in requests.items() if k not in answered] if v2 else []
    out: dict[str, Any] = {
        "protocol": "IKEv2" if v2 else "IKEv1", "messages": len(msgs), "exchanges": dict(exchanges),
        "error_notifies": dict(errors) or None,
        "unanswered_requests": len(unanswered) or None,
        "unanswered_frames": [m["frame"] for m in unanswered][:5] or None,
        "dpd_unanswered": sum(1 for m in unanswered if m["exchange"] == 37) or None,
        "nat_t": any(str(m.get("port")) == "4500" for m in msgs) or None,
    }
    fatal = sum(errors.values()) - sum(retries.values())
    if retries:
        first = next(i for i, m in enumerate(msgs) if any(n in IKE_RETRY_ERRORS for n in m["notify"]))
        came_back = any(m["exchange"] == 34 and not m["response"] for m in msgs[first + 1:])
        out["retried"] = [f"{name} x{n}: the responder asked for another DH group and the initiator "
                          + ("retried with it (normal, RFC 7296 1.3)" if came_back else "did not try again in the capture")
                          for name, n in retries.items()]
    if v2:
        if auth_ok or esp_both_ways:
            out["outcome"] = "established"
        elif fatal:
            out["outcome"] = "failed"
        elif retries:
            out["outcome"] = "incomplete"
        elif any(m["exchange"] == 34 for m in unanswered):
            out["outcome"] = "no response"
        else:
            out["outcome"] = "incomplete"
    else:
        quick_both = {m["from_a"] for m in msgs if m["exchange"] == 32} == {True, False}
        if quick_both or esp_both_ways:
            out["outcome"] = "established"
        else:
            out["outcome"] = "failed" if errors else "incomplete"
    return compact(out)


def _wireguard(b: dict[str, Any]) -> dict[str, Any]:
    msgs = b["wg"]
    inits = [m for m in msgs if m["type"] == 1]
    resp_receivers = {m["receiver"] for m in msgs if m["type"] == 2}
    unanswered = [m for m in inits if m["sender"] not in resp_receivers]
    data = [m for m in msgs if m["type"] == 4]
    out = {
        "initiations": len(inits), "responses": sum(1 for m in msgs if m["type"] == 2),
        "cookie_replies": sum(1 for m in msgs if m["type"] == 3) or None,
        "unanswered_initiations": len(unanswered) or None,
        "unanswered_frames": [m["frame"] for m in unanswered][:5] or None,
        "keepalives": sum(1 for m in data if m["keepalive"]) or None,
        "data_a_to_b": sum(1 for m in data if m["from_a"] and not m["keepalive"]),
        "data_b_to_a": sum(1 for m in data if not m["from_a"] and not m["keepalive"]),
    }
    if out["data_a_to_b"] and out["data_b_to_a"]:
        out["outcome"] = "data both ways"
    elif inits and not out["responses"]:
        out["outcome"] = "no response"
    elif out["responses"]:
        out["outcome"] = "handshake done, data one way" if (out["data_a_to_b"] or out["data_b_to_a"]) else "handshake done"
    else:
        out["outcome"] = "data one way" if data else "incomplete"
    first_init = inits[0] if inits else None
    if first_init is not None:
        out["initiator"] = "a" if first_init["from_a"] else "b"
    return compact(out)


def _openvpn(b: dict[str, Any]) -> dict[str, Any]:
    ops = b["opcodes"]
    count = lambda codes, d=None: sum(n for (op, dd), n in ops.items() if op in codes and (d is None or dd == d))  # noqa: E731
    out = {
        "opcodes": {OPENVPN_OPCODES.get(op, f"opcode {op}"): sum(n for (o, _), n in ops.items() if o == op)
                    for op in sorted({o for o, _ in ops})},
        "client_resets": count(OPENVPN_CLIENT_RESETS), "server_resets": count(OPENVPN_SERVER_RESETS),
        "data_a_to_b": count(OPENVPN_DATA, "a_to_b"), "data_b_to_a": count(OPENVPN_DATA, "b_to_a"),
    }
    if out["data_a_to_b"] and out["data_b_to_a"]:
        out["outcome"] = "data both ways"
    elif out["client_resets"] and not out["server_resets"]:
        out["outcome"] = "no response"
    else:
        out["outcome"] = "incomplete"
    return out


def _issues(row: dict[str, Any], b: dict[str, Any], overhead: int | None, mtu: int) -> list[str]:
    kind, name = b["kind"], row["kind"]
    ident = {"gre": f" key {b['id']}" if b["id"] is not None else "", "vxlan": f" VNI {b['id']}",
             "geneve": f" VNI {b['id']}", "l2tp": f" tunnel {b['id']}"}.get(kind, "")
    where = f"{name}{ident} {b['a']} -> {b['b']}"
    issues: list[str] = []
    hs = row.get("handshake") or {}
    if kind == "wireguard" and hs.get("unanswered_initiations"):
        initiator = b["a"] if hs.get("initiator") == "a" else b["b"]
        port = next(iter(b["ports"]), 51820)
        issues.append(f"{hs['unanswered_initiations']} WireGuard handshake initiations from {initiator} and no response: "
                      f"the peer's public key or endpoint is wrong, or UDP {port} is blocked")
    if kind == "openvpn" and hs.get("outcome") == "no response":
        issues.append(f"{hs['client_resets']} OpenVPN client resets from {b['a']} and no server reset back: the server "
                      "is down, the port is blocked or tls-auth/tls-crypt keys differ")
    if kind == "ipsec":
        if hs.get("error_notifies"):
            for err in hs["error_notifies"]:
                code = next((c for c, n in IKE_ERRORS.items() if n == err), None)
                if code in IKE_RETRY_ERRORS and hs.get("outcome") == "established":
                    continue  # a DH-group retry that worked: in handshake.retried, not an issue
                hint = IKE_ERROR_HINTS.get(code or -1)
                issues.append(f"IKE between {b['a']} and {b['b']} returned {err}" + (f": {hint}" if hint else ""))
        if hs.get("outcome") == "no response":
            issues.append(f"IKE_SA_INIT from {b['a']} to {b['b']} never answered: UDP 500/4500 blocked or the peer "
                          "is not configured for this address")
        if hs.get("dpd_unanswered"):
            issues.append(f"{hs['dpd_unanswered']} IKE INFORMATIONAL (dead peer detection) requests unanswered: "
                          "the peer stopped responding")
        for sa in row.get("esp_sas") or []:
            if row.get("esp_pairs") == "one direction only":
                src, dst = (b["a"], b["b"]) if sa["direction"] == "a_to_b" else (b["b"], b["a"])
                issues.append(f"ESP SPI {sa['spi']} flows only {src} -> {dst} and no SA carries traffic back: the "
                              "return SA is missing, the peer drops it, or routing is asymmetric")
    elif row["one_way"] and kind not in ("wireguard", "openvpn") and b["pk"]["a_to_b"] >= 2:
        issues.append(f"{where} carries traffic one way only ({b['pk']['a_to_b']} packets, none back): the far end "
                      "does not decapsulate, drops the tunnel, or the return path bypasses this capture point")
    over = overhead if overhead is not None else DEFAULT_OVERHEAD.get(kind)
    if over is not None and b["mss"]:
        family_extra = 60 if b["families"].get("ipv6", 0) > b["families"].get("ipv4", 0) else 40
        for mss in sorted(b["mss"]):
            wire = mss + family_extra + over
            if wire > mtu:
                issues.append(f"{where} adds {over} bytes; inner SYNs offer MSS {mss}: {wire} bytes on the wire, above "
                              f"the {mtu}-byte path MTU (an MSS of at most {mtu - family_extra - over} fits)")
    if b["df_above"]:
        issues.append(f"{b['df_above']} outer packets of {where} have DF set and are larger than the {mtu}-byte path MTU")
    if b["fragmented"]:
        issues.append(f"{b['fragmented']} packets of {where} were fragmented on the outer IP layer: the inner MTU is "
                      "too large for the path")
    return issues


def summary(rows: list[dict[str, Any]], recs: list[dict[str, Any]]) -> dict[str, Any]:
    kinds = Counter(r["kind"] for r in rows)
    return {
        "tunnels": len(rows), "packets": len(recs), "by_kind": dict(kinds),
        "tunnels_with_issues": sum(1 for r in rows if r.get("issues")),
        "one_way": sum(1 for r in rows if r.get("one_way")),
        **({"note": "no tunnel of the kinds this tool reads (" + ", ".join(KIND_NAMES.values()) + ") in the capture. "
            "A tunnel tshark does not decode on its port (an ERSPAN marker or VXLAN on another UDP port, a vendor "
            "encapsulation) shows up as plain UDP or TCP: look at conversations, then filter_packets on that port"}
           if not rows else {}),
    }

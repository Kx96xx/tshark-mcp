"""Defensive triage of the capturing network: port scans and SYN floods, beaconing, DNS tunnel
hints, TLS client fingerprints (JA4/JA3) and server fingerprints (JA3S), ARP conflicts and
cleartext credentials.

Everything here is computed from tshark fields; nothing is looked up anywhere (no threat
intelligence, no fingerprint database: that would be network egress). Credential values never
leave the parsing: only the protocol, the two addresses and a count are kept. Each check is a
heuristic with documented thresholds; findings say what was seen and why it matters, never who
is behind it.

Beaconing follows the idea of RITA's beacon score (Active Countermeasures), reimplemented and
simplified, so it is an approximation, not RITA: per (client, server, port or SNI) the connection
start intervals and sizes are scored for regularity (Bowley skew and the median absolute
deviation), and the time the series covers counts too:
``score = 0.45 * interval + 0.35 * size + 0.20 * coverage``. The raw statistics are always
returned so a jittered or low-volume beacon is still visible when its score is low.
"""

from __future__ import annotations

import math
import statistics
from typing import Any, Iterable

from .fields import iso, to_float, to_int

AGGREGATOR = "|"
KINDS = ("scans", "beacons", "dns_tunnels", "tls_fingerprints", "arp", "cleartext_credentials")
SCOPE = ("Defensive triage of traffic on the capturing network. Heuristics, not verdicts: confirm each finding "
         "with the frames it names. No attribution and no lookups outside this capture.")

TCP_FILTER = "tcp.flags.syn == 1 || tcp.flags.reset == 1"
TCP_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport",
              "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.stream"]
TLS_FILTER = "tls.handshake.type == 1 || tls.handshake.type == 2"
TLS_FIELDS = ["frame.number", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tls.handshake.type",
              "tls.handshake.ja4", "tls.handshake.ja3", "tls.handshake.ja3s", "tls.handshake.extensions_server_name",
              "tls.handshake.ja4_r"]
DNS_FILTER = "dns.flags.response == 0"
DNS_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "dns.qry.name", "dns.qry.type"]
ARP_FILTER = "arp"
ARP_FIELDS = ["frame.number", "arp.opcode", "arp.src.proto_ipv4", "arp.src.hw_mac", "arp.duplicate-address-detected"]
CRED_FILTER = ('ftp.request.command == "USER" || ftp.request.command == "PASS" || http.authorization'
               ' || pop.request.command == "USER" || pop.request.command == "PASS" || imap.request.command == "LOGIN"'
               ' || imap.request.command == "login" || smtp.req.command == "AUTH"')
CRED_FIELDS = ["frame.number", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ftp.request.command", "http.authorization",
               "pop.request.command", "imap.request.command", "smtp.req.command"]

SCAN_PORTS = 20          # distinct ports on one host from one source
SWEEP_HOSTS = 20         # distinct hosts on one port from one source
FLOOD_SYNS = 200         # SYNs to one server port
BEACON_MIN = 12          # connections or queries before a beacon score
TUNNEL_NAMES = 30        # distinct names under one zone
TUNNEL_LABEL = 20        # mean length of the leftmost label
TUNNEL_ENTROPY = 3.5     # bits per character of the leftmost label
TOP = 20


def rows(stdout: str, fields: list[str]) -> list[dict[str, str]]:
    out = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t") + [""] * len(fields)
        out.append({f: parts[i] for i, f in enumerate(fields)})
    return out


def _src(r: dict[str, str]) -> str:
    return r.get("ip.src") or r.get("ipv6.src") or ""


def _dst(r: dict[str, str]) -> str:
    return r.get("ip.dst") or r.get("ipv6.dst") or ""


def _flag(value: str) -> bool:
    return value.strip() in ("1", "True", "true")


# ------------------------------------------------------------------ scans and floods
def scans(tcp: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(findings, connection starts) from SYN / SYN-ACK / RST packets."""
    syn_targets: dict[str, dict[str, set[int]]] = {}
    sweeps: dict[tuple[str, int], set[str]] = {}
    answered: set[tuple[str, int, str]] = set()       # (server, port, client) that sent SYN-ACK
    resets: set[tuple[str, int, str]] = set()
    first_frame: dict[str, int] = {}
    per_server: dict[tuple[str, int], dict[str, Any]] = {}
    starts: list[dict[str, Any]] = []
    for r in tcp:
        src, dst = _src(r), _dst(r)
        sport, dport = to_int(r["tcp.srcport"]), to_int(r["tcp.dstport"])
        frame = to_int(r["frame.number"])
        if not src or not dst or sport is None or dport is None:
            continue
        syn, ack, rst = _flag(r["tcp.flags.syn"]), _flag(r["tcp.flags.ack"]), _flag(r["tcp.flags.reset"])
        if syn and not ack:
            syn_targets.setdefault(src, {}).setdefault(dst, set()).add(dport)
            sweeps.setdefault((src, dport), set()).add(dst)
            first_frame.setdefault(src, frame or 0)
            ps = per_server.setdefault((dst, dport), {"syns": 0, "clients": set(), "first_frame": frame})
            ps["syns"] += 1
            ps["clients"].add(src)
            starts.append({"time": to_float(r["frame.time_epoch"]), "client": src, "server": dst, "port": dport,
                           "sport": sport, "stream": to_int(r["tcp.stream"]), "frame": frame})
        elif syn and ack:
            answered.add((src, sport, dst))
        elif rst:
            resets.add((src, sport, dst))
    findings: list[dict[str, Any]] = []
    for src, targets in syn_targets.items():
        for dst, ports in targets.items():
            if len(ports) >= SCAN_PORTS:
                open_ports = sorted(p for p in ports if (dst, p, src) in answered)
                refused = sum(1 for p in ports if (dst, p, src) in resets)
                findings.append({"kind": "port_scan", "severity": "high" if len(ports) >= 100 else "medium",
                                 "summary": f"{src} probed {len(ports)} TCP ports on {dst}: {len(open_ports)} answered, "
                                            f"{refused} refused",
                                 "subject": {"source": src, "target": dst},
                                 "evidence": {"ports": len(ports), "open_ports": open_ports[:20], "refused": refused,
                                              "first_frame": first_frame.get(src)}})
    for (src, port), hosts in sweeps.items():
        if len(hosts) >= SWEEP_HOSTS:
            answered_n = sum(1 for h in hosts if (h, port, src) in answered)
            findings.append({"kind": "host_sweep", "severity": "medium",
                             "summary": f"{src} tried TCP port {port} on {len(hosts)} hosts, {answered_n} answered",
                             "subject": {"source": src, "port": port},
                             "evidence": {"hosts": len(hosts), "answered": answered_n, "first_frame": first_frame.get(src)}})
    for (dst, port), ps in per_server.items():
        if ps["syns"] >= FLOOD_SYNS:
            done = sum(1 for c in ps["clients"] if (dst, port, c) in answered)
            findings.append({"kind": "syn_flood", "severity": "high",
                             "summary": f"{ps['syns']} SYNs to {dst}:{port} from {len(ps['clients'])} source(s)",
                             "subject": {"target": dst, "port": port},
                             "evidence": {"syns": ps["syns"], "sources": len(ps["clients"]),
                                          "sources_answered": done, "first_frame": ps["first_frame"]}})
    return findings, starts


# ------------------------------------------------------------------ beacons
def _quartiles(values: list[float]) -> tuple[float, float, float]:
    s = sorted(values)
    q = statistics.quantiles(s, n=4, method="inclusive") if len(s) > 1 else [s[0]] * 3
    return q[0], q[1], q[2]


def _bowley(values: list[float]) -> float:
    q1, q2, q3 = _quartiles(values)
    return 0.0 if q3 == q1 else (q3 + q1 - 2 * q2) / (q3 - q1)


def _mad(values: list[float]) -> float:
    med = statistics.median(values)
    return statistics.median(abs(v - med) for v in values)


def _regularity(values: list[float]) -> tuple[float, dict[str, float]]:
    med = statistics.median(values)
    mad = _mad(values)
    skew = _bowley(values)
    disp = 0.0 if med == 0 else min(1.0, mad / med)
    q1, _, q3 = _quartiles(values)
    # Skew means nothing when the spread is tiny (a 60 s beacon with 1 s of jitter): count it as symmetric.
    skew_term = 1.0 if med and (q3 - q1) / med < 0.05 else 1 - abs(skew)
    score = (skew_term + (1 - disp)) / 2
    return score, {"median": round(med, 3), "mad": round(mad, 3), "bowley_skew": round(skew, 3)}


def beacons(series: dict[tuple[str, str, str], list[tuple[float, int | None, int | None]]],
            span: float | None) -> list[dict[str, Any]]:
    """Beacon candidates: per (client, server, service) the event times, sizes and frames."""
    out = []
    for (client, server, service), events in series.items():
        events = sorted((e for e in events if e[0] is not None), key=lambda e: e[0])
        if len(events) < 2:
            continue
        times = [e[0] for e in events]
        intervals = [b - a for a, b in zip(times, times[1:])]
        row: dict[str, Any] = {"client": client, "server": server, "service": service, "count": len(events),
                               "first_frame": events[0][2], "last_frame": events[-1][2],
                               "first": iso(times[0]), "last": iso(times[-1])}
        if len(events) < BEACON_MIN:
            row["insufficient_samples"] = True
            row["interval_s"] = {"median": round(statistics.median(intervals), 3)}
            out.append(row)
            continue
        i_score, i_stats = _regularity(intervals)
        row["interval_s"] = i_stats
        sizes = [e[1] for e in events if e[1] is not None]
        weights = {"interval": 0.45, "size": 0.35, "coverage": 0.20}
        parts = {"interval": i_score}
        if len(sizes) >= BEACON_MIN // 2:
            s_score, s_stats = _regularity([float(s) for s in sizes])
            row["size_bytes"] = s_stats
            parts["size"] = s_score
        else:
            weights.pop("size")
        covered = times[-1] - times[0]
        parts["coverage"] = min(1.0, covered / span) if span else 0.0
        total_w = sum(weights.values())
        row["score"] = round(sum(parts[k] * w for k, w in weights.items()) / total_w, 3)
        row["score_parts"] = {k: round(v, 3) for k, v in parts.items()}
        out.append(row)
    out.sort(key=lambda r: (-(r.get("score") or 0), -r["count"]))
    return out


def beacon_findings(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for c in candidates:
        score = c.get("score")
        if score is None or score < 0.7:
            continue
        out.append({"kind": "beacon", "severity": "high" if score >= 0.85 else "medium",
                    "summary": f"{c['client']} contacts {c['server']} ({c['service']}) {c['count']} times every "
                               f"{c['interval_s']['median']} s (MAD {c['interval_s']['mad']} s), score {score}",
                    "subject": {"client": c["client"], "server": c["server"], "service": c["service"]},
                    "evidence": {k: c[k] for k in ("count", "interval_s", "size_bytes", "score", "score_parts",
                                                   "first_frame", "last_frame") if k in c}})
    return out


# ------------------------------------------------------------------ DNS tunnels
def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def zone_of(name: str) -> str:
    labels = [x for x in name.lower().rstrip(".").split(".") if x]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "net", "org", "ac", "gov", "edu"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def dns_zones(dns: list[dict[str, str]]) -> list[dict[str, Any]]:
    zones: dict[str, dict[str, Any]] = {}
    for r in dns:
        for name in r["dns.qry.name"].split(AGGREGATOR):
            name = name.strip().lower().rstrip(".")
            if not name or "." not in name:
                continue
            zone = zone_of(name)
            z = zones.setdefault(zone, {"zone": zone, "queries": 0, "_names": set(), "_left": [], "txt": 0,
                                        "_clients": set(), "first_frame": to_int(r["frame.number"])})
            z["queries"] += 1
            z["_clients"].add(_src(r))
            sub = name[: -len(zone)].rstrip(".")
            if sub:
                z["_names"].add(name)
                z["_left"].append(max(sub.split("."), key=len))
            if r["dns.qry.type"].split(AGGREGATOR)[0].strip() in ("16", "10"):  # TXT, NULL
                z["txt"] += 1
    out = []
    for z in zones.values():
        left = z.pop("_left")
        names = z.pop("_names")
        z["clients"] = len(z.pop("_clients"))
        z["distinct_names"] = len(names)
        if left:
            z["mean_label_length"] = round(sum(len(x) for x in left) / len(left), 1)
            z["mean_entropy"] = round(sum(_entropy(x) for x in left) / len(left), 2)
        out.append(z)
    out.sort(key=lambda z: (-z["distinct_names"], -z["queries"], z["zone"]))
    return out


def tunnel_findings(zones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for z in zones:
        if z["distinct_names"] < TUNNEL_NAMES:
            continue
        long_ = z.get("mean_label_length", 0) >= TUNNEL_LABEL
        random_ = z.get("mean_entropy", 0) >= TUNNEL_ENTROPY
        if not (long_ or random_):
            continue
        out.append({"kind": "dns_tunnel_hint", "severity": "high" if long_ and random_ else "medium",
                    "summary": f"{z['distinct_names']} distinct names under {z['zone']}: leftmost label "
                               f"{z.get('mean_label_length')} characters on average, entropy {z.get('mean_entropy')} "
                               f"bits per character" + (f", {z['txt']} TXT/NULL queries" if z["txt"] else ""),
                    "subject": {"zone": z["zone"]},
                    "evidence": {k: z[k] for k in ("queries", "distinct_names", "mean_label_length", "mean_entropy",
                                                   "txt", "clients", "first_frame") if k in z}})
    return out


# ------------------------------------------------------------------ TLS fingerprints
def tls_fingerprints(tls: list[dict[str, str]], raw: bool) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[int, str]]:
    """(clients by JA4 or JA3, servers by JA3S, stream -> SNI)."""
    clients: dict[str, dict[str, Any]] = {}
    servers: dict[str, dict[str, Any]] = {}
    sni_by_stream: dict[int, str] = {}
    for r in tls:
        types = r["tls.handshake.type"].split(AGGREGATOR)
        stream = to_int(r["tcp.stream"])
        if "1" in types:
            ja4, ja3 = r["tls.handshake.ja4"].split(AGGREGATOR)[0], r["tls.handshake.ja3"].split(AGGREGATOR)[0]
            key = ja4 or (f"ja3:{ja3}" if ja3 else "")
            sni = r["tls.handshake.extensions_server_name"].split(AGGREGATOR)[0]
            if stream is not None and sni:
                sni_by_stream[stream] = sni
            if not key:
                continue
            c = clients.setdefault(key, {"ja4": ja4 or None, "ja3": ja3 or None, "hellos": 0, "_hosts": set(),
                                         "_snis": set(), "first_frame": to_int(r["frame.number"])})
            c["hellos"] += 1
            c["_hosts"].add(_src(r))
            if sni:
                c["_snis"].add(sni)
            if raw and r.get("tls.handshake.ja4_r"):
                c["ja4_r"] = r["tls.handshake.ja4_r"].split(AGGREGATOR)[0]
        if "2" in types:
            ja3s = r["tls.handshake.ja3s"].split(AGGREGATOR)[0]
            if not ja3s:
                continue
            s = servers.setdefault(ja3s, {"ja3s": ja3s, "hellos": 0, "_hosts": set(), "first_frame": to_int(r["frame.number"])})
            s["hellos"] += 1
            s["_hosts"].add(_src(r))
    out_c = []
    all_hosts = {h for c in clients.values() for h in c["_hosts"]}
    all_hellos = sum(c["hellos"] for c in clients.values())
    for c in clients.values():
        hosts, snis = sorted(c.pop("_hosts")), sorted(c.pop("_snis"))
        c["hosts"] = len(hosts)
        c["host_list"] = hosts[:10]
        c["snis"] = snis[:10]
        if len(snis) > 10:
            c["snis_more"] = len(snis) - 10
        # Rare: one host only, among at least three hosts, and a small share of all ClientHellos.
        c["rare"] = len(hosts) == 1 and len(all_hosts) >= 3 and c["hellos"] <= max(2, 0.05 * all_hellos)
        out_c.append({k: v for k, v in c.items() if v is not None})
    out_c.sort(key=lambda c: (-c["hellos"], c.get("ja4") or c.get("ja3") or ""))
    out_s = []
    for s in servers.values():
        hosts = sorted(s.pop("_hosts"))
        s["servers"] = len(hosts)
        s["server_list"] = hosts[:10]
        out_s.append(s)
    out_s.sort(key=lambda s: (-s["hellos"], s["ja3s"]))
    return out_c, out_s, sni_by_stream


def rare_ja4_findings(clients: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rare = [c for c in clients if c.get("rare")]
    if not rare:
        return []
    return [{"kind": "rare_tls_client", "severity": "low",
             "summary": f"TLS client fingerprint {c.get('ja4') or c.get('ja3')} is used by one host only "
                        f"({c['host_list'][0]}), {c['hellos']} ClientHello(s)",
             "subject": {"client": c["host_list"][0], "ja4": c.get("ja4"), "ja3": c.get("ja3")},
             "evidence": {"hellos": c["hellos"], "snis": c["snis"], "first_frame": c.get("first_frame")}} for c in rare]


# ------------------------------------------------------------------ ARP
def arp_findings(arp: list[dict[str, str]]) -> list[dict[str, Any]]:
    macs: dict[str, dict[str, int]] = {}
    duplicates = 0
    first: dict[str, int] = {}
    for r in arp:
        ip, mac = r["arp.src.proto_ipv4"], r["arp.src.hw_mac"].lower()
        if r.get("arp.duplicate-address-detected"):
            duplicates += 1
        if not ip or ip == "0.0.0.0" or not mac:
            continue
        macs.setdefault(ip, {})
        macs[ip][mac] = macs[ip].get(mac, 0) + 1
        first.setdefault(ip, to_int(r["frame.number"]) or 0)
    out = []
    for ip, seen in sorted(macs.items()):
        if len(seen) >= 2:
            out.append({"kind": "arp_conflict", "severity": "high" if len(seen) > 2 or duplicates else "medium",
                        "summary": f"{ip} is claimed by {len(seen)} MAC addresses (ARP spoofing, or a failover "
                                   "pair / proxy ARP)",
                        "subject": {"ip": ip},
                        "evidence": {"macs": dict(sorted(seen.items())), "first_frame": first[ip],
                                     "duplicate_address_frames": duplicates}})
    return out


# ------------------------------------------------------------------ cleartext credentials
def credential_findings(creds: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Per protocol, client and server: how many credential messages were sent in clear.
    The values are never read into the result."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for r in creds:
        proto = None
        if r["ftp.request.command"]:
            proto = "FTP"
        elif r["http.authorization"]:
            scheme = r["http.authorization"].split(" ", 1)[0].lower()
            proto = "HTTP Basic" if scheme == "basic" else None
        elif r["pop.request.command"]:
            proto = "POP3"
        elif r["imap.request.command"]:
            proto = "IMAP"
        elif r["smtp.req.command"]:
            proto = "SMTP AUTH"
        if proto is None:
            continue
        g = groups.setdefault((proto, _src(r), _dst(r)), {"messages": 0, "first_frame": to_int(r["frame.number"])})
        g["messages"] += 1
    return [{"kind": "cleartext_credentials", "severity": "high",
             "summary": f"{proto} credentials sent in clear from {client} to {server} ({g['messages']} message(s))",
             "subject": {"protocol": proto, "client": client, "server": server},
             "evidence": {"messages": g["messages"], "first_frame": g["first_frame"], "values": "withheld"}}
            for (proto, client, server), g in sorted(groups.items())]


SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def order(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK.get(f["severity"], 3), f["kind"],
                                           f.get("evidence", {}).get("first_frame") or 0))

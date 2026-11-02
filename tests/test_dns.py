"""dns_transactions: queries paired with responses, on synthetic captures."""

from __future__ import annotations

from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw  # type: ignore

from . import pcapgen as g
from .conftest import requires_tshark

pytestmark = requires_tshark

CLIENT = "198.51.100.20"
RES_A, RES_B = "192.0.2.53", "192.0.2.54"


class Builder:
    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.t = 1_700_020_000.0
        self.ip_id = 1

    def at(self, dt: float) -> "Builder":
        self.t += dt
        return self

    def add(self, pkt) -> None:
        self.frames.append((self.t, bytes(Ether(src=g.MAC_A, dst=g.MAC_B) / pkt)))

    def query(self, server: str, qid: int, name: str, qtype: str = "A", sport: int = 40000, copies: int = 1) -> None:
        self.ip_id += 1
        pkt = IP(src=CLIENT, dst=server, id=self.ip_id) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
        for _ in range(copies):
            self.add(pkt)

    def answer(self, server: str, qid: int, name: str, qtype: str = "A", sport: int = 40000, rcode: int = 0,
               addr: str | None = "203.0.113.5", tc: int = 0) -> None:
        an = DNSRR(rrname=name, type="A", rdata=addr, ttl=60) if addr and rcode == 0 else None
        pkt = IP(src=server, dst=CLIENT) / UDP(sport=53, dport=sport) / DNS(
            id=qid, qr=1, rd=1, ra=1, rcode=rcode, tc=tc, qd=DNSQR(qname=name, qtype=qtype), an=an)
        self.add(pkt)

    def write(self, path: Path) -> Path:
        return g._frames_to_pcap(path, self.frames)


def _tcp_dns(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, msg) -> object:
    payload = bytes(msg)
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack) / Raw(
        len(payload).to_bytes(2, "big") + payload)


def scenario(path: Path) -> Path:
    b = Builder()
    b.query(RES_A, 0x1001, "www.example.com", sport=40001)
    b.at(0.010).answer(RES_A, 0x1001, "www.example.com", sport=40001)
    b.at(0.100).query(RES_A, 0x1002, "missing.example.com", sport=40002)
    b.at(0.020).answer(RES_A, 0x1002, "missing.example.com", sport=40002, rcode=3)
    b.at(0.100).query(RES_A, 0x1003, "broken.example.net", sport=40003)
    b.at(0.030).answer(RES_A, 0x1003, "broken.example.net", sport=40003, rcode=2)
    # Unanswered, resent unchanged once, then retried with a new id to the other resolver, which answers late.
    b.at(0.100).query(RES_A, 0x2001, "slow.example.org", sport=40004)
    b.at(1.000).query(RES_A, 0x2001, "slow.example.org", sport=40004)
    b.at(1.000).query(RES_B, 0x2002, "slow.example.org", sport=40005)
    b.at(1.500).answer(RES_B, 0x2002, "slow.example.org", sport=40005)
    # A truncated UDP answer, then the same question over TCP.
    b.at(0.100).query(RES_A, 0x3001, "big.example.com", qtype="TXT", sport=40006)
    b.at(0.010).answer(RES_A, 0x3001, "big.example.com", qtype="TXT", sport=40006, addr=None, tc=1)
    q = DNS(id=0x3002, rd=1, qd=DNSQR(qname="big.example.com", qtype="TXT"))
    a = DNS(id=0x3002, qr=1, rd=1, ra=1, qd=DNSQR(qname="big.example.com", qtype="TXT"))
    b.at(0.010).add(IP(src=CLIENT, dst=RES_A) / TCP(sport=40100, dport=53, flags="S", seq=100))
    b.at(0.005).add(IP(src=RES_A, dst=CLIENT) / TCP(sport=53, dport=40100, flags="SA", seq=900, ack=101))
    b.at(0.005).add(IP(src=CLIENT, dst=RES_A) / TCP(sport=40100, dport=53, flags="A", seq=101, ack=901))
    b.at(0.001).add(_tcp_dns(CLIENT, RES_A, 40100, 53, 101, 901, q))
    b.at(0.015).add(_tcp_dns(RES_A, CLIENT, 53, 40100, 901, 101 + 2 + len(bytes(q)), a))
    # The same query captured twice (two interfaces) and answered once.
    b.at(0.100).query(RES_A, 0x4001, "copy.example.com", sport=40007, copies=2)
    b.at(0.012).answer(RES_A, 0x4001, "copy.example.com", sport=40007)
    # A resolver that is not listening: ICMP port unreachable quoting the query.
    b.at(0.100).query("192.0.2.99", 0x5001, "www.example.com", sport=40008)
    quoted = bytes(IP(src=CLIENT, dst="192.0.2.99", id=b.ip_id) / UDP(sport=40008, dport=53)
                   / DNS(id=0x5001, rd=1, qd=DNSQR(qname="www.example.com")))
    b.at(0.001).add(IP(src="192.0.2.99", dst=CLIENT) / ICMP(type=3, code=3) / Raw(quoted))
    # Near the end of the capture: asked, never answered.
    b.at(5.000).query(RES_A, 0x6001, "late.example.com", sport=40009)
    return b.write(path)


def _by_name(rows, name, **match):
    return [r for r in rows if r["name"] == name and all(r.get(k) == v for k, v in match.items())]


def test_pairing_rcodes_and_rtt(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.dns_transactions(str(scenario(tmp_path / "dns.pcap")))
    rows = out["transactions"]
    ok = _by_name(rows, "www.example.com", server=f"{RES_A}:53")[0]
    assert ok["rcode_name"] == "NOERROR" and ok["addresses"] == ["203.0.113.5"] and ok["rtt_ms"] == 10.0
    assert ok["type"] == "A" and ok["transport"] == "udp" and "unanswered" not in ok
    assert _by_name(rows, "missing.example.com")[0]["rcode_name"] == "NXDOMAIN"
    assert _by_name(rows, "broken.example.net")[0]["rcode_name"] == "SERVFAIL"
    assert out["summary"]["rcodes"] == {"NOERROR": 5, "NXDOMAIN": 1, "SERVFAIL": 1}  # the TC answer is NOERROR too
    assert any("NXDOMAIN" in i for i in out["issues"]) and any("SERVFAIL" in i for i in out["issues"])


def test_unanswered_retransmission_and_retry(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.dns_transactions(str(scenario(tmp_path / "dns.pcap")))
    rows = out["transactions"]
    first = _by_name(rows, "slow.example.org", server=f"{RES_A}:53")[0]
    assert first["unanswered"] is True and first["retransmissions"] == 1
    retry = _by_name(rows, "slow.example.org", server=f"{RES_B}:53")[0]
    assert retry["retry_of"] == first["frame"] and retry["rtt_ms"] == 1500.0
    assert out["summary"]["retransmissions"] == 1 and out["summary"]["retries"] == 1
    slow = next(n for n in out["names"] if n["name"] == "slow.example.org")
    assert slow == {"name": "slow.example.org", "queries": 2, "unanswered": 1, "rcodes": {"NOERROR": 1}, "retries": 1,
                    "slow": 1, "types": ["A"], "servers": [RES_A, RES_B]}
    late = _by_name(rows, "late.example.com")[0]
    assert late["unanswered"] is True and late["near_capture_end"] is True
    # Problem transactions come first.
    assert all(r.get("unanswered") or r.get("rcode") or r.get("retry_of") or r.get("truncated_tc")
               for r in rows[:6])


def test_truncated_answer_and_tcp_fallback(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.dns_transactions(str(scenario(tmp_path / "dns.pcap")))
    udp = _by_name(out["transactions"], "big.example.com", transport="udp")[0]
    tcp = _by_name(out["transactions"], "big.example.com", transport="tcp")[0]
    assert udp["truncated_tc"] is True and udp["tcp_fallback_frame"] == tcp["frame"]
    assert tcp["fallback_from_udp"] is True and tcp["rcode_name"] == "NOERROR" and tcp["type"] == "TXT"
    assert out["summary"]["tcp_fallbacks"] == 1 and out["summary"]["tcp_queries"] == 1
    assert any("followed by the same query over TCP" in i for i in out["issues"])


def test_copies_icmp_and_servers(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    out = srv.dns_transactions(str(scenario(tmp_path / "dns.pcap")))
    copy = _by_name(out["transactions"], "copy.example.com")[0]
    assert "retransmissions" not in copy and out["summary"]["duplicate_copies"] == 1
    assert out["summary"]["icmp_errors"] == 1
    dead = next(s for s in out["servers"] if s["server"] == "192.0.2.99")
    assert dead["unanswered"] == 1 and dead["icmp_errors"] == 1
    a = next(s for s in out["servers"] if s["server"] == RES_A)
    assert a["rtt_ms"]["min"] == 10.0 and a["rtt_ms"]["max"] == 30.0 and a["unanswered"] == 2
    assert any("ICMP errors came back for queries to 192.0.2.99" in i for i in out["issues"])
    assert out["summary"]["queries"] == out["total_found"] == 10


def test_name_filter_matches_subdomains_case_insensitively(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(scenario(tmp_path / "dns.pcap"))
    out = srv.dns_transactions(path, name="EXAMPLE.com")
    assert {r["name"] for r in out["transactions"]} == {
        "www.example.com", "missing.example.com", "big.example.com", "copy.example.com", "late.example.com"}
    only = srv.dns_transactions(path, name="slow.example.org")
    assert only["summary"]["queries"] == 2
    assert srv.dns_transactions(path, name="bad name\"")["error"]["type"] == "invalid_argument"
    narrowed = srv.dns_transactions(path, filter="udp.srcport == 40001 || udp.dstport == 40001")
    assert [r["name"] for r in narrowed["transactions"]] == ["www.example.com"]


def test_dns_inside_gtpu_tunnel_reads_inner_packet(configure, tmp_path: Path):
    ue, enb, sgw = "100.64.0.20", "192.0.2.70", "192.0.2.71"
    q = IP(src=ue, dst=RES_A, id=77) / UDP(sport=41000, dport=53) / DNS(id=0x7001, rd=1, qd=DNSQR(qname="ue.example.com"))
    a = IP(src=RES_A, dst=ue, id=78) / UDP(sport=53, dport=41000) / DNS(
        id=0x7001, qr=1, ra=1, qd=DNSQR(qname="ue.example.com"), an=DNSRR(rrname="ue.example.com", rdata="203.0.113.7"))
    frames = []
    t = 1_700_030_000.0
    for src, dst, teid, inner in ((enb, sgw, 0x1001, q), (sgw, "192.0.2.72", 0x2002, q), (sgw, enb, 0x3003, a)):
        frames.append((t, bytes(Ether(src=g.MAC_A, dst=g.MAC_B) / IP(src=src, dst=dst) / UDP(sport=2152, dport=2152)
                                / Raw(g._gtpu(teid, bytes(inner))))))
        t += 0.004
    path = g._frames_to_pcap(tmp_path / "gtpdns.pcap", frames)
    srv = configure(allow=[str(tmp_path)])
    out = srv.dns_transactions(str(path))
    assert out["summary"]["queries"] == 1 and out["summary"]["duplicate_copies"] == 1
    row = out["transactions"][0]
    assert row["client"] == f"{ue}:41000" and row["server"] == f"{RES_A}:53" and row["rtt_ms"] == 8.0

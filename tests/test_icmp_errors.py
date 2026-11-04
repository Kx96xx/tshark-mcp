"""icmp_errors: ICMP and ICMPv6 errors per sender, kind and quoted flow, echo pairing, issues."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6, ICMPv6PacketTooBig, Raw  # type: ignore

from tshark_mcp import icmperr, models

from .conftest import TSHARK, requires_tshark
from .test_capture_quality import Cap

pytestmark = requires_tshark

HOST, HOST6 = "192.0.2.10", "2001:db8::10"
WEB, UDPSRV, SSH, TRACED, PINGED = "198.51.100.50", "198.51.100.60", "198.51.100.40", "198.51.100.70", "198.51.100.80"
WEB6 = "2001:db8:1::50"
R1, R2, R3, FW = "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.254"
R6 = "2001:db8:ffff::1"


def _error(sender: str, ttl: int, typ: int, code: int, original, ip_id: int, mtu: int = 0):
    icmp = ICMP(type=typ, code=code, nexthopmtu=mtu) if mtu else ICMP(type=typ, code=code)
    return Ether() / IP(src=sender, dst=original[IP].src, ttl=ttl, id=ip_id) / icmp / Raw(bytes(original[IP])[:28])


def scenario() -> Cap:
    cap = Cap(step=0.01)
    rid = iter(range(500, 10_000))
    # Fragmentation needed, MTU 1400, for two flows to WEB; the originals are in the capture.
    for i, sport in enumerate((40001, 40002)):
        orig = Ether() / IP(src=HOST, dst=WEB, id=0x100 + i, flags="DF") / TCP(sport=sport, dport=443, flags="PA") / Raw(b"x" * 1400)
        cap.add(orig)
        cap.add(_error(R1, 254, 3, 4, orig, next(rid), mtu=1400))
    # A copy of the last error captured on a second interface: counts once.
    cap.add(cap_last := Ether(cap.frames[-1][1]))  # noqa: F841
    # Port unreachable from the endpoint itself.
    probe = Ether() / IP(src=HOST, dst=UDPSRV, id=0x200) / UDP(sport=50000, dport=9999) / Raw(b"hi")
    cap.add(probe)
    cap.add(_error(UDPSRV, 63, 3, 3, probe, next(rid)))
    # Administratively prohibited from a firewall, quoted SYN not captured.
    syn = Ether() / IP(src=HOST, dst=SSH, id=0x300) / TCP(sport=40100, dport=22, flags="S")
    cap.add(_error(FW, 250, 3, 13, syn, next(rid)))
    # A routing loop: R1 and R2 alternate TTL exceeded for retries of one flow.
    for n in range(6):
        orig = Ether() / IP(src=HOST, dst=WEB, id=0x400 + n, ttl=1) / TCP(sport=40200, dport=80, flags="S")
        cap.add(_error(R1 if n % 2 == 0 else R2, 254 - n % 2, 11, 0, orig, next(rid)))
    # A traceroute: three probes per hop, three hops.
    port = 33434
    for hop, router in enumerate((R1, R2, R3), start=1):
        for _ in range(3):
            orig = Ether() / IP(src=HOST, dst=TRACED, id=0x500 + port, ttl=hop) / UDP(sport=45000, dport=port)
            cap.add(_error(router, 255 - hop, 11, 0, orig, next(rid)))
            port += 1
    # Echo: 5 requests, 4 replies.
    for seq in range(5):
        cap.add(Ether() / IP(src=HOST, dst=PINGED, id=0x600 + seq) / ICMP(type=8, id=7, seq=seq) / Raw(b"ping"))
        if seq != 3:
            cap.add(Ether() / IP(src=PINGED, dst=HOST, id=0x700 + seq) / ICMP(type=0, id=7, seq=seq) / Raw(b"ping"))
    # ICMPv6 packet too big, MTU 1280.
    big = IPv6(src=HOST6, dst=WEB6) / TCP(sport=40300, dport=443, flags="PA") / Raw(b"y" * 1400)
    cap.add(Ether() / IPv6(src=R6, dst=HOST6, hlim=60) / ICMPv6PacketTooBig(mtu=1280) / Raw(bytes(big)[:1232]))
    return cap


def run(configure, tmp_path: Path, **kw):
    srv = configure(allow=[str(tmp_path)])
    out = srv.icmp_errors(str(scenario().write(tmp_path / "icmp.pcap")), **kw)
    assert "error" not in out, out
    TypeAdapter(models.IcmpErrorsResult).validate_python(out)
    return out


def rows_of(out, kind):
    return [r for r in out["errors"] if r["kind"] == kind]


def test_kinds_rows_and_originals(configure, tmp_path):
    out = run(configure, tmp_path)
    frag = rows_of(out, "frag_needed")
    assert len(frag) == 1 and frag[0]["count"] == 2 and frag[0]["mtu"] == 1400 and frag[0]["sender"] == R1
    assert frag[0]["quoted"] == {"src": HOST, "dst": WEB, "proto": "tcp", "ports": ["443"]}
    assert frag[0]["quoted_flow_seen"] == 1  # the original packet is frame 1
    port = rows_of(out, "port_unreachable")[0]
    assert port["sender"] == UDPSRV and port["quoted"]["ports"] == ["9999"] and isinstance(port["quoted_flow_seen"], int)
    prohibited = rows_of(out, "admin_prohibited")[0]
    assert prohibited["sender"] == FW and prohibited["quoted_flow_seen"] is False
    v6 = rows_of(out, "packet_too_big")[0]
    assert v6["sender"] == R6 and v6["mtu"] == 1280 and v6["quoted"]["dst"] == WEB6
    s = out["summary"]
    assert s["copies_dropped"] == 1 and s["by_kind"]["ttl_exceeded"] == 15


def test_error_count_matches_raw_tshark(configure, tmp_path):
    out = run(configure, tmp_path)
    raw = subprocess.run([TSHARK, "-n", "-r", str(tmp_path / "icmp.pcap"), "-Y", icmperr.ERROR_FILTER, "-T", "fields",
                          "-e", "frame.number"], capture_output=True, text=True, check=True).stdout.split()
    assert out["summary"]["errors"] == len(raw) - out["summary"]["copies_dropped"]
    assert sum(r["count"] for r in out["errors"]) == out["summary"]["errors"]


def test_senders_echo_and_issues(configure, tmp_path):
    out = run(configure, tmp_path)
    senders = {s["sender"]: s for s in out["by_sender"]}
    assert senders[UDPSRV]["role"] == "endpoint" and senders[R1]["role"] == "on_path"
    assert senders[R1]["hops_away"] == 1 and senders[FW]["hops_away"] == 5
    echo = out["echo"][0]
    assert (echo["source"], echo["destination"], echo["requests"], echo["replies"], echo["lost"]) == (HOST, PINGED, 5, 4, 1)
    assert "rtt_ms" in echo and echo["lost_frames"]
    text = " | ".join(out["issues"])
    assert f"TTL exceeded from {R1} and {R2} alternating" in text and "routing loop" in text
    assert "traceroute" in text and "next-hop MTU 1400" in text and "a firewall or ACL" in text
    assert "1 of 5 echo requests" in text
    # The traceroute is not called a loop.
    assert not any("loop" in i and TRACED in i for i in out["issues"])


def test_selectors(configure, tmp_path):
    srv = configure(allow=[str(tmp_path)])
    path = str(scenario().write(tmp_path / "icmp.pcap"))
    out = srv.icmp_errors(path, sender=FW)
    assert [r["kind"] for r in out["errors"]] == ["admin_prohibited"] and [s["sender"] for s in out["by_sender"]] == [FW]
    out = srv.icmp_errors(path, about=f"{UDPSRV}:9999")
    assert [r["kind"] for r in out["errors"]] == ["port_unreachable"]
    out = srv.icmp_errors(path, about=f"{UDPSRV}:1")
    assert out["errors"] == []
    out = srv.icmp_errors(path, kind="ttl_exceeded")
    assert {r["kind"] for r in out["errors"]} == {"ttl_exceeded"} and out["total_matched"] == 5
    out = srv.icmp_errors(path, about=f"[{WEB6}]:443")
    assert [r["kind"] for r in out["errors"]] == ["packet_too_big"]
    out = srv.icmp_errors(path, limit=2)
    assert out["returned"] == 2 and out["next_offset"] == 2


@pytest.mark.parametrize("kw,needle", [
    ({"sender": "nope"}, "sender"), ({"about": "1.2.3.4:99999"}, "about"), ({"about": "x;y"}, "about"),
    ({"kind": "bad"}, "kind"),
])
def test_bad_arguments(configure, tmp_path, kw, needle):
    srv = configure(allow=[str(tmp_path)])
    out = srv.icmp_errors(str(scenario().write(tmp_path / "icmp.pcap")), **kw)
    assert out["error"]["type"] == "invalid_argument" and needle in out["error"]["message"]

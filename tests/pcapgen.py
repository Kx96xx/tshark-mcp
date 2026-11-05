"""Synthetic capture generator for the test-suite.

Everything here is built from the protocol specifications with ``struct`` so the
tests do not depend on scapy contrib dissectors. scapy only supplies Ethernet,
IP, UDP and SCTP framing plus the pcap writer. All identifiers (IMSIs, MSISDNs,
hostnames, addresses) are documentation ranges or obviously fake test values.

Public entry points write a pcap file and return the path. They are used by the
test-suite and by ``docs/EXAMPLE.md``.
"""

from __future__ import annotations

import struct
from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, wrpcap  # type: ignore
from scapy.layers.sctp import (  # type: ignore
    SCTP,
    SCTPChunkCookieAck,
    SCTPChunkCookieEcho,
    SCTPChunkData,
    SCTPChunkHeartbeatAck,
    SCTPChunkHeartbeatReq,
    SCTPChunkInit,
    SCTPChunkInitAck,
    SCTPChunkParamHeartbeatInfo,
    SCTPChunkParamStateCookie,
)

# Test identities (TS 23.003 test PLMN 001/01, E.164 documentation-style numbers).
IMSI = "001010123456789"
IMSI_OTHER = "001010987654321"
MSISDN = "15550100123"
MSISDN_OTHER = "15550100999"
APN = "internet.test.apn"

MME_IP = "192.0.2.10"
HSS_IP = "192.0.2.20"
SGW_IP = "192.0.2.30"
PGW_IP = "192.0.2.40"
UE_IP = "100.64.0.7"
SERVER_IP = "203.0.113.80"
PCSCF_IP = "192.0.2.50"
UE_SIP_IP = "198.51.100.9"
STP_A = "192.0.2.60"
STP_B = "192.0.2.61"

MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


# --------------------------------------------------------------------------- helpers
def _frames_to_pcap(path: Path, frames: list[tuple[float, bytes]]) -> Path:
    pkts = []
    for ts, raw in frames:
        p = Ether(raw)
        p.time = ts
        pkts.append(p)
    wrpcap(str(path), pkts)
    return path


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def frames_to_pcapng(path: Path, frames: list[tuple[float, bytes, int]], interfaces: list[str]) -> Path:
    """A pcapng file with one Ethernet interface per name in ``interfaces`` (nanosecond
    timestamps); each frame is ``(time, raw Ethernet bytes, interface index)``."""
    out = [_pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))]
    for name in interfaces:
        raw = name.encode()
        opts = struct.pack("<HH", 2, len(raw)) + raw + b"\0" * (-len(raw) % 4)
        opts += struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)  # if_tsresol = 10^-9
        out.append(_pcapng_block(1, struct.pack("<HHI", 1, 0, 0xFFFF) + opts))
    for ts, raw, iface in sorted(frames, key=lambda f: f[0]):
        ns = round(ts * 1e9)
        out.append(_pcapng_block(6, struct.pack("<IIIII", iface, ns >> 32, ns & 0xFFFFFFFF, len(raw), len(raw)) + raw))
    path.write_bytes(b"".join(out))
    return path


def _pcapng_opt(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def _pcapng_str(code: int, text: str) -> bytes:
    return _pcapng_opt(code, text.encode())


def write_pcapng_metadata(path: Path, frames: list[tuple[float, bytes, int, str | None]],
                          interfaces: list[dict], shb: dict | None = None, isbs: list[dict] | None = None,
                          sections: int = 1) -> Path:
    """A pcapng file with writer options in the section header, interface options (name,
    description, snaplen, if_tsresol, capture filter), packets with optional comments and
    Interface Statistics Blocks. ``frames`` are ``(time, raw Ethernet bytes, interface, comment)``;
    an interface dict has ``name``, ``description``, ``snaplen``, ``filter`` and ``tsresol``
    (the if_tsresol byte, default 6); an ISB dict has ``iface``, ``time`` and the counters
    ``received``, ``if_drop``, ``os_drop``, ``accepted``, ``delivered``. ``sections`` repeats the
    whole section (header, interfaces, packets, statistics) that many times."""
    shb = shb or {}
    section = []
    opts = b""
    for code, key in ((1, "comment"), (2, "hardware"), (3, "os"), (4, "application")):
        if shb.get(key):
            opts += _pcapng_str(code, shb[key])
    if opts:
        opts += struct.pack("<HH", 0, 0)
    section.append(_pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + opts))
    for spec in interfaces:
        opts = b""
        if spec.get("name"):
            opts += _pcapng_str(2, spec["name"])
        if spec.get("description"):
            opts += _pcapng_str(3, spec["description"])
        resol = spec.get("tsresol", 6)
        opts += _pcapng_opt(9, bytes([resol]))
        if spec.get("filter"):
            opts += _pcapng_opt(11, b"\0" + spec["filter"].encode())
        opts += struct.pack("<HH", 0, 0)
        section.append(_pcapng_block(1, struct.pack("<HHI", 1, 0, spec.get("snaplen", 65535)) + opts))
    for ts, raw, iface, comment in sorted(frames, key=lambda f: f[0]):
        resol = interfaces[iface].get("tsresol", 6)
        units = round(ts * 10 ** resol)
        snap = interfaces[iface].get("snaplen", 65535)
        data = raw[:snap]
        opts = (_pcapng_str(1, comment) + struct.pack("<HH", 0, 0)) if comment else b""
        body = struct.pack("<IIIII", iface, units >> 32, units & 0xFFFFFFFF, len(data), len(raw))
        body += data + b"\0" * (-len(data) % 4) + opts
        section.append(_pcapng_block(6, body))
    for isb in isbs or []:
        resol = interfaces[isb["iface"]].get("tsresol", 6)
        units = round(isb["time"] * 10 ** resol)
        opts = b""
        for code, key in ((4, "received"), (5, "if_drop"), (6, "accepted"), (7, "os_drop"), (8, "delivered")):
            if key in isb:
                opts += _pcapng_opt(code, struct.pack("<Q", isb[key]))
        opts += struct.pack("<HH", 0, 0)
        section.append(_pcapng_block(5, struct.pack("<III", isb["iface"], units >> 32, units & 0xFFFFFFFF) + opts))
    path.write_bytes(b"".join(section) * sections)
    return path


def _tbcd(digits: str) -> bytes:
    if len(digits) % 2:
        digits += "F"
    out = bytearray()
    for i in range(0, len(digits), 2):
        lo, hi = digits[i], digits[i + 1]
        out.append((int(hi, 16) << 4) | int(lo, 16))
    return bytes(out)


def _ipv4(addr: str) -> bytes:
    return bytes(int(x) for x in addr.split("."))


# --------------------------------------------------------------------------- Diameter
def _avp(code: int, data: bytes, mandatory: bool = True, vendor: int | None = None) -> bytes:
    flags = 0x40 if mandatory else 0
    hdr_len = 8
    if vendor is not None:
        flags |= 0x80
        hdr_len = 12
    length = hdr_len + len(data)
    hdr = struct.pack("!I", code) + bytes([flags]) + struct.pack("!I", length)[1:]
    if vendor is not None:
        hdr += struct.pack("!I", vendor)
    pad = (-len(data)) % 4
    return hdr + data + b"\x00" * pad


def _diameter(cmd: int, app: int, hbh: int, e2e: int, request: bool, avps: list[bytes]) -> bytes:
    body = b"".join(avps)
    flags = 0x80 if request else 0x00
    if request:
        flags |= 0x40  # proxiable
    length = 20 + len(body)
    hdr = bytes([1]) + struct.pack("!I", length)[1:] + bytes([flags]) + struct.pack("!I", cmd)[1:]
    hdr += struct.pack("!III", app, hbh, e2e)
    return hdr + body


S6A = 16777251
VENDOR_3GPP = 10415


def _diam_common(session: str, origin: str, realm: str, dest_realm: str, dest_host: str | None = None) -> list[bytes]:
    avps = [
        _avp(263, session.encode()),
        _avp(264, origin.encode()),
        _avp(296, realm.encode()),
        _avp(283, dest_realm.encode()),
    ]
    if dest_host:
        avps.append(_avp(293, dest_host.encode()))
    avps.append(_avp(258, struct.pack("!I", S6A)))
    avps.append(_avp(277, struct.pack("!I", 1)))  # Auth-Session-State NO_STATE_MAINTAINED
    return avps


def _sctp_data(src: str, dst: str, sport: int, dport: int, tag: int, tsn: int, ppid: int, payload: bytes) -> bytes:
    pkt = (
        Ether(src=MAC_A, dst=MAC_B)
        / IP(src=src, dst=dst)
        / SCTP(sport=sport, dport=dport, tag=tag)
        / SCTPChunkData(beginning=1, ending=1, tsn=tsn, stream_id=0, stream_seq=tsn & 0xFFFF, proto_id=ppid, data=payload)
    )
    return bytes(pkt)


def write_diameter_pcap(path: Path) -> Path:
    """ULR/ULA (success), AIR/AIA with Experimental-Result 5420 for a second IMSI,
    an unanswered AIR, and a DWR/DWA keepalive."""
    mme = "mme01.epc.mnc001.mcc001.3gppnetwork.org"
    hss = "hss01.epc.mnc001.mcc001.3gppnetwork.org"
    realm = "epc.mnc001.mcc001.3gppnetwork.org"
    t0 = 1_700_000_000.0
    frames: list[tuple[float, bytes]] = []
    tsn = 100

    def send(ts: float, msg: bytes, from_mme: bool) -> None:
        nonlocal tsn
        if from_mme:
            frames.append((ts, _sctp_data(MME_IP, HSS_IP, 3868, 3868, 0x1111, tsn, 46, msg)))
        else:
            frames.append((ts, _sctp_data(HSS_IP, MME_IP, 3868, 3868, 0x2222, tsn, 46, msg)))
        tsn += 1

    # ULR / ULA
    sid = f"{mme};1700000000;1"
    ulr = _diameter(316, S6A, 0x1001, 0xA001, True, _diam_common(sid, mme, realm, realm) + [
        _avp(1, IMSI.encode()),
        _avp(1032, struct.pack("!I", 1004), vendor=VENDOR_3GPP),  # RAT-Type EUTRAN
        _avp(1405, struct.pack("!I", 0x22), vendor=VENDOR_3GPP),  # ULR-Flags
        _avp(1407, bytes([0x00, 0xF1, 0x10]), vendor=VENDOR_3GPP),  # Visited-PLMN-Id 001/01
    ])
    ula = _diameter(316, S6A, 0x1001, 0xA001, False, [
        _avp(263, sid.encode()),
        _avp(268, struct.pack("!I", 2001)),
        _avp(264, hss.encode()),
        _avp(296, realm.encode()),
        _avp(258, struct.pack("!I", S6A)),
        _avp(1406, struct.pack("!I", 1), vendor=VENDOR_3GPP),  # ULA-Flags
    ])
    send(t0 + 0.000, ulr, True)
    send(t0 + 0.048, ula, False)

    # AIR / AIA for the other IMSI: unknown subscriber (Experimental-Result 5001)
    sid2 = f"{mme};1700000000;2"
    air = _diameter(318, S6A, 0x1002, 0xA002, True, _diam_common(sid2, mme, realm, realm) + [
        _avp(1, IMSI_OTHER.encode()),
        _avp(1407, bytes([0x00, 0xF1, 0x10]), vendor=VENDOR_3GPP),
    ])
    aia = _diameter(318, S6A, 0x1002, 0xA002, False, [
        _avp(263, sid2.encode()),
        _avp(297, _avp(266, struct.pack("!I", VENDOR_3GPP)) + _avp(298, struct.pack("!I", 5001))),
        _avp(264, hss.encode()),
        _avp(296, realm.encode()),
        _avp(258, struct.pack("!I", S6A)),
    ])
    send(t0 + 1.000, air, True)
    send(t0 + 1.031, aia, False)

    # Unanswered AIR for the primary IMSI
    sid3 = f"{mme};1700000000;3"
    air2 = _diameter(318, S6A, 0x1003, 0xA003, True, _diam_common(sid3, mme, realm, realm) + [
        _avp(1, IMSI.encode()),
        _avp(1407, bytes([0x00, 0xF1, 0x10]), vendor=VENDOR_3GPP),
    ])
    send(t0 + 2.000, air2, True)

    # DWR / DWA (base protocol, application 0)
    dwr = _diameter(280, 0, 0x1004, 0xA004, True, [_avp(264, hss.encode()), _avp(296, realm.encode())])
    dwa = _diameter(280, 0, 0x1004, 0xA004, False, [
        _avp(268, struct.pack("!I", 2001)), _avp(264, mme.encode()), _avp(296, realm.encode()),
    ])
    send(t0 + 3.000, dwr, False)
    send(t0 + 3.004, dwa, True)
    return _frames_to_pcap(path, frames)


# --------------------------------------------------------------------------- GTPv2-C
def _ie(ie_type: int, data: bytes, instance: int = 0) -> bytes:
    return bytes([ie_type]) + struct.pack("!H", len(data)) + bytes([instance & 0x0F]) + data


def _gtpv2(msg_type: int, teid: int | None, seq: int, ies: list[bytes]) -> bytes:
    body = b"".join(ies)
    if teid is None:
        flags = 0x40
        rest = struct.pack("!I", seq << 8)
    else:
        flags = 0x48
        rest = struct.pack("!I", teid) + struct.pack("!I", seq << 8)
    length = len(rest) + len(body)
    return bytes([flags, msg_type]) + struct.pack("!H", length) + rest + body


def _fteid(iface: int, teid: int, ip: str) -> bytes:
    return bytes([0x80 | (iface & 0x3F)]) + struct.pack("!I", teid) + _ipv4(ip)


def _apn_ie(apn: str) -> bytes:
    out = b""
    for label in apn.split("."):
        out += bytes([len(label)]) + label.encode()
    return _ie(71, out)


def _udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    return bytes(Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload))


def write_gtpv2_pcap(path: Path) -> Path:
    """Echo Request/Response, Create Session Request/Response (accepted, with PAA),
    a rejected Create Session for a second IMSI (cause 78), and an unanswered
    Delete Session Request."""
    t0 = 1_700_000_100.0
    frames: list[tuple[float, bytes]] = []

    def c(ts: float, msg: bytes, from_sgw: bool = True) -> None:
        if from_sgw:
            frames.append((ts, _udp_frame(SGW_IP, PGW_IP, 2123, 2123, msg)))
        else:
            frames.append((ts, _udp_frame(PGW_IP, SGW_IP, 2123, 2123, msg)))

    # Echo
    c(t0 + 0.0, _gtpv2(1, None, 1, [_ie(3, bytes([7]))]))
    c(t0 + 0.002, _gtpv2(2, None, 1, [_ie(3, bytes([9]))]), from_sgw=False)

    # Create Session (accepted)
    csr = _gtpv2(32, 0, 10, [
        _ie(1, _tbcd(IMSI)),
        _ie(76, _tbcd(MSISDN)),
        _ie(82, bytes([6])),  # RAT type EUTRAN
        _ie(87, _fteid(6, 0x0000A001, SGW_IP)),  # S5/S8 SGW GTP-C
        _apn_ie(APN),
        _ie(99, bytes([1])),  # PDN type IPv4
        _ie(79, bytes([1, 0, 0, 0, 0])),  # PAA IPv4 0.0.0.0 (request)
        _ie(93, _ie(73, bytes([5])) + _ie(87, _fteid(4, 0x0000B001, SGW_IP), instance=2)),
    ])
    csresp = _gtpv2(33, 0x0000A001, 10, [
        _ie(2, bytes([16, 0])),  # Cause: Request accepted
        _ie(87, _fteid(7, 0x0000C001, PGW_IP), instance=1),  # S5/S8 PGW GTP-C
        _ie(79, bytes([1]) + _ipv4(UE_IP)),
        _ie(93, _ie(73, bytes([5])) + _ie(2, bytes([16, 0])) + _ie(87, _fteid(5, 0x0000D001, PGW_IP), instance=2)),
    ])
    c(t0 + 1.000, csr)
    c(t0 + 1.120, csresp, from_sgw=False)

    # Create Session for another IMSI: rejected, missing or unknown APN (78)
    csr2 = _gtpv2(32, 0, 11, [
        _ie(1, _tbcd(IMSI_OTHER)),
        _ie(76, _tbcd(MSISDN_OTHER)),
        _ie(82, bytes([6])),
        _ie(87, _fteid(6, 0x0000A002, SGW_IP)),
        _apn_ie("bogus.apn"),
        _ie(99, bytes([1])),
        _ie(93, _ie(73, bytes([5])) + _ie(87, _fteid(4, 0x0000B002, SGW_IP), instance=2)),
    ])
    csresp2 = _gtpv2(33, 0x0000A002, 11, [_ie(2, bytes([78, 0]))])
    c(t0 + 2.000, csr2)
    c(t0 + 2.030, csresp2, from_sgw=False)

    # Unanswered Delete Session Request for the first session
    dsr = _gtpv2(36, 0x0000C001, 12, [_ie(73, bytes([5]))])
    c(t0 + 3.000, dsr)
    return _frames_to_pcap(path, frames)


# --------------------------------------------------------------------------- GTP-U
def _gtpu(teid: int, inner: bytes) -> bytes:
    return bytes([0x30, 0xFF]) + struct.pack("!H", len(inner)) + struct.pack("!I", teid) + inner


def write_gtpu_pcap(path: Path) -> Path:
    """Two bearers: uplink TEID 0xD001 (UE to server) and downlink TEID 0xB001."""
    t0 = 1_700_000_200.0
    frames: list[tuple[float, bytes]] = []
    for i in range(3):
        inner_up = bytes(IP(src=UE_IP, dst=SERVER_IP) / UDP(sport=40000, dport=9000) / Raw(b"q" * 30))
        frames.append((t0 + i, _udp_frame(SGW_IP, PGW_IP, 2152, 2152, _gtpu(0x0000D001, inner_up))))
        inner_down = bytes(IP(src=SERVER_IP, dst=UE_IP) / UDP(sport=9000, dport=40000) / Raw(b"r" * 120))
        frames.append((t0 + i + 0.05, _udp_frame(PGW_IP, SGW_IP, 2152, 2152, _gtpu(0x0000B001, inner_down))))
    return _frames_to_pcap(path, frames)


# --------------------------------------------------------------------------- SIP
def _sip(lines: list[str], body: str = "") -> bytes:
    text = "\r\n".join(lines) + f"\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    return text.encode()


def write_sip_pcap(path: Path) -> Path:
    """INVITE / 100 / 180 / 200 / ACK / BYE / 200 for one call, plus a
    REGISTER that gets 401 and is never retried."""
    t0 = 1_700_000_300.0
    frames: list[tuple[float, bytes]] = []
    call_id = "a1b2c3d4@ue.example"
    frm = f'<sip:+{MSISDN}@ims.mnc001.mcc001.3gppnetwork.org>;tag=ue1'
    to = '<sip:+15550100555@ims.mnc001.mcc001.3gppnetwork.org>'
    via = "Via: SIP/2.0/UDP 198.51.100.9:5060;branch=z9hG4bK776"
    pai = f"P-Asserted-Identity: <tel:+{MSISDN}>"
    sdp = "v=0\r\no=- 1 1 IN IP4 198.51.100.9\r\ns=-\r\nc=IN IP4 198.51.100.9\r\nt=0 0\r\nm=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR/8000\r\n"

    def ue(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(UE_SIP_IP, PCSCF_IP, 5060, 5060, msg)))

    def net(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(PCSCF_IP, UE_SIP_IP, 5060, 5060, msg)))

    invite = _sip([
        "INVITE sip:+15550100555@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0", via,
        f"From: {frm}", f"To: {to}", f"Call-ID: {call_id}", "CSeq: 1 INVITE", pai,
        "Contact: <sip:198.51.100.9:5060>", "Content-Type: application/sdp",
    ], sdp)
    ue(t0, invite)
    for dt, code, reason in ((0.020, 100, "Trying"), (0.900, 180, "Ringing"), (3.500, 200, "OK")):
        resp = _sip([
            f"SIP/2.0 {code} {reason}", via, f"From: {frm}", f"To: {to};tag=net1",
            f"Call-ID: {call_id}", "CSeq: 1 INVITE",
        ], sdp if code == 200 else "")
        net(t0 + dt, resp)
    ue(t0 + 3.520, _sip([
        "ACK sip:+15550100555@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0", via, f"From: {frm}",
        f"To: {to};tag=net1", f"Call-ID: {call_id}", "CSeq: 1 ACK",
    ]))
    ue(t0 + 10.0, _sip([
        "BYE sip:+15550100555@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0", via, f"From: {frm}",
        f"To: {to};tag=net1", f"Call-ID: {call_id}", "CSeq: 2 BYE",
    ]))
    net(t0 + 10.030, _sip([
        "SIP/2.0 200 OK", via, f"From: {frm}", f"To: {to};tag=net1", f"Call-ID: {call_id}", "CSeq: 2 BYE",
    ]))

    # REGISTER for the other subscriber, challenged and never retried
    reg_from = f'<sip:+{MSISDN_OTHER}@ims.mnc001.mcc001.3gppnetwork.org>;tag=ue2'
    ue(t0 + 20.0, _sip([
        "REGISTER sip:ims.mnc001.mcc001.3gppnetwork.org SIP/2.0", via, f"From: {reg_from}",
        f"To: <sip:+{MSISDN_OTHER}@ims.mnc001.mcc001.3gppnetwork.org>", "Call-ID: reg-77@ue.example",
        "CSeq: 1 REGISTER", "Contact: <sip:198.51.100.9:5060>",
    ]))
    net(t0 + 20.040, _sip([
        "SIP/2.0 401 Unauthorized", via, f"From: {reg_from}",
        f"To: <sip:+{MSISDN_OTHER}@ims.mnc001.mcc001.3gppnetwork.org>;tag=net2",
        "Call-ID: reg-77@ue.example", "CSeq: 1 REGISTER",
        'WWW-Authenticate: Digest realm="ims.mnc001.mcc001.3gppnetwork.org", nonce="abc", algorithm=AKAv1-MD5',
    ]))
    return _frames_to_pcap(path, frames)


# --------------------------------------------------------------------------- SCTP
def write_sctp_pcap(path: Path) -> Path:
    """INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK handshake, two answered
    heartbeats and one unanswered heartbeat."""
    t0 = 1_700_000_400.0
    frames: list[tuple[float, bytes]] = []
    a_tag, b_tag = 0xAAAA0001, 0xBBBB0002

    def a2b(ts: float, chunk, tag: int) -> None:
        frames.append((ts, bytes(Ether(src=MAC_A, dst=MAC_B) / IP(src=STP_A, dst=STP_B) / SCTP(sport=2905, dport=2905, tag=tag) / chunk)))

    def b2a(ts: float, chunk, tag: int) -> None:
        frames.append((ts, bytes(Ether(src=MAC_B, dst=MAC_A) / IP(src=STP_B, dst=STP_A) / SCTP(sport=2905, dport=2905, tag=tag) / chunk)))

    a2b(t0, SCTPChunkInit(init_tag=a_tag, a_rwnd=65535, n_out_streams=2, n_in_streams=2, init_tsn=1), 0)
    b2a(t0 + 0.010, SCTPChunkInitAck(init_tag=b_tag, a_rwnd=65535, n_out_streams=2, n_in_streams=2, init_tsn=1,
                                     params=[SCTPChunkParamStateCookie(cookie=b"\x01" * 16)]), a_tag)
    a2b(t0 + 0.020, SCTPChunkCookieEcho(cookie=b"\x01" * 16), b_tag)
    b2a(t0 + 0.030, SCTPChunkCookieAck(), a_tag)
    for i in range(2):
        a2b(t0 + 1 + i, SCTPChunkHeartbeatReq(params=[SCTPChunkParamHeartbeatInfo(data=b"hb%d" % i)]), b_tag)
        b2a(t0 + 1 + i + 0.005, SCTPChunkHeartbeatAck(params=[SCTPChunkParamHeartbeatInfo(data=b"hb%d" % i)]), a_tag)
    a2b(t0 + 5, SCTPChunkHeartbeatReq(params=[SCTPChunkParamHeartbeatInfo(data=b"hb9")]), b_tag)
    return _frames_to_pcap(path, frames)


# --------------------------------------------------------------------------- SIGTRAN
def _ber(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82]) + struct.pack("!H", n)
    return bytes([tag]) + ln + content


def _addr_string(digits: str, ton_npi: int = 0x91) -> bytes:
    return bytes([ton_npi]) + _tbcd(digits)


def _invoke(invoke_id: int, opcode: int, param: bytes) -> bytes:
    return _ber(0xA1, _ber(0x02, bytes([invoke_id])) + _ber(0x02, bytes([opcode])) + param)


def _return_result_last(invoke_id: int, opcode: int, param: bytes) -> bytes:
    return _ber(0xA2, _ber(0x02, bytes([invoke_id])) + _ber(0x30, _ber(0x02, bytes([opcode])) + param))


def _tcap_begin(otid: bytes, components: bytes) -> bytes:
    return _ber(0x62, _ber(0x48, otid) + _ber(0x6C, components))


def _tcap_end(dtid: bytes, components: bytes) -> bytes:
    return _ber(0x64, _ber(0x49, dtid) + _ber(0x6C, components))


def _sccp_gt(digits: str, ssn: int) -> bytes:
    # Address indicator 0x12: SSN present, GTI=4, route on GT.
    gt = bytes([0x00, 0x11 if len(digits) % 2 else 0x12, 0x04]) + _tbcd(digits)
    body = bytes([0x12, ssn]) + gt
    return bytes([len(body)]) + body


def _sccp_udt(called: bytes, calling: bytes, data: bytes) -> bytes:
    ptr_called = 3
    ptr_calling = 2 + len(called)
    ptr_data = 1 + len(called) + len(calling)
    return bytes([0x09, 0x80, ptr_called, ptr_calling, ptr_data]) + called + calling + bytes([len(data)]) + data


def _sccp_xudt(called: bytes, calling: bytes, data: bytes, first: bool, remaining: int, slr: int) -> bytes:
    # XUDT: type 0x11, protocol class, hop counter, 4 pointers, then params.
    ptr_called = 4
    ptr_calling = 3 + len(called)
    ptr_data = 2 + len(called) + len(calling)
    ptr_opt = 1 + len(called) + len(calling) + 1 + len(data)
    seg_first = (0x80 if first else 0x00) | (remaining & 0x0F)
    seg = bytes([0x10, 0x04, seg_first]) + struct.pack("!I", slr)[1:]
    return (bytes([0x11, 0x80, 0x0F, ptr_called, ptr_calling, ptr_data, ptr_opt])
            + called + calling + bytes([len(data)]) + data + seg + b"\x00")


def _m3ua_data(opc: int, dpc: int, sccp: bytes) -> bytes:
    pd = struct.pack("!IIBBBB", opc, dpc, 3, 2, 0, 0) + sccp
    pad = (-len(pd)) % 4
    param = struct.pack("!HH", 0x0210, 4 + len(pd)) + pd + b"\x00" * pad
    return struct.pack("!BBBBI", 1, 0, 1, 1, 8 + len(param)) + param


def write_sigtran_pcap(path: Path) -> Path:
    """MAP over TCAP/SCCP/M3UA: UpdateLocation Begin/End for IMSI, an
    MO-ForwardSM Begin (unanswered), an SRI-for-SM in an XUDT first segment."""
    t0 = 1_700_000_500.0
    frames: list[tuple[float, bytes]] = []
    tsn = 500
    vlr_gt, hlr_gt, smsc_gt = "15550109001", "15550109002", "15550109003"

    def a2b(ts: float, payload: bytes) -> None:
        nonlocal tsn
        frames.append((ts, _sctp_data(STP_A, STP_B, 2905, 2905, 0x3333, tsn, 3, payload)))
        tsn += 1

    def b2a(ts: float, payload: bytes) -> None:
        nonlocal tsn
        frames.append((ts, _sctp_data(STP_B, STP_A, 2905, 2905, 0x4444, tsn, 3, payload)))
        tsn += 1

    # UpdateLocation: Begin (VLR -> HLR) and End (HLR -> VLR)
    ul_arg = _ber(0x30, _ber(0x04, _tbcd(IMSI)) + _ber(0x81, _addr_string(vlr_gt)) + _ber(0x04, _addr_string(vlr_gt)))
    begin = _tcap_begin(b"\x00\x00\x00\x01", _invoke(1, 2, ul_arg))
    a2b(t0, _m3ua_data(100, 200, _sccp_udt(_sccp_gt(hlr_gt, 6), _sccp_gt(vlr_gt, 7), begin)))
    ul_res = _ber(0x30, _ber(0x04, _addr_string(hlr_gt)))
    end = _tcap_end(b"\x00\x00\x00\x01", _return_result_last(1, 2, ul_res))
    b2a(t0 + 0.200, _m3ua_data(200, 100, _sccp_udt(_sccp_gt(vlr_gt, 7), _sccp_gt(hlr_gt, 6), end)))

    # MO-ForwardSM Begin (MSC -> SMSC), never answered
    tpdu = bytes.fromhex("01000B915155101055F500000AE8329BFD4697D9EC37")
    mo_arg = _ber(0x30,
                  _ber(0x84, _addr_string(smsc_gt))          # sm-RP-DA serviceCentreAddressDA
                  + _ber(0x82, _addr_string(MSISDN))         # sm-RP-OA msisdn
                  + _ber(0x04, tpdu)                          # sm-RP-UI
                  + _ber(0x04, _tbcd(IMSI)))                  # imsi
    begin2 = _tcap_begin(b"\x00\x00\x00\x02", _invoke(1, 46, mo_arg))
    a2b(t0 + 1.0, _m3ua_data(100, 300, _sccp_udt(_sccp_gt(smsc_gt, 8), _sccp_gt(vlr_gt, 8), begin2)))

    # SendRoutingInfoForSM in an XUDT (first segment, 1 remaining) for the other MSISDN
    sri_arg = _ber(0x30, _ber(0x80, _addr_string(MSISDN_OTHER)) + _ber(0x81, b"\x01") + _ber(0x82, _addr_string(smsc_gt)))
    begin3 = _tcap_begin(b"\x00\x00\x00\x03", _invoke(1, 45, sri_arg))
    b2a(t0 + 2.0, _m3ua_data(300, 200, _sccp_xudt(_sccp_gt(hlr_gt, 6), _sccp_gt(smsc_gt, 8), begin3, True, 1, 0x000042)))
    return _frames_to_pcap(path, frames)


# --------------------------------------------------------------------------- RTP / voice
MEDIA_GW_IP = "192.0.2.70"
UE_NAT_IP = "203.0.113.7"
UE_PRIVATE_IP = "10.0.0.5"
CALL_ID_VOICE = "voice-call-1@ue.example"
CALL_ID_NAT = "voice-nat-2@ue.example"
CALL_ID_ONEWAY = "voice-oneway-3@ue.example"
CALL_ID_488 = "voice-488-4@ue.example"
SSRC_UP = 0x11111111
SSRC_DOWN = 0x22222222


def _rtp(pt: int, seq: int, ts: int, ssrc: int, payload: bytes, marker: bool = False) -> bytes:
    return struct.pack("!BBHII", 0x80, (0x80 if marker else 0) | pt, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc) + payload


def _rtcp_sr(ssrc: int, ntp_msw: int, ntp_lsw: int, rtp_ts: int, packets: int, octets: int,
             blocks: list[tuple[int, int, int, int, int, int, int]]) -> bytes:
    """Sender report; each block is (ssrc, fraction, cum_lost, ext_high_seq, jitter, lsr, dlsr)."""
    body = struct.pack("!IIIIII", ssrc, ntp_msw, ntp_lsw, rtp_ts, packets, octets)
    for b_ssrc, fraction, cum, high, jitter, lsr, dlsr in blocks:
        body += struct.pack("!IIIIII", b_ssrc, (fraction << 24) | (cum & 0xFFFFFF), high, jitter, lsr, dlsr)
    return struct.pack("!BBH", 0x80 | len(blocks), 200, len(body) // 4) + body


def _rtcp_xr_voip(ssrc: int, source: int, r_factor: int, mos_lq_tenths: int, mos_cq_tenths: int, rt_delay: int) -> bytes:
    block = struct.pack("!BBH", 7, 0, 8) + struct.pack(
        "!IBBBBHHHHbbBBBBBBBBHHH", source, 3, 0, 0, 0, 0, 0, rt_delay, 40, -20, -60, 127, 16, r_factor, 127,
        mos_lq_tenths, mos_cq_tenths, 0, 0, 40, 80, 200)
    body = struct.pack("!I", ssrc) + block
    return struct.pack("!BBH", 0x80, 207, len(body) // 4) + body


def _sdp(addr: str, port: int, formats: list[int], rtpmaps: list[str], extra: list[str] | None = None,
         version: int = 1) -> str:
    lines = ["v=0", f"o=- 100 {version} IN IP4 {addr}", "s=-", f"c=IN IP4 {addr}", "t=0 0",
             f"m=audio {port} RTP/AVP {' '.join(str(f) for f in formats)}"]
    lines += [f"a=rtpmap:{m}" for m in rtpmaps] + (extra or [])
    return "\r\n".join(lines) + "\r\n"


def _voice_sip(call_id: str, frm_tag: str):
    frm = f'<sip:+{MSISDN}@ims.mnc001.mcc001.3gppnetwork.org>;tag={frm_tag}'
    to = '<sip:+15550100555@ims.mnc001.mcc001.3gppnetwork.org>'
    via = "Via: SIP/2.0/UDP 198.51.100.9:5060;branch=z9hG4bK" + frm_tag
    ruri = "sip:+15550100555@ims.mnc001.mcc001.3gppnetwork.org"

    def req(method: str, cseq: int, to_tag: str | None = None, extra: list[str] | None = None, body: str = "",
            ctype: str = "application/sdp") -> bytes:
        lines = [f"{method} {ruri} SIP/2.0", via, f"From: {frm}", f"To: {to}" + (f";tag={to_tag}" if to_tag else ""),
                 f"Call-ID: {call_id}", f"CSeq: {cseq} {method}"] + (extra or [])
        if body:
            lines.append(f"Content-Type: {ctype}")
        return _sip(lines, body)

    def resp(code: int, reason: str, cseq: int, method: str, to_tag: str | None = "net", extra: list[str] | None = None,
             body: str = "") -> bytes:
        lines = [f"SIP/2.0 {code} {reason}", via, f"From: {frm}", f"To: {to}" + (f";tag={to_tag}" if to_tag else ""),
                 f"Call-ID: {call_id}", f"CSeq: {cseq} {method}"] + (extra or [])
        if body:
            lines.append("Content-Type: application/sdp")
        return _sip(lines, body)

    return req, resp


def _audio(frames, t_start: float, src: str, sport: int, dst: str, dport: int, ssrc: int, pt: int, rate: int,
           count: int, seq0: int, ts0: int, *, drop=(), swap=(), jitter_ms=None, events=None) -> None:
    """``count`` packets of 20 ms audio. ``drop`` skips sequence offsets (lost), ``swap``
    exchanges the arrival of offset i and i+1, ``jitter_ms(i)`` delays arrival i, and
    ``events`` maps an offset to a list of (pt, event, end, duration) RFC 4733 packets
    sent in place of that audio packet (same timestamp, own sequence numbers)."""
    step = rate // 50
    out = []
    seq = seq0
    for i in range(count):
        arrival = t_start + i * 0.020 + ((jitter_ms(i) if jitter_ms else 0.0) / 1000.0)
        if events and i in events:
            for k, (ev_pt, ev, end, dur) in enumerate(events[i]):
                payload = struct.pack("!BBH", ev, (0x80 if end else 0) | 10, dur)
                out.append((arrival + k * 0.0001, _rtp(ev_pt, seq, ts0 + i * step, ssrc, payload, marker=(k == 0))))
                seq += 1
            continue
        if i not in drop:
            out.append((arrival, _rtp(pt, seq, ts0 + i * step, ssrc, bytes(32))))
        seq += 1
    for i in swap:
        out[i], out[i + 1] = (out[i + 1][0] - 0.0, out[i][1]), (out[i][0], out[i + 1][1])
    for ts, payload in out:
        frames.append((ts, _udp_frame(src, dst, sport, dport, payload)))


def write_voice_call_pcap(path: Path) -> Path:
    """A complete VoLTE-style call with media: INVITE (SDP offer AMR-WB, PCMA,
    telephone-event; retransmitted once), 100, 180, 200 with the SDP answer, ACK; RTP
    both ways (uplink loses 3 packets, has one reordered pair, some jitter and the
    RFC 4733 digit 5; downlink is clean), RTCP SR from each side (the network's report
    about the uplink sees the loss and gives a round trip), RTCP XR VoIP metrics, a SIP
    INFO with dtmf-relay digit 7, and a BYE from the network with a Q.850 Reason."""
    t0 = 1_700_000_500.0
    frames: list[tuple[float, bytes]] = []
    req, resp = _voice_sip(CALL_ID_VOICE, "v1")
    offer = _sdp(UE_SIP_IP, 40000, [96, 8, 101], ["96 AMR-WB/16000", "8 PCMA/8000", "101 telephone-event/16000"],
                 ["a=fmtp:101 0-15", "a=ptime:20", "a=sendrecv"])
    answer = _sdp(MEDIA_GW_IP, 30000, [96, 101], ["96 AMR-WB/16000", "101 telephone-event/16000"],
                  ["a=fmtp:101 0-15", "a=ptime:20", "a=sendrecv"])

    def ue(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(UE_SIP_IP, PCSCF_IP, 5060, 5060, msg)))

    def net(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(PCSCF_IP, UE_SIP_IP, 5060, 5060, msg)))

    invite = req("INVITE", 1, extra=["Contact: <sip:198.51.100.9:5060>"], body=offer)
    ue(t0, invite)
    ue(t0 + 0.5, invite)
    net(t0 + 0.52, resp(100, "Trying", 1, "INVITE", to_tag=None))
    net(t0 + 1.2, resp(180, "Ringing", 1, "INVITE"))
    net(t0 + 3.0, resp(200, "OK", 1, "INVITE", body=answer))
    ue(t0 + 3.02, req("ACK", 1, to_tag="net"))

    media0 = t0 + 3.1
    _audio(frames, media0, UE_SIP_IP, 40000, MEDIA_GW_IP, 30000, SSRC_UP, 96, 16000, 250, 1000, 160000,
           drop=(50, 51, 52), swap=(97,), jitter_ms=lambda i: 6.0 if i % 10 == 5 else 0.0,
           events={150: [(101, 5, False, 160), (101, 5, False, 320), (101, 5, True, 480), (101, 5, True, 480),
                         (101, 5, True, 480)]})
    _audio(frames, media0 + 0.005, MEDIA_GW_IP, 30000, UE_SIP_IP, 40000, SSRC_DOWN, 96, 16000, 250, 5000, 900000)

    # RTCP: the UE's SR (NTP 0x0000AAAA.BBBB0000), then the gateway's SR whose report block
    # about the uplink answers it (LSR = middle 32 bits, DLSR 0.1 s): round trip 100 ms.
    sr_up = _rtcp_sr(SSRC_UP, 0x0000AAAA, 0xBBBB0000, 160000 + 16000 * 2, 100, 3200,
                     [(SSRC_DOWN, 0, 0, 5099, 16, 0, 0)])
    frames.append((media0 + 2.0, _udp_frame(UE_SIP_IP, MEDIA_GW_IP, 40001, 30001, sr_up)))
    sr_down = _rtcp_sr(SSRC_DOWN, 0x0000CCCC, 0xDDDD0000, 900000 + 16000 * 2, 110, 3520,
                       [(SSRC_UP, 3, 3, 1099, 80, 0xAAAABBBB, 6554)])
    frames.append((media0 + 2.2, _udp_frame(MEDIA_GW_IP, UE_SIP_IP, 30001, 40001, sr_down)))
    xr = _rtcp_xr_voip(SSRC_DOWN, SSRC_UP, 88, 41, 40, 100)
    frames.append((media0 + 2.3, _udp_frame(MEDIA_GW_IP, UE_SIP_IP, 30001, 40001, xr)))

    info = req("INFO", 2, to_tag="net", body="Signal=7\r\nDuration=160\r\n", ctype="application/dtmf-relay")
    ue(t0 + 6.0, info)
    net(t0 + 6.03, resp(200, "OK", 2, "INFO"))
    bye = _sip([
        "BYE sip:198.51.100.9:5060 SIP/2.0", "Via: SIP/2.0/UDP 192.0.2.50:5060;branch=z9hG4bKbye1",
        "From: <sip:+15550100555@ims.mnc001.mcc001.3gppnetwork.org>;tag=net",
        f"To: <sip:+{MSISDN}@ims.mnc001.mcc001.3gppnetwork.org>;tag=v1", f"Call-ID: {CALL_ID_VOICE}",
        "CSeq: 1 BYE", 'Reason: Q.850;cause=16;text="Normal call clearing"',
    ])
    net(t0 + 8.5, bye)
    ue(t0 + 8.52, _sip([
        "SIP/2.0 200 OK", "Via: SIP/2.0/UDP 192.0.2.50:5060;branch=z9hG4bKbye1",
        "From: <sip:+15550100555@ims.mnc001.mcc001.3gppnetwork.org>;tag=net",
        f"To: <sip:+{MSISDN}@ims.mnc001.mcc001.3gppnetwork.org>;tag=v1", f"Call-ID: {CALL_ID_VOICE}", "CSeq: 1 BYE",
    ]))
    frames.sort(key=lambda f: f[0])
    return _frames_to_pcap(path, frames)


def write_voice_problems_pcap(path: Path) -> Path:
    """Three broken calls. NAT: the UE offers its private address 10.0.0.5, its RTP
    really comes from 203.0.113.7:61000, and the gateway keeps sending to the private
    address. One-way: only the UE sends RTP. 488: the offer has PCMU/PCMA only, the
    488 Not Acceptable Here lists AMR-WB, with a Warning header."""
    t0 = 1_700_000_700.0
    frames: list[tuple[float, bytes]] = []

    def ue(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(UE_SIP_IP, PCSCF_IP, 5060, 5060, msg)))

    def net(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(PCSCF_IP, UE_SIP_IP, 5060, 5060, msg)))

    # NAT call
    req, resp = _voice_sip(CALL_ID_NAT, "n2")
    ue(t0, req("INVITE", 1, body=_sdp(UE_PRIVATE_IP, 40000, [0, 101], ["0 PCMU/8000", "101 telephone-event/8000"])))
    net(t0 + 0.8, resp(180, "Ringing", 1, "INVITE"))
    net(t0 + 1.0, resp(200, "OK", 1, "INVITE", body=_sdp(MEDIA_GW_IP, 30002, [0, 101],
                                                          ["0 PCMU/8000", "101 telephone-event/8000"])))
    ue(t0 + 1.02, req("ACK", 1, to_tag="net"))
    _audio(frames, t0 + 1.1, UE_NAT_IP, 61000, MEDIA_GW_IP, 30002, 0x33333333, 0, 8000, 100, 1, 0)
    _audio(frames, t0 + 1.105, MEDIA_GW_IP, 30002, UE_PRIVATE_IP, 40000, 0x44444444, 0, 8000, 100, 1, 0)
    ue(t0 + 4.0, req("BYE", 2, to_tag="net"))
    net(t0 + 4.02, resp(200, "OK", 2, "BYE"))

    # One-way call
    req, resp = _voice_sip(CALL_ID_ONEWAY, "w3")
    ue(t0 + 10.0, req("INVITE", 1, body=_sdp(UE_SIP_IP, 40002, [8], ["8 PCMA/8000"])))
    net(t0 + 10.5, resp(200, "OK", 1, "INVITE", body=_sdp(MEDIA_GW_IP, 30004, [8], ["8 PCMA/8000"])))
    ue(t0 + 10.52, req("ACK", 1, to_tag="net"))
    _audio(frames, t0 + 10.6, UE_SIP_IP, 40002, MEDIA_GW_IP, 30004, 0x55555555, 8, 8000, 100, 1, 0)
    ue(t0 + 13.0, req("BYE", 2, to_tag="net"))
    net(t0 + 13.02, resp(200, "OK", 2, "BYE"))

    # 488 call
    req, resp = _voice_sip(CALL_ID_488, "x4")
    ue(t0 + 20.0, req("INVITE", 1, body=_sdp(UE_SIP_IP, 40004, [0, 8], ["0 PCMU/8000", "8 PCMA/8000"])))
    net(t0 + 20.05, resp(100, "Trying", 1, "INVITE", to_tag=None))
    net(t0 + 20.3, resp(488, "Not Acceptable Here", 1, "INVITE",
                        extra=['Warning: 305 pcscf.example "Incompatible media format"',
                               'Reason: SIP;cause=488;text="Not Acceptable Here"'],
                        body=_sdp(MEDIA_GW_IP, 30006, [96], ["96 AMR-WB/16000"])))
    ue(t0 + 20.32, req("ACK", 1, to_tag="net"))
    frames.sort(key=lambda f: f[0])
    return _frames_to_pcap(path, frames)


CALL_ID_DTMF = "voice-dtmf-5@ue.example"


def write_voice_dtmf_pcap(path: Path) -> Path:
    """A call that negotiates telephone-event as payload type 100 (8 kHz). The UE sends
    digit 1 as PT 100 without an end packet, then # as PT 101 (not negotiated) with
    three end packets; it also sends SIP INFO application/dtmf "9" (answered 415) and
    application/dtmf-relay "*" (answered 200)."""
    t0 = 1_700_001_100.0
    frames: list[tuple[float, bytes]] = []
    req, resp = _voice_sip(CALL_ID_DTMF, "d5")

    def ue(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(UE_SIP_IP, PCSCF_IP, 5060, 5060, msg)))

    def net(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(PCSCF_IP, UE_SIP_IP, 5060, 5060, msg)))

    ue(t0, req("INVITE", 1, body=_sdp(UE_SIP_IP, 40006, [0, 100], ["0 PCMU/8000", "100 telephone-event/8000"])))
    net(t0 + 0.5, resp(200, "OK", 1, "INVITE", body=_sdp(MEDIA_GW_IP, 30008, [0, 100],
                                                          ["0 PCMU/8000", "100 telephone-event/8000"])))
    ue(t0 + 0.52, req("ACK", 1, to_tag="net"))
    _audio(frames, t0 + 0.6, UE_SIP_IP, 40006, MEDIA_GW_IP, 30008, 0x77777777, 0, 8000, 150, 1, 0,
           events={40: [(100, 1, False, 160), (100, 1, False, 320)],
                   90: [(101, 11, False, 160), (101, 11, True, 400), (101, 11, True, 400), (101, 11, True, 400)]})
    _audio(frames, t0 + 0.605, MEDIA_GW_IP, 30008, UE_SIP_IP, 40006, 0x88888888, 0, 8000, 150, 1, 0)
    ue(t0 + 3.0, req("INFO", 2, to_tag="net", body="9", ctype="application/dtmf"))
    net(t0 + 3.02, resp(415, "Unsupported Media Type", 2, "INFO"))
    ue(t0 + 3.5, req("INFO", 3, to_tag="net", body="Signal=*\r\nDuration=250\r\n", ctype="application/dtmf-relay"))
    net(t0 + 3.52, resp(200, "OK", 3, "INFO"))
    ue(t0 + 4.0, req("BYE", 4, to_tag="net"))
    net(t0 + 4.02, resp(200, "OK", 4, "BYE"))
    frames.sort(key=lambda f: f[0])
    return _frames_to_pcap(path, frames)


def write_rtp_without_sdp_pcap(path: Path) -> Path:
    """One PCMU stream with no SIP at all: tshark decodes it only with heuristics."""
    frames: list[tuple[float, bytes]] = []
    _audio(frames, 1_700_000_900.0, "198.51.100.20", 16384, "198.51.100.21", 16386, 0x66666666, 0, 8000, 50, 1, 0)
    return _frames_to_pcap(path, frames)


IMEISV = "0012345600000101"   # test TAC 00123456
MSISDN_SHORT = "5550100"     # a seven-digit number, too short to be guessed from its length
IMSI_IMPU = "001010555000111"


def write_identity_pcap(path: Path) -> Path:
    """Identifiers in the places redaction has to find them: a GTPv2 Create Session
    with IMSI, MSISDN, MEI (IMEISV) and the UE address in the PAA; a Diameter request
    whose User-Name is the IMSI and which also carries it in an AVP tshark cannot decode
    (shown as raw bytes); and a SIP MESSAGE from an IMSI-based IMPU to a short number."""
    t0 = 1_700_000_900.0
    frames: list[tuple[float, bytes]] = []
    csr = _gtpv2(32, 0, 21, [
        _ie(1, _tbcd(IMSI)),
        _ie(76, _tbcd(MSISDN)),
        _ie(75, _tbcd(IMEISV)),
        _ie(82, bytes([6])),
        _ie(87, _fteid(6, 0x0000A101, SGW_IP)),
        _apn_ie(APN),
        _ie(99, bytes([1])),
        _ie(93, _ie(73, bytes([5])) + _ie(87, _fteid(4, 0x0000B101, SGW_IP), instance=2)),
    ])
    csresp = _gtpv2(33, 0x0000A101, 21, [
        _ie(2, bytes([16, 0])),
        _ie(87, _fteid(7, 0x0000C101, PGW_IP), instance=1),
        _ie(79, bytes([1]) + _ipv4(UE_IP)),
        _ie(93, _ie(73, bytes([5])) + _ie(2, bytes([16, 0])) + _ie(87, _fteid(5, 0x0000D101, PGW_IP), instance=2)),
    ])
    frames.append((t0, _udp_frame(SGW_IP, PGW_IP, 2123, 2123, csr)))
    frames.append((t0 + 0.05, _udp_frame(PGW_IP, SGW_IP, 2123, 2123, csresp)))
    mme = "mme01.epc.mnc001.mcc001.3gppnetwork.org"
    realm = "epc.mnc001.mcc001.3gppnetwork.org"
    air = _diameter(318, S6A, 0x2001, 0xB001, True, [
        *_diam_common(f"{mme};1700000900;9", mme, realm, realm),
        _avp(1, IMSI.encode()),
        _avp(64999, IMSI.encode(), mandatory=False, vendor=64999),  # an AVP no dictionary knows
    ])
    frames.append((t0 + 1.0, _sctp_data(MME_IP, HSS_IP, 3868, 3868, 0x51, 1, 46, air)))
    msg = _sip([
        f"MESSAGE sip:{MSISDN_SHORT}@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0",
        "Via: SIP/2.0/UDP 198.51.100.9:5060;branch=z9hG4bK901",
        f"From: <sip:{IMSI_IMPU}@ims.mnc001.mcc001.3gppnetwork.org>;tag=m1",
        f"To: <sip:{MSISDN_SHORT}@ims.mnc001.mcc001.3gppnetwork.org>",
        "Call-ID: msg-1@ue.example", "CSeq: 1 MESSAGE", "Max-Forwards: 70",
    ])
    frames.append((t0 + 2.0, _udp_frame(UE_SIP_IP, PCSCF_IP, 5060, 5060, msg)))
    return _frames_to_pcap(path, frames)


# UE addresses that a tool can show bare (as a conversation endpoint) before any tool has
# named them in a UE-address field; each is named once in one signalling field.
UE_PAA = "198.51.100.21"       # GTPv2 PDN Address Allocation
UE_EUA = "198.51.100.22"       # GTPv1 End User Address
UE_PFCP = "198.51.100.23"      # PFCP UE IP Address IE
UE_RADIUS = "198.51.100.24"    # RADIUS Framed-IP-Address
UE_INNER = "198.51.100.25"     # only ever inside a GTP-U tunnel
UE_REGISTER = "198.51.100.26"  # SIP REGISTER Contact and Via
UE_INSTANCE = "198.51.100.27"  # SIP Contact with +sip.instance in an INVITE
UE_ADDRESSES = (UE_PAA, UE_EUA, UE_PFCP, UE_RADIUS, UE_INNER, UE_REGISTER, UE_INSTANCE)
MSISDN_RADIUS = "15550100777"  # an 11-digit Calling-Station-Id
SMF_IP, UPF_IP, NAS_IP, AAA_IP = "192.0.2.90", "192.0.2.91", "192.0.2.92", "192.0.2.93"


def _radius_accounting(ident: int, attrs: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
    return bytes([4, ident]) + struct.pack("!H", 20 + len(body)) + bytes(16) + body


def write_ue_first_pcap(path: Path) -> Path:
    """Every UE address of :data:`UE_ADDRESSES` named once in signalling (GTPv2 PAA,
    GTPv1 End User Address, PFCP UE IP, RADIUS Framed-IP, a G-PDU's inner header,
    SIP REGISTER Contact/Via and an INVITE Contact with +sip.instance) and also seen
    as the outer address of plain SGi/Gm packets, so ``conversations`` lists them
    bare. The RADIUS request carries :data:`MSISDN_RADIUS` as its Calling-Station-Id."""
    t = 1_700_020_000.0
    frames: list[tuple[float, bytes]] = []

    def add(dt: float, raw: bytes) -> None:
        frames.append((t + dt, raw))

    # GTPv2 Create Session Response assigning the PAA
    add(0.0, _udp_frame(PGW_IP, SGW_IP, 2123, 2123, _gtpv2(33, 0x0000A201, 31, [
        _ie(2, bytes([16, 0])), _ie(79, bytes([1]) + _ipv4(UE_PAA))])))
    # GTPv1 Create PDP Context Response with an End User Address (IPv4)
    eua = bytes([0xF1, 0x21])  # IETF organisation, IPv4
    v1_ies = bytes([1, 128]) + bytes([128]) + struct.pack("!H", 2 + 4) + eua + _ipv4(UE_EUA)
    v1_body = struct.pack("!HBB", 0x51, 0, 0) + v1_ies
    add(0.1, _udp_frame(PGW_IP, SGW_IP, 2123, 2123, bytes([0x32, 17]) + struct.pack("!HI", len(v1_body), 0x0111) + v1_body))
    # PFCP Session Establishment Request with a PDR whose PDI names the UE IP
    pdi = _pfcp_ie(2, _pfcp_ie(20, bytes([0])) + _pfcp_ie(93, bytes([0x02]) + _ipv4(UE_PFCP)))
    pdr = _pfcp_ie(1, _pfcp_ie(56, struct.pack("!H", 1)) + _pfcp_ie(29, struct.pack("!I", 255)) + pdi)
    pfcp_body = struct.pack("!Q", 0) + struct.pack("!I", 0x61 << 8) + pdr
    pfcp = bytes([0x21, 50]) + struct.pack("!H", len(pfcp_body)) + pfcp_body
    add(0.2, _udp_frame(SMF_IP, UPF_IP, 8805, 8805, pfcp))
    # RADIUS Accounting-Request (Framed-IP-Address, Calling-Station-Id)
    add(0.3, _udp_frame(NAS_IP, AAA_IP, 40001, 1813, _radius_accounting(7, [
        (40, struct.pack("!I", 1)), (8, _ipv4(UE_RADIUS)), (31, MSISDN_RADIUS.encode())])))
    # One G-PDU whose inner source is a UE address
    inner = bytes(IP(src=UE_INNER, dst=SERVER_IP) / UDP(sport=40001, dport=9000) / Raw(b"u" * 20))
    add(0.4, _udp_frame(SGW_IP, PGW_IP, 2152, 2152, _gtpu(0x0000D201, inner)))
    # SIP REGISTER from a UE and an INVITE whose Contact carries +sip.instance
    add(0.5, _udp_frame(UE_REGISTER, PCSCF_IP, 5060, 5060, _sip([
        "REGISTER sip:ims.mnc001.mcc001.3gppnetwork.org SIP/2.0",
        f"Via: SIP/2.0/UDP {UE_REGISTER}:5060;branch=z9hG4bK31",
        f"From: <sip:{IMSI_IMPU}@ims.mnc001.mcc001.3gppnetwork.org>;tag=r1",
        f"To: <sip:{IMSI_IMPU}@ims.mnc001.mcc001.3gppnetwork.org>", "Call-ID: reg-31@ue.example",
        "CSeq: 1 REGISTER", f"Contact: <sip:{UE_REGISTER}:5060>;expires=600",
    ])))
    add(0.6, _udp_frame(PCSCF_IP, UE_INSTANCE, 5060, 5060, _sip([
        f"INVITE sip:{UE_INSTANCE}:5060 SIP/2.0", f"Via: SIP/2.0/UDP {PCSCF_IP}:5060;branch=z9hG4bK32",
        "From: <sip:alice@ims.example>;tag=i1", "To: <sip:bob@ims.example>", "Call-ID: inv-32@ims.example",
        "CSeq: 1 INVITE", f'Contact: <sip:{UE_INSTANCE}:5060>;+sip.instance="<urn:gsma:imei:00123456-000001-0>"',
    ])))
    # Plain packets in which each UE address is an outer endpoint
    for i, ue in enumerate(UE_ADDRESSES):
        add(1.0 + i * 0.01, _udp_frame(ue, SERVER_IP, 41000 + i, 9000, b"p" * 10))
    return _frames_to_pcap(path, frames)


def _pfcp_ie(ie_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ie_type, len(data)) + data


# --------------------------------------------------------------------------- IMS
IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
SCSCF_IP = "192.0.2.51"
AS_IP = "192.0.2.52"
AS2_IP = "192.0.2.53"
# Test IMSIs (PLMN 001/01), one per registration scenario.
IMS_OK = "001010000000101"         # registered: 401, 200, third-party REGISTERs, a refresh
IMS_LOOP = "001010000000102"       # challenge loop with AUTS
IMS_403 = "001010000000103"
IMS_503 = "001010000000104"
IMS_EXPIRED = "001010000000105"    # 200 for 60 s, no refresh, no smsip or MMTel
IMS_ESP = "001010000000106"        # 401, then ESP that never yields a protected REGISTER
IMS_DEREG = "001010000000107"
IMS_SILENT = "001010000000108"     # REGISTER never answered
IMS_NOTIFY = "001010000000109"     # registered, then a reg-event NOTIFY terminates it (deactivated)
IMS_MSISDN = "15550100123"         # IMS_OK's implicit tel URI
UE_IMS = {IMS_OK: "198.51.100.41", IMS_LOOP: "198.51.100.42", IMS_403: "198.51.100.43", IMS_503: "198.51.100.44",
          IMS_EXPIRED: "198.51.100.45", IMS_ESP: "198.51.100.46", IMS_DEREG: "198.51.100.47", IMS_SILENT: "198.51.100.48",
          IMS_NOTIFY: "198.51.100.49"}
PCSCF_SPI_C, PCSCF_SPI_S = 3333, 4444
MMTEL_TAG = '+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"'


def _register(imsi: str, cseq: int, expires: int, *, call_id: str | None = None, response: str = "",
              auts: str | None = None, tags: str | None = None, frm: str | None = None, ruri: str | None = None,
              ue: str | None = None, via: str | None = None) -> bytes:
    impu = f"sip:{imsi}@{IMS_DOMAIN}"
    ue = ue or UE_IMS.get(imsi, UE_SIP_IP)
    tags = f";+g.3gpp.smsip;{MMTEL_TAG}" if tags is None else tags
    auth = (f'Authorization: Digest username="{imsi}@{IMS_DOMAIN}", realm="{IMS_DOMAIN}", nonce="", '
            f'uri="sip:{IMS_DOMAIN}", response="{response}", algorithm=AKAv1-MD5')
    if auts:
        auth += f', auts="{auts}"'
    lines = [
        f"REGISTER {ruri or 'sip:' + IMS_DOMAIN} SIP/2.0",
        via or f"Via: SIP/2.0/UDP {ue}:5060;branch=z9hG4bK{imsi[-3:]}{cseq}",
        f"From: <{frm or impu}>;tag=r{cseq}", f"To: <{impu}>", f"Call-ID: {call_id or 'reg-' + imsi[-3:]}@ue.example",
        f"CSeq: {cseq} REGISTER", "Max-Forwards: 70",
        f'Contact: <sip:{ue}:5060>{tags};+sip.instance="<urn:gsma:imei:00123456-000001-0>"',
        f"Expires: {expires}", auth,
        "Security-Client: ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=1111; spi-s=2222; port-c=5100; port-s=5101",
        "Require: sec-agree", "Proxy-Require: sec-agree", "Supported: path, sec-agree",
        "User-Agent: test-ue/1.0",
    ]
    return _sip(lines)


def _reg_response(imsi: str, cseq: int, code: int, reason: str, extra: list[str] | None = None,
                  call_id: str | None = None, frm: str | None = None, ue: str | None = None) -> bytes:
    impu = f"sip:{imsi}@{IMS_DOMAIN}"
    ue = ue or UE_IMS.get(imsi, UE_SIP_IP)
    return _sip([
        f"SIP/2.0 {code} {reason}", f"Via: SIP/2.0/UDP {ue}:5060;branch=z9hG4bK{imsi[-3:]}{cseq}",
        f"From: <{frm or impu}>;tag=r{cseq}", f"To: <{impu}>;tag=s{cseq}",
        f"Call-ID: {call_id or 'reg-' + imsi[-3:]}@ue.example", f"CSeq: {cseq} REGISTER", *(extra or []),
    ])


def _reginfo(imsi: str, state: str, contact_state: str, event: str, expires: int | None = None) -> str:
    impu = f"sip:{imsi}@{IMS_DOMAIN}"
    exp = f' expires="{expires}"' if expires is not None else ""
    return ('<?xml version="1.0"?>\r\n<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">\r\n'
            f'  <registration aor="{impu}" id="a{imsi[-3:]}" state="{state}">\r\n'
            f'    <contact id="c1" state="{contact_state}" event="{event}"{exp}>\r\n'
            f'      <uri>sip:{UE_IMS[imsi]}:5060</uri>\r\n    </contact>\r\n  </registration>\r\n</reginfo>\r\n')


def _notify(imsi: str, cseq: int, body: str, *, src: str) -> bytes:
    impu = f"sip:{imsi}@{IMS_DOMAIN}"
    return _sip([
        f"NOTIFY sip:{UE_IMS[imsi]}:5060 SIP/2.0", f"Via: SIP/2.0/UDP {src}:5060;branch=z9hG4bKn{imsi[-3:]}{cseq}",
        f"From: <{impu}>;tag=sub{imsi[-3:]}", f"To: <{impu}>;tag=ue{imsi[-3:]}", f"Call-ID: sub-{imsi[-3:]}@ue.example",
        f"CSeq: {cseq} NOTIFY", "Event: reg", "Subscription-State: active;expires=600000", "Max-Forwards: 70",
        "Content-Type: application/reginfo+xml",
    ], body)


def _notify_ok(imsi: str, cseq: int, *, via_host: str) -> bytes:
    impu = f"sip:{imsi}@{IMS_DOMAIN}"
    return _sip([
        "SIP/2.0 200 OK", f"Via: SIP/2.0/UDP {via_host}:5060;branch=z9hG4bKn{imsi[-3:]}{cseq}",
        f"From: <{impu}>;tag=sub{imsi[-3:]}", f"To: <{impu}>;tag=ue{imsi[-3:]}", f"Call-ID: sub-{imsi[-3:]}@ue.example",
        f"CSeq: {cseq} NOTIFY",
    ])


def _challenge(imsi: str) -> list[str]:
    return [
        f'WWW-Authenticate: Digest realm="{IMS_DOMAIN}", nonce="cmFuZGF1dG4=", algorithm=AKAv1-MD5, '
        'ck="00112233445566778899aabbccddeeff", ik="ffeeddccbbaa99887766554433221100", qop="auth"',
        f"Security-Server: ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; ealg=null; spi-c={PCSCF_SPI_C}; "
        f"spi-s={PCSCF_SPI_S}; port-c=6100; port-s=6101",
    ]


def _ok(imsi: str, expires: int, tags: str | None = None) -> list[str]:
    ue = UE_IMS[imsi]
    tags = f";+g.3gpp.smsip;{MMTEL_TAG}" if tags is None else tags
    return [
        f"Contact: <sip:{ue}:5060>;expires={expires}{tags}",
        f"P-Associated-URI: <sip:+{IMS_MSISDN}@{IMS_DOMAIN}>, <tel:+{IMS_MSISDN}>" if imsi == IMS_OK
        else f"P-Associated-URI: <sip:{imsi}@{IMS_DOMAIN}>",
        f"Service-Route: <sip:orig@scscf.{IMS_DOMAIN};lr>", f"Path: <sip:term@pcscf.{IMS_DOMAIN};lr>",
    ]


def write_ims_register_pcap(path: Path) -> Path:
    """IMS registrations of eight test subscribers (see the ``IMS_*`` IMSIs) through a
    P-CSCF (``PCSCF_IP``) and S-CSCF (``SCSCF_IP``): a full AKA registration with a
    copied and a retransmitted REGISTER, third-party REGISTERs to two application
    servers (one refused with 500) and a refresh; a challenge loop ending in AUTS; 403;
    503 with Retry-After; a 60 s registration never refreshed, without smsip or MMTel;
    a challenge followed only by ESP to the P-CSCF's SPI; a de-registration; and a
    REGISTER nobody answers. The capture runs past every expiry."""
    t0 = 1_700_030_000.0
    frames: list[tuple[float, bytes]] = []

    def add(dt: float, src: str, dst: str, msg: bytes) -> None:
        frames.append((t0 + dt, _udp_frame(src, dst, 5060, 5060, msg)))

    p, s = PCSCF_IP, SCSCF_IP
    # 1. Full registration of IMS_OK.
    ue = UE_IMS[IMS_OK]
    add(0.000, ue, p, _register(IMS_OK, 1, 600000))
    add(0.0004, ue, p, _register(IMS_OK, 1, 600000))  # the same packet captured twice
    add(0.010, p, s, _register(IMS_OK, 1, 600000))
    add(0.050, s, p, _reg_response(IMS_OK, 1, 401, "Unauthorized", _challenge(IMS_OK)))
    add(0.060, p, ue, _reg_response(IMS_OK, 1, 401, "Unauthorized", _challenge(IMS_OK)))
    add(1.000, p, s, _register(IMS_OK, 2, 600000, response="0f1e2d3c4b5a69788796a5b4c3d2e1f0"))
    add(1.500, p, s, _register(IMS_OK, 2, 600000, response="0f1e2d3c4b5a69788796a5b4c3d2e1f0"))  # retransmission
    add(1.600, s, p, _reg_response(IMS_OK, 2, 200, "OK", _ok(IMS_OK, 3600)))
    scscf = f"sip:scscf.{IMS_DOMAIN}"
    add(1.700, s, AS_IP, _register(IMS_OK, 10, 3600, call_id="3pr-1", frm=scscf, ruri=f"sip:as1.{IMS_DOMAIN}",
                                   tags="", ue=s, via=f"Via: SIP/2.0/UDP {s}:5060;branch=z9hG4bK3p1"))
    add(1.720, AS_IP, s, _reg_response(IMS_OK, 10, 200, "OK", call_id="3pr-1", frm=scscf, ue=s))
    add(1.750, s, AS2_IP, _register(IMS_OK, 11, 3600, call_id="3pr-2", frm=scscf, ruri=f"sip:as2.{IMS_DOMAIN}",
                                    tags="", ue=s, via=f"Via: SIP/2.0/UDP {s}:5060;branch=z9hG4bK3p2"))
    add(1.790, AS2_IP, s, _reg_response(IMS_OK, 11, 500, "Server Internal Error", call_id="3pr-2", frm=scscf, ue=s))
    add(300.0, p, s, _register(IMS_OK, 3, 600000, response="1f1e2d3c4b5a69788796a5b4c3d2e1f0"))
    add(300.040, s, p, _reg_response(IMS_OK, 3, 200, "OK", _ok(IMS_OK, 3600)))
    # The reg-event NOTIFY after the refresh (state active) on both legs, answered by the UE.
    add(301.0, s, p, _notify(IMS_OK, 1, _reginfo(IMS_OK, "active", "active", "refreshed", 3600), src=s))
    add(301.01, p, ue, _notify(IMS_OK, 1, _reginfo(IMS_OK, "active", "active", "refreshed", 3600), src=s))
    add(301.03, ue, p, _notify_ok(IMS_OK, 1, via_host=s))
    # 2. Challenge loop: every answer is challenged again; the last carries AUTS.
    ue = UE_IMS[IMS_LOOP]
    add(10.0, ue, p, _register(IMS_LOOP, 1, 600000))
    add(10.05, p, ue, _reg_response(IMS_LOOP, 1, 401, "Unauthorized", _challenge(IMS_LOOP)))
    add(11.0, ue, p, _register(IMS_LOOP, 2, 600000, response="aa"))
    add(11.05, p, ue, _reg_response(IMS_LOOP, 2, 401, "Unauthorized", _challenge(IMS_LOOP)))
    add(12.0, ue, p, _register(IMS_LOOP, 3, 600000, response="bb", auts="QVVUU1RPS0VO"))
    add(12.05, p, ue, _reg_response(IMS_LOOP, 3, 401, "Unauthorized", _challenge(IMS_LOOP)))
    # 3. 403 and 4. 503 with Retry-After.
    add(20.0, UE_IMS[IMS_403], p, _register(IMS_403, 1, 600000))
    add(20.03, p, UE_IMS[IMS_403], _reg_response(IMS_403, 1, 403, "Forbidden"))
    add(25.0, UE_IMS[IMS_503], p, _register(IMS_503, 1, 600000))
    add(25.02, p, UE_IMS[IMS_503], _reg_response(IMS_503, 1, 503, "Service Unavailable", ["Retry-After: 120"]))
    # 5. Registered for 60 s and never refreshed; no smsip, no MMTel.
    ue = UE_IMS[IMS_EXPIRED]
    add(30.0, ue, p, _register(IMS_EXPIRED, 1, 60, tags=""))
    add(30.05, p, ue, _reg_response(IMS_EXPIRED, 1, 401, "Unauthorized", _challenge(IMS_EXPIRED)))
    add(31.0, p, s, _register(IMS_EXPIRED, 2, 60, response="cc", tags=""))
    add(31.05, s, p, _reg_response(IMS_EXPIRED, 2, 200, "OK", _ok(IMS_EXPIRED, 60, tags="")))
    # 6. Challenged, then ESP to the P-CSCF's spi-s with no protected REGISTER behind it.
    ue = UE_IMS[IMS_ESP]
    add(40.0, ue, p, _register(IMS_ESP, 1, 600000))
    add(40.05, p, ue, _reg_response(IMS_ESP, 1, 401, "Unauthorized", _challenge(IMS_ESP)))
    for i, dt in enumerate((40.5, 41.5, 43.5)):
        esp = struct.pack("!II", PCSCF_SPI_S, i + 1) + bytes(40)
        frames.append((t0 + dt, bytes(Ether(src=MAC_A, dst=MAC_B) / IP(src=ue, dst=p, proto=50) / Raw(esp))))
    # 7. Registered, then de-registered.
    ue = UE_IMS[IMS_DEREG]
    add(50.0, p, s, _register(IMS_DEREG, 5, 600000, response="dd"))
    add(50.04, s, p, _reg_response(IMS_DEREG, 5, 200, "OK", _ok(IMS_DEREG, 3600)))
    add(60.0, p, s, _register(IMS_DEREG, 6, 0, response="ee"))
    add(60.04, s, p, _reg_response(IMS_DEREG, 6, 200, "OK", [f"Contact: <sip:{ue}:5060>;expires=0"]))
    # 9. Registered, then de-registered by the network: a reg-event NOTIFY with the
    # registration terminated and the contact deactivated (the UE should re-register).
    ue = UE_IMS[IMS_NOTIFY]
    add(80.0, p, s, _register(IMS_NOTIFY, 7, 600000, response="ff"))
    add(80.04, s, p, _reg_response(IMS_NOTIFY, 7, 200, "OK", _ok(IMS_NOTIFY, 3600)))
    add(90.0, s, p, _notify(IMS_NOTIFY, 2, _reginfo(IMS_NOTIFY, "terminated", "terminated", "deactivated"), src=s))
    add(90.01, p, ue, _notify(IMS_NOTIFY, 2, _reginfo(IMS_NOTIFY, "terminated", "terminated", "deactivated"), src=s))
    add(90.03, ue, p, _notify_ok(IMS_NOTIFY, 2, via_host=s))
    # 8. Never answered (two retransmissions).
    ue = UE_IMS[IMS_SILENT]
    for dt in (70.0, 70.5, 71.5):
        add(dt, ue, p, _register(IMS_SILENT, 1, 600000))
    # Something unrelated at the end, so the capture outlives every expiry above.
    add(400.0, SERVER_IP, p, b"keepalive")
    frames.sort(key=lambda f: f[0])
    return _frames_to_pcap(path, frames)


SMS_A = "001010000000201"           # registered with +g.3gpp.smsip
SMS_B = "001010000000202"           # registered without it
SMS_A_MSISDN = "15550100201"
SMS_B_MSISDN = "15550100202"
SMSC = "15550100900"
SMS_PEER = "15550100300"
UE_SMS = {SMS_A: "198.51.100.61", SMS_B: "198.51.100.62"}
IPSMGW_IP = AS_IP


def _bcd_addr(digits: str) -> bytes:
    """Type of address (international, E.164) and swapped-nibble BCD digits."""
    padded = digits + ("F" if len(digits) % 2 else "")
    return bytes([0x91]) + bytes.fromhex("".join(padded[i + 1] + padded[i] for i in range(0, len(padded), 2)))


_SCTS = bytes([0x32, 0x11, 0x51, 0x01, 0x02, 0x03, 0x00])
_UD_HI = bytes([2, 0xE8, 0x34])  # TP-UDL 2 and "hi" in the GSM 7-bit alphabet


def _tp_submit(mr: int, dest: str, srr: bool = False) -> bytes:
    return bytes([0x01 | (0x20 if srr else 0), mr, len(dest)]) + _bcd_addr(dest) + bytes([0, 0]) + _UD_HI


def _tp_deliver(orig: str) -> bytes:
    return bytes([0x04, len(orig)]) + _bcd_addr(orig) + bytes([0, 0]) + _SCTS + _UD_HI


def _tp_status_report(mr: int, recipient: str, status: int) -> bytes:
    return bytes([0x06, mr, len(recipient)]) + _bcd_addr(recipient) + _SCTS + _SCTS + bytes([status])


def _rp_data_mo(mr: int, tpdu: bytes) -> bytes:
    sc = _bcd_addr(SMSC)
    return bytes([0x00, mr, 0x00, len(sc)]) + sc + bytes([len(tpdu)]) + tpdu


def _rp_data_mt(mr: int, tpdu: bytes) -> bytes:
    sc = _bcd_addr(SMSC)
    return bytes([0x01, mr, len(sc)]) + sc + bytes([0x00, len(tpdu)]) + tpdu


def _rp_ack(rp_type: int, mr: int, tpdu: bytes | None = None) -> bytes:
    return bytes([rp_type, mr]) + (bytes([0x41, len(tpdu)]) + tpdu if tpdu else b"")


def _rp_error(rp_type: int, mr: int, cause: int) -> bytes:
    return bytes([rp_type, mr, 0x01, cause])


def _sip_bin(lines: list[str], body: bytes) -> bytes:
    return ("\r\n".join(lines) + f"\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body


def _message(call_id: str, frm: str, to: str, body: bytes, cseq: int = 1, ruri: str | None = None,
             ctype: str = "application/vnd.3gpp.sms", via: str = "192.0.2.50") -> bytes:
    return _sip_bin([
        f"MESSAGE {ruri or to} SIP/2.0", f"Via: SIP/2.0/UDP {via}:5060;branch=z9hG4bK{call_id}", f"From: <{frm}>;tag=f{cseq}",
        f"To: <{to}>", f"Call-ID: {call_id}@ims.example.com", f"CSeq: {cseq} MESSAGE", "Max-Forwards: 70",
        f"Content-Type: {ctype}",
    ], body)


def _message_response(call_id: str, frm: str, to: str, code: int, reason: str, cseq: int = 1,
                      via: str = "192.0.2.50") -> bytes:
    return _sip([
        f"SIP/2.0 {code} {reason}", f"Via: SIP/2.0/UDP {via}:5060;branch=z9hG4bK{call_id}", f"From: <{frm}>;tag=f{cseq}",
        f"To: <{to}>;tag=t{cseq}", f"Call-ID: {call_id}@ims.example.com", f"CSeq: {cseq} MESSAGE",
    ])


def write_ims_sms_pcap(path: Path) -> Path:
    """SMS over IMS between two registered test UEs (:data:`SMS_A` with +g.3gpp.smsip,
    :data:`SMS_B` without), the P-CSCF and an IP-SM-GW (``IPSMGW_IP``): an MO submit
    acknowledged, with a status report delivered later; an MO submit refused with
    RP-ERROR 21; an MO submit whose RP-ACK is coded MS-to-network and never accepted by
    the UE (408); an MT delivery to the MSISDN alias answered by an RP-ACK from the
    IMSI-based identity; an MT to the UE without smsip refused with 488; an MT refused
    by the UE with RP-ERROR 22; an MO submit answered 202 and never by the RP layer; an
    RP-ACK with no RP-DATA; a pager-mode text MESSAGE; a MESSAGE whose body is missing;
    and an MO submit just before the end of the capture."""
    t0 = 1_700_040_000.0
    frames: list[tuple[float, bytes]] = []
    p, g = PCSCF_IP, IPSMGW_IP
    ua, ub = UE_SMS[SMS_A], UE_SMS[SMS_B]
    a_impu = f"sip:{SMS_A}@{IMS_DOMAIN}"
    a_tel, b_tel = f"sip:+{SMS_A_MSISDN}@{IMS_DOMAIN}", f"sip:+{SMS_B_MSISDN}@{IMS_DOMAIN}"
    sc = f"sip:+{SMSC}@{IMS_DOMAIN}"

    def add(dt: float, src: str, dst: str, msg: bytes) -> None:
        frames.append((t0 + dt, _udp_frame(src, dst, 5060, 5060, msg)))

    def register(dt: float, imsi: str, ue: str, msisdn: str, tags: str) -> None:
        impu = f"sip:{imsi}@{IMS_DOMAIN}"
        add(dt, ue, p, _sip([
            f"REGISTER sip:{IMS_DOMAIN} SIP/2.0", f"Via: SIP/2.0/UDP {ue}:5060;branch=z9hG4bKr{imsi[-3:]}",
            f"From: <{impu}>;tag=r1", f"To: <{impu}>", f"Call-ID: reg-{imsi[-3:]}@ue.example", "CSeq: 1 REGISTER",
            f'Contact: <sip:{ue}:5060>{tags}', "Expires: 600000",
            f'Authorization: Digest username="{imsi}@{IMS_DOMAIN}", realm="{IMS_DOMAIN}", nonce="", '
            f'uri="sip:{IMS_DOMAIN}", response="11"',
        ]))
        add(dt + 0.05, p, ue, _sip([
            "SIP/2.0 200 OK", f"Via: SIP/2.0/UDP {ue}:5060;branch=z9hG4bKr{imsi[-3:]}", f"From: <{impu}>;tag=r1",
            f"To: <{impu}>;tag=s1", f"Call-ID: reg-{imsi[-3:]}@ue.example", "CSeq: 1 REGISTER",
            f"Contact: <sip:{ue}:5060>;expires=3600{tags}",
            f"P-Associated-URI: <sip:+{msisdn}@{IMS_DOMAIN}>, <tel:+{msisdn}>",
        ]))

    register(0.0, SMS_A, ua, SMS_A_MSISDN, f";+g.3gpp.smsip;{MMTEL_TAG}")
    register(0.5, SMS_B, ub, SMS_B_MSISDN, f";{MMTEL_TAG}")

    # 1. MO submit (status report requested), RP-ACK with SUBMIT-REPORT, then the status report.
    add(10.0, ua, p, _message("mo1", a_tel, sc, _rp_data_mo(5, _tp_submit(9, SMS_PEER, srr=True))))
    add(10.01, p, g, _message("mo1", a_tel, sc, _rp_data_mo(5, _tp_submit(9, SMS_PEER, srr=True))))
    add(10.02, g, p, _message_response("mo1", a_tel, sc, 202, "Accepted"))
    add(10.03, p, ua, _message_response("mo1", a_tel, sc, 202, "Accepted"))
    add(10.20, g, ua, _message("ack1", sc, a_tel, _rp_ack(3, 5, bytes([0x01, 0x00]) + _SCTS)))
    add(10.25, ua, g, _message_response("ack1", sc, a_tel, 200, "OK"))
    add(15.00, g, ua, _message("sr1", sc, a_tel, _rp_data_mt(6, _tp_status_report(9, SMS_PEER, 0x00))))
    add(15.05, ua, g, _message_response("sr1", sc, a_tel, 200, "OK"))
    add(15.10, ua, g, _message("sr1ack", a_tel, sc, _rp_ack(2, 6, bytes([0x00, 0x00]))))
    add(15.15, g, ua, _message_response("sr1ack", a_tel, sc, 200, "OK"))
    # 2. MO submit refused by the SMSC: RP-ERROR cause 21.
    add(20.0, ua, g, _message("mo2", a_tel, sc, _rp_data_mo(7, _tp_submit(10, SMS_PEER))))
    add(20.02, g, ua, _message_response("mo2", a_tel, sc, 202, "Accepted"))
    add(20.30, g, ua, _message("err2", sc, a_tel, _rp_error(5, 7, 21)))
    add(20.35, ua, g, _message_response("err2", sc, a_tel, 200, "OK"))
    # 3. MO submit whose RP-ACK is coded MS to network (2) and never accepted by the UE.
    add(30.0, ua, g, _message("mo3", a_tel, sc, _rp_data_mo(17, _tp_submit(11, SMS_PEER))))
    add(30.02, g, ua, _message_response("mo3", a_tel, sc, 200, "OK"))
    for dt in (30.04, 30.54, 31.54):
        add(dt, g, ua, _message("ack3", sc, a_tel, _rp_ack(2, 17)))
    add(62.04, p, g, _message_response("ack3", sc, a_tel, 408, "Request Timeout"))
    # 4. MT delivery to the MSISDN alias, RP-ACK from the IMSI-based identity.
    add(70.0, g, ua, _message("mt4", sc, a_tel, _rp_data_mt(20, _tp_deliver(SMS_PEER))))
    add(70.05, ua, g, _message_response("mt4", sc, a_tel, 200, "OK"))
    add(70.10, ua, g, _message("ack4", a_impu, sc, _rp_ack(2, 20, bytes([0x00, 0x00]))))
    add(70.15, g, ua, _message_response("ack4", a_impu, sc, 200, "OK"))
    # 5. MT to the UE registered without smsip: 488.
    add(80.0, g, p, _message("mt5", sc, b_tel, _rp_data_mt(30, _tp_deliver(SMS_PEER))))
    add(80.02, p, g, _message_response("mt5", sc, b_tel, 488, "Not Acceptable Here"))
    # 6. MT refused by the UE: memory capacity exceeded.
    add(90.0, g, ua, _message("mt6", sc, a_tel, _rp_data_mt(40, _tp_deliver(SMS_PEER))))
    add(90.05, ua, g, _message_response("mt6", sc, a_tel, 200, "OK"))
    add(90.10, ua, g, _message("err6", a_tel, sc, _rp_error(4, 40, 22)))
    add(90.15, g, ua, _message_response("err6", a_tel, sc, 200, "OK"))
    # 7. MO submit answered 202 and never by the RP layer.
    add(100.0, ua, g, _message("mo7", a_tel, sc, _rp_data_mo(50, _tp_submit(12, SMS_PEER))))
    add(100.02, g, ua, _message_response("mo7", a_tel, sc, 202, "Accepted"))
    # 8. An RP-ACK with no RP-DATA before it; 9. a pager-mode text MESSAGE; 10. a MESSAGE without its body.
    add(110.0, g, ua, _message("orphan8", sc, a_tel, _rp_ack(3, 99)))
    add(110.05, ua, g, _message_response("orphan8", sc, a_tel, 200, "OK"))
    add(120.0, ua, p, _message("text9", a_tel, b_tel, b"hello", ctype="text/plain"))
    add(120.05, p, ua, _message_response("text9", a_tel, b_tel, 200, "OK"))
    add(130.0, ua, g, _message("nobody10", a_tel, sc, b""))
    add(130.02, g, ua, _message_response("nobody10", a_tel, sc, 202, "Accepted"))
    # 11. An MO submit five seconds before the end of the capture.
    add(195.0, ua, g, _message("mo11", a_tel, sc, _rp_data_mo(60, _tp_submit(13, SMS_PEER))))
    add(195.02, g, ua, _message_response("mo11", a_tel, sc, 202, "Accepted"))
    add(200.0, SERVER_IP, p, b"keepalive")
    frames.sort(key=lambda f: f[0])
    return _frames_to_pcap(path, frames)


GY = 4
RX = 16777236
CX = 16777216
SH = 16777217
S13 = 16777252
OCS_IP = "192.0.2.80"
PCRF_IP = "192.0.2.81"
EIR_IP = "192.0.2.82"
APPS_IMEI = "00123456000001"    # test TAC 00123456
APPS_IMPI = f"{IMS_OK}@{IMS_DOMAIN}"
APPS_IMPU = f"sip:{IMS_OK}@{IMS_DOMAIN}"
APPS_SECRET = bytes.fromhex("5a5a5a5a0123456789abcdef5a5a5a5a")  # must never be returned
APPS_SH_DATA = ('<?xml version="1.0" encoding="UTF-8"?><Sh-Data><RepositoryData><ServiceIndication>svc'
                '</ServiceIndication><SequenceNumber>1</SequenceNumber><ServiceData>private-body-text</ServiceData>'
                '</RepositoryData><Extension/></Sh-Data>')


def write_diameter_apps_pcap(path: Path) -> Path:
    """One transaction per application digest of diameter_avps. Gy: CCR-U reporting 1000
    octets used on rating group 10 (QUOTA_EXHAUSTED), answered 2001 with the MSCC refused
    4012 and a Final-Unit-Indication TERMINATE. Rx: AAR for one audio component (two
    flows, Codec-Data), answered Experimental-Result 5065. Cx: UAR answered 2001
    (Experimental), MAR answered with one SIP-Auth-Data-Item whose RAND/AUTN, XRES, CK and
    IK are APPS_SECRET. Sh: UDR for RepositoryData and InitialFilterCriteria answered with
    Sh-User-Data. S13: ECR for APPS_IMEI answered BLACKLISTED."""
    t0 = 1_700_009_000.0
    v = VENDOR_3GPP
    frames: list[tuple[float, bytes]] = []
    tsn = {"n": 0}

    def u32(code: int, value: int, vendor: int | None = v) -> bytes:
        return _avp(code, struct.pack("!I", value), vendor=vendor)

    def u64(code: int, value: int, vendor: int | None = None) -> bytes:
        return _avp(code, struct.pack("!Q", value), vendor=vendor)

    def grp(code: int, members: list[bytes], vendor: int | None = v) -> bytes:
        return _avp(code, b"".join(members), vendor=vendor)

    def common(sid: str, origin: str, app: int) -> list[bytes]:
        return [_avp(263, sid.encode()), _avp(264, origin.encode()), _avp(296, b"test.example"),
                _avp(258, struct.pack("!I", app))]

    def tx(dt: float, cmd: int, app: int, client: str, server: str, req: list[bytes], ans: list[bytes]) -> None:
        sid = f"{client};{cmd};{app}"
        hbh = 0x700 + cmd
        for k, (request, extra) in enumerate(((True, req), (False, ans))):
            tsn["n"] += 1
            src, dst = (client, server) if request else (server, client)
            body = common(sid, f"{src}.test.example", app) + ([_avp(283, b"test.example")] if request else []) + extra
            frames.append((t0 + dt + 0.01 * k, _sctp_data(src, dst, 3868, 3868, 0x30, tsn["n"], 46,
                                                         _diameter(cmd, app, hbh, hbh, request, body))))

    # Gy CCR-U / CCA-U
    tx(0.0, 272, GY, PGW_IP, OCS_IP,
       [u32(416, 2, None), u32(415, 3, None), _avp(461, b"32251@3gpp.org", vendor=None),
        grp(443, [u32(450, 0, None), _avp(444, MSISDN.encode(), vendor=None)], vendor=None),
        grp(456, [u32(432, 10, None), grp(437, [], vendor=None),
                  grp(446, [u64(421, 1000), u32(872, 3)], vendor=None)], vendor=None)],
       [u32(268, 2001, None), u32(416, 2, None), u32(415, 3, None),
        grp(456, [u32(432, 10, None), grp(431, [u64(421, 0)], vendor=None), u32(448, 600, None), u32(871, 30),
                  grp(430, [u32(449, 0, None)], vendor=None), u32(268, 4012, None)], vendor=None)])
    # Rx AAR / AAA
    codec = b"uplink\noffer\nm=audio 49152 RTP/AVP 116\na=rtpmap:116 AMR-WB/16000"
    tx(1.0, 265, RX, PCSCF_IP, PCRF_IP,
       [u32(533, 0), _avp(8, _ipv4(UE_IP), vendor=None), _avp(505, b"icid-rx-1", vendor=v),
        grp(517, [u32(518, 1), u32(520, 0), u32(511, 2), u32(516, 41000), u32(515, 41000),
                  _avp(524, codec, vendor=v),
                  grp(519, [u32(509, 1), _avp(507, b"permit out 17 from 192.0.2.1 to 198.51.100.9", vendor=v),
                            _avp(507, b"permit in 17 from 198.51.100.9 to 192.0.2.1", vendor=v)])]),
        u32(513, 2), u32(513, 4)],
       [grp(297, [u32(266, v, None), u32(298, 5065, None)], vendor=None)])
    # Cx UAR / UAA and MAR / MAA
    tx(2.0, 300, CX, PCSCF_IP, HSS_IP,
       [_avp(1, APPS_IMPI.encode(), vendor=None), _avp(601, APPS_IMPU.encode(), vendor=v), u32(623, 0),
        _avp(600, IMS_DOMAIN.encode(), vendor=v)],
       [grp(297, [u32(266, v, None), u32(298, 2001, None)], vendor=None),
        grp(603, [u32(604, 1), u32(604, 2), u32(605, 3)])])
    tx(3.0, 303, CX, SCSCF_IP, HSS_IP,
       [_avp(1, APPS_IMPI.encode(), vendor=None), _avp(601, APPS_IMPU.encode(), vendor=v), u32(607, 1),
        grp(612, [_avp(608, b"Digest-AKAv1-MD5", vendor=v)]), _avp(602, b"sip:scscf.test.example", vendor=v)],
       [u32(268, 2001, None), u32(607, 1),
        grp(612, [_avp(608, b"Digest-AKAv1-MD5", vendor=v), _avp(609, APPS_SECRET + APPS_SECRET, vendor=v),
                  _avp(610, APPS_SECRET, vendor=v), _avp(625, APPS_SECRET, vendor=v),
                  _avp(626, APPS_SECRET, vendor=v)])])
    # Sh UDR / UDA
    tx(4.0, 306, SH, AS_IP, HSS_IP,
       [grp(700, [_avp(601, APPS_IMPU.encode(), vendor=v)]), u32(703, 0), u32(703, 13)],
       [u32(268, 2001, None), _avp(702, APPS_SH_DATA.encode(), vendor=v)])
    # S13 ECR / ECA
    tx(5.0, 324, S13, MME_IP, EIR_IP,
       [_avp(1, IMSI.encode(), vendor=None),
        grp(1401, [_avp(1402, APPS_IMEI.encode(), vendor=v), _avp(1403, b"01", vendor=v)])],
       [u32(268, 2001, None), u32(1445, 1)])
    return _frames_to_pcap(path, frames)


def write_ims_pcaps(directory: Path) -> dict[str, Path]:
    """The IMS captures, in their own directory like the voice ones."""
    directory.mkdir(parents=True, exist_ok=True)
    return {"ims_register": write_ims_register_pcap(directory / "ims_register.pcap"),
            "ims_sms": write_ims_sms_pcap(directory / "ims_sms.pcap"),
            "diameter_apps": write_diameter_apps_pcap(directory / "diameter_apps.pcap")}


SBC_IP = "192.0.2.90"
CARRIER_X = "203.0.113.10"
CARRIER_Y = "203.0.113.20"
CALL_MIX_END = 1_700_007_200.5


def write_call_mix_pcap(path: Path) -> Path:
    """Ten INVITE calls from one SBC to two carriers, for call_kpis. To carrier X
    (called numbers 447700900xxx, the 4477 prefix): answered after ringing (PDD 800 ms,
    60 s), answered without ringing (1.2 s, 30 s), busy 486 with Q.850 17 after ringing,
    cancelled while ringing (487), 503 with Q.850 34 after 300 ms. To carrier Y (1555...):
    answered after 183 (PDD 2 s, 120 s), 404 with Q.850 1, an INVITE that is never
    answered (retransmitted once), one challenged with 407 and answered on the retry
    (10 s), and a last INVITE half a second before the capture ends."""
    t0 = 1_700_007_000.0
    frames: list[tuple[float, bytes]] = []

    def call(i: int, carrier: str, called: str, steps: list[tuple], ua: str | None = None) -> None:
        cid = f"mix-{i}@sbc.example"
        frm = f"<sip:+15550100{100 + i}@sbc.example>;tag=m{i}"
        to = f"<sip:{called}@carrier.example>"
        ruri = f"sip:{called}@carrier.example"
        via = f"Via: SIP/2.0/UDP {SBC_IP}:5060;branch=z9hG4bKmix{i}"
        start = t0 + 20.0 * (i - 1) if i < 10 else CALL_MIX_END - 0.5
        for offset, kind, code, cseq, method, extra in steps:
            to_hdr = f"To: {to}" + (";tag=far" if kind == "resp" and code > 100 else "")
            if kind == "req":
                lines = [f"{method} {ruri} SIP/2.0", via, f"From: {frm}", to_hdr, f"Call-ID: {cid}",
                         f"CSeq: {cseq} {method}", "Max-Forwards: 70"]
                if method == "INVITE" and ua:
                    lines.append(f"User-Agent: {ua}")
                src, dst = SBC_IP, carrier
            else:
                lines = [f"SIP/2.0 {code} {extra.pop(0) if extra else 'X'}", via, f"From: {frm}", to_hdr,
                         f"Call-ID: {cid}", f"CSeq: {cseq} {method}"]
                src, dst = carrier, SBC_IP
            lines += extra or []
            frames.append((start + offset, _udp_frame(src, dst, 5060, 5060, _sip(lines))))

    def answered(ring: float | None, answer: float, talk: float) -> list[tuple]:
        steps = [(0.0, "req", 0, 1, "INVITE", None), (0.05, "resp", 100, 1, "INVITE", ["Trying"])]
        if ring is not None:
            steps.append((ring, "resp", 180, 1, "INVITE", ["Ringing"]))
        steps += [(answer, "resp", 200, 1, "INVITE", ["OK"]), (answer + 0.02, "req", 0, 1, "ACK", None),
                  (answer + talk, "req", 0, 2, "BYE", None), (answer + talk + 0.02, "resp", 200, 2, "BYE", ["OK"])]
        return steps

    def failed(ring: float | None, at: float, code: int, phrase: str, cause: int | None) -> list[tuple]:
        steps = [(0.0, "req", 0, 1, "INVITE", None), (0.05, "resp", 100, 1, "INVITE", ["Trying"])]
        if ring is not None:
            steps.append((ring, "resp", 180, 1, "INVITE", ["Ringing"]))
        reason = [phrase] + ([f"Reason: Q.850;cause={cause}"] if cause else [])
        steps += [(at, "resp", code, 1, "INVITE", reason), (at + 0.02, "req", 0, 1, "ACK", None)]
        return steps

    call(1, CARRIER_X, "+447700900001", answered(0.8, 5.0, 60.0), ua="SBC-A/1.0")
    call(2, CARRIER_X, "+447700900002", answered(None, 1.2, 30.0), ua="SBC-A/1.0")
    call(3, CARRIER_X, "00447700900003", failed(0.5, 4.0, 486, "Busy Here", 17), ua="SBC-A/1.0")
    call(4, CARRIER_X, "+447700900004", [(0.0, "req", 0, 1, "INVITE", None), (0.6, "resp", 180, 1, "INVITE", ["Ringing"]),
                                         (10.0, "req", 0, 1, "CANCEL", None),
                                         (10.02, "resp", 200, 1, "CANCEL", ["OK"]),
                                         (10.03, "resp", 487, 1, "INVITE", ["Request Terminated"]),
                                         (10.05, "req", 0, 1, "ACK", None)], ua="SBC-A/1.0")
    call(5, CARRIER_X, "+447700900005", failed(None, 0.3, 503, "Service Unavailable", 34), ua="SBC-A/1.0")
    call(6, CARRIER_Y, "+15550100601", [(0.0, "req", 0, 1, "INVITE", None),
                                        (2.0, "resp", 183, 1, "INVITE", ["Session Progress"]),
                                        (3.0, "resp", 200, 1, "INVITE", ["OK"]), (3.02, "req", 0, 1, "ACK", None),
                                        (123.0, "req", 0, 2, "BYE", None), (123.02, "resp", 200, 2, "BYE", ["OK"])],
         ua="SBC-B/2.1")
    call(7, CARRIER_Y, "+15550100602", failed(None, 0.2, 404, "Not Found", 1), ua="SBC-B/2.1")
    call(8, CARRIER_Y, "+15550100603", [(0.0, "req", 0, 1, "INVITE", None), (0.5, "req", 0, 1, "INVITE", None)],
         ua="SBC-B/2.1")
    call(9, CARRIER_Y, "+15550100604", [(0.0, "req", 0, 1, "INVITE", None),
                                        (0.1, "resp", 407, 1, "INVITE", ["Proxy Authentication Required"]),
                                        (0.12, "req", 0, 1, "ACK", None), (0.2, "req", 0, 2, "INVITE", None),
                                        (0.9, "resp", 180, 2, "INVITE", ["Ringing"]),
                                        (2.2, "resp", 200, 2, "INVITE", ["OK"]), (2.22, "req", 0, 2, "ACK", None),
                                        (12.2, "req", 0, 3, "BYE", None), (12.22, "resp", 200, 3, "BYE", ["OK"])],
         ua="SBC-B/2.1")
    call(10, CARRIER_Y, "+15550100605", [(0.0, "req", 0, 1, "INVITE", None)], ua="SBC-B/2.1")
    frames.append((CALL_MIX_END, _udp_frame(CARRIER_Y, SBC_IP, 5060, 5060, b"\r\n\r\n")))
    frames.sort(key=lambda f: f[0])
    return _frames_to_pcap(path, frames)


LEGS_UE = "198.51.100.70"
LEGS_PEER = "192.0.2.95"
LEGS_ICID = "icid-test-0001"
LEGS_UUID_1 = "0123456789abcdef0123456789abcdef"
LEGS_UUID_2 = "fedcba9876543210fedcba9876543210"
LEGS_NUMBER = "15550100700"


def write_call_legs_pcap(path: Path) -> Path:
    """Five calls through B2BUAs, for call_legs. A (t0): UE > SBC > S-CSCF > carrier X,
    linked by icid (legs 0 and 1) and Session-ID (legs 1 and 2); the carrier answers 480
    with Q.850 18, the S-CSCF passes it on, the SBC sends 503 with Q.850 34 to the UE; the
    SBC strips the offer to PCMU and the S-CSCF adds Privacy: id. B (t0+20): peer > SBC >
    carrier Y linked by X-Orig-Call-ID, answered (SBC adds 40 ms to the INVITE and 30 ms to
    the 200). C (t0+40): peer > SBC > carrier Y with no identifier, the same SDP address and
    port on both legs, answered. D (t0+60): UE > SBC (+15550100700) > carrier X
    (015550100700, no SDP) linked only by number and time, 404 with Q.850 1 on both. E
    (t0+120): one more INVITE from the SBC to the same number, outside any window: a call of
    one leg, answered."""
    t0 = 1_700_008_000.0
    frames: list[tuple[float, bytes]] = []

    def leg(cid: str, src: str, dst: str, called: str, start: float, steps: list[tuple[float, int, list[str]]],
            extra: list[str] | None = None, body: str = "", pai: str | None = None) -> None:
        ruri = f"sip:{called}@legs.example"
        frm = f"<sip:+15550100100@legs.example>;tag={cid[:6]}"
        to = f"<{ruri}>"
        via = f"Via: SIP/2.0/UDP {src}:5060;branch=z9hG4bK{cid.replace('@', '').replace('.', '')}"
        lines = [f"INVITE {ruri} SIP/2.0", via, f"From: {frm}", f"To: {to}", f"Call-ID: {cid}", "CSeq: 1 INVITE",
                 "Max-Forwards: 70"] + ([f"P-Asserted-Identity: {pai}"] if pai else []) + (extra or [])
        if body:
            lines.append("Content-Type: application/sdp")
        frames.append((start, _udp_frame(src, dst, 5060, 5060, _sip(lines, body))))
        for offset, code, hdrs in steps:
            if code == 0:  # ACK or BYE from the caller side
                method = hdrs[0]
                cseq = 1 if method == "ACK" else 2
                req = [f"{method} {ruri} SIP/2.0", via, f"From: {frm}", f"To: {to};tag=far", f"Call-ID: {cid}",
                       f"CSeq: {cseq} {method}"]
                frames.append((start + offset, _udp_frame(src, dst, 5060, 5060, _sip(req))))
                continue
            phrase, *rest = hdrs
            cseq_line = "CSeq: 2 BYE" if phrase == "OK BYE" else "CSeq: 1 INVITE"
            resp = [f"SIP/2.0 {code} {phrase.replace(' BYE', '')}", via, f"From: {frm}",
                    f"To: {to}" + (";tag=far" if code > 100 else ""), f"Call-ID: {cid}", cseq_line] + rest
            frames.append((start + offset, _udp_frame(dst, src, 5060, 5060, _sip(resp))))

    wide = _sdp(LEGS_UE, 40000, [118, 0], ["118 AMR-WB/16000", "0 PCMU/8000"])
    narrow = _sdp(SBC_IP, 20000, [0], ["0 PCMU/8000"])
    pai = "<sip:+15550100100@legs.example>"
    # A: 480 from the carrier, 503 to the UE.
    fail = lambda code, phrase, cause: [(0.05, 100, ["Trying"]), (0.6, 180, ["Ringing"]),  # noqa: E731
                                       (3.0, code, [phrase, f"Reason: Q.850;cause={cause}"]), (3.01, 0, ["ACK"])]
    leg("legs-a1@ue.example", LEGS_UE, SBC_IP, "+15550100500", t0,
        [(0.02, 100, ["Trying"]), (0.65, 180, ["Ringing"]), (3.2, 503, ["Service Unavailable", "Reason: Q.850;cause=34"]),
         (3.21, 0, ["ACK"])], extra=[f'P-Charging-Vector: icid-value="{LEGS_ICID}";orig-ioi=legs.example'],
        body=wide, pai=pai)
    leg("legs-a2@sbc.example", SBC_IP, SCSCF_IP, "+15550100500", t0 + 0.03,
        [(0.02, 100, ["Trying"]), (0.6, 180, ["Ringing"]), (3.02, 480, ["Temporarily Unavailable",
                                                                       "Reason: Q.850;cause=18"]), (3.03, 0, ["ACK"])],
        extra=[f'P-Charging-Vector: icid-value="{LEGS_ICID}"', f"Session-ID: {LEGS_UUID_1}"], body=narrow, pai=pai)
    leg("legs-a3@scscf.example", SCSCF_IP, CARRIER_X, "+15550100500", t0 + 0.05,
        fail(480, "Temporarily Unavailable", 18),
        extra=[f"Session-ID: {LEGS_UUID_2};remote={LEGS_UUID_1}", "Privacy: id"], body=narrow, pai=pai)
    # B: answered, linked by X-Orig-Call-ID.
    tb = t0 + 20.0
    ok = lambda answer: [(0.02, 100, ["Trying"]), (answer, 200, ["OK"]), (answer + 0.01, 0, ["ACK"]),  # noqa: E731
                         (answer + 10.0, 0, ["BYE"]), (answer + 10.01, 200, ["OK BYE"])]
    leg("legs-b1@peer.example", LEGS_PEER, SBC_IP, "+15550100600", tb, ok(4.03), body=wide)
    leg("legs-b2@sbc.example", SBC_IP, CARRIER_Y, "+15550100600", tb + 0.04, ok(3.96),
        extra=["X-Orig-Call-ID: legs-b1@peer.example"], body=narrow)
    # C: no identifier, the SBC passes the SDP through.
    tc = t0 + 40.0
    leg("legs-c1@peer.example", LEGS_PEER, SBC_IP, "+15550100650", tc, ok(2.0), body=wide)
    leg("legs-c2@sbc.example", SBC_IP, CARRIER_Y, "+445550100650", tc + 0.02, ok(1.98), body=wide)
    # D: only the number and the time link the legs.
    td = t0 + 60.0
    leg("legs-d1@ue.example", LEGS_UE, SBC_IP, f"+{LEGS_NUMBER}", td,
        [(0.02, 100, ["Trying"]), (0.5, 404, ["Not Found", "Reason: Q.850;cause=1"]), (0.51, 0, ["ACK"])], body=wide)
    leg("legs-d2@sbc.example", SBC_IP, CARRIER_X, f"0{LEGS_NUMBER}", td + 0.03,
        [(0.02, 100, ["Trying"]), (0.45, 404, ["Not Found", "Reason: Q.850;cause=1"]), (0.46, 0, ["ACK"])])
    # E: the same number again, a minute later.
    leg("legs-e1@sbc.example", SBC_IP, CARRIER_X, f"0{LEGS_NUMBER}", t0 + 120.0, ok(1.0))
    frames.sort(key=lambda f: f[0])
    return _frames_to_pcap(path, frames)


def write_voice_pcaps(directory: Path) -> dict[str, Path]:
    """The voice captures, kept in their own directory so the directory scans of the
    signalling captures are unchanged."""
    directory.mkdir(parents=True, exist_ok=True)
    return {
        "voice_call": write_voice_call_pcap(directory / "voice_call.pcap"),
        "voice_problems": write_voice_problems_pcap(directory / "voice_problems.pcap"),
        "rtp_no_sdp": write_rtp_without_sdp_pcap(directory / "rtp_no_sdp.pcap"),
        "voice_dtmf": write_voice_dtmf_pcap(directory / "voice_dtmf.pcap"),
        "call_mix": write_call_mix_pcap(directory / "call_mix.pcap"),
        "call_legs": write_call_legs_pcap(directory / "call_legs.pcap"),
    }


# --------------------------------------------------------------------------- examples/
# The captures committed under examples/ in the repository. Each tells one story in a
# few dozen packets; ``tests/test_examples.py`` regenerates them and checks that the
# committed files are byte-identical and that the tools still read them as documented.

EXAMPLE_CALL_ID = "one-way-audio-1@ue.example"
EXAMPLE_IMSI_NO_EPS = "001010222333444"


def write_example_sip_one_way_audio(path: Path) -> Path:
    """One call where the called side never sends media. INVITE with an SDP offer
    (PCMA and telephone-event), 100, 180, 200 with the answer, ACK; the caller sends
    5 s of RTP to the address and port the answer named, nothing comes back; the caller
    hangs up with BYE."""
    t0 = 1_700_001_000.0
    frames: list[tuple[float, bytes]] = []
    req, resp = _voice_sip(EXAMPLE_CALL_ID, "ow1")

    def ue(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(UE_SIP_IP, PCSCF_IP, 5060, 5060, msg)))

    def net(ts: float, msg: bytes) -> None:
        frames.append((ts, _udp_frame(PCSCF_IP, UE_SIP_IP, 5060, 5060, msg)))

    offer = _sdp(UE_SIP_IP, 40010, [8, 101], ["8 PCMA/8000", "101 telephone-event/8000"],
                 ["a=fmtp:101 0-15", "a=ptime:20", "a=sendrecv"])
    answer = _sdp(MEDIA_GW_IP, 30010, [8, 101], ["8 PCMA/8000", "101 telephone-event/8000"],
                  ["a=fmtp:101 0-15", "a=ptime:20", "a=sendrecv"])
    ue(t0, req("INVITE", 1, extra=["Contact: <sip:198.51.100.9:5060>"], body=offer))
    net(t0 + 0.030, resp(100, "Trying", 1, "INVITE", to_tag=None))
    net(t0 + 0.900, resp(180, "Ringing", 1, "INVITE"))
    net(t0 + 2.400, resp(200, "OK", 1, "INVITE", body=answer))
    ue(t0 + 2.420, req("ACK", 1, to_tag="net"))
    _audio(frames, t0 + 2.5, UE_SIP_IP, 40010, MEDIA_GW_IP, 30010, 0x6A6A6A6A, 8, 8000, 250, 1, 0)
    ue(t0 + 7.600, req("BYE", 2, to_tag="net"))
    net(t0 + 7.625, resp(200, "OK", 2, "BYE"))
    frames.sort(key=lambda f: f[0])
    return _frames_to_pcap(path, frames)


def write_example_diameter_error_answer(path: Path) -> Path:
    """S6a between an MME and an HSS: an Update-Location for one subscriber answered
    DIAMETER_SUCCESS, the same request for a second subscriber answered with
    Experimental-Result 5420 (DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION), and a
    watchdog exchange."""
    mme = "mme01.epc.mnc001.mcc001.3gppnetwork.org"
    hss = "hss01.epc.mnc001.mcc001.3gppnetwork.org"
    realm = "epc.mnc001.mcc001.3gppnetwork.org"
    t0 = 1_700_002_000.0
    frames: list[tuple[float, bytes]] = []
    tsn = 500

    def send(ts: float, msg: bytes, from_mme: bool) -> None:
        nonlocal tsn
        if from_mme:
            frames.append((ts, _sctp_data(MME_IP, HSS_IP, 3868, 3868, 0x1111, tsn, 46, msg)))
        else:
            frames.append((ts, _sctp_data(HSS_IP, MME_IP, 3868, 3868, 0x2222, tsn, 46, msg)))
        tsn += 1

    def ulr(sid: str, imsi: str, hbh: int, e2e: int) -> bytes:
        return _diameter(316, S6A, hbh, e2e, True, _diam_common(sid, mme, realm, realm) + [
            _avp(1, imsi.encode()),
            _avp(1032, struct.pack("!I", 1004), vendor=VENDOR_3GPP),  # RAT-Type EUTRAN
            _avp(1405, struct.pack("!I", 0x22), vendor=VENDOR_3GPP),  # ULR-Flags
            _avp(1407, bytes([0x00, 0xF1, 0x10]), vendor=VENDOR_3GPP),  # Visited-PLMN-Id 001/01
        ])

    sid1 = f"{mme};1700002000;1"
    ula_ok = _diameter(316, S6A, 0x2001, 0xB001, False, [
        _avp(263, sid1.encode()),
        _avp(268, struct.pack("!I", 2001)),
        _avp(264, hss.encode()),
        _avp(296, realm.encode()),
        _avp(258, struct.pack("!I", S6A)),
        _avp(1406, struct.pack("!I", 1), vendor=VENDOR_3GPP),  # ULA-Flags
    ])
    send(t0 + 0.000, ulr(sid1, IMSI, 0x2001, 0xB001), True)
    send(t0 + 0.052, ula_ok, False)

    sid2 = f"{mme};1700002000;2"
    ula_err = _diameter(316, S6A, 0x2002, 0xB002, False, [
        _avp(263, sid2.encode()),
        _avp(297, _avp(266, struct.pack("!I", VENDOR_3GPP)) + _avp(298, struct.pack("!I", 5420))),
        _avp(264, hss.encode()),
        _avp(296, realm.encode()),
        _avp(258, struct.pack("!I", S6A)),
    ])
    send(t0 + 1.000, ulr(sid2, EXAMPLE_IMSI_NO_EPS, 0x2002, 0xB002), True)
    send(t0 + 1.037, ula_err, False)

    dwr = _diameter(280, 0, 0x2003, 0xB003, True, [_avp(264, hss.encode()), _avp(296, realm.encode())])
    dwa = _diameter(280, 0, 0x2003, 0xB003, False, [
        _avp(268, struct.pack("!I", 2001)), _avp(264, mme.encode()), _avp(296, realm.encode()),
    ])
    send(t0 + 5.000, dwr, False)
    send(t0 + 5.003, dwa, True)
    return _frames_to_pcap(path, frames)


def write_example_gtpv2_create_session_rejected(path: Path) -> Path:
    """S5/S8 between an SGW and a PGW: an Echo exchange, a Create Session accepted with
    a PDN address, a Create Session for a second subscriber rejected with cause 78
    (Missing or unknown APN), and the first session deleted cleanly."""
    t0 = 1_700_003_000.0
    frames: list[tuple[float, bytes]] = []

    def c(ts: float, msg: bytes, from_sgw: bool = True) -> None:
        if from_sgw:
            frames.append((ts, _udp_frame(SGW_IP, PGW_IP, 2123, 2123, msg)))
        else:
            frames.append((ts, _udp_frame(PGW_IP, SGW_IP, 2123, 2123, msg)))

    c(t0 + 0.0, _gtpv2(1, None, 1, [_ie(3, bytes([7]))]))
    c(t0 + 0.002, _gtpv2(2, None, 1, [_ie(3, bytes([9]))]), from_sgw=False)

    csr = _gtpv2(32, 0, 20, [
        _ie(1, _tbcd(IMSI)),
        _ie(76, _tbcd(MSISDN)),
        _ie(82, bytes([6])),  # RAT type EUTRAN
        _ie(87, _fteid(6, 0x0000A101, SGW_IP)),  # S5/S8 SGW GTP-C
        _apn_ie(APN),
        _ie(99, bytes([1])),  # PDN type IPv4
        _ie(79, bytes([1, 0, 0, 0, 0])),
        _ie(93, _ie(73, bytes([5])) + _ie(87, _fteid(4, 0x0000B101, SGW_IP), instance=2)),
    ])
    csresp = _gtpv2(33, 0x0000A101, 20, [
        _ie(2, bytes([16, 0])),  # Request accepted
        _ie(87, _fteid(7, 0x0000C101, PGW_IP), instance=1),
        _ie(79, bytes([1]) + _ipv4(UE_IP)),
        _ie(93, _ie(73, bytes([5])) + _ie(2, bytes([16, 0])) + _ie(87, _fteid(5, 0x0000D101, PGW_IP), instance=2)),
    ])
    c(t0 + 1.000, csr)
    c(t0 + 1.095, csresp, from_sgw=False)

    csr2 = _gtpv2(32, 0, 21, [
        _ie(1, _tbcd(IMSI_OTHER)),
        _ie(76, _tbcd(MSISDN_OTHER)),
        _ie(82, bytes([6])),
        _ie(87, _fteid(6, 0x0000A102, SGW_IP)),
        _apn_ie("internet.wrong.apn"),
        _ie(99, bytes([1])),
        _ie(93, _ie(73, bytes([5])) + _ie(87, _fteid(4, 0x0000B102, SGW_IP), instance=2)),
    ])
    csresp2 = _gtpv2(33, 0x0000A102, 21, [_ie(2, bytes([78, 0]))])  # Missing or unknown APN
    c(t0 + 2.000, csr2)
    c(t0 + 2.028, csresp2, from_sgw=False)

    dsr = _gtpv2(36, 0x0000C101, 22, [_ie(73, bytes([5]))])
    dsresp = _gtpv2(37, 0x0000A101, 22, [_ie(2, bytes([16, 0]))])
    c(t0 + 9.000, dsr)
    c(t0 + 9.041, dsresp, from_sgw=False)
    return _frames_to_pcap(path, frames)


def write_example_pcaps(directory: Path) -> dict[str, Path]:
    """The three captures committed under ``examples/``."""
    directory.mkdir(parents=True, exist_ok=True)
    return {
        "sip_one_way_audio": write_example_sip_one_way_audio(directory / "sip_one_way_audio.pcap"),
        "diameter_error_answer": write_example_diameter_error_answer(directory / "diameter_error_answer.pcap"),
        "gtpv2_create_session_rejected": write_example_gtpv2_create_session_rejected(
            directory / "gtpv2_create_session_rejected.pcap"),
    }


def write_all(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    return {
        "diameter": write_diameter_pcap(directory / "diameter.pcap"),
        "gtpv2": write_gtpv2_pcap(directory / "gtpv2.pcap"),
        "gtpu": write_gtpu_pcap(directory / "gtpu.pcap"),
        "sip": write_sip_pcap(directory / "sip.pcap"),
        "sctp": write_sctp_pcap(directory / "sctp.pcap"),
        "sigtran": write_sigtran_pcap(directory / "sigtran.pcap"),
    }


def write_merged_pcap(path: Path, directory: Path) -> Path:
    """Merge every capture produced by :func:`write_all` into one time-sorted file."""
    from scapy.all import rdpcap  # type: ignore

    packets = []
    for name in ("diameter", "gtpv2", "gtpu", "sip", "sctp", "sigtran"):
        packets.extend(rdpcap(str(directory / f"{name}.pcap")))
    packets.sort(key=lambda p: float(p.time))
    wrpcap(str(path), packets)
    return path


if __name__ == "__main__":  # pragma: no cover
    import sys

    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    for name, p in {**write_all(out), **write_voice_pcaps(out / "voice"), **write_ims_pcaps(out / "ims")}.items():
        print(name, p)

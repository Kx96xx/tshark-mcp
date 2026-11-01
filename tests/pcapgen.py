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
    for name, p in write_all(out).items():
        print(name, p)

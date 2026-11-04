"""Recognise a second copy of a packet already seen in the same capture.

A capture taken on several interfaces, a SPAN session mirroring both ingress and
egress, or a host that sees a packet tunnelled and then decapsulated holds the
same packet more than once. tshark's TCP analysis counts the later copies as
retransmissions. A copy carries the same IP identification, addresses, length
and transport header as the first; a genuine retransmission is a new packet with
a new IP ID. When the IP ID is zero (common with DF set) only packets that arrive
within a few milliseconds of each other are treated as copies. Only the
innermost IP ID counts, in the key and in the choice of window: the outer ID of a
tunnel changes between legs and between a retransmission and its original alike.
"""

from __future__ import annotations

from typing import Any, Hashable

DUPLICATE_WINDOW_S = 0.005


class CopyTracker:
    """Remembers each packet key and says whether a new packet repeats one.

    ``id_window`` bounds how far apart two packets with a non-zero IP ID may be
    and still count as copies (``None``: any distance, for a single tunnel whose
    IDs do not wrap within a capture). ``zero_window`` applies when every IP ID
    in the key is zero.
    """

    def __init__(self, id_window: float | None = None, zero_window: float = DUPLICATE_WINDOW_S) -> None:
        self.id_window = id_window
        self.zero_window = zero_window
        self._seen: dict[Hashable, tuple[float | None, Any, Any]] = {}

    def check(self, key: Hashable, nonzero_id: bool, time: float | None, info: Any = None,
              distinct: Any = None) -> tuple[bool, Any]:
        """(is a copy, the ``info`` stored with the first sighting). The latest time is kept.

        ``distinct`` is a value a true copy must share when both packets carry it (a
        verified transport checksum, see :func:`copy_distinct`): two packets whose
        ``distinct`` values differ are different packets however alike their headers, as
        with a stack that reuses one IP ID, and the newer one starts a new sighting."""
        previous = self._seen.get(key)
        if previous is not None and distinct is not None and previous[2] is not None and previous[2] != distinct:
            previous = None
        self._seen[key] = (time, previous[1] if previous is not None else info, distinct)
        if previous is None:
            return False, None
        seen_at, first_info, _ = previous
        window = self.id_window if nonzero_id else self.zero_window
        if window is None:
            return True, first_info
        if time is None or seen_at is None:
            return False, None
        return abs(time - seen_at) <= window, first_info


def nonzero(*ids: str | None) -> bool:
    """True when any of the IP IDs (hex or decimal text) is present and not zero."""
    for value in ids:
        if not value:
            continue
        try:
            if int(value, 0) != 0:
                return True
        except ValueError:
            continue
    return False


GOOD_CHECKSUM = "1"


def copy_distinct(rec: dict[str, Any], has_id: bool) -> str | None:
    """The verified TCP or UDP checksum of a generic packet record, for ``CopyTracker.check``.

    With an IP ID the checksum stays out of :func:`copy_key` because a copy taken before
    checksum offload carries a wrong one. But when tshark verified both checksums as good
    (``capture_quality`` asks it to) and they differ, the packets differ: a stack that sends
    every datagram with the same IP ID must not turn a whole RTP stream into copies."""
    if not has_id:
        return None
    transport = rec.get("tcp") or rec.get("udp")
    if transport and transport.get("checksum") == GOOD_CHECKSUM and transport.get("checksum_value"):
        return transport["checksum_value"]
    return None


def has_ip_id(rec: dict[str, Any]) -> bool:
    """Whether a generic packet record (``packets.record``) has a usable IP ID: the innermost one,
    the only one ``copy_key`` holds. An outer tunnel ID differs between legs and says nothing about
    the packet inside, so it must not choose the long window for a key that does not hold it."""
    return nonzero(rec.get("id"))


def copy_key(rec: dict[str, Any], has_id: bool) -> tuple | None:
    """The key a copy of a generic packet record (``packets.record``) shares with the original.
    Without an IP ID the transport (or ICMP) checksum is part of it: it differs with the payload.
    The ICMP checksum and the quoted echo sequence need ``icmp.checksum``, ``icmpv6.checksum``,
    ``icmp.seq`` and ``icmpv6.echo.sequence_number`` in the caller's field list, and the SCTP
    fields ``sctp.verification_tag``, ``sctp.chunk_type``, ``sctp.data_tsn_raw``,
    ``sctp.sack_cumulative_tsn_ack_raw``, ``sctp.sack_a_rwnd`` and
    ``sctp.parameter_heartbeat_information``."""
    if not rec.get("src"):
        return None
    tcp, udp = rec.get("tcp"), rec.get("udp")
    if tcp:
        transport: tuple = ("tcp", tcp["sport"], tcp["dport"], tcp["seq"], tcp["ack_no"], tcp["len"], tcp["syn"], tcp["fin"],
                            tcp["rst"], None if has_id else tcp.get("checksum_value"))
    elif udp:
        transport = ("udp", udp["sport"], udp["dport"], udp["len"], None if has_id else udp.get("checksum_value"))
    elif rec.get("sctp"):
        # SCTP: two SACKs, DATA packets or heartbeats of one association are different packets,
        # and they differ in the TSNs, the acknowledged TSN or the heartbeat information, whether
        # or not the stack gives them distinct IP IDs (Linux sends SCTP with DF and ID 0; other
        # stacks reuse one ID). The CRC32c is left out: a copy taken before checksum offload
        # carries 0 there and the copy on the wire the real value.
        sc = rec["sctp"]
        transport = ("sctp", sc["vtag"], sc["chunks"], sc["tsns"], sc["cum_tsn"], sc["a_rwnd"], sc["heartbeat"])
    else:
        # ICMP without an IP ID: the checksum tells an echo or other message from the next one. It
        # cannot tell two errors apart, though: when the quoted packets differ only in fields their
        # own checksums cover (IP ID, ports, sequence number), those checksums change by the
        # opposite amount and the ICMP checksum stays the same. So an error also keys on the
        # packet it quotes (addresses, IP ID, ports or TCP/echo sequence number).
        icmp = rec.get("icmp_error") or rec.get("icmp") or {}
        q = rec.get("quoted") or {}
        quoted = (q.get("src"), q.get("dst"), q.get("id"), q.get("proto"), q.get("sport"), q.get("dport"), q.get("seq")) \
            if rec.get("icmp_error") and not has_id else None
        transport = (rec.get("proto") or icmp.get("family"), icmp.get("type"), icmp.get("code"),
                     None if has_id else icmp.get("checksum"), quoted)
    return (rec["src"], rec["dst"], rec.get("id"), rec.get("ip_len"), *transport)


class ZeroedIdTracker:
    """Copies whose IP ID the writing tool set to 0 while the original keeps its real one.

    A capture tool that writes a decapsulated copy of each tunnelled packet may rebuild the IP header with
    IP ID 0, so ``copy_key`` (which holds the IP ID) cannot match the pair. This key leaves the IP ID out and
    keeps the transport checksum, which does not cover the IP ID, and two packets count as copies only when
    one of them has IP ID 0 and they arrive within ``window``. Two packets with different non-zero IDs are
    never copies here, however alike.
    """

    def __init__(self, window: float = DUPLICATE_WINDOW_S) -> None:
        self.window = window
        self._seen: dict[Hashable, tuple[float | None, bool]] = {}

    def check(self, rec: dict[str, Any], time: float | None) -> bool:
        key = copy_key({**rec, "id": None}, False)
        if key is None:
            return False
        zero = not nonzero(rec.get("id"))
        previous = self._seen.get(key)
        self._seen[key] = (time, zero)
        if previous is None or time is None or previous[0] is None:
            return False
        return (zero or previous[1]) and abs(time - previous[0]) <= self.window

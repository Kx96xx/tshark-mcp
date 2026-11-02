"""Recognise a second copy of a packet already seen in the same capture.

A capture taken on several interfaces, a SPAN session mirroring both ingress and
egress, or a host that sees a packet tunnelled and then decapsulated holds the
same packet more than once. tshark's TCP analysis counts the later copies as
retransmissions. A copy carries the same IP identification, addresses, length
and transport header as the first; a genuine retransmission is a new packet with
a new IP ID. When the IP ID is zero (common with DF set) only packets that arrive
within a few milliseconds of each other are treated as copies.
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
        self._seen: dict[Hashable, tuple[float | None, Any]] = {}

    def check(self, key: Hashable, nonzero_id: bool, time: float | None, info: Any = None) -> tuple[bool, Any]:
        """(is a copy, the ``info`` stored with the first sighting). The latest time is kept."""
        previous = self._seen.get(key)
        self._seen[key] = (time, previous[1] if previous is not None else info)
        if previous is None:
            return False, None
        seen_at, first_info = previous
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


def copy_key(rec: dict[str, Any], has_id: bool) -> tuple | None:
    """The key a copy of a generic packet record (``packets.record``) shares with the original.
    Without an IP ID the transport checksum is part of it: it differs with the payload."""
    if not rec.get("src"):
        return None
    tcp, udp = rec.get("tcp"), rec.get("udp")
    if tcp:
        transport: tuple = ("tcp", tcp["sport"], tcp["dport"], tcp["seq"], tcp["ack_no"], tcp["len"], tcp["syn"], tcp["fin"],
                            tcp["rst"], None if has_id else tcp.get("checksum_value"))
    elif udp:
        transport = ("udp", udp["sport"], udp["dport"], udp["len"], None if has_id else udp.get("checksum_value"))
    else:
        transport = (rec.get("proto"), (rec.get("icmp_error") or rec.get("icmp") or {}).get("type"))
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

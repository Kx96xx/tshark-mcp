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

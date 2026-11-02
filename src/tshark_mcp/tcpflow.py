"""TCP sequence tracking per direction: where was a segment lost, if at all?

Fed with TCP segments from which duplicate copies were already removed (see
``copies``), the tracker follows the highest sequence number seen in each
direction and the acknowledgements coming back from the other side:

* a segment that starts beyond the next expected byte leaves a *gap*;
* a gap later filled by a retransmission was lost before the capture point
  (``lost_before_capture``), unless the IP ID shows the filling segment was sent
  before the one that opened the gap (``out_of_order``);
* a gap the receiver acknowledges without the capture ever seeing it was missed
  by the capture itself (``missed_by_capture``): the network delivered it;
* a retransmission of bytes the capture already saw means they were lost after
  the capture point, or the acknowledgement was (``retransmitted_after_capture``);
* a gap neither filled nor acknowledged by the end stays ``unresolved``.

Sequence numbers are compared modulo 2**32.
"""

from __future__ import annotations

from typing import Any

MOD = 2 ** 32
HALF = 2 ** 31
MAX_GAPS = 256
REORDER_WINDOW_S = 0.003


def ahead(a: int, b: int) -> bool:
    """``a`` is later in sequence space than ``b``."""
    return 0 < (a - b) % MOD < HALF


def dist(a: int, b: int) -> int:
    """Bytes from ``b`` up to ``a`` (``a`` ahead of ``b``)."""
    return (a - b) % MOD


class Direction:
    __slots__ = ("isn", "next", "gaps", "acked", "segments", "data_segments", "bytes", "lost_before", "after",
                 "out_of_order", "missed", "missed_bytes", "untracked", "keepalives", "syn_retrans", "last_id",
                 "id_steps", "id_near", "packets", "first_frame", "max_len", "retrans_frames", "events", "last_zero_seq")

    def __init__(self) -> None:
        self.isn: int | None = None
        self.next: int | None = None
        self.gaps: list[list[Any]] = []  # [start, end, time, ip_id, frame]
        self.acked: int | None = None
        self.segments = self.data_segments = self.bytes = 0
        self.lost_before = self.after = self.out_of_order = 0
        self.missed = self.missed_bytes = self.untracked = 0
        self.keepalives = self.syn_retrans = 0
        self.last_id: int | None = None
        self.id_steps = self.id_near = 0
        self.packets = 0
        self.first_frame: int | None = None
        self.max_len = 0
        self.retrans_frames: list[tuple[int | None, int, int, str]] = []  # (frame, seq, len, kind)
        self.events: list[dict[str, Any]] = []
        self.last_zero_seq: int | None = None

    @property
    def sequential_ids(self) -> bool:
        return self.id_steps >= 2 and self.id_near >= 0.8 * self.id_steps

    def unresolved(self) -> int:
        return len(self.gaps)


def tcp_tsval(rec: dict[str, Any]) -> int | None:
    return (rec.get("tcp") or {}).get("tsval")


def _ip_id(value: str | None) -> int | None:
    if not value:
        return None
    try:
        v = int(value, 0)
    except ValueError:
        return None
    return v or None


class FlowTracker:
    """Per-direction state for every TCP flow, keyed by (src, sport, dst, dport)."""

    def __init__(self, keep_retrans_frames: int = 0) -> None:
        self.dirs: dict[tuple[str, str, str, str], Direction] = {}
        self.keep = keep_retrans_frames

    def direction(self, key: tuple[str, str, str, str]) -> Direction:
        d = self.dirs.get(key)
        if d is None:
            d = self.dirs[key] = Direction()
        return d

    def feed(self, rec: dict[str, Any]) -> str | None:
        """Account one segment; returns its classification when it is not plain in-order traffic:
        ``keepalive``, ``syn_retransmission``, ``gap``, ``lost_before_capture``, ``out_of_order``
        or ``retransmitted_after_capture``."""
        tcp = rec["tcp"]
        key = (rec["src"], tcp["sport"], rec["dst"], tcp["dport"])
        rkey = (rec["dst"], tcp["dport"], rec["src"], tcp["sport"])
        d = self.direction(key)
        d.packets += 1
        if d.first_frame is None:
            d.first_frame = rec.get("frame")
        kind = None if tcp["rst"] else self._sequence(d, rec, tcp)
        if tcp["ack"] and tcp["ack_no"] is not None and not tcp["rst"]:
            r = self.dirs.get(rkey)
            if r is not None:
                self._acknowledge(r, tcp["ack_no"], rec)
        return kind

    # ----------------------------------------------------------- sequence side
    def _sequence(self, d: Direction, rec: dict[str, Any], tcp: dict[str, Any]) -> str | None:
        seq, length = tcp["seq"], tcp["len"]
        if seq is None:
            return None
        d.segments += 1
        if length > 0:
            d.data_segments += 1
            d.bytes += length
            d.max_len = max(d.max_len, length)
        ip_id = _ip_id(rec.get("id"))
        if ip_id is not None:
            if d.last_id is not None:
                d.id_steps += 1
                if min((ip_id - d.last_id) % 65536, (d.last_id - ip_id) % 65536) <= 64:
                    d.id_near += 1
            if d.last_id is None or 0 < (ip_id - d.last_id) % 65536 < 32768:
                d.last_id = ip_id
        end = (seq + length + (1 if tcp["syn"] or tcp["fin"] else 0)) % MOD
        if tcp["syn"]:
            if d.isn is not None and seq == d.isn:
                d.syn_retrans += 1
                self._note(d, rec, seq, length, "syn_retransmission")
                return "syn_retransmission"
            d.isn, d.next, d.gaps = seq, end, []
            return None
        if d.next is None:
            d.next = end
            if length == 0 and not tcp["fin"]:
                d.last_zero_seq = seq
            return None
        if length == 0 and not tcp["fin"]:
            d.last_zero_seq = seq
            return None
        if length <= 1 and not tcp["fin"] and seq == (d.next - 1) % MOD:
            d.keepalives += 1
            return "keepalive"
        if ahead(seq, d.next):
            if len(d.gaps) < MAX_GAPS:
                d.gaps.append([d.next, seq, rec.get("time"), ip_id, rec.get("frame"), None, tcp.get("tsval")])
            else:
                d.untracked += 1
            d.next = end
            return "gap"
        if seq == d.next:
            d.next = end
            return None
        # Behind the highest byte seen: fills a gap, or repeats bytes the capture already saw.
        kind = self._fill(d, seq, end, rec, ip_id)
        if ahead(end, d.next):
            d.next = end
        if kind == "lost_before_capture":
            d.lost_before += 1
        elif kind == "out_of_order":
            d.out_of_order += 1
        else:
            d.after += 1
        if kind != "out_of_order":
            self._note(d, rec, seq, length, kind)
        return kind

    def _fill(self, d: Direction, seq: int, end: int, rec: dict[str, Any], ip_id: int | None) -> str:
        hit = None
        kept: list[list[Any]] = []
        for gap in d.gaps:
            g_start, g_end = gap[0], gap[1]
            if ahead(g_end, seq) and ahead(end, g_start):  # the segment overlaps the gap
                hit = hit or gap
                if ahead(seq, g_start):
                    kept.append([g_start, seq, *gap[2:]])
                if ahead(g_end, end):
                    kept.append([end, g_end, *gap[2:]])
            else:
                kept.append(gap)
        if hit is None:
            return "retransmitted_after_capture"
        d.gaps = kept
        opened_time, opened_id, opened_ts = hit[2], hit[3], hit[6]
        if ip_id is not None and opened_id is not None and d.sequential_ids:
            # Sent before the segment that opened the gap: it was overtaken, not lost.
            return "out_of_order" if 0 < (opened_id - ip_id) % 65536 < 32768 else "lost_before_capture"
        tsval = tcp_tsval(rec)
        if tsval is not None and opened_ts is not None and tsval != opened_ts:
            # The TCP timestamp option says when the sender sent it (IPv6 has no IP ID).
            return "out_of_order" if 0 < (opened_ts - tsval) % MOD < HALF else "lost_before_capture"
        t = rec.get("time")
        if t is not None and opened_time is not None and t - opened_time <= REORDER_WINDOW_S:
            return "out_of_order"
        return "lost_before_capture"

    # ----------------------------------------------------------- acknowledgement side
    def _acknowledge(self, r: Direction, ack: int, rec: dict[str, Any]) -> None:
        if r.next is None:
            return
        if ack == (r.next + 1) % MOD and r.last_zero_seq == r.next:
            # The answer to a keep-alive probe (an empty segment one byte below the next
            # sequence number) that set the baseline of a stream joined midway.
            r.keepalives += 1
            r.next = ack
        if ahead(ack, r.next):
            # The receiver acknowledges bytes beyond anything captured in that direction.
            r.missed += 1
            r.missed_bytes += dist(ack, r.next)
            self._note(r, rec, r.next, dist(ack, r.next), "missed_by_capture")
            r.next = ack
        if r.gaps:
            kept = []
            for gap in r.gaps:
                g_start, g_end = gap[0], gap[1]
                if not ahead(ack, g_start):
                    kept.append(gap)
                    continue
                covered = ack if ahead(g_end, ack) else g_end
                r.missed_bytes += dist(covered, g_start)
                if not gap[5]:  # count each gap once, even when acknowledged piece by piece
                    r.missed += 1
                    self._note(r, rec, g_start, dist(covered, g_start), "missed_by_capture")
                if covered != g_end:
                    kept.append([covered, g_end, gap[2], gap[3], gap[4], True, gap[6]])
            r.gaps = kept
        if r.acked is None or ahead(ack, r.acked):
            r.acked = ack

    def _note(self, d: Direction, rec: dict[str, Any], seq: int, length: int, kind: str) -> None:
        if len(d.retrans_frames) < self.keep:
            d.retrans_frames.append((rec.get("frame"), seq, length, kind))

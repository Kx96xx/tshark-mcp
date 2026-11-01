"""Generic request/answer pairing.

Each protocol module turns packets into :class:`Message` objects with a
``key`` (for Diameter the Hop-by-Hop and End-to-End identifiers, for GTPv2 the
sequence number and peer pair, and so on). :func:`pair_messages` then walks the
messages in time order, matching every answer to the oldest pending request
with the same key, and reports requests that never got an answer.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Hashable, Iterable

from .fields import iso


@dataclass
class Message:
    frame: int
    time: float
    src: str
    dst: str
    is_request: bool
    key: Hashable
    name: str
    fields: dict[str, Any] = field(default_factory=dict)
    expects_answer: bool = True

    @property
    def peers(self) -> frozenset[str]:
        return frozenset((self.src, self.dst))


@dataclass
class Transaction:
    request: Message | None
    answer: Message | None

    @property
    def time(self) -> float:
        if self.request is not None:
            return self.request.time
        assert self.answer is not None
        return self.answer.time

    @property
    def rtt_ms(self) -> float | None:
        if self.request is None or self.answer is None:
            return None
        return round((self.answer.time - self.request.time) * 1000.0, 3)

    @property
    def unanswered(self) -> bool:
        return self.request is not None and self.answer is None and self.request.expects_answer


Compatible = Callable[[Message, Message], bool]


def pair_messages(messages: Iterable[Message], compatible: Compatible | None = None) -> list[Transaction]:
    """Pair requests with answers sharing the same ``key``.

    ``compatible`` can veto a candidate match (for example when both sides carry
    a Session-Id and they differ). Unmatched answers are returned as
    transactions with ``request=None`` so nothing silently disappears.
    """
    ordered = sorted(messages, key=lambda m: (m.time, m.frame))
    pending: dict[Hashable, deque[Transaction]] = defaultdict(deque)
    transactions: list[Transaction] = []
    for msg in ordered:
        if msg.is_request:
            tx = Transaction(request=msg, answer=None)
            transactions.append(tx)
            pending[msg.key].append(tx)
            continue
        queue = pending.get(msg.key)
        matched = None
        if queue:
            for candidate in queue:
                if compatible is None or compatible(candidate.request, msg):  # type: ignore[arg-type]
                    matched = candidate
                    break
        if matched is None:
            transactions.append(Transaction(request=None, answer=msg))
        else:
            matched.answer = msg
            queue.remove(matched)
    transactions.sort(key=lambda t: (t.time, (t.request or t.answer).frame))  # type: ignore[union-attr]
    return transactions


def base_row(tx: Transaction) -> dict[str, Any]:
    """Fields every paired transaction shares."""
    req, ans = tx.request, tx.answer
    anchor = req or ans
    assert anchor is not None
    row: dict[str, Any] = {
        "time": iso(anchor.time),
        "src": anchor.src,
        "dst": anchor.dst,
        "request_frame": req.frame if req else None,
        "answer_frame": ans.frame if ans else None,
        "rtt_ms": tx.rtt_ms,
    }
    if tx.unanswered:
        row["unanswered"] = True
    if req is None:
        row["unmatched_answer"] = True
    return row

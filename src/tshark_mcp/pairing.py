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


Compatible = Callable[[Message, Message], "bool | int"]


def pair_messages(messages: Iterable[Message], compatible: Compatible | None = None) -> list[Transaction]:
    """Pair requests with answers sharing the same ``key``.

    ``compatible`` can veto a candidate match (for example when both sides carry
    a Session-Id and they differ) or rank it: a false or zero result rejects
    the candidate, a higher integer is preferred over a lower one, and among
    equal ranks the oldest pending request wins. Unmatched answers are returned
    as transactions with ``request=None`` so nothing silently disappears.
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
        best = 0
        if queue:
            for candidate in queue:
                rank = 1 if compatible is None else int(compatible(candidate.request, msg))  # type: ignore[arg-type]
                if rank > best:
                    matched, best = candidate, rank
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


# ------------------------------------------------------------ proxy chains
DUPLICATE_WINDOW_S = 0.05
CHAIN_WINDOW_S = 1.0


def annotate_legs(txs: list[Transaction], rows: list[dict[str, Any]], identity: Callable[[Message], Hashable | None]) -> None:
    """Explain requests without a response on captures that hold several legs of one procedure.

    ``rows[i]`` is the row built from ``txs[i]``; rows are changed in place.

    - **Duplicates**: the same request (same peers, sequence key and name) seen again
      within 50 ms is one packet captured twice (two interfaces or a mirror), not a
      retransmission; it gets ``duplicate_of_frame`` instead of ``unanswered``.
    - **Proxy chains**: requests with the same ``identity`` (for GTP: IMSI, message and
      APN) within one second of the first are legs of one procedure relayed through
      proxies. When at least one leg has no response, every leg of the chain gets
      ``chain`` (``leg`` k of ``legs`` in time order, how many legs were answered and on
      which frames); fully answered chains are left as they are. When some legs were answered, a leg without a
      response gets ``leg_without_response`` instead of ``unanswered``, with a note
      saying whether the answered leg is further along the chain (the response was not
      relayed back on this leg, or was not captured here) or before it. When no leg was
      answered every leg stays ``unanswered``: the procedure itself got no response.
    """
    seen: dict[tuple, Message] = {}
    dup: set[int] = set()
    for i, tx in enumerate(txs):
        req = tx.request
        if req is None:
            continue
        k = (req.src, req.dst, req.key, req.name)
        first_copy = seen.get(k)
        if first_copy is not None and req.time - first_copy.time <= DUPLICATE_WINDOW_S and tx.answer is None:
            dup.add(i)
            rows[i].pop("unanswered", None)
            rows[i]["duplicate_of_frame"] = first_copy.frame
            rows[i]["note"] = "the same request captured twice (identical packet seen again), not a retransmission"
        else:
            seen[k] = req
    groups: dict[Hashable, list[list[int]]] = {}
    order = sorted((i for i, tx in enumerate(txs) if tx.request is not None and i not in dup),
                   key=lambda i: (txs[i].request.time, txs[i].request.frame))  # type: ignore[union-attr]
    for i in order:
        req = txs[i].request
        assert req is not None
        ident = identity(req)
        if ident is None:
            continue
        chains = groups.setdefault(ident, [])
        if chains and req.time - txs[chains[-1][0]].request.time <= CHAIN_WINDOW_S:  # type: ignore[union-attr]
            chains[-1].append(i)
        else:
            chains.append([i])
    for chains in groups.values():
        for chain in chains:
            answered = [i for i in chain if txs[i].answer is not None]
            if len(chain) < 2 or len(answered) == len(chain):
                continue  # a single request, or every leg answered: nothing to explain
            answer_frames = [txs[i].answer.frame for i in answered]  # type: ignore[union-attr]
            for pos, i in enumerate(chain):
                row = rows[i]
                row["chain"] = {"leg": pos + 1, "legs": len(chain), "answered_legs": len(answered),
                                **({"answered_on_frames": answer_frames} if answer_frames else {})}
                if txs[i].answer is not None or not answered or not row.get("unanswered"):
                    continue
                row.pop("unanswered", None)
                row["leg_without_response"] = True
                later = [j for j in answered if chain.index(j) > pos]
                if later:
                    j = later[0]
                    row["note"] = (f"no response on this leg, but leg {chain.index(j) + 1} further along the chain was "
                                   f"answered (frame {txs[j].answer.frame}{_cause(rows[j])}): the response was not "  # type: ignore[union-attr]
                                   "relayed back to this sender, or was not captured on this leg")
                else:
                    j = answered[-1]
                    row["note"] = (f"no response on this leg; leg {chain.index(j) + 1} before it was answered (frame "
                                   f"{txs[j].answer.frame}{_cause(rows[j])}): the node that relayed this request answered "  # type: ignore[union-attr]
                                   "on its own (the next hop did not answer), or the response on this leg was not captured")


def _cause(row: dict[str, Any]) -> str:
    cause, name = row.get("cause"), row.get("cause_name")
    if cause is None:
        return ""
    return f", cause {cause} {name}" if name else f", cause {cause}"
